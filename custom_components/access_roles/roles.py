"""Turning roles into Home Assistant permission groups.

Home Assistant already has per-entity permissions in its core: a user belongs to
groups, every group has a policy ("entities" -> read / control by entity,
device, area or domain), and the core checks them for states (REST, WebSocket),
entity actions and the frontend. There is just no UI to create groups. This
module creates one group per role and puts the role's users into it.

Groups are stored by Home Assistant itself (``.storage/auth``), so restrictions
stay in force even while this integration is disabled; removing the integration
gives every user back the groups they had before.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.models import Group, User
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    CONF_CONTROL_AREAS,
    CONF_CONTROL_DEVICES,
    CONF_CONTROL_ENTITIES,
    CONF_READ_AREAS,
    CONF_READ_DEVICES,
    CONF_READ_ENTITIES,
    CONF_USERS,
    GROUP_PREFIX,
    STORE_KEY,
    STORE_VERSION,
)

_LOGGER = logging.getLogger(__name__)


class RolesUnavailable(Exception):
    """Home Assistant's auth internals are not as expected."""


def _auth_store(hass: HomeAssistant):
    store = getattr(hass.auth, "_store", None)
    groups = getattr(store, "_groups", None)
    if store is None or not isinstance(groups, dict) or not hasattr(store, "_async_schedule_save"):
        raise RolesUnavailable("hass.auth._store._groups / _async_schedule_save not found")
    try:
        Group(name="check", policy={"entities": {}}, id="check", system_generated=False)
    except TypeError as err:
        raise RolesUnavailable(f"auth Group model changed: {err}") from err
    return store


def build_policy(data: dict[str, Any]) -> dict[str, Any]:
    """The Home Assistant policy of one role."""
    entities: dict[str, dict[str, dict[str, bool]]] = {}

    def grant(category: str, ids: list[str], control: bool) -> None:
        for item in ids or []:
            value = entities.setdefault(category, {}).setdefault(item, {})
            value["read"] = True
            if control:
                value["control"] = True

    grant("area_ids", data.get(CONF_READ_AREAS), False)
    grant("device_ids", data.get(CONF_READ_DEVICES), False)
    grant("entity_ids", data.get(CONF_READ_ENTITIES), False)
    grant("area_ids", data.get(CONF_CONTROL_AREAS), True)
    grant("device_ids", data.get(CONF_CONTROL_DEVICES), True)
    grant("entity_ids", data.get(CONF_CONTROL_ENTITIES), True)
    return {"entities": entities}


class RoleManager:
    """Applies the configured roles to Home Assistant's users and groups."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        # user_id -> group ids the user had before a role was applied
        self._store: Store[dict[str, list[str]]] = Store(hass, STORE_VERSION, STORE_KEY, private=True)
        self.original: dict[str, list[str]] = {}

    async def async_load(self) -> None:
        self.original = await self._store.async_load() or {}

    async def async_apply(self, roles: dict[str, tuple[str, dict[str, Any]]]) -> dict[str, Any]:
        """roles: subentry_id -> (title, data). Returns a summary."""
        store = _auth_store(self.hass)
        users = {u.id: u for u in await self.hass.auth.async_get_users()}

        # 1. One group per role (created or updated in place).
        wanted: dict[str, Group] = {}
        for role_id, (title, data) in roles.items():
            gid = GROUP_PREFIX + role_id
            policy = build_policy(data)
            group = store._groups.get(gid)  # noqa: SLF001
            if group is None:
                group = Group(name=title, policy=policy, id=gid, system_generated=False)
                store._groups[gid] = group  # noqa: SLF001
            else:
                group.name = title
                group.policy = policy
            wanted[gid] = group

        # 2. Which roles each user gets.
        user_roles: dict[str, list[str]] = {}
        skipped_admins: list[str] = []
        for role_id, (_title, data) in roles.items():
            for user_id in data.get(CONF_USERS) or []:
                user = users.get(user_id)
                if user is None or user.system_generated:
                    continue
                if user.is_owner or any(g.id == GROUP_ID_ADMIN for g in user.groups):
                    skipped_admins.append(user.name or user_id)
                    continue
                user_roles.setdefault(user_id, []).append(GROUP_PREFIX + role_id)

        # 3. Put users into their role groups (remembering what they had).
        for user_id, gids in user_roles.items():
            user = users[user_id]
            if user_id not in self.original:
                self.original[user_id] = [g.id for g in user.groups if not g.id.startswith(GROUP_PREFIX)]
            await self.hass.auth.async_update_user(user, group_ids=gids)

        # 4. Users no longer in any role get their old groups back.
        #    (Someone made admin in the meantime keeps being admin.)
        for user_id in [u for u in self.original if u not in user_roles]:
            saved = self.original.pop(user_id)
            user = users.get(user_id)
            if user is not None and not any(g.id == GROUP_ID_ADMIN for g in user.groups):
                await self._restore_user(user, saved)

        # 5. Drop groups of deleted roles (nobody is in them any more).
        for gid in [g for g in store._groups if g.startswith(GROUP_PREFIX) and g not in wanted]:  # noqa: SLF001
            for user in users.values():
                if any(g.id == gid for g in user.groups):
                    await self.hass.auth.async_update_user(
                        user, group_ids=[g.id for g in user.groups if g.id != gid] or [GROUP_ID_USER])
            del store._groups[gid]  # noqa: SLF001

        # 6. Policies may have changed in place: drop every cached permission.
        for user in users.values():
            user.invalidate_cache()
        store._async_schedule_save()  # noqa: SLF001
        await self._store.async_save(self.original)
        if skipped_admins:
            _LOGGER.warning("access_roles: administrators are not restricted by roles: %s",
                            ", ".join(skipped_admins))
        return {"roles": len(wanted), "users": len(user_roles), "skipped_admins": skipped_admins}

    async def _restore_user(self, user: User | None, group_ids: list[str]) -> None:
        if user is None:
            return
        store = _auth_store(self.hass)
        valid = [g for g in group_ids if g in store._groups] or [GROUP_ID_USER]  # noqa: SLF001
        await self.hass.auth.async_update_user(user, group_ids=valid)

    async def async_remove_all(self) -> None:
        """Integration removed: everyone gets their old groups, role groups go."""
        store = _auth_store(self.hass)
        users = {u.id: u for u in await self.hass.auth.async_get_users()}
        for user_id, gids in list(self.original.items()):
            await self._restore_user(users.get(user_id), gids)
        for user in users.values():
            if any(g.id.startswith(GROUP_PREFIX) for g in user.groups):
                await self.hass.auth.async_update_user(
                    user, group_ids=[g.id for g in user.groups if not g.id.startswith(GROUP_PREFIX)]
                    or [GROUP_ID_USER])
        for gid in [g for g in store._groups if g.startswith(GROUP_PREFIX)]:  # noqa: SLF001
            del store._groups[gid]  # noqa: SLF001
        for user in users.values():
            user.invalidate_cache()
        store._async_schedule_save()  # noqa: SLF001
        self.original = {}
        await self._store.async_remove()
