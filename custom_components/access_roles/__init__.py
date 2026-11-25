"""Access Roles: per-user access to areas, devices and entities, set up in the UI.

Every role (a subentry of the single config entry) becomes a Home Assistant
permission group. Users of a role see only what the role allows ("read") and can
operate only what it allows ("control"); Home Assistant's core enforces it.
Administrators are never restricted.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import __version__ as HA_VERSION
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers import config_validation as cv, issue_registry as ir
from homeassistant.helpers.service import async_register_admin_service

try:  # Home Assistant 2026.x moved from voluptuous to probatio
    import probatio as vol
except ImportError:  # pragma: no cover
    import voluptuous as vol

from .const import DOMAIN, SUBENTRY_ROLE
from .roles import RoleManager, RolesUnavailable

_LOGGER = logging.getLogger(__name__)


def _roles(entry: ConfigEntry) -> dict[str, tuple[str, dict[str, Any]]]:
    return {
        sid: (sub.title, dict(sub.data))
        for sid, sub in entry.subentries.items()
        if sub.subentry_type == SUBENTRY_ROLE
    }


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    manager = RoleManager(hass)
    await manager.async_load()
    try:
        summary = await manager.async_apply(_roles(entry))
    except RolesUnavailable as err:
        ir.async_create_issue(
            hass, DOMAIN, "incompatible", is_fixable=False, severity=ir.IssueSeverity.ERROR,
            translation_key="incompatible",
            translation_placeholders={"reason": str(err), "version": HA_VERSION})
        raise ConfigEntryError(str(err)) from err
    ir.async_delete_issue(hass, DOMAIN, "incompatible")
    if summary["skipped_admins"]:
        ir.async_create_issue(
            hass, DOMAIN, "admins_in_roles", is_fixable=False, severity=ir.IssueSeverity.WARNING,
            translation_key="admins_in_roles",
            translation_placeholders={"users": ", ".join(summary["skipped_admins"])})
    else:
        ir.async_delete_issue(hass, DOMAIN, "admins_in_roles")
    _LOGGER.info("access_roles: %s roles applied to %s users", summary["roles"], summary["users"])
    entry.runtime_data = manager
    _register_services(hass)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


async def _async_reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.config_entries.async_schedule_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    # Groups stay in Home Assistant's auth storage: disabling the integration
    # must not silently give restricted users full access.
    hass.services.async_remove(DOMAIN, "check")
    return True


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Integration deleted: give everyone their previous groups back."""
    manager = RoleManager(hass)
    await manager.async_load()
    try:
        await manager.async_remove_all()
    except RolesUnavailable as err:
        _LOGGER.error("access_roles: could not restore user groups: %s", err)
    for issue in ("incompatible", "admins_in_roles"):
        ir.async_delete_issue(hass, DOMAIN, issue)


def _register_services(hass: HomeAssistant) -> None:
    async def _check(call: ServiceCall) -> dict[str, Any]:
        """What a user may do with an entity (for testing roles)."""
        users = await hass.auth.async_get_users()
        ident = call.data["user"]
        user = next((u for u in users if u.id == ident or u.name == ident), None)
        if user is None:
            return {"error": f"user {ident!r} not found"}
        result: dict[str, Any] = {
            "user": user.name, "is_admin": user.is_admin,
            "groups": [g.name for g in user.groups], "entities": {},
        }
        for entity_id in call.data["entity_id"]:
            result["entities"][entity_id] = {
                "read": user.permissions.check_entity(entity_id, "read"),
                "control": user.permissions.check_entity(entity_id, "control"),
            }
        return result

    # Administrators only: it reveals other users' permissions.
    async_register_admin_service(
        hass, DOMAIN, "check", _check,
        schema=vol.Schema({vol.Required("user"): cv.string,
                           vol.Required("entity_id"): cv.entity_ids}),
        supports_response=SupportsResponse.ONLY)
