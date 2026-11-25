"""Config flow for Access Roles: one entry, every role is a subentry."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homeassistant.auth.const import GROUP_ID_ADMIN
from homeassistant.config_entries import (
    SOURCE_RECONFIGURE,
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    ConfigSubentryFlow,
    SubentryFlowResult,
)
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    AreaSelector,
    AreaSelectorConfig,
    DeviceSelector,
    DeviceSelectorConfig,
    EntitySelector,
    EntitySelectorConfig,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
)
from homeassistant.helpers.translation import async_get_translations

try:  # Home Assistant 2026.x moved from voluptuous to probatio
    import probatio as vol
except ImportError:  # pragma: no cover
    import voluptuous as vol

from .const import (
    CONF_CONTROL_AREAS,
    CONF_CONTROL_DEVICES,
    CONF_CONTROL_ENTITIES,
    CONF_READ_AREAS,
    CONF_READ_DEVICES,
    CONF_READ_ENTITIES,
    CONF_USERS,
    DOMAIN,
    SCOPE_KEYS,
    SUBENTRY_ROLE,
)


async def _text(hass: HomeAssistant, category: str, key: str, default: str) -> str:
    """Text in the language of the Home Assistant server."""
    texts = await async_get_translations(hass, hass.config.language, category, {DOMAIN})
    return texts.get(f"component.{DOMAIN}.{category}.{key}", default)


class AccessRolesConfigFlow(ConfigFlow, domain=DOMAIN):
    """Add Access Roles (single instance)."""

    VERSION = 1

    @classmethod
    @callback
    def async_get_supported_subentry_types(cls, config_entry: ConfigEntry) -> dict[str, type[ConfigSubentryFlow]]:
        return {SUBENTRY_ROLE: RoleSubentryFlow}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is not None:
            title = await _text(self.hass, "config", "step.user.title", "Access Roles")
            return self.async_create_entry(title=title, data={})
        return self.async_show_form(step_id="user", data_schema=vol.Schema({}))


class RoleSubentryFlow(ConfigSubentryFlow):
    """Add or edit one role."""

    async def _user_options(self) -> list[SelectOptionDict]:
        unrestricted = await _text(self.hass, "common", "administrator", "administrator, not restricted")
        options = []
        for user in await self.hass.auth.async_get_users():
            if user.system_generated:
                continue
            admin = user.is_owner or any(g.id == GROUP_ID_ADMIN for g in user.groups)
            label = (user.name or user.id) + (f" ({unrestricted})" if admin else "")
            options.append(SelectOptionDict(value=user.id, label=label))
        return sorted(options, key=lambda o: o["label"].lower())

    async def _schema(self, d: Mapping[str, Any]) -> vol.Schema:
        def multi(key: str, selector) -> tuple:
            return vol.Optional(key, default=list(d.get(key) or [])), selector

        area = AreaSelector(AreaSelectorConfig(multiple=True))
        device = DeviceSelector(DeviceSelectorConfig(multiple=True))
        entity = EntitySelector(EntitySelectorConfig(multiple=True))
        fields: dict[Any, Any] = {
            vol.Required(CONF_NAME, default=d.get(CONF_NAME, "")): TextSelector(),
            vol.Optional(CONF_USERS, default=list(d.get(CONF_USERS) or [])): SelectSelector(
                SelectSelectorConfig(options=await self._user_options(), multiple=True,
                                     mode=SelectSelectorMode.LIST)),
        }
        for key, sel in ((CONF_READ_AREAS, area), (CONF_READ_DEVICES, device),
                         (CONF_READ_ENTITIES, entity), (CONF_CONTROL_AREAS, area),
                         (CONF_CONTROL_DEVICES, device), (CONF_CONTROL_ENTITIES, entity)):
            k, s = multi(key, sel)
            fields[k] = s
        return vol.Schema(fields)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        return await self._form("user", user_input)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        return await self._form("reconfigure", user_input)

    async def _form(self, step_id: str, user_input: dict[str, Any] | None) -> SubentryFlowResult:
        reconfigure = self.source == SOURCE_RECONFIGURE
        errors: dict[str, str] = {}
        if user_input is not None:
            name = user_input.pop(CONF_NAME).strip()
            data = {k: list(user_input.get(k) or []) for k in (CONF_USERS, *SCOPE_KEYS)}
            if not name:
                errors[CONF_NAME] = "name_required"
            elif not any(data[k] for k in SCOPE_KEYS):
                errors["base"] = "nothing_allowed"
            else:
                if reconfigure:
                    return self.async_update_and_abort(
                        self._get_entry(), self._get_reconfigure_subentry(), title=name, data=data)
                return self.async_create_entry(title=name, data=data)
            defaults: Mapping[str, Any] = {CONF_NAME: name, **data}
        elif reconfigure:
            sub = self._get_reconfigure_subentry()
            defaults = {CONF_NAME: sub.title, **sub.data}
        else:
            defaults = {}
        return self.async_show_form(step_id=step_id, data_schema=await self._schema(defaults),
                                    errors=errors)
