"""Read checks Home Assistant's core does not make for restricted users.

Home Assistant checks entity permissions for states, history and entity actions,
but some commands return entity data to any signed-in user: templates, the
logbook, statistics, condition subscriptions and a few others. For users without
access to all entities (administrators and ordinary users are not affected) the
guard refuses those commands or limits them to the allowed entities.

It works on a fixed list of commands, so it cannot know about commands of other
integrations or ones added by later Home Assistant versions.
"""

from __future__ import annotations

from collections.abc import Callable
import logging
from typing import Any

from homeassistant.const import EVENT_COMPONENT_LOADED, EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import CoreState, HomeAssistant, callback
from homeassistant.exceptions import Unauthorized

_LOGGER = logging.getLogger(__name__)

DATA_GUARD = "access_roles_guard"
READ = "read"
CONTROL = "control"

# Commands that cannot be limited to entities: refused.
DENY = frozenset({
    "render_template",
    "subscribe_condition",
    "logbook/event_stream",
    "logbook/get_events",
    "energy/fossil_energy_consumption",
    "energy/solar_forecast",
    "recorder/validate_statistics",
})
DENY_SUFFIX = "/start_preview"  # template/, group/, history_stats/, ... previews

# Commands about one entity: command -> needed permission.
ENTITY = {
    "todo/item/list": READ,
    "todo/item/subscribe": READ,
    "todo/item/move": CONTROL,
    "weather/subscribe_forecast": READ,
    "camera/capabilities": READ,
    "camera/stream": READ,
    "camera/get_prefs": READ,
}

# What must be found when the component is loaded, else the guard is incomplete.
EXPECTED = {
    "websocket_api": ("render_template", "subscribe_condition"),
    "logbook": ("logbook/event_stream", "logbook/get_events"),
    "recorder": ("recorder/statistic_during_period", "recorder/statistics_during_period",
                 "recorder/list_statistic_ids", "recorder/get_statistics_metadata"),
}


def restricted(user: Any) -> bool:
    """Whether the user may see only some entities."""
    return not user.is_admin and not user.permissions.access_all_entities(READ)


def _deny(connection: Any, msg: dict[str, Any]) -> None:
    connection.send_error(msg["id"], "unauthorized", "Not allowed for your role")


def _allowed(user: Any, ids: list[str]) -> list[str]:
    # External statistics ("domain:name") belong to no entity: not allowed.
    return [i for i in ids if "." in i and ":" not in i and user.permissions.check_entity(i, READ)]


def check_command(command: str, hass: Any, connection: Any, msg: dict[str, Any],
                  call: Callable[[Any, Any, dict[str, Any]], Any]) -> Any:
    """Run one guarded command for a restricted user."""
    user = connection.user
    if command in DENY or command.endswith(DENY_SUFFIX):
        return _deny(connection, msg)
    if (permission := ENTITY.get(command)) is not None:
        entity_id = msg.get("entity_id")
        if not isinstance(entity_id, str) or not user.permissions.check_entity(entity_id, permission):
            return _deny(connection, msg)
        return call(hass, connection, msg)
    if command == "recorder/statistic_during_period":
        if not _allowed(user, [msg.get("statistic_id") or ""]):
            return _deny(connection, msg)
        return call(hass, connection, msg)
    if command == "recorder/statistics_during_period":
        if not (ids := _allowed(user, msg.get("statistic_ids") or [])):
            return connection.send_result(msg["id"], {})
        return call(hass, connection, {**msg, "statistic_ids": ids})
    if command == "recorder/get_statistics_metadata":
        # Without ids the command would return everything.
        if not (ids := _allowed(user, msg.get("statistic_ids") or [])):
            return connection.send_result(msg["id"], [])
        return call(hass, connection, {**msg, "statistic_ids": ids})
    if command == "recorder/list_statistic_ids":
        return connection.send_result(msg["id"], [])
    return _deny(connection, msg)


def is_guarded(command: str) -> bool:
    return (command in DENY or command in ENTITY or command.endswith(DENY_SUFFIX)
            or command in EXPECTED["recorder"])


class Guard:
    """Wraps the registered commands; installed once until Home Assistant stops."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    def _wrap(self, command: str, handler: Callable[[Any, Any, dict[str, Any]], Any]):
        @callback
        def guarded(hass: Any, connection: Any, msg: dict[str, Any]) -> Any:
            if restricted(connection.user):
                return check_command(command, hass, connection, msg, handler)
            return handler(hass, connection, msg)

        guarded._access_roles = True  # type: ignore[attr-defined]  # noqa: SLF001
        return guarded

    @callback
    def refresh(self, _event: Any = None) -> None:
        """Wrap commands that appeared since the last time."""
        handlers = self.hass.data.get("websocket_api")
        if isinstance(handlers, dict):
            for command, value in list(handlers.items()):
                if not is_guarded(command) or not isinstance(value, tuple) or len(value) != 2:
                    continue
                if not getattr(value[0], "_access_roles", False):
                    handlers[command] = (self._wrap(command, value[0]), value[1])
        self._guard_logbook_rest()

    def _guard_logbook_rest(self) -> None:
        if "logbook" not in self.hass.config.components:
            return
        from homeassistant.components.http import KEY_HASS_USER, current_request  # noqa: PLC0415
        from homeassistant.components.logbook import rest_api  # noqa: PLC0415

        original = getattr(rest_api, "EventProcessor", None)
        if original is None or getattr(original, "_access_roles", False):
            return

        def guarded(*args: Any, **kwargs: Any) -> Any:
            # Only used by the view, so there always is a request.
            request = current_request.get()
            user = request.get(KEY_HASS_USER) if request is not None else None
            if user is None or restricted(user):
                raise Unauthorized
            return original(*args, **kwargs)

        guarded._access_roles = True  # type: ignore[attr-defined]  # noqa: SLF001
        rest_api.EventProcessor = guarded

    def missing(self) -> list[str]:
        """Protections that should be there but are not."""
        handlers = self.hass.data.get("websocket_api")
        if not isinstance(handlers, dict):
            return ["websocket_api"]
        out = [c for component, commands in EXPECTED.items()
               if component in self.hass.config.components
               for c in commands
               if not (isinstance(handlers.get(c), tuple)
                       and getattr(handlers[c][0], "_access_roles", False))]
        if "logbook" in self.hass.config.components:
            from homeassistant.components.logbook import rest_api  # noqa: PLC0415

            if not getattr(getattr(rest_api, "EventProcessor", None), "_access_roles", False):
                out.append("/api/logbook")
        return out


@callback
def async_install(hass: HomeAssistant, on_ready: Callable[[list[str]], None]) -> None:
    """Install the guard once; ``on_ready`` gets what could not be protected."""
    guard: Guard | None = hass.data.get(DATA_GUARD)
    if guard is None:
        guard = hass.data[DATA_GUARD] = Guard(hass)
        hass.bus.async_listen(EVENT_COMPONENT_LOADED, guard.refresh)
    guard.refresh()

    @callback
    def _report(_event: Any = None) -> None:
        guard.refresh()
        on_ready(guard.missing())

    if hass.state is CoreState.running:
        _report()
    else:
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _report)
