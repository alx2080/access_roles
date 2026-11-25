# Access Roles

**English** | [Українська](README.uk.md)

A Home Assistant custom integration: per-user access set up in the UI. A role defines which areas, devices and entities a user **sees** and which ones they **operate**.

## How it works

The Home Assistant core already has per-entity permissions:
- a user belongs to groups, and a group has a policy: read and control by entity, device and area;
- the core checks these permissions when it serves states (REST, WebSocket, browser) and for entity actions.

There is just no UI to set them. This integration adds it: each role becomes a group, and the role's users become its members.

- **Sees:** the user receives states and history only of these areas, devices and entities (for exceptions see "Limitations").
- **Operates:** Home Assistant refuses actions on other entities with an "Unauthorized" error. "Operates" includes "Sees".
- **An area** covers all devices in it and their entities, **a device** covers all its entities.
- **Several roles:** permissions add up.
- **Administrators** are not restricted. A warning appears under Repairs if an administrator is selected in a role.

## Installation and setup

1. **Install.**
   - HACS: Custom repositories → `https://github.com/alx2080/access_roles` (Integration).
   - Or manually: copy `custom_components/access_roles` to `config/custom_components/`.

   Then restart Home Assistant.
2. Settings → Devices & services → Add integration → Access Roles.
3. On the integration card press **+ Add role**: name, users, "Sees" and "Operates".
4. To edit or delete a role use ⋮ next to it. Changes apply immediately; the user sees them after reloading the page.

Create users as usual under Settings → People, **without** the "Administrator" checkbox.

## Safety

- **Disabling the integration** does not lift the role restrictions: Home Assistant itself keeps the groups in `.storage/auth`. But the additional read protection (below) does not work after a Home Assistant restart without the integration.
- **Editing a user under People** resets their groups; the integration puts the role back right away.
- **Removing the integration** gives every user back the groups they had before the roles.
- **After a Home Assistant update** the integration checks the authorization internals. If something changed, it changes nothing and reports it under Repairs. Restrictions applied earlier stay in force.

## Checking permissions

The action `access_roles.check` (administrators only) shows what a user may do with entities:

```yaml
action: access_roles.check
data:
  user: Operator
  entity_id: [sensor.temp_1, switch.pump_1]
```

## Read protection

The Home Assistant 2026.11.2 core checks permissions for states, history and entity actions, but serves part of the data to any user. For restricted users the integration closes:

| What | How |
|---|---|
| templates (`render_template`), `subscribe_condition`, previews (`*/start_preview`) | refused |
| logbook: WebSocket and `/api/logbook` | refused |
| statistics (`recorder/*`) | allowed entities only, lists are empty |
| energy statistics | refused |
| to-do lists, weather forecast, cameras (WebSocket) | allowed entities only |

That is why **Activity and template-based cards** (for example Markdown) **do not work** for restricted users. Administrators and ordinary users without a role are not affected.

If one of these logbook, statistics or template entry points cannot be closed on a newer Home Assistant version, a message appears under Repairs.

## Limitations

> **This does not protect confidential data.** A known list of commands is closed. The integration does not know about commands of other integrations or of newer Home Assistant versions.

- **Not closed:** the Assist voice assistant (it sees entities exposed to it in the settings), HTTP links of cameras, names in the device and entity registries, commands of third-party integrations.
- **Actions without an entity** (`mqtt.publish`, notifications and so on) are not limited by entity permissions.
- **The first seconds after Home Assistant starts:** a subscription opened before the integration has loaded stays until it reconnects.
- **Dashboards are not hidden automatically.** Cards of entities that are not allowed show that the entity is unavailable.

**What was tested** on Home Assistant 2026.11.2 signed in as a restricted user (a role that sees one device): states, history, logbook, statistics, templates, conditions, to-do lists, weather forecast, refused actions. A role that allows "Operates", cameras, energy statistics, previews and removal of the integration were not tested live.
