"""Constants for Access Roles."""

from typing import Final

DOMAIN: Final = "access_roles"
SUBENTRY_ROLE: Final = "role"
GROUP_PREFIX: Final = "access_roles_"

CONF_USERS: Final = "users"
CONF_READ_AREAS: Final = "read_areas"
CONF_READ_DEVICES: Final = "read_devices"
CONF_READ_ENTITIES: Final = "read_entities"
CONF_CONTROL_AREAS: Final = "control_areas"
CONF_CONTROL_DEVICES: Final = "control_devices"
CONF_CONTROL_ENTITIES: Final = "control_entities"

SCOPE_KEYS: Final = (
    CONF_READ_AREAS, CONF_READ_DEVICES, CONF_READ_ENTITIES,
    CONF_CONTROL_AREAS, CONF_CONTROL_DEVICES, CONF_CONTROL_ENTITIES,
)

STORE_KEY: Final = f"{DOMAIN}.original_groups"
STORE_VERSION: Final = 1
