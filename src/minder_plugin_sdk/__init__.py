"""Minder plugin authoring SDK.

    from minder_plugin_sdk import PluginMetadata, Plugin

See ``contract.py`` for the lifecycle + the CONFIG_SCHEMA / ACTIONS / AI_TOOLS /
DISPLAY extension points, ``schema.py`` for JSON-Schema config, ``capabilities.py``
for the capability model, ``docs/rfc/0001-extensible-plugin-contract.md`` for the
design, and ``examples/`` for a worked plugin.
"""

from .capabilities import KNOWN_CAPABILITIES, capabilities
from .contract import Plugin, PluginMetadata
from .schema import fields_to_json_schema, resolve_config_schema

API_VERSION = "minder.dev/v1"

__all__ = [
    "PluginMetadata",
    "Plugin",
    "capabilities",
    "KNOWN_CAPABILITIES",
    "resolve_config_schema",
    "fields_to_json_schema",
    "API_VERSION",
    "__version__",
]

__version__ = "0.3.0"
