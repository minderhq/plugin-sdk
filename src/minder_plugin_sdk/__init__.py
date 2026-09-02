"""Minder plugin authoring SDK.

    from minder_plugin_sdk import PluginMetadata, Plugin

See ``contract.py`` for the full lifecycle and the optional CONFIG_SCHEMA /
ACTIONS / AI_TOOLS extension points, and ``examples/`` for a worked plugin.
"""

from .contract import Plugin, PluginMetadata

__all__ = ["PluginMetadata", "Plugin", "__version__"]

__version__ = "0.2.0"
