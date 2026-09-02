"""The smallest useful plugin — inherit PluginBase, override only what you need.

PluginBase supplies initialize / health_check / analyze / shutdown / apply_config,
so a data-source plugin is really just ``register`` + ``collect_data``.
"""

from minder_plugin_sdk import PluginBase, PluginMetadata

__all__ = ["MinimalPlugin"]


class MinimalPlugin(PluginBase):
    async def register(self) -> PluginMetadata:
        return PluginMetadata(
            name="minimal",
            version="1.0.0",
            description="A minimal data-source plugin.",
            author="minderhq",
            capabilities=["collect"],
        )

    async def collect_data(self) -> dict:
        self._last = {"value": 42, "note": "replace with a real fetch"}
        return self._last
