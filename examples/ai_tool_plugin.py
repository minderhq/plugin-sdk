"""An AI-tool-only plugin — no data collection, just a function-calling tool.

Shows a plugin whose whole job is to expose an ``ai-tools`` capability: an ACTION
the LLM can call. It doesn't poll anything, so it leans entirely on PluginBase's
defaults and declares its capabilities explicitly.
"""

from minder_plugin_sdk import PluginBase, PluginMetadata

__all__ = ["UnitConverterPlugin"]

_FACTORS_TO_METERS = {"m": 1.0, "km": 1000.0, "mi": 1609.344, "ft": 0.3048}


class UnitConverterPlugin(PluginBase):
    CAPABILITIES = ["actions", "ai-tools"]

    ACTIONS = frozenset({"convert_length"})
    READ_ONLY_ACTIONS = frozenset({"convert_length"})

    AI_TOOLS = [
        {
            "name": "convert_length",
            "description": "Convert a length between units (m, km, mi, ft).",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {"type": "number"},
                    "from_unit": {"type": "string", "enum": list(_FACTORS_TO_METERS)},
                    "to_unit": {"type": "string", "enum": list(_FACTORS_TO_METERS)},
                },
                "required": ["value", "from_unit", "to_unit"],
            },
            "action": "convert_length",
            "method": "GET",
        },
    ]

    async def register(self) -> PluginMetadata:
        return PluginMetadata(
            name="unit-converter",
            version="1.0.0",
            description="Convert lengths between units, as an AI tool.",
            author="minderhq",
            capabilities=["ai-tools"],
        )

    async def convert_length(self, value: float, from_unit: str, to_unit: str) -> dict:
        try:
            meters = float(value) * _FACTORS_TO_METERS[from_unit]
            result = meters / _FACTORS_TO_METERS[to_unit]
        except (KeyError, TypeError, ValueError):
            return {"error": f"cannot convert {from_unit!r} → {to_unit!r}"}
        return {"value": result, "unit": to_unit}
