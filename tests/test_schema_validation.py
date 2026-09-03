"""config validation flags unknown keys, and PluginBase health gates on init."""

import asyncio

from minder_plugin_sdk import (
    PluginBase,
    PluginMetadata,
    config_errors,
    resolve_config_schema,
)


class _P:
    CONFIG_SCHEMA = [{"key": "ENABLED", "type": "bool", "default": True}]


def test_unknown_config_key_is_flagged():
    schema, _ = resolve_config_schema(_P())
    errs = config_errors(schema, {"ENABLED": True, "TYPOD": 1})
    assert any("TYPOD" in e and "unknown" in e for e in errs), errs
    # a declared key alone is valid
    assert config_errors(schema, {"ENABLED": True}) == []


def test_pluginbase_healthy_only_after_initialize():
    class _B(PluginBase):
        async def register(self) -> PluginMetadata:
            return PluginMetadata(
                name="b", version="1.0.0", description="d", author="a"
            )

    p = _B()
    # pre-init status is "registered" → must NOT read healthy
    assert asyncio.run(p.health_check()) == {"healthy": False}
    asyncio.run(p.initialize())
    assert asyncio.run(p.health_check()) == {"healthy": True}
