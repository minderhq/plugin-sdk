"""Contract tests: a plugin that implements the lifecycle satisfies ``Plugin``,
and the worked example honours the one easy-to-miss rule (health_check →
``{"healthy": bool}``)."""

import asyncio
import sys
from pathlib import Path

from minder_plugin_sdk import Plugin, PluginMetadata

# Make the examples/ dir importable for the worked-plugin test.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))


class _FullPlugin:
    """Implements the whole Protocol, incl. the optional apply_config hook."""

    async def register(self) -> PluginMetadata:
        return PluginMetadata(name="full", version="1.0.0", description="d", author="a")

    async def initialize(self) -> None: ...

    async def health_check(self):
        return {"healthy": True}

    async def collect_data(self):
        return {}

    async def analyze(self):
        return {}

    async def shutdown(self) -> None: ...

    def apply_config(self, config) -> None: ...


class _DuckTypedPlugin:
    """The registry loads any class that defines ``register`` — no apply_config."""

    async def register(self) -> PluginMetadata:
        return PluginMetadata(name="duck", version="1.0.0", description="d", author="a")


def test_full_plugin_satisfies_protocol():
    # runtime_checkable checks presence of ALL Protocol members (incl. apply_config).
    assert isinstance(_FullPlugin(), Plugin)


def test_loader_criterion_is_register_presence():
    # The registry duck-types on register(), so a class without the optional
    # apply_config is still a loadable plugin — even though it won't satisfy the
    # full runtime_checkable Protocol.
    assert hasattr(_DuckTypedPlugin(), "register")
    assert not isinstance(_DuckTypedPlugin(), Plugin)  # missing apply_config


def test_metadata_registered_at_isoformats():
    # the loader calls .isoformat() on registered_at
    md = PluginMetadata(name="n", version="1.0.0", description="d", author="a")
    assert md.registered_at.isoformat()
    assert md.dependencies == [] and md.capabilities == []


def test_example_weather_plugin_is_a_valid_plugin():
    from weather_plugin import WeatherPlugin  # type: ignore

    p = WeatherPlugin()
    assert isinstance(p, Plugin)
    md = asyncio.run(p.register())
    assert isinstance(md, PluginMetadata) and md.name == "weather"
    health = asyncio.run(p.health_check())
    # THE gotcha: monitoring reads health["healthy"] — it must be a bool.
    assert isinstance(health.get("healthy"), bool)
    # extension points are declared as class attributes
    assert "get_weather" in WeatherPlugin.ACTIONS
    assert WeatherPlugin.AI_TOOLS[0]["action"] in WeatherPlugin.ACTIONS


def test_example_presentation_contract_is_well_formed():
    """The plugin-driven UI metadata: DISPLAY branding + per-field widgets, and
    any options_action must reference a declared READ_ONLY action."""
    from weather_plugin import WeatherPlugin  # type: ignore

    # DISPLAY branding for the client card
    assert WeatherPlugin.DISPLAY["logo"] and WeatherPlugin.DISPLAY["label"]

    fields = {f["key"]: f for f in WeatherPlugin.CONFIG_SCHEMA}
    # the long value renders as a textarea, the flag as a toggle
    assert fields["WEATHER_LOCATIONS"]["widget"] == "textarea"
    assert fields["WEATHER_SINK_INFLUXDB"]["widget"] == "toggle"

    # the city field autocompletes from a source, and that source is a real
    # read-only action on the plugin (so the client can safely call it).
    city = fields["WEATHER_DEFAULT_CITY"]
    assert city["widget"] == "autocomplete"
    src = city["options_action"]
    assert src in WeatherPlugin.READ_ONLY_ACTIONS
    assert callable(getattr(WeatherPlugin, src))
