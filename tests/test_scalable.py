"""RFC 0001: capability negotiation + JSON-Schema config compilation."""

import sys
from pathlib import Path

from minder_plugin_sdk import (
    KNOWN_CAPABILITIES,
    capabilities,
    fields_to_json_schema,
    resolve_config_schema,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))


def test_flat_fields_compile_to_json_schema_and_ui():
    fields = [
        {
            "key": "notes",
            "type": "string",
            "default": "",
            "description": "d",
            "widget": "textarea",
            "rows": 6,
            "group": "General",
            "required": True,
        },
        {
            "key": "level",
            "type": "int",
            "min": 1,
            "max": 5,
            "options": [{"value": 1, "label": "low"}, {"value": 5, "label": "high"}],
        },
        {"key": "token", "type": "string", "secret": True},
        {
            "key": "city",
            "type": "string",
            "widget": "autocomplete",
            "options_action": "search",
        },
    ]
    schema, ui = fields_to_json_schema(fields)

    assert schema["type"] == "object"
    assert schema["properties"]["notes"]["type"] == "string"
    assert schema["properties"]["level"]["type"] == "integer"
    assert schema["properties"]["level"]["minimum"] == 1
    assert schema["properties"]["level"]["enum"] == [1, 5]
    assert schema["required"] == ["notes"]

    assert ui["notes"]["ui:widget"] == "textarea"
    assert ui["notes"]["ui:options"] == {"rows": 6}
    assert ui["notes"]["ui:group"] == "General"
    assert ui["token"]["ui:widget"] == "secret"  # secret → secret widget
    assert ui["city"]["ui:optionsAction"] == "search"


def test_resolve_prefers_jsonschema_then_flat_then_empty():
    class Advanced:
        CONFIG_JSONSCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}
        UI_SCHEMA = {"x": {"ui:widget": "textarea"}}

    class Simple:
        CONFIG_SCHEMA = [{"key": "y", "type": "bool", "widget": "toggle"}]

    class Bare:
        pass

    s, u = resolve_config_schema(Advanced())
    assert (
        s["properties"]["x"]["type"] == "string" and u["x"]["ui:widget"] == "textarea"
    )

    s, u = resolve_config_schema(Simple())
    assert s["properties"]["y"]["type"] == "boolean" and u["y"]["ui:widget"] == "toggle"

    s, u = resolve_config_schema(Bare())
    assert s == {"type": "object", "properties": {}} and u == {}


def test_capabilities_explicit_wins_else_inferred():
    class Explicit:
        CAPABILITIES = ["ai-tools", "some-future-capability"]

    class Inferred:
        CONFIG_SCHEMA = [{"key": "k", "type": "string"}]
        ACTIONS = frozenset({"go"})
        AI_TOOLS = [{"name": "t", "action": "go"}]

        async def collect_data(self):
            return {}

    # explicit declaration is taken verbatim — including unknown/future capabilities
    assert capabilities(Explicit()) == {"ai-tools", "some-future-capability"}
    # inference from what's present
    assert capabilities(Inferred()) == {"config", "data-source", "actions", "ai-tools"}


def test_known_capabilities_is_a_nonempty_vocabulary():
    assert {"config", "data-source", "ai-tools"} <= KNOWN_CAPABILITIES


def test_weather_example_resolves_and_declares_caps():
    from weather_plugin import WeatherPlugin  # type: ignore

    schema, ui = resolve_config_schema(WeatherPlugin())
    # the textarea + autocomplete survive compilation to UI Schema
    assert ui["WEATHER_LOCATIONS"]["ui:widget"] == "textarea"
    assert ui["WEATHER_DEFAULT_CITY"]["ui:optionsAction"] == "search_cities"
    assert schema["properties"]["WEATHER_SINK_INFLUXDB"]["type"] == "boolean"
    caps = capabilities(WeatherPlugin())
    assert {"config", "data-source", "actions", "ai-tools"} <= caps
