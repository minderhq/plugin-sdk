"""PluginBase, harness, ai_tools, manifest, config validation, and the CLI."""

import asyncio
import sys
from pathlib import Path

import pytest

from minder_plugin_sdk import (
    ConfigError,
    ManifestError,
    PluginBase,
    PluginMetadata,
    ai_tool_errors,
    build_tool_definitions,
    check_plugin,
    config_errors,
    run_lifecycle,
    validate_config,
    validate_manifest,
)
from minder_plugin_sdk import cli

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
sys.path.insert(0, str(EXAMPLES))


# ── PluginBase + harness ──────────────────────────────────────────────────────
def test_plugin_base_gives_working_defaults():
    from minimal_plugin import MinimalPlugin  # type: ignore

    out = asyncio.run(run_lifecycle(MinimalPlugin()))
    assert isinstance(out["metadata"], PluginMetadata)
    assert out["health_check"]["healthy"] is True
    assert out["collect_data"]["value"] == 42
    assert out["analyze"] == out["collect_data"]  # analyze returns last collect


@pytest.mark.parametrize(
    "module,cls",
    [
        ("weather_plugin", "WeatherPlugin"),
        ("minimal_plugin", "MinimalPlugin"),
        ("ai_tool_plugin", "UnitConverterPlugin"),
    ],
)
def test_check_plugin_passes_on_examples(module, cls):
    mod = __import__(module)
    assert check_plugin(getattr(mod, cls)()) == []


def test_check_plugin_flags_real_violations():
    class Broken(PluginBase):
        ACTIONS = frozenset({"missing_method"})
        AI_TOOLS = [{"name": "t", "action": "nope"}]  # action not in ACTIONS

        async def register(self):
            return PluginMetadata(name="", version="1.0.0", description="d", author="a")

        async def health_check(self):
            return {"healthy": "yes"}  # not a bool

    problems = check_plugin(Broken())
    joined = " ".join(problems)
    assert "PluginMetadata.name is empty" in joined
    assert "healthy" in joined
    assert "nope" in joined  # ai tool → unknown action
    assert "missing_method" in joined  # ACTIONS names a missing method


# ── config validation ─────────────────────────────────────────────────────────
def test_config_errors_catch_type_enum_range():
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {
            "a": {"type": "string"},
            "n": {"type": "integer", "minimum": 1, "maximum": 5},
            "e": {"type": "string", "enum": ["x", "y"]},
        },
    }
    assert config_errors(schema, {"a": "ok", "n": 3, "e": "x"}) == []
    errs = config_errors(
        schema, {"n": True, "e": "z"}
    )  # missing a; bool for int; bad enum
    joined = " ".join(errs)
    assert "a: required" in joined
    assert "boolean" in joined  # bool rejected for integer
    assert "not one of" in joined


def test_validate_config_raises_configerror():
    class P:
        CONFIG_SCHEMA = [
            {"key": "level", "type": "int", "min": 1, "max": 3, "widget": "number"}
        ]

    assert validate_config(P(), {"level": 2}) == {"level": 2}
    with pytest.raises(ConfigError) as ei:
        validate_config(P(), {"level": 9})
    assert ei.value.errors  # per-field messages present


# ── ai tools ───────────────────────────────────────────────────────────────────
def test_build_tool_definitions_openai_shape():
    from ai_tool_plugin import UnitConverterPlugin  # type: ignore

    tools = build_tool_definitions(UnitConverterPlugin())
    assert tools[0]["type"] == "function"
    assert tools[0]["function"]["name"] == "convert_length"
    assert tools[0]["function"]["parameters"]["type"] == "object"
    assert ai_tool_errors(UnitConverterPlugin()) == []


# ── manifest ───────────────────────────────────────────────────────────────────
def test_manifest_validates_the_example_and_rejects_garbage():
    text = (EXAMPLES / "discord_manifest.yaml").read_text(encoding="utf-8")
    m = validate_manifest(text)
    assert m["metadata"]["name"] == "discord-ingestor"
    with pytest.raises(ManifestError):
        validate_manifest({"kind": "Plugin"})  # missing apiVersion/metadata/spec


# ── CLI ────────────────────────────────────────────────────────────────────────
def test_cli_scaffold_then_validate_then_inspect(tmp_path, capsys):
    out = tmp_path / "acme_plugin.py"
    assert cli.main(["scaffold", "acme", "-o", str(out)]) == 0
    assert out.exists()
    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["inspect", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "capabilities" in printed


def test_cli_validate_manifest_file():
    assert cli.main(["validate", str(EXAMPLES / "discord_manifest.yaml")]) == 0
