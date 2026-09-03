"""Tests for the ai-tools helpers: building OpenAI/Ollama tool definitions from
AI_TOOLS, and validating each tool maps to a declared ACTION.
"""

import pytest

from minder_plugin_sdk.ai_tools import ai_tool_errors, build_tool_definitions
from minder_plugin_sdk.errors import PluginError


class _Plugin:
    ACTIONS = frozenset({"get_thing"})
    AI_TOOLS = [
        {
            "name": "get_thing",
            "description": "Get a thing.",
            "parameters": {"type": "object", "properties": {"q": {"type": "string"}}},
            "action": "get_thing",
        }
    ]


# ── build_tool_definitions ───────────────────────────────────────────────────
def test_build_wraps_each_tool_in_the_function_shape():
    tools = build_tool_definitions(_Plugin())
    assert tools == [
        {
            "type": "function",
            "function": {
                "name": "get_thing",
                "description": "Get a thing.",
                "parameters": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                },
            },
        }
    ]


def test_build_defaults_description_and_parameters():
    class P:
        AI_TOOLS = [{"name": "bare", "action": "bare"}]

    fn = build_tool_definitions(P())[0]["function"]
    assert fn["description"] == ""
    assert fn["parameters"] == {"type": "object", "properties": {}}


def test_build_raises_on_missing_name():
    class P:
        AI_TOOLS = [{"description": "no name"}]

    with pytest.raises(PluginError, match="missing 'name'"):
        build_tool_definitions(P())


def test_build_empty_when_no_ai_tools():
    class P:
        pass

    assert build_tool_definitions(P()) == []


# ── ai_tool_errors ───────────────────────────────────────────────────────────
def test_ai_tool_errors_none_for_valid_plugin():
    assert ai_tool_errors(_Plugin()) == []


def test_ai_tool_errors_flags_missing_name():
    class P:
        ACTIONS = frozenset({"a"})
        AI_TOOLS = [{"action": "a"}]

    assert any("missing 'name'" in e for e in ai_tool_errors(P()))


def test_ai_tool_errors_flags_missing_action():
    class P:
        ACTIONS = frozenset({"a"})
        AI_TOOLS = [{"name": "t"}]

    assert any("missing 'action'" in e for e in ai_tool_errors(P()))


def test_ai_tool_errors_flags_action_not_in_actions():
    class P:
        ACTIONS = frozenset({"a"})
        AI_TOOLS = [{"name": "t", "action": "b"}]

    assert any("not in ACTIONS" in e for e in ai_tool_errors(P()))


def test_ai_tool_errors_flags_non_dict_parameters():
    class P:
        ACTIONS = frozenset({"a"})
        AI_TOOLS = [{"name": "t", "action": "a", "parameters": "nope"}]

    assert any("must be a JSON Schema object" in e for e in ai_tool_errors(P()))
