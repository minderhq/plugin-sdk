"""Tests for tool effect declarations: validation errors, warnings (missing
effect, contradictions), the MCP annotation mapping, and backward
compatibility for plugins that declare nothing."""

from typing import Any, Dict, List, Optional

import pytest

from minder_plugin_sdk import (
    EFFECTS,
    PluginBase,
    PluginMetadata,
    build_tool_definitions,
    check_plugin,
    check_plugin_warnings,
    mcp_annotations,
    tool_annotations,
)
from minder_plugin_sdk.tool_effects import (
    suggest_effect,
    tool_effect_errors,
    tool_effect_warnings,
)


def _plugin(**tool: Any) -> Any:
    spec: Dict[str, Any] = {"name": "get_thing", "action": "get_thing", **tool}

    class P:
        ACTIONS = frozenset({spec["action"]})
        AI_TOOLS = [spec]

    return P()


def _props(*names: str, **sensitivities: str) -> Dict[str, Any]:
    props: Dict[str, Any] = {n: {"type": "string"} for n in names}
    for arg, value in sensitivities.items():
        props.setdefault(arg, {"type": "string"})["sensitivity"] = value
    return {"type": "object", "properties": props}


# ── validation errors ────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "tool, expected",
    [
        ({}, []),
        *[({"effect": e}, []) for e in EFFECTS],
        ({"effect": "Read"}, ["effect 'Read' must be one of"]),
        ({"effect": "delete"}, ["effect 'delete' must be one of"]),
        ({"effect": 1}, ["effect 1 must be one of"]),
        ({"effect": "read", "idempotent": True}, []),
        ({"effect": "read", "idempotent": "yes"}, ["'idempotent' must be a bool"]),
        ({"parameters": _props(to="recipient")}, []),
        ({"parameters": _props(u="url", a="amount", t="free_text")}, []),
        ({"parameters": _props(user="bound:email")}, []),
        ({"parameters": _props(user="bound:")}, ["sensitivity 'bound:'"]),
        ({"parameters": _props(x="secret")}, ["sensitivity 'secret'"]),
        ({"sensitivities": {"x": "recipient"}}, []),
        ({"sensitivities": {"x": "nope"}}, ["sensitivity 'nope'"]),
        ({"sensitivities": ["x"]}, ["'sensitivities' must map"]),
        ({"hosts": ["api.example.com", "*.example.org"]}, []),
        ({"hosts": "api.example.com"}, ["'hosts' must be a list"]),
        ({"hosts": ["https://api.example.com"]}, ["host 'https://api.example.com'"]),
        ({"hosts": ["api.example.com:443"]}, ["host 'api.example.com:443'"]),
        ({"hosts": ["*.com"]}, ["host '*.com'"]),
    ],
)
def test_effect_errors(tool: Dict[str, Any], expected: List[str]) -> None:
    errors = tool_effect_errors(_plugin(**tool))
    assert len(errors) == len(expected), errors
    for err, fragment in zip(errors, expected):
        assert fragment in err


def test_invalid_effect_fails_check_plugin() -> None:
    class P(PluginBase):
        ACTIONS = frozenset({"get_thing"})
        AI_TOOLS = [{"name": "get_thing", "action": "get_thing", "effect": "maybe"}]

        async def register(self) -> PluginMetadata:
            return PluginMetadata(name="p", version="1", description="d", author="a")

        async def get_thing(self) -> dict:
            return {}

    assert any("effect 'maybe'" in p for p in check_plugin(P()))


# ── warnings: missing effect ─────────────────────────────────────────────────
class _Legacy(PluginBase):
    """A plugin written before effects existed."""

    ACTIONS = frozenset({"get_thing"})
    AI_TOOLS = [{"name": "get_thing", "action": "get_thing"}]

    async def register(self) -> PluginMetadata:
        return PluginMetadata(name="p", version="1", description="d", author="a")

    async def get_thing(self) -> dict:
        return {}


def test_missing_effect_is_a_warning_not_an_error() -> None:
    plugin = _Legacy()
    assert check_plugin(plugin) == []
    warnings = check_plugin_warnings(plugin)
    assert len(warnings) == 1
    assert "'get_thing' declares no 'effect'" in warnings[0]


def test_no_ai_tools_no_warnings() -> None:
    class P:
        pass

    assert check_plugin_warnings(P()) == []


# ── warnings: contradictions ─────────────────────────────────────────────────
@pytest.mark.parametrize(
    "tool, suggested, contradicted_by",
    [
        # Consistent declarations: no warning.
        ({"name": "get_weather", "effect": "read", "method": "GET"}, "read", []),
        ({"name": "send_message", "effect": "send"}, "send", []),
        ({"name": "delete_note", "effect": "destructive"}, "destructive", []),
        ({"name": "update_contact", "effect": "write"}, "write", []),
        # Declaring stricter than the evidence is fine.
        ({"name": "get_weather", "effect": "write"}, "read", []),
        ({"name": "echo", "effect": "read"}, None, []),
        # Name verbs.
        ({"name": "send_email", "effect": "read"}, "send", ["verb 'send'"]),
        ({"name": "delete_note", "effect": "read"}, "destructive", ["verb 'delete'"]),
        ({"name": "delete_note", "effect": "send"}, "destructive", ["verb 'delete'"]),
        ({"name": "notifyTeam", "effect": "write"}, "send", ["verb 'notify'"]),
        ({"name": "crm_contact_update", "effect": "read"}, "write", ["verb 'update'"]),
        # A leading read verb wins; a noun-like verb later in the name is ignored.
        ({"name": "get_update_status", "effect": "read"}, "read", []),
        ({"name": "ticket_email", "effect": "read"}, None, []),
        # The action name counts too.
        (
            {"name": "notes", "action": "remove_note", "effect": "read"},
            "destructive",
            ["action verb 'remove'"],
        ),
        # Methods.
        (
            {"name": "notes", "method": "DELETE", "effect": "write"},
            "destructive",
            ["method DELETE"],
        ),
        ({"name": "notes", "method": "post", "effect": "read"}, None, []),
        # Arguments and sensitivities.
        (
            {"name": "notes", "effect": "read", "parameters": _props("to")},
            "send",
            ["argument 'to'"],
        ),
        (
            {"name": "notes", "effect": "write", "parameters": _props("webhook_url")},
            "send",
            ["argument 'webhook_url'"],
        ),
        (
            {"name": "notes", "effect": "read", "parameters": _props(who="recipient")},
            "send",
            ["sensitivity 'recipient'"],
        ),
        (
            {
                "name": "notes",
                "effect": "read",
                "parameters": _props("who"),
                "sensitivities": {"who": "recipient"},
            },
            "send",
            ["sensitivity 'recipient'"],
        ),
        # Weak evidence never contradicts.
        (
            {"name": "notes", "effect": "read", "parameters": _props("email", "url")},
            None,
            [],
        ),
        ({"name": "notes", "effect": "read", "parameters": _props(u="url")}, None, []),
        # Several rules fire: one warning each.
        (
            {"name": "send_mail", "effect": "read", "parameters": _props("to", "cc")},
            "send",
            ["verb 'send'", "argument 'cc'", "argument 'to'"],
        ),
    ],
)
def test_contradictions(
    tool: Dict[str, Any], suggested: Optional[str], contradicted_by: List[str]
) -> None:
    tool.setdefault("action", tool["name"])
    assert suggest_effect(tool) == suggested
    warnings = tool_effect_warnings(_plugin(**tool))
    assert len(warnings) == len(contradicted_by), warnings
    for warning, fragment in zip(warnings, contradicted_by):
        assert f"declared {tool['effect']!r}" in warning
        assert fragment in warning


def test_undeclared_tool_is_never_flagged_as_contradiction() -> None:
    warnings = tool_effect_warnings(_plugin(name="send_email", action="send_email"))
    assert len(warnings) == 1 and "declares no 'effect'" in warnings[0]


def test_invalid_effect_gets_no_contradiction_warning() -> None:
    plugin = _plugin(name="send_email", action="send_email", effect="bogus")
    assert tool_effect_warnings(plugin) == []


def test_sensitivity_for_unknown_argument_warns() -> None:
    plugin = _plugin(
        effect="read", parameters=_props("q"), sensitivities={"missing": "url"}
    )
    warnings = tool_effect_warnings(plugin)
    assert len(warnings) == 1 and "'missing'" in warnings[0]


# ── MCP annotations ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "effect, idempotent, expected",
    [
        ("read", None, {"readOnlyHint": True, "destructiveHint": False}),
        ("write", None, {"readOnlyHint": False, "destructiveHint": False}),
        (
            "send",
            None,
            {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
        ),
        ("destructive", None, {"readOnlyHint": False, "destructiveHint": True}),
        (
            "write",
            True,
            {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
        ),
        (
            "destructive",
            False,
            {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
        ),
        (None, None, {}),
        (None, True, {"idempotentHint": True}),
    ],
)
def test_mcp_annotations(
    effect: Optional[str], idempotent: Optional[bool], expected: Dict[str, bool]
) -> None:
    assert mcp_annotations(effect, idempotent) == expected


def test_mcp_annotations_reject_unknown_effect() -> None:
    with pytest.raises(ValueError, match="unknown effect"):
        mcp_annotations("delete")


def test_mcp_annotations_return_a_fresh_dict() -> None:
    mcp_annotations("read")["readOnlyHint"] = False
    assert mcp_annotations("read")["readOnlyHint"] is True


def test_tool_annotations_reads_the_tool_entry() -> None:
    tool = {"name": "x", "effect": "send", "idempotent": False}
    assert tool_annotations(tool) == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "openWorldHint": True,
        "idempotentHint": False,
    }
    assert tool_annotations({"name": "x", "idempotent": "no"}) == {}


# ── tool definitions ─────────────────────────────────────────────────────────
def test_build_tool_definitions_strips_sensitivity() -> None:
    params = _props("q", to="recipient")
    plugin = _plugin(name="send_x", action="send_x", effect="send", parameters=params)
    fn = build_tool_definitions(plugin)[0]["function"]
    assert fn["parameters"]["properties"] == {
        "q": {"type": "string"},
        "to": {"type": "string"},
    }
    # The plugin's own declaration is left untouched.
    assert params["properties"]["to"]["sensitivity"] == "recipient"
