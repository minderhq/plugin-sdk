"""Helpers for the ``ai-tools`` capability — turn a plugin's ``AI_TOOLS`` into the
OpenAI / Ollama function-calling tool format, and validate that each tool maps to
a real action. Effect declarations (``effect``, ``idempotent``, ``sensitivity``,
``hosts``) are checked by ``tool_effects``."""

from typing import Any, Dict, List

from .errors import PluginError
from .tool_effects import tool_effect_errors, tool_effect_warnings

__all__ = ["build_tool_definitions", "ai_tool_errors", "ai_tool_warnings"]


def _without_sensitivity(parameters: Any) -> Any:
    """``parameters`` without the per-argument ``sensitivity`` annotations,
    which are for Minder, not for the model."""
    if not isinstance(parameters, dict):
        return parameters
    props = parameters.get("properties")
    if not isinstance(props, dict) or not any(
        isinstance(spec, dict) and "sensitivity" in spec for spec in props.values()
    ):
        return parameters
    return {
        **parameters,
        "properties": {
            arg: (
                {k: v for k, v in spec.items() if k != "sensitivity"}
                if isinstance(spec, dict)
                else spec
            )
            for arg, spec in props.items()
        },
    }


def build_tool_definitions(plugin: Any) -> List[Dict[str, Any]]:
    """Return OpenAI/Ollama tool definitions for the plugin's ``AI_TOOLS`` — the
    shape ``GET /v1/plugins/ai/tools`` serves and chat function-calling expects:

        {"type": "function",
         "function": {"name", "description", "parameters"}}

    Per-argument ``sensitivity`` annotations are left out of ``parameters``.
    Raises :class:`PluginError` if a tool is malformed."""
    tools: List[Dict[str, Any]] = []
    for spec in getattr(plugin, "AI_TOOLS", []) or []:
        name = spec.get("name")
        if not name:
            raise PluginError(f"AI_TOOLS entry missing 'name': {spec!r}")
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": spec.get("description", ""),
                    "parameters": _without_sensitivity(
                        spec.get("parameters", {"type": "object", "properties": {}})
                    ),
                },
            }
        )
    return tools


def ai_tool_errors(plugin: Any) -> List[str]:
    """Validate a plugin's ``AI_TOOLS`` against its ``ACTIONS`` (empty ⇒ ok). Every
    tool must name an ``action`` that is a declared action, so the tool call can
    be routed to ``POST /v1/plugins/<name>/actions/<action>``. Invalid effect
    declarations are errors too (see ``tool_effects``)."""
    actions = set(getattr(plugin, "ACTIONS", frozenset()) or ())
    errors: List[str] = []
    for spec in getattr(plugin, "AI_TOOLS", []) or []:
        name = spec.get("name", "<unnamed>")
        if not spec.get("name"):
            errors.append("a tool is missing 'name'")
        action = spec.get("action")
        if not action:
            errors.append(f"tool {name!r} is missing 'action'")
        elif action not in actions:
            errors.append(f"tool {name!r} → action {action!r} is not in ACTIONS")
        params = spec.get("parameters")
        if params is not None and not isinstance(params, dict):
            errors.append(f"tool {name!r} 'parameters' must be a JSON Schema object")
    errors.extend(tool_effect_errors(plugin))
    return errors


def ai_tool_warnings(plugin: Any) -> List[str]:
    """Non-fatal findings on a plugin's ``AI_TOOLS`` (empty: nothing to say): a
    tool without ``effect`` and a declaration that evidence contradicts. See
    ``tool_effects.tool_effect_warnings``."""
    return tool_effect_warnings(plugin)
