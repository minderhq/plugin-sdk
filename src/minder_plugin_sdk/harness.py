"""Testing utilities for plugin authors.

``check_plugin(plugin)`` returns a list of contract violations (empty ⇒ the
plugin honours the SDK contract). ``run_lifecycle(plugin)`` drives the full
lifecycle the registry would and returns each step's output — drop either into
your test suite.
"""

import asyncio
import inspect
from typing import Any, Coroutine, Dict, List, cast

from .ai_tools import ai_tool_errors
from .capabilities import capabilities
from .contract import PluginMetadata
from .schema import config_errors, resolve_config_schema, resolve_effective_config

__all__ = ["check_plugin", "run_lifecycle"]


def _await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return asyncio.run(cast("Coroutine[Any, Any, Any]", value))
    return value


def check_plugin(plugin: Any) -> List[str]:
    """Static + light-dynamic contract checks. Empty list ⇒ the plugin is valid."""
    problems: List[str] = []

    if not callable(getattr(plugin, "register", None)):
        problems.append("missing register() — the registry loads on its presence")
        return problems

    md = _await(plugin.register())
    if not isinstance(md, PluginMetadata):
        problems.append("register() must return a PluginMetadata")
    else:
        for f in ("name", "version", "description", "author"):
            if not getattr(md, f, None):
                problems.append(f"PluginMetadata.{f} is empty")

    if callable(getattr(plugin, "health_check", None)):
        health = _await(plugin.health_check())
        if not isinstance(health, dict) or not isinstance(health.get("healthy"), bool):
            problems.append('health_check() must return {"healthy": <bool>, ...}')

    # AI tools must map to declared actions.
    problems.extend(ai_tool_errors(plugin))

    # ACTIONS must name real methods.
    for action in getattr(plugin, "ACTIONS", frozenset()) or ():
        if not callable(getattr(plugin, action, None)):
            problems.append(f"ACTIONS names {action!r} but there is no such method")

    # options_action references must be READ_ONLY actions that exist.
    _schema, ui = resolve_config_schema(plugin)
    read_only = set(getattr(plugin, "READ_ONLY_ACTIONS", frozenset()) or ())
    for key, hints in ui.items():
        src = hints.get("ui:optionsAction")
        if src and src not in read_only:
            problems.append(
                f"field {key!r} options_action {src!r} is not a READ_ONLY action"
            )

    # Default config must validate against the plugin's own schema.
    schema, _ = resolve_config_schema(plugin)
    defaults = resolve_effective_config(plugin)
    problems.extend(config_errors(schema, defaults))

    # Capabilities must be resolvable.
    try:
        capabilities(plugin)
    except Exception as exc:  # pragma: no cover - defensive
        problems.append(f"capabilities() failed: {exc}")

    return problems


async def run_lifecycle(plugin: Any) -> Dict[str, Any]:
    """Drive register → initialize → health_check → collect_data → analyze →
    shutdown (skipping any the plugin doesn't implement) and return the outputs."""
    out: Dict[str, Any] = {}
    out["metadata"] = await plugin.register()
    for step in ("initialize", "health_check", "collect_data", "analyze", "shutdown"):
        fn = getattr(plugin, step, None)
        if callable(fn):
            result = fn()
            out[step] = await result if inspect.isawaitable(result) else result
    return out
