"""Capability negotiation (RFC 0001).

A plugin is not one fixed lifecycle — it may be a data source, an AI-tool
provider, an event ingestor, a scheduler, a connection provider, a UI-panel
contributor… Rather than force every plugin through ``collect_data``/``analyze``,
a plugin **declares the capabilities it implements** (explicitly via a
``CAPABILITIES`` class attr, or we infer them), and the platform drives only
those. The vocabulary is **open**: an unknown capability is ignored, never fatal.
"""

from typing import Any, FrozenSet, Set

__all__ = ["KNOWN_CAPABILITIES", "capabilities"]

# A non-exhaustive vocabulary — plugins MAY declare capabilities outside this set;
# the platform ignores ones it doesn't understand (graceful degradation).
KNOWN_CAPABILITIES: FrozenSet[str] = frozenset(
    {
        "config",  # exposes CONFIG_SCHEMA / CONFIG_JSONSCHEMA
        "data-source",  # implements collect_data (polled/manual)
        "ai-tools",  # exposes AI_TOOLS (function calling)
        "actions",  # exposes ACTIONS (HTTP-invokable methods)
        "webhook-ingest",  # manifest webhook → store
        "scheduler",  # declares its own schedule/cron
        "connection",  # OAuth / credential connection provider
        "ui-panel",  # contributes a data-driven client surface
    }
)


def _has(plugin: Any, attr: str) -> bool:
    return callable(getattr(plugin, attr, None))


def capabilities(plugin: Any) -> Set[str]:
    """The capabilities a plugin implements. Prefers an explicit ``CAPABILITIES``
    class attr; otherwise infers from the attributes/methods present, so existing
    plugins get sensible capabilities for free."""
    declared = getattr(plugin, "CAPABILITIES", None)
    if declared is not None:
        return set(declared)
    caps: Set[str] = set()
    if getattr(plugin, "CONFIG_JSONSCHEMA", None) or getattr(
        plugin, "CONFIG_SCHEMA", None
    ):
        caps.add("config")
    if _has(plugin, "collect_data"):
        caps.add("data-source")
    if getattr(plugin, "AI_TOOLS", None):
        caps.add("ai-tools")
    if getattr(plugin, "ACTIONS", None):
        caps.add("actions")
    return caps
