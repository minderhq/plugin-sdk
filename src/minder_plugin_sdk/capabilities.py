"""Capability negotiation (RFC 0001).

A plugin is not one fixed lifecycle — it may be a data source, an AI-tool
provider, an event ingestor, a scheduler, a connection provider, a UI-panel
contributor… Rather than force every plugin through ``collect_data``/``analyze``,
a plugin **declares the capabilities it implements** (explicitly via a
``CAPABILITIES`` class attr, or we infer them), and the platform drives only
those. The vocabulary is **open**: an unknown capability is ignored, never fatal.
"""

from typing import Any, Dict, FrozenSet, List, Protocol, Set, runtime_checkable

__all__ = [
    "KNOWN_CAPABILITIES",
    "capabilities",
    "DataSource",
    "Scheduler",
    "WebhookHandler",
    "ConnectionProvider",
    "UIPanelProvider",
]

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
        # A bare string would otherwise set()-split into single characters
        # (silently dropping the plugin's real capability, since each char is an
        # unknown capability the platform ignores). Accept it as one capability.
        if isinstance(declared, str):
            return {declared}
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
    if _has(plugin, "handle_webhook"):
        caps.add("webhook-ingest")
    if _has(plugin, "schedule"):
        caps.add("scheduler")
    if _has(plugin, "connect"):
        caps.add("connection")
    if _has(plugin, "panels"):
        caps.add("ui-panel")
    return caps


# ── per-capability interfaces (type-check against the one you implement) ───────
# These document the extra methods a plugin adds when it declares a capability
# beyond the base lifecycle. Each is runtime_checkable and optional.


@runtime_checkable
class DataSource(Protocol):
    """``data-source``: polled/manual collection driven by the registry."""

    async def collect_data(self) -> Dict[str, Any]: ...

    async def analyze(self) -> Dict[str, Any]: ...


@runtime_checkable
class Scheduler(Protocol):
    """``scheduler``: the plugin declares its own cadence as a cron expression
    instead of the default hourly loop."""

    def schedule(self) -> str: ...


@runtime_checkable
class WebhookHandler(Protocol):
    """``webhook-ingest``: handle an inbound webhook payload (returns a result to
    store / acknowledge)."""

    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]: ...


@runtime_checkable
class ConnectionProvider(Protocol):
    """``connection``: an external account/credential connection (e.g. OAuth)."""

    async def connect(self, credentials: Dict[str, Any]) -> Dict[str, Any]: ...

    async def disconnect(self) -> None: ...

    async def is_connected(self) -> bool: ...


@runtime_checkable
class UIPanelProvider(Protocol):
    """``ui-panel``: contribute data-driven client surfaces. Returns panel
    descriptors ({id, title, kind: table|chart|kv|timeline, dataAction}); the
    trusted client renders them — the plugin never ships markup."""

    def panels(self) -> List[Dict[str, Any]]: ...
