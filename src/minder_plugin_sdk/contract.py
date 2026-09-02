"""The Minder module-plugin authoring contract.

Single source of truth for ``PluginMetadata`` and the ``Plugin`` lifecycle, so a
plugin never re-guesses the shape the registry drives. Import from the SDK:

    from minder_plugin_sdk import PluginMetadata, Plugin

Plugins are **duck-typed** — the registry loader matches a class by the presence
of ``register``, so a plugin need not inherit anything. ``Plugin`` below is a
``Protocol`` you can type-check against (editor / mypy); it documents the exact
lifecycle the registry drives and the one easy-to-miss rule: ``health_check()``
MUST return ``{"healthy": <bool>, ...}`` (monitoring reads ``health["healthy"]``).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Protocol, runtime_checkable

__all__ = ["PluginMetadata", "Plugin"]


@dataclass
class PluginMetadata:
    """Return shape for ``register()`` — the fields the registry loader reads:
    name / version / description / author / dependencies / capabilities /
    data_sources / databases / registered_at (a ``datetime`` — the loader calls
    ``.isoformat()`` on it)."""

    name: str
    version: str
    description: str
    author: str
    dependencies: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@runtime_checkable
class Plugin(Protocol):
    """The async lifecycle the registry drives. Match these methods (duck-typed);
    inheriting is optional — use it for editor/mypy checking."""

    async def register(self) -> PluginMetadata: ...

    async def initialize(self) -> None: ...

    async def health_check(self) -> Dict[str, Any]:  # MUST return {"healthy": bool}
        ...

    async def collect_data(self) -> Dict[str, Any]: ...

    async def analyze(self) -> Dict[str, Any]: ...

    async def shutdown(self) -> None: ...

    def apply_config(self, config: Dict[str, Any]) -> None:  # optional; see below
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Optional extension points — declare these as CLASS ATTRIBUTES on your plugin.
#
# CONFIG_SCHEMA — make the plugin configurable over the API (no container env +
#   restart). A list of field descriptors, each a plain dict. The DATA keys are:
#     {"key": str, "type": "string|int|float|bool", "default": Any,
#      "description": str, "secret": bool (optional)}
#   The registry resolves each field as default → env[key] → persisted (API-set)
#   value (persisted wins), then calls ``apply_config(effective: dict)``. __init__
#   SHOULD build its initial config the same way and call apply_config, so there
#   is one config→state path. Exposed via:
#     GET  /v1/plugins/<name>/config   → {schema, values}  (secret values masked)
#     PUT  /v1/plugins/<name>/config   → validate, persist, apply live (JWT-gated)
#
#   PRESENTATION keys (all OPTIONAL) tell the *trusted client* how to render each
#   field — the plugin never ships HTML, only this declarative metadata:
#     "widget":  text | textarea | number | toggle | select | multiselect |
#                secret | autocomplete   (default: inferred from "type")
#     "placeholder": str            "rows": int (textarea height)
#     "options": [{"value": Any, "label": str}]   — a STATIC select/multiselect
#     "options_action": str         — name of a READ_ONLY action returning
#                                     [{value, label}] → a DYNAMIC autocomplete
#                                     (e.g. a city search); reuses ACTIONS.
#     "min"/"max"/"step": number    "required": bool    "group": str (section)
#   Unknown keys are ignored; a field with none of these renders as a plain input,
#   so old {key,type,default,description} schemas keep working unchanged.
#
# ACTIONS — a frozenset of method names invokable via
#   ``POST /v1/plugins/<name>/actions/<method>`` (JWT-gated; JSON body → kwargs).
#   Only names in ACTIONS are reachable. Reads use /collect + /analysis; ACTIONS
#   is for state changes. Optionally declare READ_ONLY_ACTIONS (a subset) to allow
#   GET access to side-effect-free actions.
#
# AI_TOOLS — advertise Ollama / OpenAI function-calling tools. A list of dicts:
#     {name, description, parameters (JSON Schema), action}
#   where ``action`` is one of ACTIONS. ``GET /v1/plugins/ai/tools`` aggregates
#   these into tool definitions for function-calling chat.
#
# DISPLAY — branding for the plugin's card in the client. A plain dict:
#     {"label": str, "summary": str, "logo": str, "color": str, "category": str}
#   ``logo`` is a **lucide icon name** (the client has a lucide Icon registry) —
#   safe by default; an inline SVG / URL MAY be allowed but is sanitized by the
#   client. Absent → the client falls back to the plugin name + a default icon.
