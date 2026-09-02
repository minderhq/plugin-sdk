"""``PluginBase`` — an optional convenience base class.

Inheriting is never required (the registry duck-types on ``register``), but
``PluginBase`` gives every lifecycle method a sensible default so a plugin only
overrides what it actually needs — often just ``register`` and ``collect_data``.
It also wires the standard config flow (default → env → persisted → apply_config)
so a plugin gets runtime-editable config for free.
"""

import os
from typing import Any, Dict, FrozenSet, List, Optional

from .contract import PluginMetadata
from .schema import resolve_effective_config

__all__ = ["PluginBase"]


class PluginBase:
    """Sensible defaults for the plugin lifecycle. Override ``register`` (required)
    and anything else you need."""

    # Subclasses may set these (see contract.py); defaults keep a bare plugin valid.
    CONFIG_SCHEMA: List[Any] = []
    ACTIONS: FrozenSet[str] = frozenset()

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        # ``config`` is the storage-backend config the registry injects
        # (config["postgres"], config["influxdb"], …).
        self.config: Dict[str, Any] = config or {}
        self.status: str = "registered"
        self._last: Dict[str, Any] = {}
        # Seed settings from defaults+env via the one config→state path; the
        # registry re-applies with persisted (API-set) overrides after load.
        self.apply_config(resolve_effective_config(self, env=os.environ))

    # ── lifecycle (override as needed) ────────────────────────────────────────
    async def register(self) -> PluginMetadata:  # pragma: no cover - must override
        raise NotImplementedError("every plugin must implement register()")

    async def initialize(self) -> None:
        self.status = "ready"

    async def health_check(self) -> Dict[str, Any]:
        # MUST return {"healthy": <bool>} — the default says healthy once ready.
        return {"healthy": self.status in ("ready", "registered")}

    async def collect_data(self) -> Dict[str, Any]:
        return {}

    async def analyze(self) -> Dict[str, Any]:
        return self._last or {"message": "no data collected yet"}

    async def shutdown(self) -> None:
        self.status = "shutdown"

    def apply_config(self, config: Dict[str, Any]) -> None:
        """Map centrally-managed config → runtime state (no restart). The default
        stores each known key as an attribute (lowercased); override for custom
        mapping. See CONFIG_SCHEMA."""
        for key, value in config.items():
            setattr(self, key.lower(), value)
