"""What a plugin needs from the platform: **services** and **bundles**.

A plugin that sinks to InfluxDB needs the ``influxdb`` service; one that does
semantic search needs ``qdrant`` (and the ``rag`` bundle). Declaring this lets the
platform (a) refuse to enable a plugin whose hard requirements are missing,
(b) offer to enable the bundles it needs, and (c) show requirements on the plugin's
card. Declare a ``REQUIRES`` class attribute::

    REQUIRES = {
        "services": ["influxdb"],          # hard — the plugin can't run without them
        "optional_services": ["qdrant"],   # used if present, degrades if not
        "bundles": ["rag"],                # bundles that should be enabled
    }

The service/bundle vocabularies are platform-bounded (unlike widgets/capabilities);
an unknown name is almost always a typo, so it's flagged.
"""

from typing import Any, Dict, List

__all__ = [
    "KNOWN_SERVICES",
    "KNOWN_BUNDLES",
    "requirements",
    "requirement_errors",
]

# Storage backends + inference a plugin may depend on (CLAUDE.md service map).
KNOWN_SERVICES = frozenset(
    {"postgres", "redis", "qdrant", "neo4j", "minio", "influxdb", "rabbitmq", "ollama"}
)

# Capability bundles (docs/architecture/bundles.md).
KNOWN_BUNDLES = frozenset(
    {"core", "monitoring", "inference", "rag", "graph-rag", "chat", "voice"}
)

_KEYS = ("services", "optional_services", "bundles")


def requirements(plugin: Any) -> Dict[str, List[str]]:
    """The plugin's declared requirements, normalized to
    ``{services, optional_services, bundles}`` (each a list; missing → empty)."""
    declared = getattr(plugin, "REQUIRES", None) or {}
    return {key: list(declared.get(key, []) or []) for key in _KEYS}


def requirement_errors(plugin: Any) -> List[str]:
    """Validate a plugin's ``REQUIRES`` (empty ⇒ ok): it must be a mapping with only
    known keys, and every service/bundle name must be one the platform provides."""
    declared = getattr(plugin, "REQUIRES", None)
    if declared is None:
        return []
    errors: List[str] = []
    if not isinstance(declared, dict):
        return ["REQUIRES must be a dict of {services, optional_services, bundles}"]
    for key in declared:
        if key not in _KEYS:
            errors.append(f"REQUIRES has unknown key {key!r} (allowed: {list(_KEYS)})")
    req = requirements(plugin)
    for name in req["services"] + req["optional_services"]:
        if name not in KNOWN_SERVICES:
            errors.append(f"unknown service {name!r} (known: {sorted(KNOWN_SERVICES)})")
    for name in req["bundles"]:
        if name not in KNOWN_BUNDLES:
            errors.append(f"unknown bundle {name!r} (known: {sorted(KNOWN_BUNDLES)})")
    return errors
