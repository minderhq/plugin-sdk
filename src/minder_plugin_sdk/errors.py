"""SDK exception types. Plugins and tooling raise/catch these instead of bare
``Exception`` so failures are classifiable."""

from typing import List, Optional

__all__ = [
    "PluginError",
    "ConfigError",
    "ManifestError",
    "CapabilityError",
    "CapabilityDenied",
    "CapabilityUnavailable",
    "CapabilityInvalid",
    "UnsafeURLError",
]


class PluginError(Exception):
    """Base class for all SDK / plugin errors."""


class ConfigError(PluginError):
    """A config value failed validation against the plugin's schema.

    ``errors`` is a list of human-readable messages (one per offending field)."""

    def __init__(self, message: str, errors: Optional[List[str]] = None) -> None:
        super().__init__(message)
        self.errors: List[str] = errors or []


class ManifestError(PluginError):
    """A plugin manifest is malformed or fails schema validation."""

    def __init__(self, message: str, errors: Optional[List[str]] = None) -> None:
        super().__init__(message)
        self.errors: List[str] = errors or []


# ── platform-context (contract v2) errors ────────────────────────────────────
# Raised by ``self.ctx.*`` calls (see ``context.py``). Messages name the
# capability and a short reason only. They never carry argument VALUES (a secret,
# a document body, a TOML region), so they are safe to log and to surface in an
# action's error response. Implementations must keep it that way: pass a reason
# that describes the failure, never the data involved.


class CapabilityError(PluginError):
    """Base class for platform-capability failures. ``capability`` is the
    capability name (e.g. ``"secrets.read"``); ``reason`` the short reason."""

    _verb = "failed"

    def __init__(self, capability: str, reason: Optional[str] = None) -> None:
        self.capability = capability
        self.reason = reason
        message = f"platform capability {capability!r} {self._verb}"
        if reason:
            message = f"{message}: {reason}"
        super().__init__(message)


class CapabilityDenied(CapabilityError):
    """The platform refused the call: the capability is not granted to this
    plugin for this invocation (undeclared, wrong owner/tenant, expired grant,
    an undeclared plugin-to-plugin edge, ...). Retrying will not help."""

    _verb = "denied"


class CapabilityUnavailable(CapabilityError):
    """The capability cannot be served right now: no platform context is bound
    (a contract-v1 host, or a unit test without a fake), or the platform side is
    unreachable. Plugins should degrade gracefully (skip the feature, report it
    in ``health_check()``) rather than crash."""

    _verb = "unavailable"


class CapabilityInvalid(CapabilityError):
    """The platform rejected the call's arguments (e.g. a telegraf region with a
    disallowed table, an unknown target action, an oversized document)."""

    _verb = "rejected an invalid request"


class UnsafeURLError(PluginError):
    """``safe_http`` refused a URL: wrong scheme, a host outside the plugin's
    allowlist, or a destination that resolves to a non-public address."""
