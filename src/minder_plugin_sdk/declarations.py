"""Contract-v2 class-attribute declarations and their shape checks.

All of these are OPTIONAL. A plugin that declares none of them is a contract-v1
plugin and keeps working unchanged.

``CONTRACT_VERSION`` (int, default 1)
    ``2`` states that the plugin relies on the platform context (``self.ctx``,
    see ``context.py``). A host refuses a plugin that declares a higher version
    than it supports, with a clear error, rather than running it half-working.

``MANAGES`` (list of str)
    Platform-managed sidecars whose config this plugin owns through
    ``ctx.<name>.*`` (e.g. ``["telegraf"]``). The platform derives the
    plugin's ``<name>.*`` capabilities from it. Requires ``CONTRACT_VERSION = 2``.

``EGRESS`` (``"public"`` | ``"lan"`` | list of host patterns)
    Where the plugin connects to. ``"public"``: the public internet;
    ``"lan"``: also private/LAN addresses (e.g. network scanning); a list:
    only those hosts (``"api.example.com"``, or ``"*.example.com"`` for any
    subdomain). Hosts may use it to place and firewall the plugin.

``TIMESERIES`` (dict)
    ``{"measurements": ["my_measurement", ...]}``, the time-series
    measurements the plugin writes. Declared only for now: hosts may use it to
    scope writes to these names.
"""

import re
from typing import Any, List

__all__ = [
    "SUPPORTED_CONTRACT_VERSION",
    "KNOWN_MANAGED_SERVICES",
    "EGRESS_KEYWORDS",
    "contract_version",
    "declaration_errors",
    "is_host_pattern",
]

#: The highest ``CONTRACT_VERSION`` this SDK understands.
SUPPORTED_CONTRACT_VERSION = 2

#: Sidecars a plugin may declare in ``MANAGES``. Platform-bounded (like
#: ``KNOWN_SERVICES``): an unknown name is flagged.
KNOWN_MANAGED_SERVICES = frozenset({"telegraf"})

EGRESS_KEYWORDS = frozenset({"public", "lan"})

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^(\*\.)?{_LABEL}(\.{_LABEL})*$")
_MEASUREMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def contract_version(plugin: Any) -> int:
    """The plugin's declared contract version (``1`` when undeclared). Does not
    validate; see :func:`declaration_errors`."""
    value = getattr(plugin, "CONTRACT_VERSION", None)
    if value is None:
        return 1
    return value if isinstance(value, int) and not isinstance(value, bool) else 1


def is_host_pattern(value: Any) -> bool:
    """A bare hostname (``api.example.com``) or a one-level wildcard
    (``*.example.com``): lowercase, no scheme, port, path or IP literal."""
    if not isinstance(value, str) or not _HOST_RE.match(value):
        return False
    # Reject IPv4 literals: an allowlist names hosts, not addresses.
    return not re.match(r"^[0-9.]+$", value)


def _str_list(value: Any) -> bool:
    return isinstance(value, (list, tuple, frozenset, set)) and all(
        isinstance(v, str) and v for v in value
    )


def declaration_errors(plugin: Any) -> List[str]:
    """Validate the contract-v2 declarations (empty ⇒ ok, or none declared)."""
    errors: List[str] = []

    raw_version = getattr(plugin, "CONTRACT_VERSION", None)
    version = 1
    if raw_version is not None:
        if not isinstance(raw_version, int) or isinstance(raw_version, bool):
            errors.append(
                f"CONTRACT_VERSION must be an int, got {type(raw_version).__name__}"
            )
        elif raw_version < 1:
            errors.append(f"CONTRACT_VERSION must be >= 1, got {raw_version}")
        elif raw_version > SUPPORTED_CONTRACT_VERSION:
            errors.append(
                f"CONTRACT_VERSION {raw_version} is newer than this SDK supports "
                f"(max {SUPPORTED_CONTRACT_VERSION}); upgrade minder-plugin-sdk "
                "or lower the declared version"
            )
        else:
            version = raw_version

    manages = getattr(plugin, "MANAGES", None)
    if manages is not None:
        if not _str_list(manages):
            errors.append('MANAGES must be a list of names, e.g. ["telegraf"]')
        else:
            for name in manages:
                if name not in KNOWN_MANAGED_SERVICES:
                    errors.append(
                        f"MANAGES names unknown service {name!r} "
                        f"(known: {sorted(KNOWN_MANAGED_SERVICES)})"
                    )
            if manages and version < 2:
                errors.append(
                    "MANAGES requires CONTRACT_VERSION = 2 (managed services are "
                    "reached through self.ctx)"
                )

    egress = getattr(plugin, "EGRESS", None)
    if egress is not None:
        if isinstance(egress, str):
            if egress not in EGRESS_KEYWORDS:
                errors.append(
                    f"EGRESS must be one of {sorted(EGRESS_KEYWORDS)} or a list of "
                    f"host patterns, got {egress!r}"
                )
        elif not isinstance(egress, (list, tuple, frozenset, set)):
            errors.append(
                'EGRESS must be "public", "lan" or a list of host patterns, '
                f"got {type(egress).__name__}"
            )
        else:
            for pattern in egress:
                if not is_host_pattern(pattern):
                    errors.append(
                        f"EGRESS entry {pattern!r} is not a host pattern "
                        '(use "api.example.com" or "*.example.com"; no scheme, '
                        "port, path or IP)"
                    )

    timeseries = getattr(plugin, "TIMESERIES", None)
    if timeseries is not None:
        if not isinstance(timeseries, dict):
            errors.append('TIMESERIES must be a dict like {"measurements": [...]}')
        else:
            for key in timeseries:
                if key != "measurements":
                    errors.append(
                        f"TIMESERIES has unknown key {key!r} (allowed: "
                        "['measurements'])"
                    )
            measurements = timeseries.get("measurements", [])
            if not _str_list(measurements):
                errors.append("TIMESERIES['measurements'] must be a list of names")
            else:
                for m in measurements:
                    if not _MEASUREMENT_RE.match(m):
                        errors.append(
                            f"TIMESERIES measurement {m!r} is not a valid name "
                            "(letters, digits, _ . -; no spaces or commas)"
                        )

    return errors
