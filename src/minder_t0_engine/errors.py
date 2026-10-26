"""Errors of the T0 connector engine.

Every message here is fixed or built from manifest-declared names only: never
from a parameter value, a config value, a secret, a URL with its query, or an
upstream body. The host returns some of them to plugin-registry.
"""

from typing import Optional


class EngineError(Exception):
    """Base class. ``str(e)`` is safe to return to the caller."""


class ManifestError(EngineError):
    """The declarative manifest is invalid; it is refused at load."""


class ParamsError(EngineError, ValueError):
    """The tool or action parameters do not match their JSON Schema.

    A ``ValueError`` so the runner host maps it to ``invalid_argument``."""


class EgressDenied(EngineError):
    """A request the plugin's egress policy refuses (host, scheme, address or
    redirect). Logged with the plugin name and counted (quarantine)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"egress denied: {reason}")
        self.reason = reason


class LimitExceeded(EngineError):
    """A bound was hit: response size, time, rate, pages, fan-out, requests."""

    def __init__(self, limit: str) -> None:
        super().__init__(f"limit exceeded: {limit}")
        self.limit = limit


class UpstreamError(EngineError):
    """The upstream API failed (transport error, non-accepted status, or a body
    that does not parse as the declared format)."""

    def __init__(self, reason: str, status: Optional[int] = None) -> None:
        super().__init__(
            f"upstream error: {reason}" + (f" (HTTP {status})" if status else "")
        )
        self.reason = reason
        self.status = status


class ParseError(UpstreamError):
    """The upstream answered, but its body does not decode as the declared
    format (invalid JSON or XML, or an empty body a request declares
    ``empty_body: error`` for). ``error_output`` sees it as ``kind: parse``,
    apart from transport and status failures."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)


class MappingError(EngineError):
    """A placeholder or JMESPath mapping could not be applied."""


class SecretUnavailable(EngineError):
    """An auth secret is not set for the invoking tenant, or there is no
    invocation grant to read it under."""

    def __init__(self, key: str) -> None:
        super().__init__(f"secret {key!r} is not available for this invocation")
        self.key = key
