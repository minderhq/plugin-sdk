"""The T0 declarative connector engine.

The same engine runs in Minder's declarative plugin runner and in
``minder-plugin try``, so an author sees exactly what the runner will do.

A declarative plugin is a manifest, not code: HTTP requests on declared
bases, engine-injected auth, JMESPath / XML mapping, bounded pagination,
fan-out and chaining, exposed as AI tools, actions and a schedule trigger.
The engine enforces strict per-plugin egress itself.

- ``model``: validate and compile a manifest (``load_manifest``).
- ``placeholders``: the minimal ``{params.x}`` substitution, encoded per URL
  component.
- ``mapping``: JMESPath and XML->JSON.
- ``egress``: per-plugin host/scheme/address/redirect checks, IP pinning and
  limits; denials are counted (``DENIALS``).
- ``engine``: runs tools, actions and the schedule, one invocation at a time.
"""

from .egress import DENIALS, DenialCounter, PluginEgress
from .engine import Engine, Invocation
from .errors import (
    EgressDenied,
    EngineError,
    LimitExceeded,
    ManifestError,
    MappingError,
    ParamsError,
    ParseError,
    SecretUnavailable,
    UpstreamError,
)
from .model import DeclarativeManifest, load_manifest

__all__ = [
    "DENIALS",
    "DeclarativeManifest",
    "DenialCounter",
    "EgressDenied",
    "Engine",
    "EngineError",
    "Invocation",
    "LimitExceeded",
    "ManifestError",
    "MappingError",
    "ParamsError",
    "ParseError",
    "PluginEgress",
    "SecretUnavailable",
    "UpstreamError",
    "load_manifest",
]
