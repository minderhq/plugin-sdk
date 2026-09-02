"""Minder plugin authoring SDK.

    from minder_plugin_sdk import PluginBase, PluginMetadata

Modules: ``contract`` (Plugin Protocol + PluginMetadata + CONFIG_SCHEMA / ACTIONS
/ AI_TOOLS / DISPLAY extension points) · ``base`` (PluginBase convenience class) ·
``schema`` (JSON-Schema config: compile, resolve, validate) · ``capabilities``
(the capability model + per-capability protocols) · ``ai_tools`` · ``manifest`` ·
``harness`` (test helpers) · ``errors``. Design: ``docs/rfc/0001-*``. CLI:
``minder-plugin``. Worked plugins in ``examples/``.
"""

from .ai_tools import ai_tool_errors, build_tool_definitions
from .base import PluginBase
from .capabilities import (
    KNOWN_CAPABILITIES,
    ConnectionProvider,
    DataSource,
    Scheduler,
    UIPanelProvider,
    WebhookHandler,
    capabilities,
)
from .contract import Plugin, PluginMetadata
from .errors import ConfigError, ManifestError, PluginError
from .harness import check_plugin, run_lifecycle
from .manifest import load_manifest, manifest_schema, validate_manifest
from .requirements import (
    KNOWN_BUNDLES,
    KNOWN_SERVICES,
    requirement_errors,
    requirements,
)
from .schema import (
    FORMATS,
    WIDGETS,
    config_errors,
    fields_to_json_schema,
    resolve_config_schema,
    resolve_effective_config,
    validate_config,
)

API_VERSION = "minder.dev/v1"

__all__ = [
    # core contract
    "Plugin",
    "PluginMetadata",
    "PluginBase",
    "API_VERSION",
    # capabilities
    "capabilities",
    "KNOWN_CAPABILITIES",
    "DataSource",
    "Scheduler",
    "WebhookHandler",
    "ConnectionProvider",
    "UIPanelProvider",
    # config schema
    "resolve_config_schema",
    "fields_to_json_schema",
    "resolve_effective_config",
    "config_errors",
    "validate_config",
    "WIDGETS",
    "FORMATS",
    # ai tools
    "build_tool_definitions",
    "ai_tool_errors",
    # manifest
    "load_manifest",
    "validate_manifest",
    "manifest_schema",
    # requirements (services / bundles a plugin needs)
    "requirements",
    "requirement_errors",
    "KNOWN_SERVICES",
    "KNOWN_BUNDLES",
    # testing
    "check_plugin",
    "run_lifecycle",
    # errors
    "PluginError",
    "ConfigError",
    "ManifestError",
    "__version__",
]

__version__ = "0.1.0"
