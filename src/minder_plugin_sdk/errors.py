"""SDK exception types. Plugins and tooling raise/catch these instead of bare
``Exception`` so failures are classifiable."""

from typing import List, Optional

__all__ = ["PluginError", "ConfigError", "ManifestError"]


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
