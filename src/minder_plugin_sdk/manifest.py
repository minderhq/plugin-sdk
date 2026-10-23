"""Manifests — plugins expressed as data, with no plugin code.

Two documents share ``apiVersion: minder.dev/v1alpha1`` / ``kind: Plugin``:

* a **manifest plugin**: one trigger (``webhook``, ``schedule``, ``poll``) and
  one action (``store-vector``, ``http-request``, ``plugin-action``) —
  ``schemas/manifest.schema.json``;
* a **declarative connector** (``spec.runtime.kind: declarative``): HTTP tools,
  actions, a schedule and a webhook run by Minder's connector engine —
  ``schemas/declarative-manifest.schema.json``.

This module loads a manifest (YAML text or an already-parsed dict) and validates
it against the bundled JSON Schema for its kind. If the optional ``jsonschema``
extra is installed it does full validation; otherwise it falls back to a light
structural check of the required shape.
"""

import json
from importlib import resources
from typing import Any, Dict, List, Union, cast

from .errors import ManifestError

__all__ = [
    "load_manifest",
    "validate_manifest",
    "manifest_schema",
    "declarative_manifest_schema",
    "is_declarative_manifest",
]


def _bundled_schema(name: str) -> Dict[str, Any]:
    text = (
        resources.files("minder_plugin_sdk.schemas")
        .joinpath(name)
        .read_text(encoding="utf-8")
    )
    return cast(Dict[str, Any], json.loads(text))


def manifest_schema() -> Dict[str, Any]:
    """The bundled manifest-plugin JSON Schema (draft-07)."""
    return _bundled_schema("manifest.schema.json")


def declarative_manifest_schema() -> Dict[str, Any]:
    """The bundled declarative-connector manifest JSON Schema (draft-07)."""
    return _bundled_schema("declarative-manifest.schema.json")


def is_declarative_manifest(manifest: Any) -> bool:
    """Whether ``manifest`` declares the declarative connector runtime
    (``spec.runtime.kind: declarative``)."""
    spec = manifest.get("spec") if isinstance(manifest, dict) else None
    runtime = spec.get("runtime") if isinstance(spec, dict) else None
    return isinstance(runtime, dict) and runtime.get("kind") == "declarative"


def load_manifest(source: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Parse a manifest from YAML text (needs the ``examples``/``yaml`` extra) or
    accept an already-parsed dict. Raises :class:`ManifestError` on parse failure."""
    if isinstance(source, dict):
        return source
    try:
        import yaml  # optional; only needed to parse YAML text
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise ManifestError(
            "parsing a YAML manifest needs PyYAML — `pip install pyyaml` "
            "(or pass an already-parsed dict)"
        ) from exc
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a mapping at the top level")
    return data


def _light_errors(m: Dict[str, Any]) -> List[str]:
    """Structural check when ``jsonschema`` isn't installed."""
    errors: List[str] = []
    for key in ("apiVersion", "kind", "metadata", "spec"):
        if key not in m:
            errors.append(f"missing required key: {key}")
    if m.get("apiVersion") not in (None, "minder.dev/v1alpha1"):
        errors.append(f"unsupported apiVersion: {m.get('apiVersion')!r}")
    if m.get("kind") not in (None, "Plugin"):
        errors.append(f"unsupported kind: {m.get('kind')!r}")
    meta = m.get("metadata")
    if "metadata" in m and not isinstance(meta, dict):
        errors.append("metadata must be an object")
    elif isinstance(meta, dict):
        for key in ("name", "version"):
            if not meta.get(key):
                errors.append(f"metadata.{key} is required")
    spec = m.get("spec")
    if "spec" in m and not isinstance(spec, dict):
        errors.append("spec must be an object")
    elif is_declarative_manifest(m):
        assert isinstance(spec, dict)
        if not isinstance(spec.get("egress"), list) or not spec["egress"]:
            errors.append("spec.egress needs at least one host")
        if not isinstance(spec.get("bases"), dict) or not spec["bases"]:
            errors.append("spec.bases needs at least one base")
        if not (spec.get("tools") or spec.get("actions") or spec.get("schedule")):
            errors.append("spec: declare at least one tool, action or schedule")
    elif isinstance(spec, dict):
        trigger = spec.get("trigger")
        if "trigger" not in spec:
            errors.append("spec.trigger is required")
        elif not isinstance(trigger, dict) or not trigger.get("type"):
            errors.append("spec.trigger.type is required")
        action = spec.get("action")
        if "action" not in spec:
            errors.append("spec.action is required")
        elif not isinstance(action, dict) or not action.get("type"):
            errors.append("spec.action.type is required")
        elif action.get("type") == "store-vector":
            store = action.get("store")
            if not isinstance(store, dict) or not store.get("collection"):
                errors.append("spec.action.store.collection is required")
            elif not (
                isinstance(store.get("input"), dict) and store["input"].get("text")
            ):
                errors.append("spec.action.store.input.text is required")
    return errors


def validate_manifest(source: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Validate a manifest; return the parsed dict on success, else raise
    :class:`ManifestError` with per-issue messages. A declarative connector
    (``spec.runtime.kind: declarative``) is checked against
    :func:`declarative_manifest_schema`, any other manifest against
    :func:`manifest_schema`. Uses ``jsonschema`` for full validation when
    available, else a light structural check."""
    manifest = load_manifest(source)
    schema = (
        declarative_manifest_schema()
        if is_declarative_manifest(manifest)
        else manifest_schema()
    )
    try:
        import jsonschema  # optional extra for full validation

        validator = jsonschema.Draft7Validator(schema)
        errors = [
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in validator.iter_errors(manifest)
        ]
    except ImportError:
        errors = _light_errors(manifest)
    if errors:
        raise ManifestError(f"invalid manifest: {'; '.join(errors)}", errors=errors)
    return manifest
