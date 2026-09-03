"""Config as JSON Schema + UI Schema (RFC 0001).

The scalable way to describe *any* plugin's settings: **standard JSON Schema** for
the data shape (nested objects, arrays, enums, formats, conditionals, validation)
plus a **UI Schema** of rendering hints the trusted client maps to widgets. The
simple flat ``CONFIG_SCHEMA`` list stays supported — it is *compiled* to JSON
Schema here, so simple plugins remain one-liners while the platform always speaks
JSON Schema.

The client resolves ``ui:widget`` names against its own widget registry and
**falls back to the JSON type's default widget** for anything it doesn't know —
so a plugin can ask for a widget that doesn't exist yet without breaking.
"""

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .errors import ConfigError

__all__ = [
    "fields_to_json_schema",
    "resolve_config_schema",
    "resolve_effective_config",
    "config_errors",
    "validate_config",
    "WIDGETS",
    "FORMATS",
]

# simple field "type" → JSON Schema "type"
_TYPE_TO_JSON = {
    "string": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
}

# The widget names the client's registry is expected to know. The list is OPEN —
# a plugin may name a widget outside it; the client falls back to the JSON type's
# default. Documented here as the canonical vocabulary for authors.
WIDGETS = (
    "text",
    "textarea",
    "number",
    "toggle",
    "select",
    "multiselect",
    "secret",
    "autocomplete",
    "radio",
    "slider",
    "date",
    "datetime",
    "color",
    "code",
    "kv-list",
    "file",
)

# Standard string ``format`` values a rich widget may key on (also open-ended).
FORMATS = (
    "uri",
    "email",
    "date-time",
    "date",
    "duration",
    "hostname",
    "ipv4",
    "geo-point",
    "cron",
)

# JSON Schema "type" → the Python types accepted for it (bool BEFORE int: in
# Python bool is an int subclass, so an int field must reject True/False).
_JSON_PY_TYPES: Dict[str, Tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "object": (dict,),
    "array": (list,),
}


def fields_to_json_schema(
    fields: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Compile the flat ``CONFIG_SCHEMA`` list → ``(json_schema, ui_schema)``."""
    properties: Dict[str, Any] = {}
    required: List[str] = []
    ui: Dict[str, Any] = {}
    for f in fields:
        key = f["key"]
        prop: Dict[str, Any] = {
            "type": _TYPE_TO_JSON.get(f.get("type", "string"), "string")
        }
        if "default" in f:
            prop["default"] = f["default"]
        if f.get("description"):
            prop["description"] = f["description"]
        if "min" in f:
            prop["minimum"] = f["min"]
        if "max" in f:
            prop["maximum"] = f["max"]
        if f.get("options"):
            prop["enum"] = [o["value"] for o in f["options"]]
        properties[key] = prop
        if f.get("required"):
            required.append(key)

        hints: Dict[str, Any] = {}
        widget = "secret" if f.get("secret") else f.get("widget")
        if widget:
            hints["ui:widget"] = widget
        if f.get("placeholder"):
            hints["ui:placeholder"] = f["placeholder"]
        if f.get("rows"):
            hints["ui:options"] = {"rows": f["rows"]}
        if f.get("options_action"):
            hints["ui:optionsAction"] = f["options_action"]
        if f.get("group"):
            hints["ui:group"] = f["group"]
        if hints:
            ui[key] = hints

    schema: Dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema, ui


def resolve_config_schema(plugin: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return ``(json_schema, ui_schema)`` for a plugin, regardless of how it
    declared config: prefer the advanced ``CONFIG_JSONSCHEMA`` (+ optional
    ``UI_SCHEMA``); else compile the flat ``CONFIG_SCHEMA``; else an empty object.
    This is the single entry point the registry/client should call."""
    json_schema = getattr(plugin, "CONFIG_JSONSCHEMA", None)
    if json_schema is not None:
        return json_schema, getattr(plugin, "UI_SCHEMA", None) or {}
    fields = getattr(plugin, "CONFIG_SCHEMA", None)
    if fields:
        return fields_to_json_schema(fields)
    return {"type": "object", "properties": {}}, {}


def _coerce(value: Any, jtype: Optional[str]) -> Any:
    """Coerce an env-sourced string to the field's JSON-Schema type — env values
    are always strings, so a ``bool``/``integer``/``number`` field would otherwise
    keep a string (``"false"`` is truthy!). A value that can't be coerced is
    returned unchanged so validation surfaces it instead of the coercion masking
    a bad input."""
    if not isinstance(value, str):
        return value
    if jtype == "boolean":
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off", ""):
            return False
        return value
    if jtype == "integer":
        try:
            return int(value)
        except ValueError:
            return value
    if jtype == "number":
        try:
            return float(value)
        except ValueError:
            return value
    return value


def resolve_effective_config(
    plugin: Any,
    env: Optional[Mapping[str, str]] = None,
    persisted: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolve each config key by the standard precedence **default → env →
    persisted** (persisted wins). Works for both the flat list and full JSON
    Schema (defaults are read from the compiled schema's properties). This is the
    one shared implementation the registry and ``PluginBase`` both use, so config
    resolution can never drift between them."""
    env = env or {}
    persisted = persisted or {}
    schema, _ = resolve_config_schema(plugin)
    out: Dict[str, Any] = {}
    for key, prop in schema.get("properties", {}).items():
        value: Any = prop.get("default")
        if key in env:
            value = _coerce(env[key], prop.get("type"))
        if key in persisted:
            value = persisted[key]
        out[key] = value
    return out


def _prop_errors(key: str, prop: Dict[str, Any], value: Any) -> List[str]:
    errs: List[str] = []
    jtype = prop.get("type")
    accepted = _JSON_PY_TYPES.get(jtype) if jtype else None
    if accepted is not None:
        # bool is an int subclass — an integer/number field must reject booleans.
        if jtype in ("integer", "number") and isinstance(value, bool):
            errs.append(f"{key}: expected {jtype}, got boolean")
            return errs
        if not isinstance(value, accepted):
            errs.append(f"{key}: expected {jtype}, got {type(value).__name__}")
            return errs
    if "enum" in prop and value not in prop["enum"]:
        errs.append(f"{key}: {value!r} is not one of {prop['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in prop and value < prop["minimum"]:
            errs.append(f"{key}: {value} < minimum {prop['minimum']}")
        if "maximum" in prop and value > prop["maximum"]:
            errs.append(f"{key}: {value} > maximum {prop['maximum']}")
    if isinstance(value, str):
        if "minLength" in prop and len(value) < prop["minLength"]:
            errs.append(f"{key}: shorter than minLength {prop['minLength']}")
        if "maxLength" in prop and len(value) > prop["maxLength"]:
            errs.append(f"{key}: longer than maxLength {prop['maxLength']}")
        pattern = prop.get("pattern")
        if pattern and not re.search(pattern, value):
            errs.append(f"{key}: does not match pattern {pattern!r}")
    return errs


def config_errors(schema: Dict[str, Any], values: Mapping[str, Any]) -> List[str]:
    """Return a list of human-readable validation errors for ``values`` against a
    JSON ``schema`` (empty ⇒ valid). A light, dependency-free validator covering
    the subset this SDK emits: type, required, enum, minimum/maximum,
    minLength/maxLength, pattern. For full JSON Schema (arrays/nested/conditionals)
    install the optional ``jsonschema`` extra and use it directly."""
    errors: List[str] = []
    for key in schema.get("required", []):
        if key not in values:
            errors.append(f"{key}: required")
    props = schema.get("properties", {})
    for key, value in values.items():
        prop = props.get(key)
        if isinstance(prop, dict):
            errors.extend(_prop_errors(key, prop, value))
    return errors


def validate_config(plugin: Any, values: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate ``values`` against the plugin's config schema. Returns the values
    (as a dict) on success; raises :class:`ConfigError` with per-field messages
    otherwise."""
    schema, _ = resolve_config_schema(plugin)
    errors = config_errors(schema, values)
    if errors:
        raise ConfigError(f"invalid config: {'; '.join(errors)}", errors=errors)
    return dict(values)
