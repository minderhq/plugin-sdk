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

from typing import Any, Dict, List, Tuple

__all__ = ["fields_to_json_schema", "resolve_config_schema"]

# simple field "type" → JSON Schema "type"
_TYPE_TO_JSON = {
    "string": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
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
