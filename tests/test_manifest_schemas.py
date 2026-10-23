"""The bundled manifest schemas: the manifest-plugin trigger/action types, the
declarative connector schema, and every catalog manifest against them.

``tests/fixtures/catalog/`` is a copy of the declarative manifests in the plugin
catalog (minderhq/plugins). The catalog validates its own manifests with this
SDK too; the copy keeps this repo's suite self-contained.
"""

import copy
from pathlib import Path
from typing import Any, Dict, List

import jsonschema
import pytest
import yaml

from minder_plugin_sdk import (
    declarative_manifest_schema,
    is_declarative_manifest,
    manifest_schema,
    validate_manifest,
)
from minder_plugin_sdk.errors import ManifestError
from minder_plugin_sdk.manifest import _light_errors

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parent.parent / "examples"
CATALOG = sorted((FIXTURES / "catalog").glob("*.yml"))
DECLARATIVE = CATALOG + sorted((FIXTURES / "declarative").glob("*.yml"))
EVERY_FIELD = FIXTURES / "declarative" / "every_field.yml"


def _load(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _errors(manifest: Dict[str, Any]) -> List[str]:
    try:
        validate_manifest(manifest)
    except ManifestError as exc:
        return list(exc.errors)
    return []


# ── both schemas ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "schema, file",
    [
        (manifest_schema, "manifest.v1alpha1.json"),
        (declarative_manifest_schema, "declarative-manifest.v1alpha1.json"),
    ],
)
def test_schemas_are_draft07_with_a_published_id(schema, file):
    doc = schema()
    jsonschema.Draft7Validator.check_schema(doc)
    assert doc["$id"] == f"https://minderhq.github.io/docs/schemas/{file}"


# ── manifest plugins: trigger and action types ──────────────────────────────
def _plugin(trigger: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "apiVersion": "minder.dev/v1alpha1",
        "kind": "Plugin",
        "metadata": {"name": "sample", "version": "1.0.0"},
        "spec": {"trigger": trigger, "action": action},
    }


WEBHOOK = {"type": "webhook", "webhook": {"path": "/in", "secretRef": "in.secret"}}
SCHEDULE = {"type": "schedule", "schedule": {"cron": "0 * * * *"}}
POLL = {
    "type": "poll",
    "poll": {"url": "https://example.com/feed", "headers": {"Accept": "*/*"}},
}
STORE = {
    "type": "store-vector",
    "store": {"collection": "events", "input": {"text": "{{ .content }}"}},
}
HTTP = {
    "type": "http-request",
    "httpRequest": {
        "method": "PUT",
        "url": "https://example.com/{{ .id }}",
        "headers": {"X-Id": "{{ .id }}"},
        "body": {"id": "{{ .id }}"},
    },
}
PLUGIN_ACTION = {
    "type": "plugin-action",
    "pluginAction": {"plugin": "weather", "action": "refresh", "params": {}},
}


@pytest.mark.parametrize("trigger", [WEBHOOK, SCHEDULE, POLL])
@pytest.mark.parametrize("action", [STORE, HTTP, PLUGIN_ACTION])
def test_every_trigger_and_action_type_is_accepted(trigger, action):
    assert _errors(_plugin(trigger, action)) == []


@pytest.mark.parametrize(
    "trigger, action",
    [
        ({"type": "schedule"}, STORE),
        ({"type": "poll"}, STORE),
        ({"type": "poll", "poll": {"url": "ftp://example.com/x"}}, STORE),
        ({"type": "schedule", "schedule": {"cron": "hourly"}}, STORE),
        ({"type": "cron", "cron": {}}, STORE),
        (WEBHOOK, {"type": "http-request"}),
        (WEBHOOK, {"type": "http-request", "httpRequest": {"url": "file:///x"}}),
        (WEBHOOK, {"type": "plugin-action"}),
        (WEBHOOK, {"type": "plugin-action", "pluginAction": {"plugin": "weather"}}),
        (WEBHOOK, {"type": "store-vector"}),
        (WEBHOOK, {"type": "run-code"}),
    ],
)
def test_incomplete_or_unknown_trigger_and_action_types_are_refused(trigger, action):
    assert _errors(_plugin(trigger, action))


def test_a_webhook_without_a_secret_ref_is_refused():
    unsigned = {"type": "webhook", "webhook": {"path": "/in"}}
    assert any("secretRef" in e for e in _errors(_plugin(unsigned, STORE)))


def test_the_t0_webhook_prefix_is_reserved():
    t0 = {"type": "webhook", "webhook": {"path": "/t0/in", "secretRef": "s"}}
    assert _errors(_plugin(t0, STORE))


def test_an_empty_store_text_template_is_refused():
    action = copy.deepcopy(STORE)
    action["store"]["input"]["text"] = ""
    assert _errors(_plugin(WEBHOOK, action))


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*manifest*.yaml")))
def test_the_example_manifests_are_valid(path):
    assert _errors(_load(path)) == []


# ── declarative connectors ───────────────────────────────────────────────────
@pytest.mark.parametrize("path", DECLARATIVE, ids=lambda p: p.stem)
def test_every_catalog_declarative_manifest_is_valid(path):
    manifest = _load(path)
    assert is_declarative_manifest(manifest)
    assert _errors(manifest) == []


def test_the_catalog_snapshot_is_not_empty():
    assert {p.stem for p in CATALOG} >= {
        "arxiv",
        "frankfurter",
        "openlibrary",
        "wikipedia",
    }


def test_declarative_dispatch_uses_the_declarative_schema():
    # A declarative manifest has no trigger/action; the manifest-plugin schema
    # alone would refuse it.
    manifest = _load(EVERY_FIELD)
    v = jsonschema.Draft7Validator(manifest_schema())
    assert not v.is_valid(manifest)
    assert _errors(manifest) == []


def _mutate(path: str, value: Any = None, delete: bool = False) -> Dict[str, Any]:
    manifest = _load(EVERY_FIELD)
    node: Any = manifest
    keys: List[Any] = [int(k) if k.isdigit() else k for k in path.split(".")]
    for key in keys[:-1]:
        node = node[key]
    if delete:
        del node[keys[-1]]
    else:
        node[keys[-1]] = value
    return manifest


@pytest.mark.parametrize(
    "path",
    [
        "extra",
        "metadata.extra",
        "spec.extra",
        "spec.runtime.extra",
        "spec.egress.0.extra",
        "spec.bases.api.extra",
        "spec.bases.api.auth.extra",
        "spec.limits.extra",
        "spec.timeseries.extra",
        "spec.tools.search.extra",
        "spec.tools.search.steps.0.extra",
        "spec.tools.search.steps.0.request.extra",
        "spec.tools.search.steps.0.request.paginate.extra",
        "spec.actions.ingest.steps.0.request.body.extra",
        "spec.actions.feed.steps.0.request.xml.extra",
        "spec.actions.feed.timeseries.extra",
        "spec.schedule.extra",
        "spec.webhook.extra",
    ],
)
def test_unknown_fields_are_refused_at_every_level(path):
    assert _errors(_mutate(path, "x"))


@pytest.mark.parametrize(
    "path",
    [
        "apiVersion",
        "metadata.name",
        "metadata.version",
        "spec.runtime",
        "spec.runtime.kind",
        "spec.egress",
        "spec.bases",
        "spec.egress.0.host",
        "spec.bases.api.url",
        "spec.tools.search.description",
        "spec.tools.search.steps",
        "spec.tools.search.steps.0.name",
        "spec.tools.search.steps.0.request",
        "spec.tools.search.steps.0.request.base",
        "spec.tools.search.steps.0.request.paginate.type",
        "spec.actions.feed.timeseries.points",
        "spec.schedule.steps",
        "spec.schedule.measurement",
        "spec.schedule.points",
        "spec.webhook.action",
        "spec.webhook.secret",
    ],
)
def test_required_fields_are_required(path):
    assert _errors(_mutate(path, delete=True))


@pytest.mark.parametrize(
    "path, value",
    [
        ("spec.runtime.kind", "python"),
        ("spec.runtime.engine", 2),
        ("metadata.name", "Has Caps"),
        ("spec.egress", []),
        ("spec.bases", {}),
        ("spec.limits.timeout_s", 0),
        ("spec.limits.timeout_s", 31),
        ("spec.limits.max_concurrency", 9),
        ("spec.limits.max_response_bytes", 512),
        ("spec.tools.search.steps.0.max_items", 21),
        ("spec.tools.search.steps.0.request.method", "TRACE"),
        ("spec.tools.search.steps.0.request.response", "html"),
        ("spec.tools.search.steps.0.request.paginate.max_pages", 11),
        ("spec.tools.search.steps.0.request.query", {"q": ["a"]}),
        ("spec.tools.search.effect", "maybe"),
        ("spec.tools.search.parameters", {"type": "array"}),
        ("spec.tools.search.description", ""),
        ("spec.tools.search.steps.0.name", "Bad-Name"),
        ("spec.bases.api.auth.type", "oauth"),
        ("spec.bases.api.auth.in", "cookie"),
        ("spec.timeseries.measurements", []),
        ("spec.timeseries.measurements", ["Bad-Name"]),
        ("spec.schedule.cron", "every hour"),
        ("spec.schedule.tags", {"owner_id": "'x'"}),
        ("spec.webhook.secret", "not a key"),
        ("spec.config_schema", [{"type": "string"}]),
    ],
)
def test_out_of_range_values_are_refused(path, value):
    assert _errors(_mutate(path, value))


def test_reserved_and_malformed_operation_names_are_refused():
    for name in ("schedule", "health_check", "Search", "9lives"):
        manifest = _load(EVERY_FIELD)
        manifest["spec"]["tools"][name] = manifest["spec"]["tools"].pop("search")
        assert _errors(manifest), name


def test_a_tool_cannot_write_time_series_and_an_action_has_no_effect():
    manifest = _load(EVERY_FIELD)
    manifest["spec"]["tools"]["search"]["timeseries"] = copy.deepcopy(
        manifest["spec"]["actions"]["feed"]["timeseries"]
    )
    assert _errors(manifest)
    manifest = _load(EVERY_FIELD)
    manifest["spec"]["actions"]["feed"]["effect"] = "read"
    assert _errors(manifest)


def test_a_connector_needs_a_tool_an_action_or_a_schedule():
    manifest = _load(EVERY_FIELD)
    for key in ("tools", "actions", "schedule", "webhook"):
        del manifest["spec"][key]
    assert _errors(manifest)
    manifest["spec"]["tools"] = {}
    assert _errors(manifest)


def test_optional_fields_accept_null():
    for path in (
        "metadata.stable_id",
        "spec.display",
        "spec.timeseries",
        "spec.schedule",
        "spec.webhook",
        "spec.tools.search.output",
        "spec.tools.search.read_only",
        "spec.tools.search.steps.0.when",
        "spec.tools.search.steps.0.request.paginate",
        "spec.tools.search.steps.0.request.follow_redirects",
        "spec.schedule.cron",
    ):
        assert _errors(_mutate(path, None)) == [], path


def test_light_fallback_checks_the_declarative_shape():
    manifest = _load(EVERY_FIELD)
    assert _light_errors(manifest) == []
    del manifest["spec"]["bases"]
    manifest["spec"]["egress"] = []
    for key in ("tools", "actions", "schedule"):
        del manifest["spec"][key]
    errs = _light_errors(manifest)
    assert any("spec.egress" in e for e in errs)
    assert any("spec.bases" in e for e in errs)
    assert any("at least one tool" in e for e in errs)
    assert not any("trigger" in e for e in errs)


def test_is_declarative_manifest():
    assert is_declarative_manifest({"spec": {"runtime": {"kind": "declarative"}}})
    assert not is_declarative_manifest({"spec": {"runtime": {"kind": "python"}}})
    assert not is_declarative_manifest({"spec": {"runtime": "declarative"}})
    assert not is_declarative_manifest({"spec": []})
    assert not is_declarative_manifest([])
