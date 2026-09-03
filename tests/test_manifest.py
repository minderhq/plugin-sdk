"""Tests for manifest loading + validation: the dict/YAML parse paths and their
error branches, the full jsonschema validation, and the light structural
fallback used when jsonschema isn't installed (forced via sys.modules).
"""

import sys

import pytest

from minder_plugin_sdk.errors import ManifestError
from minder_plugin_sdk.manifest import (
    _light_errors,
    load_manifest,
    manifest_schema,
    validate_manifest,
)

VALID = {
    "apiVersion": "minder.dev/v1alpha1",
    "kind": "Plugin",
    "metadata": {"name": "discord-ingest", "version": "1.0.0"},
    "spec": {
        "trigger": {"type": "webhook", "webhook": {"path": "/discord/webhook"}},
        "action": {
            "type": "store-vector",
            "store": {
                "collection": "discord-messages",
                "input": {"text": "{{ .content }}"},
            },
        },
    },
}

VALID_YAML = """
apiVersion: minder.dev/v1alpha1
kind: Plugin
metadata:
  name: discord-ingest
  version: 1.0.0
spec:
  trigger:
    type: webhook
    webhook:
      path: /discord/webhook
  action:
    type: store-vector
    store:
      collection: discord-messages
      input:
        text: "{{ .content }}"
"""


# ── manifest_schema ──────────────────────────────────────────────────────────
def test_manifest_schema_is_the_bundled_draft07():
    schema = manifest_schema()
    assert schema["required"] == ["apiVersion", "kind", "metadata", "spec"]


# ── load_manifest ────────────────────────────────────────────────────────────
def test_load_manifest_passes_a_dict_through():
    d = {"already": "parsed"}
    assert load_manifest(d) is d


def test_load_manifest_parses_yaml_text():
    assert load_manifest(VALID_YAML)["metadata"]["name"] == "discord-ingest"


def test_load_manifest_rejects_invalid_yaml():
    with pytest.raises(ManifestError, match="invalid YAML"):
        load_manifest("key: [unterminated")


def test_load_manifest_rejects_non_mapping_top_level():
    with pytest.raises(ManifestError, match="must be a mapping"):
        load_manifest("just a scalar string")


# ── validate_manifest (full jsonschema path) ─────────────────────────────────
def test_validate_manifest_accepts_a_valid_manifest():
    assert validate_manifest(VALID) == VALID


def test_validate_manifest_accepts_valid_yaml():
    assert validate_manifest(VALID_YAML)["kind"] == "Plugin"


def test_validate_manifest_reports_schema_errors_with_paths():
    bad = {
        "apiVersion": "minder.dev/v1alpha1",
        "kind": "Plugin",
        "metadata": {"name": "x"},  # missing version
        "spec": {"trigger": {"type": "webhook"}},  # missing action
    }
    with pytest.raises(ManifestError) as ei:
        validate_manifest(bad)
    assert ei.value.errors  # per-issue messages populated
    joined = "; ".join(ei.value.errors)
    assert "action" in joined and "version" in joined


def test_validate_manifest_rejects_bad_webhook_path():
    bad = {
        **VALID,
        "spec": {
            "trigger": {"type": "webhook", "webhook": {"path": "no-leading-slash"}},
            "action": VALID["spec"]["action"],
        },
    }
    with pytest.raises(ManifestError):
        validate_manifest(bad)


# ── _light_errors (structural fallback) ──────────────────────────────────────
def test_light_errors_empty_for_valid():
    assert _light_errors(VALID) == []


def test_light_errors_flags_missing_top_level_keys():
    errs = _light_errors({})
    assert any("apiVersion" in e for e in errs)
    assert any("kind" in e for e in errs)
    assert any("metadata" in e for e in errs)
    assert any("spec" in e for e in errs)


def test_light_errors_flags_unsupported_apiversion_and_kind():
    errs = _light_errors(
        {"apiVersion": "wrong", "kind": "Nope", "metadata": {}, "spec": {}}
    )
    assert any("unsupported apiVersion" in e for e in errs)
    assert any("unsupported kind" in e for e in errs)


def test_light_errors_flags_missing_metadata_and_spec_fields():
    errs = _light_errors(
        {
            "apiVersion": "minder.dev/v1alpha1",
            "kind": "Plugin",
            "metadata": {"name": ""},  # empty name, missing version
            "spec": {},  # missing trigger + action
        }
    )
    assert any("metadata.name is required" in e for e in errs)
    assert any("metadata.version is required" in e for e in errs)
    assert any("spec.trigger is required" in e for e in errs)
    assert any("spec.action is required" in e for e in errs)


# ── fallback wired through validate_manifest when jsonschema is absent ────────
def test_validate_manifest_falls_back_to_light_check_without_jsonschema(monkeypatch):
    # Force `import jsonschema` inside validate_manifest to raise ImportError so
    # the structural fallback runs — its error wording ("missing required key")
    # differs from jsonschema's, proving which path executed.
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    with pytest.raises(ManifestError) as ei:
        validate_manifest({"kind": "Plugin"})
    assert any("missing required key" in e for e in ei.value.errors)


def test_light_errors_rejects_non_dict_metadata_and_spec():
    errs = _light_errors(
        {
            "apiVersion": "minder.dev/v1alpha1",
            "kind": "Plugin",
            "metadata": "oops",
            "spec": "nope",
        }
    )
    assert any("metadata must be an object" in e for e in errs)
    assert any("spec must be an object" in e for e in errs)


def test_light_errors_flags_missing_nested_required():
    errs = _light_errors(
        {
            "apiVersion": "minder.dev/v1alpha1",
            "kind": "Plugin",
            "metadata": {"name": "n", "version": "1.0.0"},
            "spec": {"trigger": {}, "action": {"type": "store-vector"}},
        }
    )
    assert any("trigger.type" in e for e in errs)
    assert any("store.collection" in e for e in errs)
