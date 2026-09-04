"""Tests for the `minder-plugin` CLI: validate (plugin.py + manifest), inspect,
scaffold, and the plugin-class loader's discovery + error branches. Each command
is driven through `cli.main([...])` and asserted on its exit code / output.
"""

from pathlib import Path

import pytest

from minder_plugin_sdk import cli

VALID_MODULE_ALL = '''\
"""p"""
from minder_plugin_sdk import PluginBase, PluginMetadata

__all__ = ["MyPlugin"]


class MyPlugin(PluginBase):
    async def register(self):
        return PluginMetadata(name="my", version="1.0.0", description="d", author="a")

    async def collect_data(self):
        self._last = {"ok": True}
        return self._last
'''

# no module-level __all__ → loader falls back to scanning for a register() class
VALID_SCAN = VALID_MODULE_ALL.replace('__all__ = ["MyPlugin"]\n\n\n', "")

# register() returns a dict, not PluginMetadata → check_plugin flags it
BROKEN_PLUGIN = '''\
"""p"""


class BrokenPlugin:
    async def register(self):
        return {"not": "metadata"}
'''

NO_CLASS = '''\
"""just a helper module, no plugin class"""

VALUE = 1
'''

VALID_MANIFEST = """\
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


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ── _load_plugin_class discovery ─────────────────────────────────────────────
def test_load_plugin_class_uses_module_all(tmp_path):
    cls = cli._load_plugin_class(_write(tmp_path, "via_all.py", VALID_MODULE_ALL))
    assert cls.__name__ == "MyPlugin"


def test_load_plugin_class_scans_when_no_all(tmp_path):
    cls = cli._load_plugin_class(_write(tmp_path, "via_scan.py", VALID_SCAN))
    assert cls.__name__ == "MyPlugin"


def test_load_plugin_class_raises_without_a_plugin_class(tmp_path):
    with pytest.raises(RuntimeError, match="no plugin class"):
        cli._load_plugin_class(_write(tmp_path, "no_class.py", NO_CLASS))


# ── validate ─────────────────────────────────────────────────────────────────
def test_validate_ok_plugin_returns_zero(tmp_path, capsys):
    rc = cli.main(["validate", str(_write(tmp_path, "ok_plugin.py", VALID_MODULE_ALL))])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_validate_reports_contract_problems(tmp_path, capsys):
    rc = cli.main(["validate", str(_write(tmp_path, "broken.py", BROKEN_PLUGIN))])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "PluginMetadata" in out


def test_validate_ok_manifest_returns_zero(tmp_path, capsys):
    rc = cli.main(["validate", str(_write(tmp_path, "m.yaml", VALID_MANIFEST))])
    assert rc == 0
    assert "manifest is valid" in capsys.readouterr().out


def test_validate_invalid_manifest_returns_one(tmp_path, capsys):
    rc = cli.main(["validate", str(_write(tmp_path, "bad.yml", "kind: Plugin\n"))])
    assert rc == 1
    assert "FAIL invalid manifest" in capsys.readouterr().out


# ── inspect ──────────────────────────────────────────────────────────────────
def test_inspect_prints_json_report(tmp_path, capsys):
    import json

    rc = cli.main(["inspect", str(_write(tmp_path, "insp.py", VALID_MODULE_ALL))])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    # the exact set is derived by the SDK; just assert the report shape is whole
    assert isinstance(report["capabilities"], list)
    for key in ("capabilities", "requires", "config_schema", "ui_schema", "ai_tools"):
        assert key in report


# ── scaffold ─────────────────────────────────────────────────────────────────
def test_scaffold_writes_a_valid_plugin(tmp_path, capsys):
    out = tmp_path / "generated.py"
    rc = cli.main(["scaffold", "my-cool-plugin", "-o", str(out)])
    assert rc == 0 and out.exists()
    # round-trip: the generated skeleton must itself pass validate
    assert cli.main(["validate", str(out)]) == 0


def test_scaffold_refuses_to_overwrite(tmp_path, capsys):
    out = tmp_path / "exists.py"
    out.write_text("# already here\n", encoding="utf-8")
    rc = cli.main(["scaffold", "x", "-o", str(out)])
    assert rc == 1
    assert "refusing to overwrite" in capsys.readouterr().out
    assert out.read_text(encoding="utf-8") == "# already here\n"  # untouched


def test_load_plugin_class_raises_when_unimportable(tmp_path):
    # A non-Python suffix has no import loader, so spec_from_file_location returns
    # None -> _load_plugin_class raises rather than crashing with AttributeError.
    p = tmp_path / "not_python.txt"
    p.write_text("nope", encoding="utf-8")
    with pytest.raises(RuntimeError, match="cannot import"):
        cli._load_plugin_class(p)
