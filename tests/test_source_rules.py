"""Source rules run by check_plugin: no platform secrets read from os.environ,
no imports of platform internals (core.*). Plugin modules are written to a temp
dir and loaded the way the CLI loads them."""

import textwrap
from pathlib import Path

import pytest

from minder_plugin_sdk import check_plugin
from minder_plugin_sdk.cli import _load_plugin_class, main
from minder_plugin_sdk.source_rules import (
    is_platform_secret_name,
    plugin_source_errors,
    source_errors,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "name",
    [
        "JWT_SECRET",
        "NEO4J_AUTH",
        "RABBITMQ_PASSWORD",
        "POSTGRES_PASSWORD",
        "SERVICE_SYNC_TOKEN",
        "SERVICE_SIGNING_KEY_V2",
        "DB_HOST",
        "REDIS_URL",
        "INFLUXDB_TOKEN",
        "GITHUB_TOKEN",
        "SOME_SECRET",
        "x_password",
    ],
)
def test_secret_names(name):
    assert is_platform_secret_name(name)


@pytest.mark.parametrize(
    "name",
    ["WEATHER_API_BASE", "HTTP_TIMEOUT", "TOKENS_LIMIT", "NEO4J_HTTP", "RABBITMQ_URL"],
)
def test_non_secret_names(name):
    assert not is_platform_secret_name(name)


@pytest.mark.parametrize(
    "line",
    [
        'os.environ["JWT_SECRET"]',
        'os.environ.get("NEO4J_AUTH")',
        'os.environ.get("RABBITMQ_PASSWORD", "")',
        'os.environ.setdefault("DB_PASSWORD", "x")',
        'os.environ.pop("REDIS_PASSWORD", None)',
        'os.getenv("POSTGRES_PASSWORD")',
        'environ["SERVICE_SYNC_TOKEN"]',
        'getenv("INFLUXDB_TOKEN")',
        'o.environ["JWT_SECRET"]',
        'o.getenv("NEO4J_AUTH")',
        'env.get("RABBITMQ_PASSWORD")',
        'ge("REDIS_PASSWORD")',
    ],
)
def test_env_secret_reads_are_flagged(line):
    errors = source_errors(
        "import os, os as o\nfrom os import environ, getenv, environ as env\n"
        f"from os import getenv as ge\nx = {line}\n"
    )
    assert len(errors) == 1
    assert "reads platform secret" in errors[0]
    assert "<plugin>:4:" in errors[0]


@pytest.mark.parametrize(
    "line",
    [
        'os.environ.get("WEATHER_API_BASE")',
        'os.environ["HTTP_TIMEOUT"]',
        "os.environ.get(name)",  # dynamic: not seen (documented limitation)
        'config.get("API_TOKEN")',  # not the environment
        "os.environ.copy()",
    ],
)
def test_non_secret_reads_pass(line):
    assert source_errors(f"import os\nname = 'x'\nconfig = {{}}\nx = {line}\n") == []


def test_unrelated_environ_names_are_not_os_environ():
    # a local dict that happens to be called "environ" isn't the process env
    src = 'environ = {}\nx = environ["JWT_SECRET"]\n'
    assert source_errors(src) == []


def test_config_schema_keys_are_allowed():
    src = 'import os\nx = os.environ.get("GITHUB_TOKEN")\n'
    assert source_errors(src) != []
    assert source_errors(src, allowed_env=["GITHUB_TOKEN"]) == []


@pytest.mark.parametrize(
    "line",
    [
        "import core",
        "import core.state",
        "from core import state",
        "from core.secrets import ScopedSecretReader",
        "import importlib\nm = importlib.import_module('core.state')",
        "import importlib as il\nm = il.import_module('core')",
        "from importlib import import_module as im\nm = im('core.x')",
        "m = __import__('core.state')",
    ],
)
def test_core_imports_are_flagged(line):
    errors = source_errors(line + "\n")
    assert len(errors) == 1 and "imports platform internals" in errors[0]


@pytest.mark.parametrize(
    "line",
    [
        "from .core import helper",
        "import corelib",
        "from coredata import x",
        "import importlib\nm = importlib.import_module('corelib')",
        "import importlib\nm = importlib.import_module(name)",
    ],
)
def test_non_platform_imports_pass(line):
    assert source_errors(line + "\n") == []


def test_unparsable_source_is_reported():
    assert "cannot parse source" in source_errors("def (:\n")[0]


PLUGIN = '''\
"""p"""
import os

from minder_plugin_sdk import PluginBase, PluginMetadata

__all__ = ["P"]


class P(PluginBase):
    CONFIG_SCHEMA = [
        {"key": "P_API_TOKEN", "type": "string", "default": "", "secret": True}
    ]

    async def register(self):
        return PluginMetadata(name="p", version="1.0.0", description="d", author="a")

    def token(self):
        return os.environ.get("P_API_TOKEN")
{extra}
'''


def load(tmp_path, extra="", name="srcplug"):
    path = tmp_path / f"{name}.py"
    path.write_text(PLUGIN.replace("{extra}", textwrap.indent(extra, "    ")))
    return path, _load_plugin_class(path)()


def test_plugin_reading_own_config_key_is_clean(tmp_path):
    _, p = load(tmp_path, name="clean_plug")
    assert plugin_source_errors(p) == []
    assert check_plugin(p) == []


def test_plugin_reading_platform_secret_fails_check(tmp_path):
    extra = 'def neo(self):\n    return os.environ["NEO4J_AUTH"]\n'
    path, p = load(tmp_path, extra, name="bad_plug")
    problems = check_plugin(p)
    assert len(problems) == 1
    assert "NEO4J_AUTH" in problems[0] and "bad_plug.py" in problems[0]
    # the CLI surfaces it too
    assert main(["validate", str(path)]) == 1


def test_plugin_importing_core_fails_check(tmp_path):
    extra = "def state(self):\n    import core.state\n    return core.state\n"
    _, p = load(tmp_path, extra, name="core_plug")
    assert any("'core.state'" in e for e in check_plugin(p))


def test_subclass_in_another_module_is_scanned(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(tmp_path))
    (tmp_path / "base_mod.py").write_text(
        "import os\n\n\nclass Base:\n    T = os.getenv('JWT_SECRET')\n"
    )
    (tmp_path / "child_mod.py").write_text(
        "from base_mod import Base\n\n\nclass Child(Base):\n    pass\n"
    )
    import child_mod

    errors = plugin_source_errors(child_mod.Child)
    assert len(errors) == 1 and "base_mod.py" in errors[0]


@pytest.mark.parametrize(
    "example", ["weather_plugin.py", "minimal_plugin.py", "ai_tool_plugin.py"]
)
def test_examples_pass_the_source_rules(example):
    p = _load_plugin_class(ROOT / "examples" / example)()
    assert plugin_source_errors(p) == []


def test_package_helper_modules_are_scanned(tmp_path):
    pkg = tmp_path / "pkgplug"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        "from minder_plugin_sdk import PluginBase, PluginMetadata\n"
        "from .helpers import neo\n\n"
        '__all__ = ["P"]\n\n\n'
        "class P(PluginBase):\n"
        "    async def register(self):\n"
        "        return PluginMetadata(\n"
        '            name="p", version="1.0.0", description="d", author="a"\n'
        "        )\n"
    )
    (pkg / "helpers.py").write_text(
        "import os\n\n\ndef neo():\n    return os.environ['NEO4J_AUTH']\n"
    )
    (pkg / "sub").mkdir()
    (pkg / "sub" / "deep.py").write_text("from core import state\n")
    p = _load_plugin_class(pkg / "__init__.py")()
    errors = plugin_source_errors(p)
    assert any("helpers.py" in e and "NEO4J_AUTH" in e for e in errors), errors
    assert any("deep.py" in e and "'core'" in e for e in errors), errors
    assert len(errors) == 2
