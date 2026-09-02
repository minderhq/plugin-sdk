"""``minder-plugin`` — a small CLI for plugin authors.

minder-plugin validate path/to/plugin.py        # or a manifest.yaml
minder-plugin inspect  path/to/plugin.py         # capabilities + config schema
minder-plugin scaffold my-plugin [-o out.py]     # generate a skeleton
"""

import argparse
import importlib.util
import inspect
import json
import sys
from pathlib import Path
from typing import Any, List, Optional

from .ai_tools import build_tool_definitions
from .capabilities import capabilities
from .harness import check_plugin
from .manifest import validate_manifest
from .schema import resolve_config_schema

_SCAFFOLD = '''"""{title} plugin."""

from minder_plugin_sdk import PluginBase, PluginMetadata


class {cls}(PluginBase):
    __all__ = ["{cls}"]

    CONFIG_SCHEMA = [
        {{
            "key": "{upper}_EXAMPLE",
            "type": "string",
            "default": "",
            "description": "An example setting.",
            "widget": "text",
        }},
    ]

    async def register(self) -> PluginMetadata:
        return PluginMetadata(
            name="{name}",
            version="0.1.0",
            description="TODO: describe {name}",
            author="you",
            capabilities=["collect"],
        )

    async def collect_data(self) -> dict:
        # TODO: fetch/produce data here (runs hourly or on demand)
        self._last = {{"ok": True}}
        return self._last
'''


def _load_plugin_class(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    names = getattr(module, "__all__", None)
    if names:
        return getattr(module, names[0])
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if obj.__module__ == module.__name__ and hasattr(obj, "register"):
            return obj
    raise RuntimeError(f"no plugin class (with register()) found in {path}")


def _cmd_validate(path: Path) -> int:
    if path.suffix in (".yaml", ".yml"):
        try:
            validate_manifest(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL invalid manifest: {exc}")
            return 1
        print("OK   manifest is valid")
        return 0
    plugin = _load_plugin_class(path)()
    problems: List[str] = check_plugin(plugin)
    if problems:
        print(f"FAIL {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("OK   plugin honours the contract")
    return 0


def _cmd_inspect(path: Path) -> int:
    plugin = _load_plugin_class(path)()
    schema, ui = resolve_config_schema(plugin)
    report = {
        "capabilities": sorted(capabilities(plugin)),
        "config_schema": schema,
        "ui_schema": ui,
        "ai_tools": build_tool_definitions(plugin),
        "display": getattr(type(plugin), "DISPLAY", {}),
    }
    print(json.dumps(report, indent=2, default=str))
    return 0


def _cmd_scaffold(name: str, out: Optional[str]) -> int:
    cls = "".join(part.capitalize() for part in name.replace("-", "_").split("_"))
    cls = cls + "Plugin" if not cls.endswith("Plugin") else cls
    code = _SCAFFOLD.format(
        title=name,
        cls=cls,
        name=name,
        upper=name.replace("-", "_").upper(),
    )
    target = Path(out) if out else Path(f"{name.replace('-', '_')}_plugin.py")
    if target.exists():
        print(f"FAIL refusing to overwrite {target}")
        return 1
    target.write_text(code, encoding="utf-8")
    print(f"OK   wrote {target}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="minder-plugin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate a plugin.py or manifest.yaml")
    v.add_argument("path")
    i = sub.add_parser("inspect", help="print capabilities + config schema")
    i.add_argument("path")
    s = sub.add_parser("scaffold", help="generate a plugin skeleton")
    s.add_argument("name")
    s.add_argument("-o", "--out", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "validate":
        return _cmd_validate(Path(args.path))
    if args.cmd == "inspect":
        return _cmd_inspect(Path(args.path))
    if args.cmd == "scaffold":
        return _cmd_scaffold(args.name, args.out)
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
