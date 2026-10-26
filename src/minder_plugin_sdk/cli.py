"""``minder-plugin`` — a small CLI for plugin authors.

minder-plugin validate path/to/plugin.py        # or a manifest.yaml
minder-plugin inspect  path/to/plugin.py         # capabilities + config schema
minder-plugin scaffold my-plugin [-o out.py]     # generate a skeleton
minder-plugin serve    path/to/plugin.py --minder-url https://...  # run as T4
"""

import argparse
import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any, List, Optional

from .ai_tools import build_tool_definitions
from .capabilities import capabilities
from .declarations import contract_version
from .harness import check_plugin, check_plugin_warnings
from .manifest import validate_manifest
from .requirements import requirements
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
    if path.name == "__init__.py":
        # A package-style plugin (more than one file, e.g. an __init__.py
        # that imports a sibling helpers.py). A bare file-location load
        # here would name the module "__init__" with no search locations,
        # leaving __package__ unset -- any "from .sibling import ..." in
        # it then fails with "attempted relative import with no known
        # parent package". Naming it after the plugin's own directory and
        # giving it that directory as a submodule search path makes it a
        # real package, so relative imports among its own files resolve.
        name = path.parent.name
        spec = importlib.util.spec_from_file_location(
            name, path, submodule_search_locations=[str(path.parent)]
        )
    else:
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
    if path.suffix in (".yaml", ".yml", ".json"):
        try:
            validate_manifest(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL invalid manifest: {exc}")
            return 1
        print("OK   manifest is valid")
        return 0
    plugin = _load_plugin_class(path)()
    problems: List[str] = check_plugin(plugin)
    for w in check_plugin_warnings(plugin):
        print(f"WARN {w}")
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
        "requires": requirements(plugin),
        "config_schema": schema,
        "ui_schema": ui,
        "ai_tools": build_tool_definitions(plugin),
        "display": getattr(type(plugin), "DISPLAY", {}),
        "contract_version": contract_version(plugin),
        "manages": list(getattr(plugin, "MANAGES", None) or []),
        "egress": getattr(plugin, "EGRESS", None),
        "timeseries": getattr(plugin, "TIMESERIES", None),
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


DEFAULT_KEY_ENV = "MINDER_PLUGIN_INSTALLATION_KEY"


def _cmd_serve(args: argparse.Namespace) -> int:
    minder_url = args.minder_url or os.environ.get("MINDER_URL")
    if not minder_url:
        print("FAIL --minder-url (or MINDER_URL) is required")
        return 2
    try:
        import uvicorn

        from .t4 import InstallationKey
        from .t4_server import create_app
    except ImportError:
        print(
            "FAIL serve needs the serve extra: pip install 'minder-plugin-sdk[serve]'"
        )
        return 2
    key = None
    seed = os.environ.get(args.installation_key_env)
    if seed:
        try:
            key = InstallationKey.from_seed_b64(seed)
        except ValueError:
            # Never echo the value: it is a private key.
            print(f"FAIL {args.installation_key_env} is not base64 of a 32-byte seed")
            return 2
    else:
        print(
            f"WARN {args.installation_key_env} is not set: self.ctx callbacks "
            "will be unavailable"
        )
    missing = [
        flag
        for flag, value in (
            ("--public-authority", args.public_authority),
            ("--installation-id", args.installation_id),
        )
        if not value
    ]
    if missing and not args.insecure_host_authority:
        print(
            f"FAIL {' and '.join(missing)} required: without them a request "
            "signed for another plugin or installation could be replayed here "
            "(--insecure-host-authority allows it for local development only)"
        )
        return 2
    plugin = _load_plugin_class(Path(args.path))()
    try:
        app = create_app(
            plugin,
            minder_url=minder_url,
            installation_key=key,
            installation_id=args.installation_id,
            path_prefix=args.path_prefix,
            public_authority=args.public_authority,
            insecure_host_authority=args.insecure_host_authority,
        )
    except ValueError as exc:
        print(f"FAIL {exc}")
        return 2
    if key is not None:
        print(f"OK   installation keyid {key.keyid}")
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
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
    sv = sub.add_parser(
        "serve",
        help="run a plugin as a remote (T4) plugin (needs the serve extra)",
        description=(
            "Serve POST /minder/v1/invoke for a plugin: verify Minder's signed "
            "invocations and sign the plugin's callbacks with the installation "
            "key, read from an environment variable (never a flag)."
        ),
    )
    sv.add_argument("path")
    sv.add_argument("--minder-url", default=None, help="default: $MINDER_URL")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument(
        "--installation-id",
        default=os.environ.get("MINDER_PLUGIN_INSTALLATION_ID"),
        help=(
            "this installation's id; invocations for another one are refused "
            "(default: $MINDER_PLUGIN_INSTALLATION_ID; required)"
        ),
    )
    sv.add_argument(
        "--installation-key-env",
        default=DEFAULT_KEY_ENV,
        help="variable holding base64 of the 32-byte Ed25519 seed",
    )
    sv.add_argument(
        "--public-authority",
        default=os.environ.get("MINDER_PLUGIN_PUBLIC_AUTHORITY"),
        help=(
            "this server's public host[:port] as in the installation's endpoint; "
            "signatures for another host are refused (default: "
            "$MINDER_PLUGIN_PUBLIC_AUTHORITY; required)"
        ),
    )
    sv.add_argument(
        "--insecure-host-authority",
        action="store_true",
        help=(
            "LOCAL DEVELOPMENT ONLY: allow a missing --public-authority or "
            "--installation-id (checks the Host header instead, so requests "
            "signed for other plugins can be replayed here)"
        ),
    )
    sv.add_argument("--path-prefix", default="", help="external path prefix")
    sv.add_argument("--log-level", default="info")
    tr = sub.add_parser(
        "try",
        help="run one operation of a T0 manifest locally (needs the t0 extra)",
        description=(
            "Load a declarative (T0) manifest and run one tool or action with "
            "the runner's own engine and egress rules, then print the mapped "
            "output. --record saves upstream responses; --replay runs offline "
            "from them."
        ),
    )
    tr.add_argument("manifest", help="manifest.yaml or .json")
    tr.add_argument("operation", help="the tool or action name")
    tr.add_argument("--args", default=None, help="parameters as a JSON object")
    tr.add_argument("--config", default=None, help="config values as a JSON object")
    tr.add_argument(
        "--secret",
        action="append",
        metavar="KEY=VALUE",
        help="an auth secret the manifest injects (repeatable)",
    )
    mode = tr.add_mutually_exclusive_group()
    mode.add_argument("--record", metavar="DIR", default=None)
    mode.add_argument("--replay", metavar="DIR", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "validate":
        return _cmd_validate(Path(args.path))
    if args.cmd == "inspect":
        return _cmd_inspect(Path(args.path))
    if args.cmd == "scaffold":
        return _cmd_scaffold(args.name, args.out)
    if args.cmd == "serve":
        return _cmd_serve(args)
    if args.cmd == "try":
        from .t0_try import cmd_try

        return cmd_try(args)
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
