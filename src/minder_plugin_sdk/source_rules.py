"""Static source rules for plugin code (run by ``check_plugin``).

A plugin may run in a process that holds no platform credentials, so it must
not depend on them, and it must not import platform internals. Two rules:

* **No platform secrets from the environment.** Reading a platform-credential
  name through ``os.environ[...]``, ``os.environ.get(...)`` or ``os.getenv(...)``
  is flagged (e.g. ``JWT_SECRET``, ``NEO4J_AUTH``, ``POSTGRES_*``, ``DB_*``,
  ``REDIS_*``, anything ending in ``_TOKEN`` / ``_SECRET`` / ``_PASSWORD`` /
  ``_AUTH``), including through aliases (``import os as o``,
  ``from os import environ as env``). Names the plugin
  declares in its own ``CONFIG_SCHEMA`` are its configuration, not platform
  secrets, and are allowed. Use ``CONFIG_SCHEMA`` (``"secret": True``) or
  ``self.ctx.secrets.get(...)`` instead.
* **No platform internals.** ``import core`` / ``from core... import ...``
  (the registry's own package), and the literal dynamic forms
  ``importlib.import_module("core...")`` / ``__import__("core...")``, are
  flagged; plugins talk to the platform only through this SDK.

``plugin_source_errors`` scans the module of every class in the plugin's MRO
and, when that module belongs to a package, every module of that package
(helpers included).

This is a **lint, not a security boundary**: it is syntactic and best-effort
(names built at runtime are not seen). The real controls are the runner's
isolation (no platform credentials in its environment, no route to platform
services) and the platform's per-call grant checks.
"""

import ast
import inspect
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, List, Optional, Set

__all__ = ["is_platform_secret_name", "source_errors", "plugin_source_errors"]

_SECRET_NAMES = frozenset(
    {
        "JWT_SECRET",
        "JWT_SIGNING_PRIVATE_KEY",
        "SERVICE_SYNC_TOKEN",
        "POSTGRES_PASSWORD",
        "NEO4J_AUTH",
        "RABBITMQ_PASSWORD",
        "REDIS_PASSWORD",
        "INFLUXDB_TOKEN",
        "PLUGIN_SECRETS_VAULT_SECRET",
        "MODEL_PROVIDER_VAULT_SECRET",
    }
)
# Whole prefixes that are platform connection settings. NEO4J_* / RABBITMQ_*
# are deliberately NOT here: their non-secret names (e.g. a URL) are fine, and
# their credentials are caught by the exact names and the suffix rules.
_SECRET_PREFIXES = (
    "DB_",
    "REDIS_",
    "POSTGRES_",
    "SERVICE_SIGNING_KEY",
    "JWT_",
)
_SECRET_SUFFIXES = ("_TOKEN", "_SECRET", "_PASSWORD", "_PRIVATE_KEY", "_AUTH")

_INTERNAL_PACKAGES = ("core",)


def is_platform_secret_name(name: str) -> bool:
    """Whether an environment variable name looks like a platform credential."""
    upper = name.upper()
    return (
        upper in _SECRET_NAMES
        or upper.startswith(_SECRET_PREFIXES)
        or upper.endswith(_SECRET_SUFFIXES)
    )


class _Aliases:
    """Local names bound to ``os``, ``os.environ``, ``os.getenv``,
    ``importlib`` and ``importlib.import_module`` in one module."""

    def __init__(self, tree: ast.AST) -> None:
        self.os: Set[str] = set()
        self.environ: Set[str] = set()
        self.getenv: Set[str] = set()
        self.importlib: Set[str] = set()
        self.import_module: Set[str] = {"__import__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name == "os":
                        self.os.add(local)
                    elif alias.name == "importlib":
                        self.importlib.add(local)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                for alias in node.names:
                    local = alias.asname or alias.name
                    if node.module == "os" and alias.name == "environ":
                        self.environ.add(local)
                    elif node.module == "os" and alias.name == "getenv":
                        self.getenv.add(local)
                    elif node.module == "importlib" and alias.name == "import_module":
                        self.import_module.add(local)

    def _named(self, node: ast.AST, attr: str, names: Set[str], mods: Set[str]) -> bool:
        if isinstance(node, ast.Attribute) and node.attr == attr:
            return isinstance(node.value, ast.Name) and node.value.id in mods
        return isinstance(node, ast.Name) and node.id in names

    def is_environ(self, node: ast.AST) -> bool:
        return self._named(node, "environ", self.environ, self.os)

    def is_getenv(self, node: ast.AST) -> bool:
        return self._named(node, "getenv", self.getenv, self.os)

    def is_import_module(self, node: ast.AST) -> bool:
        return self._named(node, "import_module", self.import_module, self.importlib)


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _env_reads(tree: ast.AST, aliases: _Aliases) -> Iterable[ast.AST]:
    """Yield the name node of every environment-variable read."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and aliases.is_environ(node.value):
            yield node.slice
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            if aliases.is_getenv(func):
                yield node.args[0]
            elif (
                isinstance(func, ast.Attribute)
                and func.attr in ("get", "setdefault", "pop")
                and aliases.is_environ(func.value)
            ):
                yield node.args[0]


def _is_internal(module: str) -> bool:
    return module.split(".")[0] in _INTERNAL_PACKAGES


def _internal_imports(tree: ast.AST, aliases: _Aliases) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_internal(alias.name):
                    yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if _is_internal(node.module):
                yield node.module
        elif (
            isinstance(node, ast.Call)
            and node.args
            and aliases.is_import_module(node.func)
        ):
            name = _const_str(node.args[0])
            if name and _is_internal(name):
                yield name


def source_errors(
    source: str,
    filename: str = "<plugin>",
    allowed_env: Iterable[str] = (),
) -> List[str]:
    """Apply the source rules to one module's source (empty ⇒ ok).

    ``allowed_env`` are environment names the plugin legitimately reads (its own
    ``CONFIG_SCHEMA`` keys)."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [f"{filename}: cannot parse source: {exc.msg}"]
    aliases = _Aliases(tree)
    allowed = {name.upper() for name in allowed_env}
    errors: List[str] = []
    for name_node in _env_reads(tree, aliases):
        name = _const_str(name_node)
        if name is None or name.upper() in allowed:
            continue
        if is_platform_secret_name(name):
            line = getattr(name_node, "lineno", "?")
            errors.append(
                f"{filename}:{line}: reads platform secret {name!r} from the "
                "environment; declare it in CONFIG_SCHEMA or use "
                "self.ctx.secrets.get()"
            )
    for module in _internal_imports(tree, aliases):
        errors.append(
            f"{filename}: imports platform internals {module!r}; use the SDK "
            "(self.ctx) instead"
        )
    return errors


def _config_keys(plugin: Any) -> Set[str]:
    keys: Set[str] = set()
    for f in getattr(plugin, "CONFIG_SCHEMA", None) or []:
        if isinstance(f, dict) and isinstance(f.get("key"), str):
            keys.add(f["key"])
    return keys


def _skipped(modname: str) -> bool:
    top = modname.split(".")[0]
    return (
        modname == "builtins"
        or top == __name__.split(".")[0]
        or top in sys.stdlib_module_names
    )


def _module_files(module: ModuleType) -> List[Path]:
    """The module's own file, or every ``.py`` file of its top-level package."""
    package = (getattr(module, "__package__", None) or "").split(".")[0]
    top = sys.modules.get(package) if package else None
    roots = list(getattr(top, "__path__", None) or []) if top is not None else []
    if roots:
        files: List[Path] = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
                files.extend(
                    Path(dirpath, f) for f in sorted(filenames) if f.endswith(".py")
                )
        return files
    try:
        filename = inspect.getsourcefile(module)
    except TypeError:
        return []
    return [Path(filename)] if filename else []


def plugin_source_errors(plugin: Any) -> List[str]:
    """Apply the source rules to the plugin's code: the module of every class
    in its MRO and, for a packaged plugin, every module of that package
    (skipping this SDK and the standard library). Unreadable files are
    skipped."""
    cls = plugin if isinstance(plugin, type) else type(plugin)
    allowed = _config_keys(plugin)
    seen_modules: Set[str] = set()
    seen_files: Set[str] = set()
    errors: List[str] = []
    for klass in cls.__mro__:
        modname = klass.__module__
        if modname in seen_modules or _skipped(modname):
            continue
        seen_modules.add(modname)
        module = sys.modules.get(modname)
        if module is None:
            continue
        for path in _module_files(module):
            key = str(path.resolve())
            if key in seen_files:
                continue
            seen_files.add(key)
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            errors.extend(source_errors(source, str(path), allowed))
    return errors
