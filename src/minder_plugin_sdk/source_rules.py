"""Static source rules for plugin code (run by ``check_plugin``).

A plugin may run in a process that holds no platform credentials, so it must
not depend on them, and it must not import platform internals. Two rules:

* **No platform secrets from the environment.** Reading a platform-credential
  name through ``os.environ[...]``, ``os.environ.get(...)`` or ``os.getenv(...)``
  is flagged (e.g. ``JWT_SECRET``, ``POSTGRES_PASSWORD``, ``DB_*``, ``REDIS_*``,
  anything ending in ``_TOKEN`` / ``_SECRET`` / ``_PASSWORD``). Names the plugin
  declares in its own ``CONFIG_SCHEMA`` are its configuration, not platform
  secrets, and are allowed. Use ``CONFIG_SCHEMA`` (``"secret": True``) or
  ``self.ctx.secrets.get(...)`` instead.
* **No platform internals.** ``import core`` / ``from core... import ...``
  (the registry's own package) is flagged; plugins talk to the platform only
  through this SDK.

The scan is best-effort and syntactic: names built at runtime are not seen.
"""

import ast
import inspect
import sys
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
_SECRET_PREFIXES = (
    "DB_",
    "REDIS_",
    "POSTGRES_",
    "NEO4J_",
    "RABBITMQ_",
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


def _is_os_environ(node: ast.AST) -> bool:
    # os.environ  |  environ (from os import environ)
    if isinstance(node, ast.Attribute) and node.attr == "environ":
        return isinstance(node.value, ast.Name) and node.value.id == "os"
    return isinstance(node, ast.Name) and node.id == "environ"


def _is_getenv(node: ast.AST) -> bool:
    # os.getenv  |  getenv (from os import getenv)
    if isinstance(node, ast.Attribute) and node.attr == "getenv":
        return isinstance(node.value, ast.Name) and node.value.id == "os"
    return isinstance(node, ast.Name) and node.id == "getenv"


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _env_reads(tree: ast.AST) -> Iterable[ast.AST]:
    """Yield (name-node) for every literal environment-variable read."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and _is_os_environ(node.value):
            yield node.slice
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            if _is_getenv(func):
                yield node.args[0]
            elif (
                isinstance(func, ast.Attribute)
                and func.attr in ("get", "setdefault", "pop")
                and _is_os_environ(func.value)
            ):
                yield node.args[0]


def _internal_imports(tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _INTERNAL_PACKAGES:
                    yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.split(".")[0] in _INTERNAL_PACKAGES:
                yield node.module


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
    allowed = {name.upper() for name in allowed_env}
    errors: List[str] = []
    for name_node in _env_reads(tree):
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
    for module in _internal_imports(tree):
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


def plugin_source_errors(plugin: Any) -> List[str]:
    """Apply the source rules to every module that defines a class in the
    plugin's MRO (skipping this SDK and the standard library). Modules whose
    source is unavailable are skipped."""
    cls = plugin if isinstance(plugin, type) else type(plugin)
    allowed = _config_keys(plugin)
    seen: Set[str] = set()
    errors: List[str] = []
    for klass in cls.__mro__:
        modname = klass.__module__
        if (
            modname in seen
            or modname == "builtins"
            or modname.split(".")[0] == __name__.split(".")[0]
            or modname in sys.stdlib_module_names
        ):
            continue
        seen.add(modname)
        module = sys.modules.get(modname)
        if module is None:
            continue
        try:
            source = inspect.getsource(module)
            filename = inspect.getsourcefile(module) or modname
        except (OSError, TypeError):
            continue
        errors.extend(source_errors(source, filename, allowed))
    return errors
