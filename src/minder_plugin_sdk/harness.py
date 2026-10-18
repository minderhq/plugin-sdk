"""Testing utilities for plugin authors.

``check_plugin(plugin)`` returns a list of contract violations (empty ⇒ the
plugin honours the SDK contract). ``check_plugin_warnings(plugin)`` returns
non-fatal findings (e.g. an ``AI_TOOLS`` entry without ``effect``).
``run_lifecycle(plugin)`` drives the full lifecycle the registry would and
returns each step's output — drop any of them into your test suite.
``FakePlatformContext`` is an in-memory platform context (contract v2) for
unit-testing plugins that use ``self.ctx``.
"""

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Coroutine,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

from .ai_tools import ai_tool_errors, ai_tool_warnings
from .capabilities import capabilities
from .context import (
    CAP_DOCUMENTS_INDEX,
    CAP_PLUGINS_INVOKE,
    CAP_SECRETS_READ,
    CAP_TELEGRAF_CLEAR_MANAGED_REGION,
    CAP_TELEGRAF_RELOAD,
    CAP_TELEGRAF_SET_MANAGED_REGION,
    CAP_TIMESERIES_LATEST,
    CAP_TIMESERIES_WRITE,
    PlatformContext,
    capability_granted,
)
from .contract import PluginMetadata
from .declarations import declaration_errors
from .errors import CapabilityDenied, CapabilityInvalid, CapabilityUnavailable
from .requirements import requirement_errors
from .schema import config_errors, resolve_config_schema, resolve_effective_config
from .source_rules import plugin_source_errors

__all__ = [
    "check_plugin",
    "check_plugin_warnings",
    "run_lifecycle",
    "FakePlatformContext",
    "RecordedCall",
]


def _await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return asyncio.run(cast("Coroutine[Any, Any, Any]", value))
    return value


def check_plugin(plugin: Any) -> List[str]:
    """Static + light-dynamic contract checks. Empty list ⇒ the plugin is valid."""
    problems: List[str] = []

    if not callable(getattr(plugin, "register", None)):
        problems.append("missing register() — the registry loads on its presence")
        return problems

    md = _await(plugin.register())
    if not isinstance(md, PluginMetadata):
        problems.append("register() must return a PluginMetadata")
    else:
        for f in ("name", "version", "description", "author"):
            if not getattr(md, f, None):
                problems.append(f"PluginMetadata.{f} is empty")

    if callable(getattr(plugin, "health_check", None)):
        health = _await(plugin.health_check())
        if not isinstance(health, dict) or not isinstance(health.get("healthy"), bool):
            problems.append('health_check() must return {"healthy": <bool>, ...}')

    # AI tools must map to declared actions.
    problems.extend(ai_tool_errors(plugin))

    # Declared service/bundle requirements must name real platform pieces.
    problems.extend(requirement_errors(plugin))

    # ACTIONS must name real methods.
    for action in getattr(plugin, "ACTIONS", frozenset()) or ():
        if not callable(getattr(plugin, action, None)):
            problems.append(f"ACTIONS names {action!r} but there is no such method")

    # options_action references must be READ_ONLY actions that exist.
    _schema, ui = resolve_config_schema(plugin)
    read_only = set(getattr(plugin, "READ_ONLY_ACTIONS", frozenset()) or ())
    for key, hints in ui.items():
        src = hints.get("ui:optionsAction")
        if src and src not in read_only:
            problems.append(
                f"field {key!r} options_action {src!r} is not a READ_ONLY action"
            )

    # Default config must validate against the plugin's own schema. Validate only
    # the fields that actually have a value: a REQUIRED field with no default (the
    # common "user must supply an API key" shape) is unset at check time and
    # supplied at runtime — it's not a plugin defect, so don't type-check its
    # None or enforce `required` here (that would falsely fail a valid plugin).
    schema, _ = resolve_config_schema(plugin)
    defaults = resolve_effective_config(plugin)
    present = {k: v for k, v in defaults.items() if v is not None}
    problems.extend(config_errors({**schema, "required": []}, present))

    # Contract-v2 declarations (CONTRACT_VERSION, MANAGES, EGRESS, TIMESERIES).
    problems.extend(declaration_errors(plugin))

    # Source rules: no platform secrets from os.environ, no platform internals.
    problems.extend(plugin_source_errors(plugin))

    # Capabilities must be resolvable.
    try:
        capabilities(plugin)
    except Exception as exc:  # pragma: no cover - defensive
        problems.append(f"capabilities() failed: {exc}")

    return problems


def check_plugin_warnings(plugin: Any) -> List[str]:
    """Non-fatal findings that :func:`check_plugin` does not fail on. Empty ⇒
    nothing to report. Today: ``AI_TOOLS`` entries without an ``effect``, and
    declared effects that the tool's name, method or arguments contradict
    (see ``tool_effects``). A missing ``effect`` may become an error in a
    later release."""
    return ai_tool_warnings(plugin)


async def run_lifecycle(
    plugin: Any, ctx: Optional[PlatformContext] = None
) -> Dict[str, Any]:
    """Drive register → initialize → health_check → collect_data → analyze →
    shutdown (skipping any the plugin doesn't implement) and return the outputs.

    With ``ctx`` (e.g. a ``FakePlatformContext``), it is bound through the
    plugin's ``bind_context`` hook (if any) right after ``register()``."""
    out: Dict[str, Any] = {}
    out["metadata"] = await plugin.register()
    if ctx is not None and callable(getattr(plugin, "bind_context", None)):
        plugin.bind_context(ctx)
    for step in ("initialize", "health_check", "collect_data", "analyze", "shutdown"):
        fn = getattr(plugin, step, None)
        if callable(fn):
            result = fn()
            out[step] = await result if inspect.isawaitable(result) else result
    return out


# ── FakePlatformContext ──────────────────────────────────────────────────────
@dataclass
class RecordedCall:
    """One capability call seen by :class:`FakePlatformContext`. ``args`` holds
    identifying arguments only: a secret's key (never its value), the target
    plugin/action and the kwarg NAMES of an invoke, a document's kb/filename/
    content type, a telegraf region's size."""

    capability: str
    args: Dict[str, Any] = field(default_factory=dict)


InvokeHandler = Union[Any, Callable[..., Any]]


class _FakeSecrets:
    def __init__(self, fake: "FakePlatformContext") -> None:
        self._fake = fake

    async def get(self, key: str) -> Optional[str]:
        self._fake._enter(CAP_SECRETS_READ, {"key": key})
        return self._fake.secrets_store.get(key)


class _FakePlugins:
    def __init__(self, fake: "FakePlatformContext") -> None:
        self._fake = fake

    async def invoke(self, plugin: str, action: str, **kwargs: Any) -> Any:
        self._fake._enter(
            CAP_PLUGINS_INVOKE,
            {"plugin": plugin, "action": action, "kwargs": sorted(kwargs)},
        )
        key = (plugin, action)
        if key not in self._fake.invoke_results:
            raise CapabilityInvalid(
                CAP_PLUGINS_INVOKE, f"no fake result for {plugin}.{action}"
            )
        handler = self._fake.invoke_results[key]
        if callable(handler):
            result = handler(**kwargs)
            return await result if inspect.isawaitable(result) else result
        return handler


class _FakeDocuments:
    def __init__(self, fake: "FakePlatformContext") -> None:
        self._fake = fake

    async def index(
        self,
        kb_id: str,
        filename: str,
        content: Union[bytes, str],
        content_type: str,
    ) -> Dict[str, Any]:
        self._fake._enter(
            CAP_DOCUMENTS_INDEX,
            {"kb_id": kb_id, "filename": filename, "content_type": content_type},
        )
        doc = {
            "document_id": f"fake-doc-{len(self._fake.indexed) + 1}",
            "kb_id": kb_id,
            "filename": filename,
            "content_type": content_type,
            "content": content,
        }
        self._fake.indexed.append(doc)
        return {k: v for k, v in doc.items() if k != "content"}


class _FakeTelegraf:
    def __init__(self, fake: "FakePlatformContext") -> None:
        self._fake = fake

    async def set_managed_region(self, toml: str) -> Dict[str, Any]:
        self._fake._enter(CAP_TELEGRAF_SET_MANAGED_REGION, {"bytes": len(toml)})
        if self._fake.telegraf_validator is not None:
            self._fake.telegraf_validator(toml)
        self._fake.telegraf_region = toml
        return {"ok": True, "bytes": len(toml)}

    async def clear_managed_region(self) -> Dict[str, Any]:
        self._fake._enter(CAP_TELEGRAF_CLEAR_MANAGED_REGION, {})
        self._fake.telegraf_region = ""
        return {"ok": True}

    async def reload(self, force: bool = False) -> Dict[str, Any]:
        self._fake._enter(CAP_TELEGRAF_RELOAD, {"force": force})
        self._fake.telegraf_reloads.append(force)
        return {"ok": True, "restarted": force}


class _FakeTimeseries:
    def __init__(self, fake: "FakePlatformContext") -> None:
        self._fake = fake

    async def write(
        self, lines: Union[str, Iterable[str]], precision: str = "s"
    ) -> int:
        batch = lines.splitlines() if isinstance(lines, str) else list(lines)
        batch = [ln for ln in batch if ln]
        self._fake._enter(
            CAP_TIMESERIES_WRITE, {"lines": len(batch), "precision": precision}
        )
        self._fake.timeseries_lines.extend(batch)
        return len(batch)

    async def latest(
        self,
        measurement: str,
        tag_key: str,
        tag_value: str,
        fields: Optional[Iterable[str]] = None,
    ) -> Union[None, str, Dict[str, Any]]:
        wanted = None if fields is None else list(fields)
        self._fake._enter(
            CAP_TIMESERIES_LATEST,
            {
                "measurement": measurement,
                "tag_key": tag_key,
                "tag_value": tag_value,
                "fields": wanted,
            },
        )
        point = self._fake.timeseries_latest.get((measurement, tag_key, tag_value))
        if point is None:
            return None
        if isinstance(point, str):
            point = {"time": point, "fields": {}}
        if wanted is None:
            return cast(Optional[str], point.get("time"))
        values = point.get("fields") or {}
        return {"time": point.get("time"), "fields": {f: values.get(f) for f in wanted}}


class FakePlatformContext:
    """An in-memory :class:`~minder_plugin_sdk.context.PlatformContext` for
    plugin unit tests: no platform needed.

    * ``secrets``: the plugin's secrets (``ctx.secrets.get(key)``; a missing key
      returns ``None``).
    * ``grants``: the granted capability names (``"secrets.read"``,
      ``"telegraf"`` for all ``telegraf.*``, ...). An ungranted call raises
      ``CapabilityDenied``. ``None`` (default) grants **everything**, which is
      convenient but more than the platform would grant; use
      :meth:`for_plugin` to start from the plugin's own declarations instead.
    * ``denied`` / ``unavailable``: capabilities that raise
      ``CapabilityDenied`` / ``CapabilityUnavailable`` regardless of grants.
    * ``invoke_results``: ``{(plugin, action): value-or-callable}`` for
      ``ctx.plugins.invoke``; a callable gets the kwargs (may be async). An
      unknown target raises ``CapabilityInvalid``.
    * ``telegraf_validator``: optional callable run on each managed region; raise
      ``CapabilityInvalid`` from it to simulate the platform rejecting it.
    * ``timeseries_latest``: ``{(measurement, tag_key, tag_value): point}`` for
      ``ctx.timeseries.latest``, where a point is an ISO timestamp or
      ``{"time": ..., "fields": {...}}``; an unknown series returns ``None``.

    Every call (allowed or not) is appended to ``calls``. Side effects are kept
    in ``indexed`` (documents, with content), ``telegraf_region``,
    ``telegraf_reloads`` and ``timeseries_lines`` (every line-protocol line written).

        ctx = FakePlatformContext(secrets={"API_TOKEN": "t"}, grants={"secrets.read"})
        await run_lifecycle(MyPlugin(), ctx=ctx)
        assert ctx.called("secrets.read")
    """

    def __init__(
        self,
        secrets: Optional[Mapping[str, str]] = None,
        grants: Optional[Iterable[str]] = None,
        denied: Iterable[str] = (),
        unavailable: Iterable[str] = (),
        invoke_results: Optional[Mapping[Tuple[str, str], InvokeHandler]] = None,
        telegraf_validator: Optional[Callable[[str], None]] = None,
        timeseries_latest: Optional[
            Mapping[Tuple[str, str, str], Union[str, Dict[str, Any]]]
        ] = None,
    ) -> None:
        self.secrets_store: Dict[str, str] = dict(secrets or {})
        self.grants: Optional[Set[str]] = None if grants is None else set(grants)
        self.denied: Set[str] = set(denied)
        self.unavailable: Set[str] = set(unavailable)
        self.invoke_results: Dict[Tuple[str, str], InvokeHandler] = dict(
            invoke_results or {}
        )
        self.telegraf_validator = telegraf_validator
        self.calls: List[RecordedCall] = []
        self.indexed: List[Dict[str, Any]] = []
        self.telegraf_region: Optional[str] = None
        self.telegraf_reloads: List[bool] = []
        self.timeseries_latest: Dict[
            Tuple[str, str, str], Union[str, Dict[str, Any]]
        ] = dict(timeseries_latest or {})
        self.timeseries_lines: List[str] = []
        self.secrets = _FakeSecrets(self)
        self.plugins = _FakePlugins(self)
        self.documents = _FakeDocuments(self)
        self.telegraf = _FakeTelegraf(self)
        self.timeseries = _FakeTimeseries(self)

    @classmethod
    def for_plugin(
        cls,
        plugin: Any,
        dependencies: Iterable[str] = (),
        **kwargs: Any,
    ) -> "FakePlatformContext":
        """A fake whose grants approximate what the platform derives from the
        plugin's declarations (the platform remains authoritative):

        * ``secrets.read`` always (a plugin's own secrets);
        * ``plugins.invoke`` when ``dependencies`` (your
          ``PluginMetadata.dependencies``) is non-empty;
        * ``documents.index`` when ``REQUIRES`` lists the ``rag`` bundle;
        * ``<name>.*`` for each name in ``MANAGES``;
        * ``timeseries.*`` when ``TIMESERIES`` is declared (the platform also
          limits writes to the declared measurements; this fake does not).

        Other keyword arguments are passed to the constructor."""
        grants = {CAP_SECRETS_READ}
        if list(dependencies):
            grants.add(CAP_PLUGINS_INVOKE)
        requires = getattr(plugin, "REQUIRES", None) or {}
        if isinstance(requires, dict) and "rag" in (requires.get("bundles") or []):
            grants.add(CAP_DOCUMENTS_INDEX)
        for name in getattr(plugin, "MANAGES", None) or []:
            grants.add(f"{name}.*")
        if getattr(plugin, "TIMESERIES", None) is not None:
            grants.add("timeseries.*")
        return cls(grants=grants, **kwargs)

    def has(self, capability: str) -> bool:
        if capability_granted(self.denied, capability) or capability_granted(
            self.unavailable, capability
        ):
            return False
        return self.grants is None or capability_granted(self.grants, capability)

    def called(self, capability: str) -> List[RecordedCall]:
        """The recorded calls for ``capability`` (exact name)."""
        return [c for c in self.calls if c.capability == capability]

    def _enter(self, capability: str, args: Dict[str, Any]) -> None:
        self.calls.append(RecordedCall(capability, dict(args)))
        if capability_granted(self.unavailable, capability):
            raise CapabilityUnavailable(capability, "unavailable in this test")
        if capability_granted(self.denied, capability) or not (
            self.grants is None or capability_granted(self.grants, capability)
        ):
            raise CapabilityDenied(capability, "not granted in this test")


if TYPE_CHECKING:  # pragma: no cover - static conformance check for mypy

    def _conforms(fake: FakePlatformContext) -> PlatformContext:
        return fake
