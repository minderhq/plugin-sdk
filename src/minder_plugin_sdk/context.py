"""The platform context (contract v2): what a plugin may ask the platform for.

A context-aware plugin never reads platform credentials, opens platform files or
talks to platform services directly. It asks the host through ``self.ctx``, and
the host checks every call against the grant it issued for the current
invocation (the plugin, the tenant/owner, and the declared capabilities). This
works the same whether the plugin runs inside the registry process or in a
separate runner process, so a plugin is written once for both.

    class MyPlugin(PluginBase):
        CONTRACT_VERSION = 2

        async def sync(self) -> dict:
            token = await self.ctx.secrets.get("API_TOKEN")
            ...

The host binds the context by calling ``plugin.bind_context(ctx)`` (duck-typed:
``PluginBase`` provides it; a plain class may define its own). Until then
``PluginBase.ctx`` is :data:`UNBOUND_CONTEXT`, whose calls raise
:class:`~minder_plugin_sdk.errors.CapabilityUnavailable` and whose ``has()`` is
always ``False``, so a plugin can degrade cleanly instead of crashing.

Every capability call is ``async`` (it may cross a process boundary). Each one
raises :class:`CapabilityDenied` when the capability is not granted,
:class:`CapabilityUnavailable` when it cannot be served, and
:class:`CapabilityInvalid` when the platform rejects the arguments.

For unit tests use :class:`minder_plugin_sdk.harness.FakePlatformContext`.
"""

from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    Optional,
    Protocol,
    Union,
    runtime_checkable,
)

from .errors import CapabilityUnavailable

__all__ = [
    "PlatformContext",
    "SecretsAPI",
    "PluginsAPI",
    "DocumentsAPI",
    "TelegrafAPI",
    "UnboundPlatformContext",
    "UNBOUND_CONTEXT",
    "HOST_CAPABILITIES",
    "CAP_SECRETS_READ",
    "CAP_PLUGINS_INVOKE",
    "CAP_DOCUMENTS_INDEX",
    "CAP_TELEGRAF_SET_MANAGED_REGION",
    "CAP_TELEGRAF_CLEAR_MANAGED_REGION",
    "CAP_TELEGRAF_RELOAD",
    "capability_granted",
]

# ── capability names ─────────────────────────────────────────────────────────
# The names a grant is expressed in, and what ``ctx.has(...)`` accepts. The
# platform derives a plugin's grant from its declarations: its own secrets,
# ``PluginMetadata.dependencies`` (plugins.invoke along those edges only),
# ``REQUIRES`` (e.g. the ``rag`` bundle for documents.index) and ``MANAGES``
# (``telegraf.*`` for ``MANAGES = ["telegraf"]``).
CAP_SECRETS_READ = "secrets.read"
CAP_PLUGINS_INVOKE = "plugins.invoke"
CAP_DOCUMENTS_INDEX = "documents.index"
CAP_TELEGRAF_SET_MANAGED_REGION = "telegraf.set_managed_region"
CAP_TELEGRAF_CLEAR_MANAGED_REGION = "telegraf.clear_managed_region"
CAP_TELEGRAF_RELOAD = "telegraf.reload"

HOST_CAPABILITIES: FrozenSet[str] = frozenset(
    {
        CAP_SECRETS_READ,
        CAP_PLUGINS_INVOKE,
        CAP_DOCUMENTS_INDEX,
        CAP_TELEGRAF_SET_MANAGED_REGION,
        CAP_TELEGRAF_CLEAR_MANAGED_REGION,
        CAP_TELEGRAF_RELOAD,
    }
)


def _namespace(name: str) -> str:
    return name.split(".", 1)[0]


def capability_granted(granted: Iterable[str], capability: str) -> bool:
    """Whether ``capability`` is covered by the ``granted`` names.

    * an exact name matches itself (``"telegraf.reload"``);
    * a namespace grant (``"telegraf"`` or ``"telegraf.*"``) covers every
      capability in it;
    * asking for a bare namespace (``has("telegraf")``) is true when ANY
      capability in that namespace is granted.
    """
    wanted_ns = _namespace(capability)
    bare = "." not in capability
    for g in granted:
        if g == capability:
            return True
        if g in (wanted_ns, f"{wanted_ns}.*"):
            return True
        if bare and _namespace(g) == capability:
            return True
    return False


# ── the protocol ─────────────────────────────────────────────────────────────
@runtime_checkable
class SecretsAPI(Protocol):
    async def get(self, key: str) -> Optional[str]:
        """This plugin's secret ``key`` for the invoking tenant/owner, or
        ``None`` when it is not set. Only the plugin's OWN secrets are readable
        (capability ``secrets.read``)."""
        ...


@runtime_checkable
class PluginsAPI(Protocol):
    async def invoke(self, plugin: str, action: str, **kwargs: Any) -> Any:
        """Call ``action`` on another plugin (capability ``plugins.invoke``).
        Allowed only along a declared ``PluginMetadata.dependencies`` edge;
        the target's own action rules still apply. Returns the action's
        JSON result."""
        ...


@runtime_checkable
class DocumentsAPI(Protocol):
    async def index(
        self,
        kb_id: str,
        filename: str,
        content: Union[bytes, str],
        content_type: str,
    ) -> Dict[str, Any]:
        """Upload a document into knowledge base ``kb_id`` on behalf of the
        invoking user (capability ``documents.index``). Returns the platform's
        upload response (e.g. the new document's id)."""
        ...


@runtime_checkable
class TelegrafAPI(Protocol):
    """The managed telegraf region (capabilities ``telegraf.*``; granted only to
    plugins that declare ``MANAGES = ["telegraf"]``). The platform validates
    the TOML (allowlisted input plugins only, size caps) and writes it
    atomically; telegraf picks the change up without a restart."""

    async def set_managed_region(self, toml: str) -> Dict[str, Any]:
        """Replace the plugin-managed region of the telegraf config."""
        ...

    async def clear_managed_region(self) -> Dict[str, Any]:
        """Empty the plugin-managed region."""
        ...

    async def reload(self, force: bool = False) -> Dict[str, Any]:
        """Ask for the config to be applied. ``force=True`` requests a
        container restart (a rare fallback, audit-logged by the platform)."""
        ...


@runtime_checkable
class PlatformContext(Protocol):
    """What ``self.ctx`` provides to a contract-v2 plugin."""

    @property
    def secrets(self) -> SecretsAPI: ...

    @property
    def plugins(self) -> PluginsAPI: ...

    @property
    def documents(self) -> DocumentsAPI: ...

    @property
    def telegraf(self) -> TelegrafAPI: ...

    def has(self, capability: str) -> bool:
        """Whether ``capability`` is granted for this binding (see
        :func:`capability_granted` for name matching). Use it to switch optional
        features on or off; a granted call can still fail at call time."""
        ...


# ── the unbound default ──────────────────────────────────────────────────────
_UNBOUND_REASON = (
    "no platform context is bound (contract-v1 host, or a unit test without "
    "harness.FakePlatformContext)"
)


def _unbound(capability: str) -> CapabilityUnavailable:
    return CapabilityUnavailable(capability, _UNBOUND_REASON)


class _UnboundSecrets:
    async def get(self, key: str) -> Optional[str]:
        raise _unbound(CAP_SECRETS_READ)


class _UnboundPlugins:
    async def invoke(self, plugin: str, action: str, **kwargs: Any) -> Any:
        raise _unbound(CAP_PLUGINS_INVOKE)


class _UnboundDocuments:
    async def index(
        self,
        kb_id: str,
        filename: str,
        content: Union[bytes, str],
        content_type: str,
    ) -> Dict[str, Any]:
        raise _unbound(CAP_DOCUMENTS_INDEX)


class _UnboundTelegraf:
    async def set_managed_region(self, toml: str) -> Dict[str, Any]:
        raise _unbound(CAP_TELEGRAF_SET_MANAGED_REGION)

    async def clear_managed_region(self) -> Dict[str, Any]:
        raise _unbound(CAP_TELEGRAF_CLEAR_MANAGED_REGION)

    async def reload(self, force: bool = False) -> Dict[str, Any]:
        raise _unbound(CAP_TELEGRAF_RELOAD)


class UnboundPlatformContext:
    """The context a plugin sees before (or without) a host binding: every call
    raises :class:`CapabilityUnavailable` and ``has()`` is always ``False``."""

    def __init__(self) -> None:
        self.secrets = _UnboundSecrets()
        self.plugins = _UnboundPlugins()
        self.documents = _UnboundDocuments()
        self.telegraf = _UnboundTelegraf()

    def has(self, capability: str) -> bool:
        return False

    def __repr__(self) -> str:
        return "UnboundPlatformContext()"


UNBOUND_CONTEXT: PlatformContext = UnboundPlatformContext()
