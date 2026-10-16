"""``minder-plugin serve``: run a ``PluginBase`` plugin as a remote (T4) plugin.

:func:`create_app` wraps a plugin instance in an ASGI app (Starlette) with two
routes:

``POST /minder/v1/invoke``
    Minder's signed invocation. The server verifies the RFC 9421 signature
    against Minder's published keys (see ``t4``), its freshness, the nonce and
    the content digest, then dispatches the JSON envelope::

        {"contract": "minder.t4/v1", "installation_id": "...",
         "invocation_id": "...", "kind": "tool" | "action", "target": "...",
         "kwargs": {...}, "deadline_ms": 30000, "grant": "...",
         "callback_base": "https://minder.example", "tenant_ref": "...",
         "owner_ref": "..."}

    ``kind: "tool"`` runs the ``AI_TOOLS`` entry named ``target`` (through its
    ``action``); ``kind: "action"`` runs the method ``target`` from
    ``ACTIONS``. The call is bounded by ``deadline_ms``. A synchronous
    (non-``async``) target runs in a worker thread so it can't stall the event
    loop; when its deadline passes the server answers 504, but Python can't
    kill a thread, so the call keeps running in the background until it
    returns. Prefer ``async`` targets, and keep sync ones short. While it runs,
    ``self.ctx`` is a :class:`~minder_plugin_sdk.t4_callbacks.
    CallbackPlatformContext` for this invocation's grant, and
    :func:`current_invocation` describes the invocation.

``GET /minder/v1/health``
    Signed the same way; answers the plugin's ``health_check()``.

Every signature must cover this server's own ``@authority`` (the
``public_authority`` it is configured with, never the request's ``Host``) and
``installation_id`` must match the envelope's, so a request Minder signed for
another plugin or installation is refused. :func:`create_app` refuses to start
without both unless ``insecure_host_authority=True`` (local development only).

``@path`` is verified as the route this server serves (``path_prefix`` plus
``/minder/v1/invoke`` or ``/minder/v1/health``), not the raw path received:
stricter than a raw target, since an alias of the route (``//minder/...``,
percent-encoded segments) can never match a signature made for another path.

Every answer is JSON. Success is ``{"ok": true, "invocation_id", "result"}``;
a failure is ``{"ok": false, "invocation_id", "error": {"code", "message"}}``
with a stable ``code`` and never a traceback (that goes to the server log):

====  ==========================================================================
400   ``invalid_envelope``, ``unsupported_contract``, ``unsupported_kind``,
      ``invalid_arguments``
401   ``invalid_signature`` (``error.reason`` says why, e.g. ``nonce_replayed``)
403   ``wrong_installation`` (``error.reason``: ``installation_mismatch``)
404   ``unknown_target``
413   ``payload_too_large``
424   ``capability_denied``, ``capability_unavailable``, ``capability_invalid``
      (a ``self.ctx`` call failed; ``error.capability`` names it)
500   ``plugin_error``, ``internal_error``, ``result_not_serializable``
503   ``key_set_unavailable``
504   ``deadline_exceeded``
====  ==========================================================================

Needs the ``serve`` extra: ``pip install 'minder-plugin-sdk[serve]'``. Run it
behind a TLS-terminating reverse proxy; Minder only calls ``https`` origins.
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Optional,
    Tuple,
)

from .context import UNBOUND_CONTEXT, PlatformContext
from .errors import (
    CapabilityDenied,
    CapabilityError,
    CapabilityInvalid,
    CapabilityUnavailable,
    PluginError,
)
from .t4 import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    DEFAULT_MAX_AGE_SECONDS,
    HEALTH_PATH,
    INVOKE_PATH,
    InMemoryNonceCache,
    InstallationKey,
    KeyResolver,
    KeySetUnavailable,
    MinderKeySet,
    NonceCache,
    SignatureError,
    authority_from_origin,
    normalize_authority,
    origin_of,
    verify_request,
)
from .t4_callbacks import CallbackPlatformContext

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route
except ImportError as _exc:  # pragma: no cover - depends on the install
    raise ImportError(
        "minder-plugin serve needs the serve extra: "
        "pip install 'minder-plugin-sdk[serve]'"
    ) from _exc

__all__ = [
    "CONTRACT",
    "Invocation",
    "InvocationError",
    "create_app",
    "current_invocation",
]

logger = logging.getLogger("minder_plugin_sdk.t4_server")

#: The envelope ``contract`` this server speaks.
CONTRACT = "minder.t4/v1"
KINDS = ("tool", "action")
DEFAULT_DEADLINE_MS = 30_000
MAX_DEADLINE_MS = 15 * 60 * 1000
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,128}\Z")
_REF = re.compile(r"^[A-Za-z0-9._:\-=+/]{1,256}\Z")
# A grant is an opaque bearer token: visible ASCII, no spaces.
_GRANT = re.compile(r"^[\x21-\x7e]{1,4096}\Z")


@dataclass(frozen=True)
class Invocation:
    """The invocation being served (see :func:`current_invocation`).

    ``tenant_ref`` / ``owner_ref`` are pseudonymous references (an HMAC Minder
    computes per installation), never Minder's internal ids: use them to key
    per-tenant state. The grant itself is not exposed."""

    installation_id: str
    invocation_id: str
    kind: str
    target: str
    kwargs: Dict[str, Any]
    deadline_ms: int
    callback_base: Optional[str] = None
    tenant_ref: Optional[str] = None
    owner_ref: Optional[str] = None
    granted: Optional[FrozenSet[str]] = None
    grant: Optional[str] = field(default=None, repr=False)


_INVOCATION: "contextvars.ContextVar[Optional[Invocation]]" = contextvars.ContextVar(
    "minder_t4_invocation", default=None
)
_CONTEXT: "contextvars.ContextVar[Optional[PlatformContext]]" = contextvars.ContextVar(
    "minder_t4_context", default=None
)


def current_invocation() -> Optional[Invocation]:
    """The invocation the current task is serving, or None outside one."""
    return _INVOCATION.get()


class _InvocationContext:
    """What the plugin is bound to once: it forwards each call to the context
    of the invocation the current task is serving (so concurrent invocations
    never see each other's grant), and to ``UNBOUND_CONTEXT`` outside one."""

    @staticmethod
    def _current() -> PlatformContext:
        return _CONTEXT.get() or UNBOUND_CONTEXT

    @property
    def secrets(self) -> Any:
        return self._current().secrets

    @property
    def plugins(self) -> Any:
        return self._current().plugins

    @property
    def documents(self) -> Any:
        return self._current().documents

    @property
    def telegraf(self) -> Any:
        return self._current().telegraf

    @property
    def timeseries(self) -> Any:
        return self._current().timeseries

    def has(self, capability: str) -> bool:
        return self._current().has(capability)

    def __repr__(self) -> str:
        return "T4InvocationContext()"


class InvocationError(Exception):
    """A refusal with an HTTP status and a stable code (no internals)."""

    def __init__(self, status: int, code: str, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra


def _json_response(status: int, document: Dict[str, Any]) -> Response:
    return Response(
        json.dumps(document, separators=(",", ":"), allow_nan=False),
        status_code=status,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


def _error(err: InvocationError, invocation_id: Optional[str] = None) -> Response:
    detail: Dict[str, Any] = {"code": err.code, "message": err.message}
    detail.update(err.extra)
    return _json_response(
        err.status, {"ok": False, "invocation_id": invocation_id, "error": detail}
    )


def _invalid(message: str) -> InvocationError:
    return InvocationError(400, "invalid_envelope", message)


def _parse_grant(value: Any) -> Tuple[Optional[str], Optional[FrozenSet[str]]]:
    """``grant`` is the opaque token, or ``{"token", "capabilities"?}``."""
    if value is None:
        return None, None
    granted: Optional[FrozenSet[str]] = None
    token = value
    if isinstance(value, dict):
        token = value.get("token")
        caps = value.get("capabilities")
        if caps is not None:
            if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
                raise _invalid("grant.capabilities must be a list of names")
            granted = frozenset(caps)
    if not isinstance(token, str) or not _GRANT.match(token):
        raise _invalid("grant is not a bearer token")
    return token, granted


def _optional_ref(envelope: Dict[str, Any], name: str) -> Optional[str]:
    value = envelope.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not _REF.match(value):
        raise _invalid(f"{name} is malformed")
    return value


def parse_envelope(
    body: bytes,
    *,
    installation_id: Optional[str],
    callback_origins: FrozenSet[str],
    default_deadline_ms: int,
    max_deadline_ms: int,
) -> Invocation:
    """Validate an invocation body. Raises :class:`InvocationError`."""
    try:
        envelope = json.loads(body)
    except ValueError:
        raise _invalid("body is not JSON") from None
    if not isinstance(envelope, dict):
        raise _invalid("body is not a JSON object")
    if envelope.get("contract") != CONTRACT:
        raise InvocationError(
            400, "unsupported_contract", f"this server speaks {CONTRACT}"
        )
    ids = {}
    for name in ("installation_id", "invocation_id"):
        value = envelope.get(name)
        if not isinstance(value, str) or not _ID.match(value):
            raise _invalid(f"{name} is missing or malformed")
        ids[name] = value
    if installation_id is not None and ids["installation_id"] != installation_id:
        raise InvocationError(
            403,
            "wrong_installation",
            "not addressed to this installation",
            reason="installation_mismatch",
        )
    kind = envelope.get("kind")
    if kind not in KINDS:
        raise InvocationError(400, "unsupported_kind", "kind must be tool or action")
    target = envelope.get("target")
    if not isinstance(target, str) or not target:
        raise _invalid("target is missing")
    kwargs = envelope.get("kwargs", {})
    if kwargs is None:
        kwargs = {}
    if not isinstance(kwargs, dict):
        raise _invalid("kwargs must be an object")
    deadline_ms = envelope.get("deadline_ms", default_deadline_ms)
    if isinstance(deadline_ms, bool) or not isinstance(deadline_ms, int):
        raise _invalid("deadline_ms must be an integer")
    if deadline_ms <= 0:
        raise _invalid("deadline_ms must be positive")
    deadline_ms = min(deadline_ms, max_deadline_ms)
    grant, granted = _parse_grant(envelope.get("grant"))
    callback_base = envelope.get("callback_base")
    if callback_base is not None:
        if not isinstance(callback_base, str):
            raise _invalid("callback_base must be a URL")
        try:
            origin = origin_of(callback_base)
        except ValueError:
            raise _invalid("callback_base is not an allowed URL") from None
        if origin not in callback_origins:
            raise _invalid("callback_base is not Minder's origin")
    return Invocation(
        installation_id=ids["installation_id"],
        invocation_id=ids["invocation_id"],
        kind=kind,
        target=target,
        kwargs=kwargs,
        deadline_ms=deadline_ms,
        callback_base=callback_base,
        tenant_ref=_optional_ref(envelope, "tenant_ref"),
        owner_ref=_optional_ref(envelope, "owner_ref"),
        granted=granted,
        grant=grant,
    )


def resolve_target(plugin: Any, kind: str, target: str) -> Callable[..., Any]:
    """The plugin method an invocation runs. Only declared ``ACTIONS`` (and
    ``AI_TOOLS`` that map to one) are reachable."""
    actions = set(getattr(plugin, "ACTIONS", frozenset()) or ())
    action: Optional[str] = target
    if kind == "tool":
        action = None
        for spec in getattr(plugin, "AI_TOOLS", []) or []:
            if isinstance(spec, dict) and spec.get("name") == target:
                action = spec.get("action")
                break
    if not isinstance(action, str) or action not in actions or action.startswith("_"):
        raise InvocationError(404, "unknown_target", f"no such {kind}")
    method = getattr(plugin, action, None)
    if not callable(method):
        raise InvocationError(404, "unknown_target", f"no such {kind}")
    return method  # type: ignore[no-any-return]


_CAPABILITY_CODES = (
    (CapabilityDenied, "capability_denied"),
    (CapabilityUnavailable, "capability_unavailable"),
    (CapabilityInvalid, "capability_invalid"),
)


def _capability_error(exc: CapabilityError) -> InvocationError:
    code = "capability_unavailable"
    for cls, name in _CAPABILITY_CODES:
        if isinstance(exc, cls):
            code = name
            break
    # CapabilityError messages name the capability and a reason, never values.
    return InvocationError(424, code, str(exc), capability=exc.capability)


class _Server:
    def __init__(
        self,
        plugin: Any,
        *,
        resolve_key: KeyResolver,
        nonce_cache: NonceCache,
        installation_key: Optional[InstallationKey],
        installation_id: Optional[str],
        callback_origins: FrozenSet[str],
        path_prefix: str,
        public_authority: Optional[str],
        max_body_bytes: int,
        default_deadline_ms: int,
        max_deadline_ms: int,
        max_age: float,
        clock_skew: float,
        http_client: Any,
    ) -> None:
        self.plugin = plugin
        self.resolve_key = resolve_key
        self.nonce_cache = nonce_cache
        self.installation_key = installation_key
        self.installation_id = installation_id
        self.callback_origins = callback_origins
        self.path_prefix = path_prefix
        self.public_authority = public_authority
        self.max_body_bytes = max_body_bytes
        self.default_deadline_ms = default_deadline_ms
        self.max_deadline_ms = max_deadline_ms
        self.max_age = max_age
        self.clock_skew = clock_skew
        self.http_client = http_client

    async def _read_body(self, request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit():
            if int(declared) > self.max_body_bytes:
                raise InvocationError(413, "payload_too_large", "body too large")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > self.max_body_bytes:
                raise InvocationError(413, "payload_too_large", "body too large")
        return bytes(body)

    def _authority(self, request: Request) -> str:
        if self.public_authority is not None:
            return self.public_authority
        # Fallback (no public_authority configured): the Host header. The
        # sender controls it, so it does not stop a request signed for
        # another plugin from being replayed here; configure the authority.
        host = request.headers.get("host")
        if not host:
            raise InvocationError(
                401,
                "invalid_signature",
                "signature refused",
                reason="invalid_component",
            )
        return host

    async def _verify(self, request: Request, path: str, body: bytes) -> None:
        try:
            raw_query = request.scope.get("query_string", b"").decode("ascii")
        except UnicodeDecodeError:
            raise InvocationError(
                401,
                "invalid_signature",
                "signature refused",
                reason="invalid_component",
            ) from None
        try:
            await verify_request(
                method=request.method,
                authority=self._authority(request),
                path=self.path_prefix + path,
                query=raw_query,
                headers=request.headers,
                body=body,
                resolve_key=self.resolve_key,
                nonce_cache=self.nonce_cache,
                max_age=self.max_age,
                clock_skew=self.clock_skew,
            )
        except KeySetUnavailable:
            raise InvocationError(
                503, "key_set_unavailable", "cannot fetch Minder's keys yet"
            ) from None
        except SignatureError as e:
            raise InvocationError(
                401, "invalid_signature", "signature refused", reason=e.reason
            ) from None

    def _context_for(self, invocation: Invocation, started: float) -> PlatformContext:
        if invocation.callback_base is None or invocation.grant is None:
            return UNBOUND_CONTEXT
        return CallbackPlatformContext(
            callback_base=invocation.callback_base,
            grant=invocation.grant,
            key=self.installation_key,
            granted=invocation.granted,
            deadline=started + invocation.deadline_ms / 1000.0,
            client=self.http_client,
        )

    async def _run(self, invocation: Invocation) -> Any:
        method = resolve_target(self.plugin, invocation.kind, invocation.target)
        try:
            inspect.signature(method).bind(**invocation.kwargs)
        except TypeError:
            raise InvocationError(
                400, "invalid_arguments", "kwargs do not match the target"
            ) from None
        except ValueError:  # pragma: no cover - no introspectable signature
            pass
        started = time.monotonic()
        _INVOCATION.set(invocation)
        _CONTEXT.set(self._context_for(invocation, started))

        async def call() -> Any:
            if inspect.iscoroutinefunction(method):
                result = method(**invocation.kwargs)
            else:
                # A sync target runs in a thread (with this task's context),
                # so a blocking call can't stall the event loop and the
                # deadline below still applies. A timed-out thread can't be
                # killed: it keeps running until the call returns.
                result = await asyncio.to_thread(method, **invocation.kwargs)
            if inspect.isawaitable(result):
                result = await result
            return result

        try:
            return await asyncio.wait_for(call(), invocation.deadline_ms / 1000.0)
        except asyncio.TimeoutError:
            raise InvocationError(
                504, "deadline_exceeded", "the plugin did not answer in time"
            ) from None
        except CapabilityError as e:
            raise _capability_error(e) from None
        except PluginError:
            logger.exception(
                "plugin error in %s %s", invocation.kind, invocation.target
            )
            raise InvocationError(500, "plugin_error", "the plugin failed") from None
        except Exception:
            logger.exception(
                "unhandled error in %s %s", invocation.kind, invocation.target
            )
            raise InvocationError(500, "internal_error", "the plugin failed") from None

    async def invoke(self, request: Request) -> Response:
        invocation_id: Optional[str] = None
        try:
            body = await self._read_body(request)
            await self._verify(request, INVOKE_PATH, body)
            invocation = parse_envelope(
                body,
                installation_id=self.installation_id,
                callback_origins=self.callback_origins,
                default_deadline_ms=self.default_deadline_ms,
                max_deadline_ms=self.max_deadline_ms,
            )
            invocation_id = invocation.invocation_id
            result = await self._run(invocation)
            document = {"ok": True, "invocation_id": invocation_id, "result": result}
            try:
                return _json_response(200, document)
            except (TypeError, ValueError):
                raise InvocationError(
                    500, "result_not_serializable", "the result is not JSON"
                ) from None
        except InvocationError as err:
            if err.status >= 500 or err.status == 401:
                logger.warning("invocation refused: %s", err.code)
            return _error(err, invocation_id)

    async def health(self, request: Request) -> Response:
        try:
            body = await self._read_body(request)
            await self._verify(request, HEALTH_PATH, body)
            try:
                result = await self.plugin.health_check()
            except Exception:
                logger.exception("health_check failed")
                result = {"healthy": False}
            return _json_response(
                200, {"ok": True, "invocation_id": None, "result": result}
            )
        except InvocationError as err:
            return _error(err)


def create_app(
    plugin: Any,
    *,
    minder_url: str,
    installation_key: Optional[InstallationKey] = None,
    installation_id: Optional[str] = None,
    key_set: Optional[Any] = None,
    nonce_cache: Optional[NonceCache] = None,
    callback_origins: Optional[Iterable[str]] = None,
    path_prefix: str = "",
    public_authority: Optional[str] = None,
    insecure_host_authority: bool = False,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    default_deadline_ms: int = DEFAULT_DEADLINE_MS,
    max_deadline_ms: int = MAX_DEADLINE_MS,
    max_age: float = DEFAULT_MAX_AGE_SECONDS,
    clock_skew: float = DEFAULT_CLOCK_SKEW_SECONDS,
    http_client: Any = None,
) -> Starlette:
    """An ASGI app serving ``plugin`` (an instance) as a remote plugin.

    - ``minder_url``: the Minder instance (``https://...``). Its keys are
      fetched from ``<minder_url>/.well-known/minder/plugin-jwks.json`` unless
      ``key_set`` (anything with ``async get(kid)``, e.g.
      :class:`~minder_plugin_sdk.t4.StaticKeySet`) is given, and callbacks may
      only go to its origin unless ``callback_origins`` says otherwise.
    - ``installation_key``: signs this plugin's callbacks; without it
      ``self.ctx`` calls raise ``CapabilityUnavailable``.
    - ``installation_id``: this installation's id. Required: an invocation for
      another installation is refused (403, ``installation_mismatch``).
    - ``nonce_cache``: per-process by default; give several replicas a shared
      one (see :class:`~minder_plugin_sdk.t4.NonceCache`).
    - ``public_authority``: this server's public ``host[:port]`` (or its
      origin URL), the one in the installation's endpoint. Required: every
      signature covers ``@authority`` and the server checks it against this
      value, so a request Minder signed for another plugin can't be replayed
      here.
    - ``insecure_host_authority``: LOCAL DEVELOPMENT ONLY. Start without
      ``public_authority`` and/or ``installation_id``: ``@authority`` is then
      checked against the request's ``Host`` header, which the sender controls,
      and the installation is not checked, so cross-plugin replay is possible.
      Logged as an error at startup.
    - ``path_prefix``: the external path prefix when a reverse proxy mounts
      the app below ``/`` (the signature covers the path Minder addressed).
    - ``http_client``: an ``httpx.AsyncClient`` for callbacks (tests).

    The plugin's ``register()`` and ``initialize()`` run at startup and
    ``shutdown()`` at shutdown.
    """
    origin = origin_of(minder_url)
    authority: Optional[str] = None
    if public_authority:
        authority = (
            authority_from_origin(public_authority)
            if "://" in public_authority
            else normalize_authority(public_authority)
        )
    if not installation_id:
        installation_id = None
    missing = [
        name
        for name, value in (
            ("public_authority", authority),
            ("installation_id", installation_id),
        )
        if value is None
    ]
    if missing and not insecure_host_authority:
        raise ValueError(
            f"{' and '.join(missing)} required: without them a request signed "
            "for another plugin or installation could be replayed here "
            "(insecure_host_authority=True allows it for local development only)"
        )
    if missing:
        logger.error(
            "INSECURE: serving without %s (insecure_host_authority). @authority "
            "is checked against the Host header and/or the installation is not "
            "checked: requests signed for OTHER plugins can be replayed here. "
            "Local development only; never expose this server.",
            " and ".join(missing),
        )
    if path_prefix and (not path_prefix.startswith("/") or path_prefix.endswith("/")):
        raise ValueError("path_prefix must start with / and not end with /")
    origins = frozenset(
        origin_of(o) for o in (callback_origins if callback_origins else [origin])
    )
    keys = key_set if key_set is not None else MinderKeySet(origin)
    server = _Server(
        plugin,
        resolve_key=keys.get,
        nonce_cache=(nonce_cache if nonce_cache is not None else InMemoryNonceCache()),
        installation_key=installation_key,
        installation_id=installation_id,
        callback_origins=origins,
        path_prefix=path_prefix,
        public_authority=authority,
        max_body_bytes=max_body_bytes,
        default_deadline_ms=default_deadline_ms,
        max_deadline_ms=max_deadline_ms,
        max_age=max_age,
        clock_skew=clock_skew,
        http_client=http_client,
    )
    bind = getattr(plugin, "bind_context", None)
    if callable(bind):
        bind(_InvocationContext())

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        await plugin.register()
        initialize = getattr(plugin, "initialize", None)
        if callable(initialize):
            await initialize()
        try:
            yield
        finally:
            shutdown = getattr(plugin, "shutdown", None)
            if callable(shutdown):
                await shutdown()

    routes = [
        Route(INVOKE_PATH, server.invoke, methods=["POST"]),
        Route(HEALTH_PATH, server.health, methods=["GET"]),
    ]
    return Starlette(routes=routes, lifespan=lifespan)
