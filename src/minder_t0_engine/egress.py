"""Strict per-plugin egress for declarative plugins.

The ``declarative`` runner group has direct internet egress; the engine
itself is the boundary that keeps each T0 plugin to its own declared hosts. It
is first-party code and a manifest cannot run code, so unlike the in-process
backstop for code plugins this is enforced on
every request the engine makes. Every hop of every request must pass:

- **Host:** the plugin's own ``egress`` declaration, an exact host or a
  declared subdomain suffix. IP literals are never declared, so never match.
  The platform's name rules (``egress_policy.check_host``) also
  apply: no single-label (Docker service) names, ``.internal``/``.local``,
  Minder's service names, ``localhost`` or metadata names.
- **Scheme:** ``https``, or ``http`` only for a host declared with
  ``http: true``. No userinfo in the URL.
- **Address:** the name is resolved once per hop and every address must be
  globally routable (``address_refused(allow_private=False)``: private,
  loopback, link-local, ``169.254.169.254`` and the other metadata endpoints,
  CGNAT, ULA, multicast, reserved, and IPv4 wrapped in IPv6 are refused). The
  connection is **pinned** to the checked address (TLS SNI and certificate
  verification stay on the host name), so a second lookup cannot rebind it.
- **Redirects:** followed by the engine (GET/HEAD only, unless a request
  declares ``follow_redirects: false``), each hop re-checked as above; a hop
  to another origin drops the manifest's headers and the injected auth.
- **Limits:** response size (streamed and capped), wall time per request
  (all hops and the body), per-plugin concurrency and a per-plugin rate.

A denial raises :class:`EgressDenied`, is logged with the plugin name, and is
counted in :data:`DENIALS` (the hook for automatic quarantine). The
egress proxy adds defense in depth later.
"""

import asyncio
import ipaddress
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple

import httpx

from .egress_policy import (
    EgressPolicyError,
    address_refused,
    check_host,
    resolve_host,
)

from .errors import EgressDenied, LimitExceeded, UpstreamError
from .model import MAX_REDIRECTS, DeclarativeManifest

logger = logging.getLogger("minder.plugin-runner.declarative")

# httpx logs every request line (URL with its query) at INFO, and httpcore
# traces at DEBUG. An engine request can carry an API key in its query, so
# both stay silent for requests made inside PluginEgress.fetch.
_ENGINE_REQUEST: ContextVar[bool] = ContextVar(
    "declarative_engine_request", default=False
)


class _QuietEngineRequests(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _ENGINE_REQUEST.get()


_QUIET_LOGGERS = (
    "httpx",
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
)


def _install_log_filter() -> None:
    # A logger's filters only see records logged on it, not on its children,
    # so httpcore's own loggers are listed one by one.
    for name in _QUIET_LOGGERS:
        target = logging.getLogger(name)
        if not any(isinstance(f, _QuietEngineRequests) for f in target.filters):
            target.addFilter(_QuietEngineRequests())


_install_log_filter()

Resolver = Callable[[str, int], Awaitable[List[str]]]
DenialHook = Callable[[str, str], None]
Origin = Tuple[str, str, int]

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECTS = frozenset({301, 302, 303, 307, 308})


class DenialCounter:
    """Egress denials per plugin and reason. ``hook(plugin, reason)`` is
    called on every denial: quarantine subscribes here."""

    def __init__(self, hook: Optional[DenialHook] = None) -> None:
        self.hook = hook
        self._counts: Dict[Tuple[str, str], int] = {}

    def record(self, plugin: str, reason: str, host: str = "") -> None:
        key = (plugin, reason)
        self._counts[key] = self._counts.get(key, 0) + 1
        logger.warning(
            "T0 egress denied: plugin=%s reason=%s host=%s", plugin, reason, host
        )
        if self.hook is not None:
            try:
                self.hook(plugin, reason)
            except Exception:  # a broken subscriber must not break enforcement
                logger.exception("Egress denial hook failed")

    def count(self, plugin: Optional[str] = None, reason: Optional[str] = None) -> int:
        return sum(
            n
            for (p, r), n in self._counts.items()
            if (plugin is None or p == plugin) and (reason is None or r == reason)
        )

    def snapshot(self) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for (plugin, reason), n in self._counts.items():
            out.setdefault(plugin, {})[reason] = n
        return out

    def reset(self) -> None:
        self._counts.clear()


#: The process-wide counter the runner exposes.
DENIALS = DenialCounter()


class RateLimiter:
    """A token bucket: ``per_minute`` requests, refilled continuously."""

    def __init__(
        self, per_minute: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self.tokens = self.capacity
        self.clock = clock
        self.updated = clock()

    def try_acquire(self) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


@dataclass
class AuthInjection:
    """Credentials the engine adds, only to requests for ``origin``."""

    origin: Origin
    headers: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, str] = field(default_factory=dict)


@dataclass
class Fetched:
    status: int
    headers: httpx.Headers
    content: bytes
    url: httpx.URL  # the last hop, by host name (never the pinned address)
    encoding: str = "utf-8"


def origin_of(url: httpx.URL) -> Origin:
    scheme = url.scheme.lower()
    host = _host(url)
    return scheme, host, url.port or _DEFAULT_PORTS.get(scheme, 0)


def _host(url: httpx.URL) -> str:
    try:
        raw = url.raw_host.decode("ascii")
    except UnicodeDecodeError:
        raw = url.host
    return raw.strip("[]").rstrip(".").lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True


class PluginEgress:
    """The only way a declarative plugin reaches the network."""

    def __init__(
        self,
        manifest: DeclarativeManifest,
        *,
        resolver: Optional[Resolver] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        denials: Optional[DenialCounter] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.manifest = manifest
        self.plugin = manifest.name
        self.limits = manifest.limits
        self._resolver: Resolver = resolver or resolve_host
        # Tests inject a mock transport; in production each hop gets a fresh
        # client with httpx's own transport (no pooling across pinned hosts).
        self._transport = transport
        self.denials = denials if denials is not None else DENIALS
        self._sem = asyncio.Semaphore(self.limits.max_concurrency)
        self._rate = RateLimiter(self.limits.rate_per_minute, clock)

    # ── policy ───────────────────────────────────────────────────────────
    def _deny(self, reason: str, host: str = "") -> EgressDenied:
        self.denials.record(self.plugin, reason, host)
        return EgressDenied(reason)

    def check_url(self, url: httpx.URL) -> Origin:
        """The static checks: scheme, userinfo, declared host, name rules.
        Returns the origin; raises EgressDenied (recorded)."""
        scheme = url.scheme.lower()
        host = _host(url)
        if scheme not in _DEFAULT_PORTS:
            raise self._deny("scheme", host)
        if url.userinfo:
            raise self._deny("userinfo", host)
        if not host or _is_ip(host):
            raise self._deny("ip literal", host)
        rule = self.manifest.rule_for(host)
        if rule is None:
            raise self._deny("undeclared host", host)
        if scheme == "http" and not rule.http:
            raise self._deny("http not declared", host)
        try:
            check_host(host, allow_private=False)
        except EgressPolicyError:
            raise self._deny("internal name", host) from None
        return scheme, host, url.port or _DEFAULT_PORTS[scheme]

    async def pin(self, host: str, port: int) -> str:
        """Resolve ``host`` once and return the address to connect to. Every
        address must be global; raises EgressDenied (recorded)."""
        try:
            addresses = await self._resolver(host, port)
        except (OSError, UnicodeError):
            raise UpstreamError("cannot resolve host") from None
        if not addresses:
            raise UpstreamError("cannot resolve host")
        for address in addresses:
            if address_refused(str(address), allow_private=False):
                raise self._deny("non-global address", host)
        return str(addresses[0]).split("%", 1)[0]

    # ── requests ─────────────────────────────────────────────────────────
    async def fetch(
        self,
        method: str,
        url: httpx.URL,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        json: Any = None,
        has_json: bool = False,
        data: Optional[Mapping[str, str]] = None,
        auth: Optional[AuthInjection] = None,
        follow_redirects: bool = True,
    ) -> Fetched:
        """One request (plus redirects) under the plugin's policy and limits.

        Redirects are followed for GET/HEAD only, and only when
        ``follow_redirects``; otherwise the 3xx response is returned as is."""
        token = _ENGINE_REQUEST.set(True)
        try:
            return await self._fetch_limited(
                method,
                url,
                params,
                headers,
                json,
                has_json,
                data,
                auth,
                follow_redirects,
            )
        finally:
            _ENGINE_REQUEST.reset(token)

    async def _fetch_limited(
        self,
        method: str,
        url: httpx.URL,
        params: Optional[Mapping[str, str]],
        headers: Optional[Mapping[str, str]],
        json: Any,
        has_json: bool,
        data: Optional[Mapping[str, str]],
        auth: Optional[AuthInjection],
        follow_redirects: bool,
    ) -> Fetched:
        async with self._sem:
            try:
                return await asyncio.wait_for(
                    self._fetch(
                        method.upper(),
                        url.copy_merge_params(dict(params or {})),
                        dict(headers or {}),
                        json,
                        has_json,
                        dict(data) if data is not None else None,
                        auth,
                        follow_redirects,
                    ),
                    self.limits.timeout_s,
                )
            except asyncio.TimeoutError:
                raise LimitExceeded("time") from None

    async def _fetch(
        self,
        method: str,
        url: httpx.URL,
        headers: Dict[str, str],
        json: Any,
        has_json: bool,
        data: Optional[Dict[str, str]],
        auth: Optional[AuthInjection],
        follow_redirects: bool,
    ) -> Fetched:
        first = origin_of(url)
        current = url
        follow = follow_redirects and method in ("GET", "HEAD")
        for _hop in range(MAX_REDIRECTS + 1):
            if not self._rate.try_acquire():
                logger.warning("T0 rate limit hit: plugin=%s", self.plugin)
                raise LimitExceeded("rate")
            scheme, host, port = self.check_url(current)
            address = await self.pin(host, port)
            same_origin = (scheme, host, port) == first
            send_headers = dict(headers) if same_origin else {}
            hop_url = current
            if auth is not None and (scheme, host, port) == auth.origin:
                send_headers.update(auth.headers)
                if auth.query:
                    hop_url = hop_url.copy_merge_params(auth.query)
            send_headers.setdefault(
                "User-Agent", f"minder-declarative/1 ({self.plugin})"
            )
            send_headers["Connection"] = "close"
            kwargs: Dict[str, Any] = {"headers": send_headers}
            if same_origin and has_json:
                kwargs["json"] = json
            elif same_origin and data is not None:
                kwargs["data"] = data
            # A fresh client per hop: a pinned connection is never pooled for
            # another host, and never goes through a proxy (trust_env=False).
            async with httpx.AsyncClient(
                transport=self._transport,
                trust_env=False,
                follow_redirects=False,
                timeout=self.limits.timeout_s,
            ) as client:
                request = client.build_request(method, hop_url, **kwargs)
                # Pin: connect to the checked address. The Host header (set
                # from the URL above) and TLS SNI / certificate verification
                # keep the host name.
                request.url = request.url.copy_with(host=address)
                if scheme == "https":
                    request.extensions["sni_hostname"] = host
                try:
                    response = await client.send(request, stream=True)
                except httpx.HTTPError as e:
                    raise UpstreamError(
                        f"transport error ({type(e).__name__})"
                    ) from None
                try:
                    location = response.headers.get("location")
                    if follow and response.status_code in _REDIRECTS and location:
                        try:
                            current = current.join(location)
                        except (httpx.InvalidURL, ValueError):
                            raise UpstreamError("invalid redirect") from None
                        continue
                    content = await self._read_capped(response)
                    return Fetched(
                        status=response.status_code,
                        headers=response.headers,
                        content=content,
                        url=current,
                        encoding=response.encoding or "utf-8",
                    )
                finally:
                    await response.aclose()
        raise LimitExceeded("redirects")

    async def _read_capped(self, response: httpx.Response) -> bytes:
        cap = self.limits.max_response_bytes
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > cap:
            raise LimitExceeded("response size")
        chunks: List[bytes] = []
        size = 0
        try:
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > cap:
                    raise LimitExceeded("response size")
                chunks.append(chunk)
        except httpx.HTTPError as e:
            raise UpstreamError(f"transport error ({type(e).__name__})") from None
        return b"".join(chunks)
