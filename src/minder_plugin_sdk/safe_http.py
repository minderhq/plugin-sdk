"""``safe_http``: outbound HTTP for URLs a plugin does not fully control.

Use it whenever a plugin fetches a configured or user-supplied URL (a feed, a
web page to crawl, a webhook target). It applies the platform's egress rules on
the plugin side, so a crafted URL cannot reach internal services, the LAN, or
cloud metadata endpoints:

* ``http`` / ``https`` only;
* the host is resolved and **every** resolved address must be public
  (loopback, private, link-local, CGNAT, multicast, reserved and unspecified
  ranges are refused, including IPv4 embedded in IPv6: ``::ffff:a.b.c.d``,
  NAT64 ``64:ff9b::/96`` and 6to4 ``2002::/16``);
* the connection is **pinned** to the address that was checked (no second DNS
  lookup that could return something else), with TLS still verified against
  the hostname;
* redirects are followed manually and **every hop is re-checked**;
* the response body is capped (``max_bytes``).

Optionally pass ``allowed_hosts`` (e.g. your plugin's ``EGRESS`` list) to also
restrict which hosts may be contacted at all.

    from minder_plugin_sdk.safe_http import safe_request

    resp = await safe_request("GET", url, allowed_hosts=MyPlugin.EGRESS)
    data = resp.json()

Requires ``httpx`` (``pip install httpx``); the rest of the SDK does not.
Connections are made directly (``trust_env=False``: no proxy from the
environment), since the address check is only meaningful for a direct
connection. ``check_url`` is usable without ``httpx``.
"""

import asyncio
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)
from urllib.parse import urljoin, urlsplit

from .errors import UnsafeURLError

if TYPE_CHECKING:  # pragma: no cover
    import httpx

__all__ = [
    "SafeResponse",
    "check_url",
    "host_allowed",
    "is_public_address",
    "safe_request",
]

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_TIMEOUT = 30.0

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_REDIRECTS = frozenset({301, 302, 303, 307, 308})


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    return None


def is_public_address(ip: Union[str, IPAddress]) -> bool:
    """Whether ``ip`` is a public, unicast, globally routable address."""
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.scope_id:
            return False
        inner = _embedded_ipv4(addr)
        if inner is not None:
            return is_public_address(inner)
    return addr.is_global and not addr.is_multicast


def host_allowed(host: str, patterns: Iterable[str]) -> bool:
    """Whether ``host`` matches one of ``patterns`` (``"api.example.com"`` exact,
    ``"*.example.com"`` any subdomain, not the apex)."""
    host = host.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.lower()
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]) and host != pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


async def _resolve(host: str, port: int) -> List[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _patterns(allowed_hosts: Optional[Iterable[str]]) -> Optional[List[str]]:
    # A plain string is an EGRESS keyword ("public" / "lan"): no host allowlist,
    # the address rules still apply.
    if allowed_hosts is None or isinstance(allowed_hosts, str):
        return None
    return list(allowed_hosts)


async def check_url(
    url: str, allowed_hosts: Optional[Iterable[str]] = None
) -> Tuple[str, str]:
    """Validate ``url`` against the egress rules and resolve it.

    Returns ``(host, address)``: the hostname and the checked address to pin
    the connection to. ``allowed_hosts`` is a list of host patterns (see
    :func:`host_allowed`); a plain string such as an ``EGRESS`` keyword means
    no host allowlist. Raises :class:`UnsafeURLError` when refused."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsafeURLError(f"scheme {scheme or '(none)'!r} is not allowed")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise UnsafeURLError("URL has no host")
    if parts.username or parts.password:
        raise UnsafeURLError("URLs with embedded credentials are not allowed")
    patterns = _patterns(allowed_hosts)
    if patterns is not None:
        if not host_allowed(host, patterns):
            raise UnsafeURLError(f"host {host!r} is not in the allowed hosts")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise UnsafeURLError("URL has an invalid port") from None

    try:
        literal: Optional[IPAddress] = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            addresses = await _resolve(host, port)
        except OSError:
            raise UnsafeURLError(f"cannot resolve host {host!r}") from None
    if not addresses:
        raise UnsafeURLError(f"cannot resolve host {host!r}")
    for address in addresses:
        if not is_public_address(address.split("%", 1)[0]):
            raise UnsafeURLError(f"host {host!r} resolves to a non-public address")
    return host, addresses[0]


@dataclass
class SafeResponse:
    """The (fully read, size-capped) response of :func:`safe_request`."""

    status_code: int
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    encoding: str = "utf-8"

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300


async def _read_capped(response: "httpx.Response", max_bytes: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise UnsafeURLError(f"response body exceeds {max_bytes} bytes")
    chunks: List[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > max_bytes:
            raise UnsafeURLError(f"response body exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


async def safe_request(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    params: Optional[Mapping[str, Any]] = None,
    content: Optional[bytes] = None,
    json_body: Any = None,
    allowed_hosts: Optional[Iterable[str]] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    timeout: float = DEFAULT_TIMEOUT,
    client: Optional["httpx.AsyncClient"] = None,
) -> SafeResponse:
    """Make one HTTP request under the egress rules (see module docstring).

    Redirects are followed (re-checked per hop) only for ``GET`` / ``HEAD``;
    other methods return the redirect response as-is. ``client`` lets a caller
    reuse a client or inject a test transport; the request is still sent with
    redirects disabled and the address pinned."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError("safe_http requires httpx: pip install httpx") from exc

    method = method.upper()
    follow = method in ("GET", "HEAD")
    patterns = _patterns(allowed_hosts)
    send_headers = dict(headers or {})
    origin = (urlsplit(url).hostname or "").lower()
    owned = client is None
    http = client or httpx.AsyncClient(timeout=timeout, trust_env=False)
    try:
        current = url
        for _hop in range(max_redirects + 1):
            host, address = await check_url(current, patterns)
            if host.lower() != origin:
                # Never forward credentials to a different host on redirect.
                send_headers = {
                    k: v
                    for k, v in send_headers.items()
                    if k.lower() not in ("authorization", "cookie")
                }
            request = http.build_request(
                method,
                current,
                headers=send_headers,
                params=params,
                content=content,
                json=json_body,
            )
            # Pin: connect to the checked address, keep Host and TLS SNI /
            # certificate verification on the real hostname.
            # (httpx already set the Host header from the original URL.)
            request.url = request.url.copy_with(host=address)
            if request.url.scheme == "https":
                request.extensions["sni_hostname"] = host
            response = await http.send(request, stream=True, follow_redirects=False)
            try:
                location = response.headers.get("location")
                if follow and response.status_code in _REDIRECTS and location:
                    current = urljoin(current, location)
                    params = None  # already part of the redirect target
                    continue
                body = await _read_capped(response, max_bytes)
                return SafeResponse(
                    status_code=response.status_code,
                    url=current,
                    headers=dict(response.headers),
                    content=body,
                    encoding=response.encoding or "utf-8",
                )
            finally:
                await response.aclose()
        raise UnsafeURLError(f"more than {max_redirects} redirects")
    finally:
        if owned:
            await http.aclose()
