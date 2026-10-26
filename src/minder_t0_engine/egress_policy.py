"""Egress policy for outbound URLs that come from configuration or manifests.

Without a policy, a configured URL could point at the deployment's internal
network (a database service name, ``169.254.169.254``, a VPN peer...) and the
response could be used to scan it. This module is the stdlib-only guard Minder
uses for such URLs; the T0 engine applies it to every request:

- :func:`validate_outbound_base_url` is the save-time check (create/patch). It
  needs no DNS: scheme, userinfo, host and port syntax, IP literals, and the
  host-name rules below.
- :func:`assert_public_destination` is the request-time check. It resolves the
  host (every A/AAAA record) and vets each address, so a name that resolved to
  a public address at save time and to an internal one now (DNS rebinding) is
  refused. It returns the vetted addresses so the caller can connect to one of
  them instead of resolving the name a second time.

``allow_private`` is the one switch. Some destinations are refused even when it
is true: loopback (``localhost`` / 127.0.0.0/8 / ``::1``), link-local
(169.254.0.0/16, fe80::/10), the cloud metadata endpoints (169.254.169.254,
``fd00:ec2::254``, 100.100.100.200, ``metadata.google.internal``), unspecified
(0.0.0.0/8, ``::``), multicast and reserved ranges, IPv4 hidden in an IPv6 form
(mapped, NAT64 ``64:ff9b::/96``, 6to4, Teredo; the local-use NAT64 space
``64:ff9b:1::/48`` is refused outright), and Minder's own compose
services by name (``minder-*`` container names and service names such as
``postgres``, ``redis``, ``api-gateway``; only ``ollama``/``minder-ollama``,
an inference endpoint, is exempt). When it is false only globally routable
unicast addresses pass, which also refuses RFC 1918, CGNAT (100.64.0.0/10, the
Tailscale range), ULA (fc00::/7), and host names that only make sense inside a
deployment: single-label names and private-use suffixes such as
``.internal``, ``.local`` and ``.ts.net``.

**Trust boundary with allow_private** (a self-host ``is_local`` row): the
caller is trusted to reach its own LAN -- a network Ollama/vLLM at
``192.168.x.y``, a Tailscale peer, or ``host.docker.internal`` (Docker
Desktop's name for the host, deliberately allowed). The name rules keep it off
Minder's own services, but an RFC 1918 *address* is not mapped back to a
container, so an org admin who types the Docker-network IP of, say, Postgres
can still reach it. On self-host that admin is normally the operator; a
multi-tenant deployment must run with allow_private off (SaaS mode).

The error text is fixed and never echoes the URL, so a caller can return it to
the client without leaking a credential embedded in the input. Resolution
failures and refused addresses raise the same message, so the check is not an
oracle for which internal names exist.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import List, Optional, Union
from urllib.parse import urlsplit

from .url_userinfo import has_userinfo

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

# The address tables are explicit on purpose: the stdlib's is_private /
# is_reserved / is_global tables changed between Python 3.12.3 and 3.13
# (CVE-2024-4032 follow-ups), and this policy must not depend on the
# interpreter. The stdlib's is_global is only used as an EXTRA refusal when
# allow_private is false (it can only make the check stricter).
#
# Link-local and the cloud metadata endpoints: refused by every policy here,
# and on their own by address_is_metadata() (plugin-runner's socket-level
# backstop,, which must still reach the LAN/data-network peers).
_METADATA_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.0.0/16",  # link-local, incl. 169.254.169.254 (cloud metadata)
        "100.100.100.200/32",  # Alibaba Cloud metadata (inside CGNAT)
        "168.63.129.16/32",  # Azure WireServer
        "fe80::/10",  # link-local
        "fd00:ec2::254/128",  # AWS IMDS over IPv6 (inside ULA)
    )
)
# Refused even with allow_private: there is no legitimate model endpoint here.
_ALWAYS_BLOCKED_NETWORKS = _METADATA_NETWORKS + tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"; 0.0.0.0 connects to the local host
        "127.0.0.0/8",  # loopback
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, incl. 255.255.255.255
        # IPv6. ::/8 covers ::, ::1, IPv4-compatible ::a.b.c.d and the RFC 8215
        # local-use NAT64 space 64:ff9b:1::/48 (operators carve /48../96
        # prefixes from it, so where the IPv4 octets sit is unknowable and it
        # is refused). Mapped ::ffff:a.b.c.d and the well-known NAT64
        # 64:ff9b::/96 are unwrapped to their IPv4 address before this check.
        "::/8",
        "100::/64",  # discard-only
        "2001::/32",  # Teredo: tunnels to an arbitrary IPv4 address
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)
# Refused unless allow_private (a self-host is_local row).
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # CGNAT / Tailscale
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "fc00::/7",  # ULA
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation (RFC 9637)
        "2001:2::/48",  # benchmarking
        "2001:10::/28",  # ORCHIDv1 (deprecated)
        "2001:20::/28",  # ORCHIDv2
        "5f00::/16",  # SRv6 SIDs
    )
)
# RFC 6052 well-known /96 prefix: the IPv4 address is the low 32 bits.
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_ALWAYS_BLOCKED_HOSTS = frozenset(
    {"localhost", "metadata", "metadata.google.internal", "instance-data"}
)
# Minder's own compose services (service names; their `minder-*` container
# names are covered by _PRIVATE_PREFIXES). Refused even with allow_private:
# an is_local provider is an inference endpoint, never the platform's own
# databases, brokers or APIs. `ollama` / `minder-ollama` stay allowed -- the
# platform Ollama is an inference endpoint, which is what is_local is for.
_PLATFORM_SERVICE_NAMES = frozenset(
    {
        "postgres",
        "redis",
        "neo4j",
        "rabbitmq",
        "qdrant",
        "minio",
        "influxdb",
        "timeseries-gateway",
        "schema-registry",
        "api-gateway",
        "plugin-registry",
        "marketplace",
        "orchestrator",
        "rag-pipeline",
        "model-management",
        "graph-rag",
        "tts-stt",
        "tts-stt-router",
        "ollama-router",
        "platform-ops",
        "bundle-reconciler",
        "client",
        "openwebui",
        "traefik",
        "authelia",
        "grafana",
        "prometheus",
        "alertmanager",
        "jaeger",
        "otel-collector",
        "telegraf",
        "cadvisor",
        "node-exporter",
        "postgres-exporter",
        "redis-exporter",
        "rabbitmq-exporter",
        "blackbox-exporter",
        "docker-socket-proxy",
    }
)
_ALLOWED_PLATFORM_NAMES = frozenset({"ollama", "minder-ollama"})
# Names that resolve only inside a deployment / LAN / tailnet.
_PRIVATE_SUFFIXES = (
    ".internal",
    ".local",
    ".localdomain",
    ".lan",
    ".home.arpa",
    ".intranet",
    ".corp",
    ".ts.net",
)
_PRIVATE_PREFIXES = ("minder-",)
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_FORBIDDEN_CHARS = re.compile(r"[\s\\\x00-\x1f\x7f]")

REFUSED_DESTINATION = (
    "provider base_url is not permitted: it must be an http(s) URL whose host "
    "resolves only to addresses this deployment allows"
)


class EgressPolicyError(Exception):
    """A destination the egress policy refuses. ``str(e)`` is fixed text that
    never contains the URL, safe to return to the caller."""


@dataclass(frozen=True)
class NormalizedURL:
    url: str  # the input, stripped of surrounding whitespace
    scheme: str  # lower-case
    host: str  # lower-case, IDNA-encoded, no brackets, no trailing dot
    port: int  # explicit, else the scheme default


def _parse_ip(raw: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(raw.split("%", 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return None


def _effective_target(ip: IPAddress) -> IPAddress:
    """The address a connection to ``ip`` really reaches: the IPv4 address
    inside a v4-mapped (``::ffff:a.b.c.d``), well-known NAT64
    (``64:ff9b::a.b.c.d``) or 6to4 (``2002:AABB:CCDD::``) IPv6 address, so an
    IPv6 form is judged exactly like the IPv4 address it wraps. Teredo and
    the local-use NAT64 space are refused by _ALWAYS_BLOCKED_NETWORKS."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64_WKP:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _SIX_TO_FOUR:
            return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return ip


def address_is_metadata(raw: str) -> bool:
    """True if the IP address ``raw`` is link-local or a cloud metadata
    endpoint, including when wrapped in an IPv6 form (mapped, NAT64, 6to4).
    A value that isn't an IP address is not (callers vet names separately)."""
    ip = _parse_ip(raw)
    if ip is None:
        return False
    target = _effective_target(ip)
    return any(target in net for net in _METADATA_NETWORKS)


def address_refused(raw: str, *, allow_private: bool) -> bool:
    """True if the policy refuses connecting to the IP address ``raw``. A
    value that isn't an IP address is refused."""
    ip = _parse_ip(raw)
    if ip is None:
        return True
    target = _effective_target(ip)
    if any(target in net for net in _ALWAYS_BLOCKED_NETWORKS):
        return True
    if any(target in net for net in _PRIVATE_NETWORKS):
        return not allow_private
    # Not in any table above: public unless the stdlib also says otherwise --
    # used only to refuse MORE when allow_private is false, never to allow.
    return not allow_private and not target.is_global


def _host_refused(host: str, *, allow_private: bool) -> bool:
    """Name rules for a (normalized, non-IP) host."""
    if host in _ALWAYS_BLOCKED_HOSTS or host.endswith(".localhost"):
        return True
    labels = host.split(".")
    if any(not label for label in labels):
        return True
    # 2130706433, 0x7f.1, 0177.0.0.1: resolvers read these as IP addresses.
    if all(_NUMERIC_LABEL.match(label) for label in labels):
        return True
    platform_name = host in _PLATFORM_SERVICE_NAMES or (
        host.startswith(_PRIVATE_PREFIXES) and host not in _ALLOWED_PLATFORM_NAMES
    )
    if platform_name:
        return True  # Minder's own services, even for an is_local row
    if allow_private:
        return False
    if len(labels) == 1:  # Docker service names, bare intranet hosts
        return True
    if host.endswith(_PRIVATE_SUFFIXES):
        return True
    return False


def _normalize_host(raw: str) -> str:
    host = raw.strip().rstrip(".").lower()
    if not host:
        raise EgressPolicyError(REFUSED_DESTINATION)
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        raise EgressPolicyError(REFUSED_DESTINATION) from None


def check_host(host: str, *, allow_private: bool) -> str:
    """Normalize ``host`` and apply the IP-literal and name rules (no DNS).
    Returns the normalized host; raises :class:`EgressPolicyError`."""
    if "%" in host:
        # A zone-scoped IPv6 literal (fe80::1%eth0) names an interface on
        # this host -- never a provider endpoint.
        raise EgressPolicyError(REFUSED_DESTINATION)
    if _parse_ip(host.strip("[]")) is not None:
        literal = host.strip("[]").lower()
        if address_refused(literal, allow_private=allow_private):
            raise EgressPolicyError(REFUSED_DESTINATION)
        return literal
    normalized = _normalize_host(host)
    if _host_refused(normalized, allow_private=allow_private):
        raise EgressPolicyError(REFUSED_DESTINATION)
    return normalized


def host_always_refused(host: str) -> bool:
    """True for a host that no exception may open up: a zone-scoped or
     always-blocked IP literal (loopback, link-local / cloud metadata,
     unspecified, multicast, reserved, also IPv6-wrapped), a loopback or
     metadata name (``localhost``, ``*.localhost``,
     ``metadata.google.internal``...), or a name a resolver reads as an IP
     address. Private ranges and Minder's service names are not included: this
     is the floor under an allowlist (plugin-runner's sanctioned backend hosts,
    ), not a policy on its own."""
    if not isinstance(host, str) or "%" in host:
        return True
    literal = host.strip().strip("[]")
    if _parse_ip(literal) is not None:
        return address_refused(literal, allow_private=True)
    try:
        normalized = _normalize_host(host)
    except EgressPolicyError:
        return True
    labels = normalized.split(".")
    return (
        normalized in _ALWAYS_BLOCKED_HOSTS
        or normalized.endswith(".localhost")
        or any(not label for label in labels)
        or all(_NUMERIC_LABEL.match(label) for label in labels)
    )


def validate_outbound_base_url(url: str, *, allow_private: bool) -> NormalizedURL:
    """Save-time check of an outbound base URL: http(s) only, no userinfo, a
    host, a sane port, and the host rules from the module docstring. No DNS
    lookup (that happens per request in :func:`assert_public_destination`).
    Raises :class:`EgressPolicyError` with fixed text."""
    if not isinstance(url, str):
        raise EgressPolicyError(REFUSED_DESTINATION)
    value = url.strip()
    if not value or _FORBIDDEN_CHARS.search(value) or has_userinfo(value):
        raise EgressPolicyError(REFUSED_DESTINATION)
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError:  # "http://[abc", "http://h:99999", "http://h:x"
        raise EgressPolicyError(REFUSED_DESTINATION) from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES or not parts.netloc or not hostname:
        raise EgressPolicyError(REFUSED_DESTINATION)
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    elif not 1 <= port <= 65535:
        raise EgressPolicyError(REFUSED_DESTINATION)
    host = check_host(hostname, allow_private=allow_private)
    return NormalizedURL(url=value, scheme=scheme, host=host, port=port)


async def resolve_host(host: str, port: int) -> List[str]:
    """Every address ``host`` resolves to (A and AAAA), in resolver order.
    Module-level so tests can replace it."""
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    )
    seen: List[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


async def assert_public_destination(
    host: str, *, allow_private: bool, port: int = 0
) -> List[str]:
    """Request-time check: resolve ``host`` now and refuse it unless EVERY
    address passes the policy. Returns the vetted addresses (an IP literal is
    returned as itself) so the caller can connect to one of them instead of
    resolving again. Any resolution error fails closed with the same
    :class:`EgressPolicyError` as a refused address."""
    normalized = check_host(host, allow_private=allow_private)
    if _parse_ip(normalized) is not None:
        return [normalized]
    try:
        addresses = await resolve_host(normalized, port)
    except (OSError, UnicodeError):
        raise EgressPolicyError(REFUSED_DESTINATION) from None
    if not addresses or any(
        address_refused(a, allow_private=allow_private) for a in addresses
    ):
        raise EgressPolicyError(REFUSED_DESTINATION)
    return addresses


__all__ = [
    "REFUSED_DESTINATION",
    "EgressPolicyError",
    "NormalizedURL",
    "address_is_metadata",
    "address_refused",
    "assert_public_destination",
    "check_host",
    "resolve_host",
    "validate_outbound_base_url",
]
