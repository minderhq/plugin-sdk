"""T4 remote plugins: verify Minder's signed invocations, sign your callbacks.

A remote (T4) plugin runs on its author's or user's own infrastructure. Minder
calls it with ``POST <endpoint>/minder/v1/invoke`` and the plugin calls Minder
back with ``POST <callback_base>/v1/plugin-callbacks/<capability>``. Both
directions are signed with the same profile of **RFC 9421 HTTP Message
Signatures**:

- Ed25519 (``alg="ed25519"``), one signature labelled ``sig1``;
- covered components, in this order: ``"@method"``, ``"@authority"``,
  ``"@path"``, ``"@query"``, ``"content-digest"``, then ``"authorization"``
  whenever the request carries an ``Authorization`` header (a callback's
  grant);
- ``@authority`` is the host the signer addressed, lowercased, with the
  scheme's default port dropped (RFC 9421 section 2.2.3). A verifier compares
  it with ITS OWN public authority, never a value the request supplies, so a
  request signed for another plugin can't be replayed against yours;
- ``@query`` is ``?`` plus the raw query, so ``?`` when there is none (RFC
  9421 section 2.2.7);
- parameters ``created``, ``nonce``, ``keyid``, ``alg``, in that order;
  ``keyid`` is the key's RFC 7638 JWK thumbprint;
- ``Content-Digest: sha-256=:<base64>:`` (RFC 9530) over the exact body bytes,
  also for an empty body;
- a signature is accepted while ``now - created <= 300`` and
  ``created - now <= 10`` (clock skew, never extending the 300 s), and each
  nonce once per key until the wall-clock instant ``created + 300``.

Minder publishes the keys it signs with at
``<minder>/.well-known/minder/plugin-jwks.json``; :class:`MinderKeySet` fetches
and caches them. Your plugin signs callbacks with its **installation key**
(:class:`InstallationKey`), the Ed25519 key registered for the installation.

Most authors never call this module directly: ``minder-plugin serve`` (see
``t4_server``) verifies every invocation and gives the plugin a ``self.ctx``
that signs its callbacks. Authors writing a T4 server in another language
should read ``docs/t4/verifying-minder-signatures.md``; the shared test vectors
in ``tests/fixtures/rfc9421_t4_vectors.json`` pin the profile byte for byte.

Signing and parsing are stdlib only. Keys need ``cryptography`` and fetching
the key set needs ``httpx``; both come with ``pip install
'minder-plugin-sdk[serve]'`` and are imported only when used.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Union,
)
from urllib.parse import urlsplit

from .errors import PluginError

if TYPE_CHECKING:  # pragma: no cover
    import httpx
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

__all__ = [
    "ALG",
    "LABEL",
    "DEFAULT_MAX_AGE_SECONDS",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "INVOKE_PATH",
    "HEALTH_PATH",
    "JWKS_PATH",
    "CALLBACK_PATH_PREFIX",
    "SignatureError",
    "KeySetUnavailable",
    "VerifiedRequest",
    "Signer",
    "NonceCache",
    "InMemoryNonceCache",
    "InstallationKey",
    "MinderKeySet",
    "StaticKeySet",
    "content_digest",
    "content_digest_matches",
    "signature_base",
    "sign_request",
    "verify_request",
    "new_nonce",
    "key_id",
    "public_jwk",
    "public_key_from_jwk",
    "load_ed25519_seed",
    "origin_of",
    "normalize_authority",
    "query_component",
]

logger = logging.getLogger("minder_plugin_sdk.t4")

LABEL = "sig1"
ALG = "ed25519"
DEFAULT_MAX_AGE_SECONDS = 300
DEFAULT_CLOCK_SKEW_SECONDS = 10

#: Where Minder sends invocations, relative to the installation's origin.
INVOKE_PATH = "/minder/v1/invoke"
#: A signed, side-effect-free liveness probe.
HEALTH_PATH = "/minder/v1/health"
#: Where Minder publishes the keys it signs invocations with.
JWKS_PATH = "/.well-known/minder/plugin-jwks.json"
#: Callbacks go to ``<callback_base>/v1/plugin-callbacks/<capability>``.
CALLBACK_PATH_PREFIX = "/v1/plugin-callbacks/"

METHOD = "@method"
AUTHORITY = "@authority"
PATH = "@path"
QUERY = "@query"
CONTENT_DIGEST = "content-digest"
AUTHORIZATION = "authorization"
#: Every component this profile can cover, in signing order.
SUPPORTED_COMPONENTS = (METHOD, AUTHORITY, PATH, QUERY, CONTENT_DIGEST, AUTHORIZATION)
#: Components every signature must cover.
REQUIRED_COMPONENTS = (METHOD, AUTHORITY, PATH, QUERY, CONTENT_DIGEST)
_DEFAULT_PORTS = {"https": 443, "http": 80}
_PARAM_ORDER = ("created", "nonce", "keyid", "alg")

_KEYID = re.compile(r"^[A-Za-z0-9._:\-]{1,128}\Z")
_NONCE = re.compile(r"^[A-Za-z0-9_\-]{16,128}\Z")
_METHOD = re.compile(r"^[A-Za-z]{1,16}\Z")
# Whitespace and control characters would let a component value span lines of
# the signature base, or differ from what goes on the wire.
_UNSAFE_PATH = re.compile(r"[\x00-\x20\x7f-\x9f]")
_UNSAFE_QUERY = re.compile(r"[\x00-\x20\x7f-\x9f#]")
_UNSAFE_FIELD = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_JWK_X = re.compile(r"[A-Za-z0-9_\-]{43}")
_ED25519_SIGNATURE_LEN = 64
_SEED_LEN = 32


def _crypto_missing(exc: ImportError) -> ImportError:
    return ImportError(
        "T4 keys need cryptography: pip install 'minder-plugin-sdk[serve]'"
    )


# ── errors and results ───────────────────────────────────────────────────────


class SignatureError(PluginError):
    """A request signature was refused. ``reason`` is a stable code (e.g.
    ``signature_expired``, ``nonce_replayed``); the message never contains key
    material or header values."""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason


class KeySetUnavailable(SignatureError):
    """Minder's key set could not be fetched, so the signature can't be
    checked. Retrying later may help (a server answers 503)."""

    def __init__(self, message: str = "") -> None:
        super().__init__("key_set_unavailable", message)


@dataclass(frozen=True)
class VerifiedRequest:
    """What a verified signature established."""

    keyid: str
    created: int
    nonce: str
    components: Tuple[str, ...]


class Signer(Protocol):
    """Produces an Ed25519 signature over a signature base."""

    def sign(self, data: bytes) -> bytes: ...


# ── nonce replay ─────────────────────────────────────────────────────────────


class NonceCache(Protocol):
    """Remembers nonces for replay refusal.

    ``check_and_store`` returns True when ``nonce`` is new for ``scope`` (and
    records it until ``expires_at``), False when it was already seen or can't
    be recorded. ``expires_at`` is an absolute WALL-clock instant (unix
    seconds, ``created + max_age``), not a duration: a signature stops being
    fresh at that same instant, so a clock step can never open a window where
    a nonce is forgotten but its signature is still accepted. It must be
    atomic: two concurrent calls with the same nonce must not both return
    True. A server with several processes or replicas needs a shared store
    (e.g. Redis ``SET key 1 NX EXAT <expires_at>``); see
    :class:`InMemoryNonceCache` for the single-process default.
    """

    async def check_and_store(
        self, scope: str, nonce: str, expires_at: float
    ) -> bool: ...


class InMemoryNonceCache:
    """A per-process :class:`NonceCache` with wall-clock expiry and a size bound.

    When it is full of live nonces it refuses new ones (fail closed) rather
    than evicting one that could then be replayed. Only requests with a valid
    signature reach it, so filling it needs a valid key.
    """

    def __init__(
        self,
        max_entries: int = 100_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max = max_entries
        self._clock = clock
        self._seen: "OrderedDict[Tuple[str, str], float]" = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def _purge(self, now: float, full: bool) -> None:
        while self._seen:
            key, expiry = next(iter(self._seen.items()))
            if expiry >= now:  # live up to and including expires_at
                break
            del self._seen[key]
        if full and len(self._seen) >= self._max:
            for key in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[key]

    async def check_and_store(self, scope: str, nonce: str, expires_at: float) -> bool:
        now = self._clock()
        key = (scope, nonce)
        with self._lock:
            self._purge(now, full=len(self._seen) >= self._max)
            expiry = self._seen.get(key)
            if expiry is not None and expiry >= now:
                return False
            if len(self._seen) >= self._max:
                return False
            if float(expires_at) < now:
                return False  # already stale: never accepted
            self._seen[key] = float(expires_at)
            self._seen.move_to_end(key)
            return True


# ── RFC 9530 Content-Digest ──────────────────────────────────────────────────


def content_digest(body: bytes) -> str:
    """RFC 9530 ``Content-Digest`` (sha-256) of the exact body bytes."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def content_digest_matches(header_value: str, body: bytes) -> bool:
    """True iff ``header_value`` carries a sha-256 digest equal to ``body``'s.
    Other algorithms are ignored; sha-256 must be present. Constant time."""
    try:
        members = _parse_dictionary(header_value)
    except _ParseError:
        return False
    value = members.get("sha-256")
    if value is None or not isinstance(value[0], bytes) or value[1]:
        return False
    return hmac.compare_digest(value[0], hashlib.sha256(body).digest())


# ── RFC 8941 structured fields (the subset RFC 9421 needs) ───────────────────


class _ParseError(ValueError):
    pass


_SF_KEY = re.compile(r"[a-z*][a-z0-9_\-.*]*")
_SF_TOKEN = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")
_SF_INT = re.compile(r"-?[0-9]{1,15}")
_SF_B64 = re.compile(r"[A-Za-z0-9+/=]*")


class _Token(str):
    """An sf-token, kept distinct from an sf-string."""


BareItem = Union[str, int, bool, bytes, _Token]
Params = List[Tuple[str, BareItem]]
# A dictionary member: (value, params); value is a bare item or an inner list.
Member = Tuple[Any, Params]


class _Parser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t"):
            self.i += 1

    def match(self, pattern: "re.Pattern[str]") -> str:
        m = pattern.match(self.s, self.i)
        if not m or not m.group(0):
            raise _ParseError("expected a value")
        self.i = m.end()
        return m.group(0)

    def key(self) -> str:
        return self.match(_SF_KEY)

    def string(self) -> str:
        self.i += 1  # opening quote
        out = []
        while True:
            c = self.peek()
            if c == "":
                raise _ParseError("unterminated string")
            self.i += 1
            if c == "\\":
                nxt = self.peek()
                if nxt not in ('"', "\\"):
                    raise _ParseError("bad escape")
                out.append(nxt)
                self.i += 1
            elif c == '"':
                return "".join(out)
            elif not (" " <= c <= "~"):
                raise _ParseError("bad string character")
            else:
                out.append(c)

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == '"':
            return self.string()
        if c == ":":
            self.i += 1
            raw = self.match(_SF_B64) if self.peek() != ":" else ""
            if self.peek() != ":":
                raise _ParseError("unterminated byte sequence")
            self.i += 1
            try:
                return base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError) as e:
                raise _ParseError("bad byte sequence") from e
        if c == "?":
            self.i += 1
            b = self.peek()
            if b not in ("0", "1"):
                raise _ParseError("bad boolean")
            self.i += 1
            return b == "1"
        if c == "-" or c.isdigit():
            text = self.match(_SF_INT)
            if self.peek() == ".":
                raise _ParseError("decimals are not supported")
            return int(text)
        if c and (c.isalpha() or c == "*"):
            return _Token(self.match(_SF_TOKEN))
        raise _ParseError("expected a bare item")

    def params(self) -> Params:
        out: Params = []
        seen = set()
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            name = self.key()
            value: BareItem = True
            if self.peek() == "=":
                self.i += 1
                value = self.bare_item()
            if name in seen:
                raise _ParseError("duplicate parameter")
            seen.add(name)
            out.append((name, value))
        return out

    def inner_list(self) -> List[Tuple[BareItem, Params]]:
        self.i += 1  # "("
        items: List[Tuple[BareItem, Params]] = []
        while True:
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return items
            item = self.bare_item()
            items.append((item, self.params()))
            if self.peek() not in (" ", ")"):
                raise _ParseError("bad inner list")


def _parse_dictionary(text: str) -> Dict[str, Member]:
    """An RFC 8941 dictionary. A duplicate key is an error here (RFC 8941
    keeps the last; for signatures an ambiguous header is refused)."""
    p = _Parser(text)
    p.skip_sp()
    out: Dict[str, Member] = {}
    if p.peek() == "":
        raise _ParseError("empty dictionary")
    while True:
        name = p.key()
        if name in out:
            raise _ParseError("duplicate dictionary key")
        value: Any
        if p.peek() == "=":
            p.i += 1
            if p.peek() == "(":
                value = p.inner_list()
            else:
                value = p.bare_item()
        else:
            value = True
        out[name] = (value, p.params())
        p.skip_ows()
        if p.peek() == "":
            return out
        if p.peek() != ",":
            raise _ParseError("expected a comma")
        p.i += 1
        p.skip_ows()
        if p.peek() == "":
            raise _ParseError("trailing comma")


def _serialize_bare(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode() + ":"
    if isinstance(value, _Token):
        return str(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _serialize_params(params: Iterable[Tuple[str, BareItem]]) -> str:
    out = []
    for name, value in params:
        out.append(f";{name}" if value is True else f";{name}={_serialize_bare(value)}")
    return "".join(out)


def _signature_params_value(
    components: Iterable[str], params: Iterable[Tuple[str, BareItem]]
) -> str:
    inner = " ".join(_serialize_bare(c) for c in components)
    return f"({inner}){_serialize_params(params)}"


# ── the signature base ───────────────────────────────────────────────────────


def normalize_authority(value: str, scheme: str = "https") -> str:
    """The ``@authority`` form of a host (RFC 9421 section 2.2.3): lowercase,
    IPv6 in brackets, the scheme's default port dropped. ``value`` is
    ``host``, ``host:port`` or an absolute URL (whose own scheme then counts).
    Raises ValueError for anything else."""
    text = value.strip()
    if "://" in text:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
    else:
        parts = urlsplit("//" + text)
        if parts.path or parts.query or parts.fragment:
            raise ValueError("an authority is host[:port]")
    try:
        port = parts.port
    except ValueError as e:
        raise ValueError("invalid port") from e
    host = (parts.hostname or "").lower()
    if not host or parts.username is not None or parts.password is not None:
        raise ValueError("an authority is host[:port], without credentials")
    if _UNSAFE_PATH.search(host) or "/" in host:
        raise ValueError("invalid host")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS.get(scheme.lower()):
        netloc = f"{netloc}:{port}"
    return netloc


def query_component(query: str) -> str:
    """The ``@query`` value for a raw (still percent-encoded) query string:
    ``?`` followed by it, so ``?`` when it is empty (RFC 9421 section 2.2.7).
    A leading ``?`` in ``query`` is accepted."""
    raw = query[1:] if query.startswith("?") else query
    if _UNSAFE_QUERY.search(raw):
        raise ValueError("query must not contain whitespace, controls or #")
    return "?" + raw


def signature_base(
    *,
    method: str,
    authority: str,
    path: str,
    query: str,
    headers: Mapping[str, str],
    components: Iterable[str],
    signature_params: str,
) -> bytes:
    """RFC 9421 section 2.5 signature base: one ``"<component>": <value>`` line
    per covered component, then ``"@signature-params": <inner list>``, joined
    with ``\\n`` and no trailing newline.

    ``authority`` must already be normalised (:func:`normalize_authority`) and
    ``query`` is the raw query (``""`` when none; the line reads ``?``).
    ``headers`` maps lowercase field names to their (combined) values. Raises
    :class:`SignatureError` (``missing_component``) when a covered field is
    absent and ``invalid_component`` for a value that can't be represented on
    one line."""
    lines = []
    for component in components:
        if component == METHOD:
            value: Optional[str] = method.upper()
        elif component == AUTHORITY:
            value = authority
        elif component == PATH:
            value = path
        elif component == QUERY:
            try:
                value = query_component(query)
            except ValueError as e:
                raise SignatureError("invalid_component", "@query") from e
        else:
            raw = headers.get(component)
            value = None if raw is None else raw.strip(" \t")
        if value is None:
            raise SignatureError("missing_component", f"{component} is not present")
        if _UNSAFE_FIELD.search(value):
            raise SignatureError("invalid_component", f"{component} has controls")
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines).encode("utf-8")


def _lower_headers(headers: Any) -> Dict[str, str]:
    """Lowercase name -> value; repeated fields are combined with ", " (RFC
    9421 section 2.1). Accepts a mapping, anything with ``items()`` (e.g.
    starlette's ``Headers``, whose ``items()`` yields every field line), or an
    iterable of pairs."""
    out: Dict[str, str] = {}
    pairs = headers.items() if hasattr(headers, "items") else headers
    for name, value in pairs:
        key = str(name).lower()
        text = str(value).strip(" \t")
        out[key] = f"{out[key]}, {text}" if key in out else text
    return out


def new_nonce() -> str:
    """128 random bits, base64url (22 characters)."""
    return secrets.token_urlsafe(16)


def _check_path(path: str) -> None:
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("path must be an absolute path without query or fragment")
    if _UNSAFE_PATH.search(path):
        raise ValueError("path must not contain whitespace or controls")


# ── signing ──────────────────────────────────────────────────────────────────


def sign_request(
    signer: Signer,
    *,
    keyid: str,
    method: str,
    authority: str,
    path: str,
    query: str = "",
    body: bytes = b"",
    authorization: Optional[str] = None,
    created: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """The ``Content-Digest``, ``Signature-Input`` and ``Signature`` headers
    for a request.

    ``authority`` is the host the request goes to (``host[:port]`` or the
    URL; normalised here). ``path`` is the absolute path as sent and ``query``
    the raw query string sent with it (``""`` for none). Pass the request's
    ``Authorization`` value as ``authorization`` to cover it; the request must
    then carry exactly that header. ``created`` defaults to now, ``nonce`` to
    a fresh one."""
    if not _KEYID.match(keyid):
        raise ValueError("keyid does not fit the profile")
    if not _METHOD.match(method):
        raise ValueError("method must be an HTTP method token")
    _check_path(path)
    authority = normalize_authority(authority)
    query_component(query)
    created = int(time.time()) if created is None else int(created)
    if created < 0:
        raise ValueError("created must be a unix time")
    nonce = new_nonce() if nonce is None else nonce
    if not _NONCE.match(nonce):
        raise ValueError("nonce must be 16-128 base64url characters")
    digest = content_digest(body)
    headers = {CONTENT_DIGEST: digest}
    components: List[str] = list(REQUIRED_COMPONENTS)
    if authorization is not None:
        headers[AUTHORIZATION] = authorization
        components.append(AUTHORIZATION)
    params: Params = [
        ("created", created),
        ("nonce", nonce),
        ("keyid", keyid),
        ("alg", ALG),
    ]
    sig_params = _signature_params_value(components, params)
    base = signature_base(
        method=method,
        authority=authority,
        path=path,
        query=query,
        headers=headers,
        components=components,
        signature_params=sig_params,
    )
    signature = base64.b64encode(signer.sign(base)).decode()
    return {
        "Content-Digest": digest,
        "Signature-Input": f"{LABEL}={sig_params}",
        "Signature": f"{LABEL}=:{signature}:",
    }


# ── verification ─────────────────────────────────────────────────────────────

#: Maps a ``keyid`` to its public key, or None when unknown. May be async
#: (e.g. :meth:`MinderKeySet.get`, which can re-fetch the key set).
KeyResolver = Callable[
    [str],
    Union[Optional["Ed25519PublicKey"], Awaitable[Optional["Ed25519PublicKey"]]],
]


def _parse_signature_input(
    value: str,
) -> Tuple[List[str], Dict[str, BareItem], Params]:
    try:
        members = _parse_dictionary(value)
    except _ParseError as e:
        raise SignatureError("malformed_signature_input") from e
    if LABEL not in members:
        raise SignatureError("malformed_signature_input", f"no {LABEL} member")
    inner, params = members[LABEL]
    if not isinstance(inner, list):
        raise SignatureError("malformed_signature_input", "not an inner list")
    components: List[str] = []
    for item, item_params in inner:
        if not isinstance(item, str) or isinstance(item, _Token):
            raise SignatureError("malformed_signature_input", "component not a string")
        if item_params:
            raise SignatureError("unsupported_component", "component parameters")
        if item not in SUPPORTED_COMPONENTS:
            raise SignatureError("unsupported_component", "component not supported")
        if item in components:
            raise SignatureError("malformed_signature_input", "duplicate component")
        components.append(item)
    named = dict(params)
    if set(named) - set(_PARAM_ORDER):
        raise SignatureError("unsupported_parameter")
    return components, named, params


def _parse_signature(value: str) -> bytes:
    try:
        members = _parse_dictionary(value)
    except _ParseError as e:
        raise SignatureError("malformed_signature") from e
    member = members.get(LABEL)
    if member is None:
        raise SignatureError("malformed_signature", f"no {LABEL} member")
    sig, params = member
    if not isinstance(sig, bytes) or params or len(sig) != _ED25519_SIGNATURE_LEN:
        raise SignatureError("malformed_signature")
    return sig


def _string_param(named: Mapping[str, BareItem], name: str) -> str:
    value = named.get(name)
    if not isinstance(value, str) or isinstance(value, _Token):
        raise SignatureError("missing_parameter", name)
    return value


async def verify_request(
    *,
    method: str,
    authority: str,
    path: str,
    query: str = "",
    headers: Any,
    body: bytes,
    resolve_key: KeyResolver,
    nonce_cache: NonceCache,
    max_age: float = DEFAULT_MAX_AGE_SECONDS,
    clock_skew: float = DEFAULT_CLOCK_SKEW_SECONDS,
    require_authorization: bool = False,
    now: Optional[float] = None,
) -> VerifiedRequest:
    """Verify a signed request; raise :class:`SignatureError` on any doubt.

    ``authority`` is the verifier's OWN public authority (the host Minder was
    told to call, e.g. ``plugin.example``), never the request's ``Host``
    header, which the sender controls: a request signed for another host then
    fails as ``bad_signature``. ``path`` is the path the SIGNER addressed:
    behind a reverse proxy that rewrites paths, pass the external one.
    ``query`` is the raw query string of the request target (``""`` for
    none). ``headers`` is a mapping,
    a ``Headers`` object or an iterable of pairs. ``authorization`` must be
    covered whenever the request has an ``Authorization`` header, and always
    with ``require_authorization``.

    Freshness: ``now - created <= max_age`` and ``created - now <=
    clock_skew``; the skew never extends ``max_age``. The nonce is remembered
    until the wall-clock instant ``created + max_age``.

    Checks run in this order: the headers parse; the required components are
    covered; ``alg``; freshness; the key is known; the content digest; the
    signature; and last the nonce, so a forged request can't burn a nonce.
    """
    try:
        _check_path(path)
    except ValueError as e:
        raise SignatureError("invalid_component", "path") from e
    try:
        authority = normalize_authority(authority)
        query_component(query)
    except ValueError as e:
        raise SignatureError("invalid_component", "authority or query") from e
    if not _METHOD.match(method or ""):
        raise SignatureError("invalid_component", "method")
    fields = _lower_headers(headers)
    sig_input = fields.get("signature-input")
    sig_value = fields.get("signature")
    if not sig_input or not sig_value:
        raise SignatureError("missing_signature")
    components, named, params = _parse_signature_input(sig_input)
    signature = _parse_signature(sig_value)

    needed = list(REQUIRED_COMPONENTS)
    if require_authorization or AUTHORIZATION in fields:
        needed.append(AUTHORIZATION)
    for component in needed:
        if component not in components:
            raise SignatureError("missing_component", f"{component} is not covered")

    created = named.get("created")
    if isinstance(created, bool) or not isinstance(created, int):
        raise SignatureError("missing_parameter", "created")
    keyid = _string_param(named, "keyid")
    nonce = _string_param(named, "nonce")
    alg = _string_param(named, "alg")
    if alg != ALG:
        raise SignatureError("unsupported_algorithm")
    if not _KEYID.match(keyid):
        raise SignatureError("malformed_signature_input", "keyid")
    if not _NONCE.match(nonce):
        raise SignatureError("malformed_signature_input", "nonce")

    current = time.time() if now is None else now
    if created > current + clock_skew:
        raise SignatureError("created_in_future")
    if current - created > max_age:
        raise SignatureError("signature_expired")

    resolved = resolve_key(keyid)
    public_key = await resolved if inspect.isawaitable(resolved) else resolved
    if public_key is None:
        raise SignatureError("unknown_key")

    digest_header = fields.get(CONTENT_DIGEST)
    if digest_header is None or not content_digest_matches(digest_header, body):
        raise SignatureError("content_digest_mismatch")

    base = signature_base(
        method=method,
        authority=authority,
        path=path,
        query=query,
        headers=fields,
        components=components,
        signature_params=_signature_params_value(components, params),
    )
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(signature, base)
    except InvalidSignature as e:
        raise SignatureError("bad_signature") from e

    if not await nonce_cache.check_and_store(keyid, nonce, created + max_age):
        raise SignatureError("nonce_replayed")
    return VerifiedRequest(
        keyid=keyid, created=created, nonce=nonce, components=tuple(components)
    )


# ── keys and JWKs ────────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_public(public_key: "Ed25519PublicKey") -> bytes:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def key_id(public_key: "Ed25519PublicKey") -> str:
    """The key's ``keyid``/``kid``: its RFC 7638 JWK thumbprint (SHA-256 of
    ``{"crv":"Ed25519","kty":"OKP","x":"<base64url>"}``, base64url)."""
    members = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(_raw_public(public_key))}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def public_jwk(public_key: "Ed25519PublicKey") -> Dict[str, str]:
    """An RFC 8037 OKP public JWK, ``kid`` = RFC 7638 thumbprint."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(_raw_public(public_key)),
        "kid": key_id(public_key),
        "use": "sig",
    }


def public_key_from_jwk(jwk: Mapping[str, Any]) -> "Ed25519PublicKey":
    """The Ed25519 public key in an OKP JWK. Raises ValueError for any other
    shape, including a JWK that carries the private ``d``."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("not an OKP Ed25519 JWK")
    if "d" in jwk:
        raise ValueError("a public JWK must not carry the private key")
    x = jwk.get("x")
    if not isinstance(x, str) or not _JWK_X.fullmatch(x):
        raise ValueError("JWK x is not a base64url 32-byte key")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise _crypto_missing(exc) from exc
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x + "="))


def load_ed25519_seed(value: str) -> "Ed25519PrivateKey":
    """A private key from base64 (standard alphabet) of its 32-byte Ed25519
    seed. Raises ValueError, never echoing the value."""
    try:
        seed = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("not base64 of a 32-byte Ed25519 seed") from e
    if len(seed) != _SEED_LEN:
        raise ValueError("not base64 of a 32-byte Ed25519 seed")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise _crypto_missing(exc) from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


class InstallationKey:
    """The installation's Ed25519 key, which signs callbacks to Minder.

    Load it from the base64 of its 32-byte seed (keep that in a secret store
    or an environment variable, never in code or on a command line)::

        key = InstallationKey.from_seed_b64(os.environ["MINDER_PLUGIN_INSTALLATION_KEY"])
        key.keyid          # the RFC 7638 thumbprint Minder knows it by
        key.public_jwk()   # what gets registered for the installation

    ``repr()`` never shows key material.
    """

    def __init__(self, private_key: "Ed25519PrivateKey") -> None:
        self._key = private_key
        self.keyid = key_id(private_key.public_key())

    @classmethod
    def from_seed_b64(cls, value: str) -> "InstallationKey":
        return cls(load_ed25519_seed(value))

    @classmethod
    def generate(cls) -> "InstallationKey":
        """A fresh random key (e.g. for tests or first-time setup)."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise _crypto_missing(exc) from exc
        return cls(Ed25519PrivateKey.generate())

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def public_jwk(self) -> Dict[str, str]:
        return public_jwk(self._key.public_key())

    def sign_request(
        self,
        *,
        method: str,
        authority: str,
        path: str,
        query: str = "",
        body: bytes = b"",
        authorization: Optional[str] = None,
        created: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """:func:`sign_request` with this key and its ``keyid``."""
        return sign_request(
            self,
            keyid=self.keyid,
            method=method,
            authority=authority,
            path=path,
            query=query,
            body=body,
            authorization=authorization,
            created=created,
            nonce=nonce,
        )

    def __repr__(self) -> str:
        return f"InstallationKey(keyid={self.keyid!r})"


# ── Minder's key set ─────────────────────────────────────────────────────────


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` of an absolute URL, lowercased and without the
    scheme's default port (the ``@authority`` form). Only ``https``
    is accepted, plus ``http`` to a loopback host for local development.
    Raises ValueError otherwise."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not host or parts.username or parts.password:
        raise ValueError("expected an absolute http(s) URL without credentials")
    if scheme != "https" and not (scheme == "http" and _is_loopback(host)):
        raise ValueError("Minder URLs must be https (http only to loopback)")
    return f"{scheme}://{normalize_authority(url)}"


def _parse_jwks(document: Any) -> Dict[str, "Ed25519PublicKey"]:
    """kid -> key for every usable key; a key whose ``kid`` isn't its
    thumbprint, or that isn't a public OKP/Ed25519 key, is skipped."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a JWKS")
    keys: Dict[str, "Ed25519PublicKey"] = {}
    for jwk in document["keys"]:
        if not isinstance(jwk, dict):
            continue
        try:
            public_key = public_key_from_jwk(jwk)
        except ValueError:
            logger.warning("skipping a JWK that is not a public Ed25519 key")
            continue
        kid = key_id(public_key)
        if jwk.get("kid") != kid:
            logger.warning("skipping a JWK whose kid is not its thumbprint")
            continue
        keys[kid] = public_key
    return keys


class StaticKeySet:
    """A fixed key set (a JWKS document), e.g. for tests or a pinned key."""

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self._keys = _parse_jwks(dict(jwks))

    async def get(self, kid: str) -> Optional["Ed25519PublicKey"]:
        return self._keys.get(kid)


class MinderKeySet:
    """Minder's signing keys, fetched from ``<minder>/.well-known/minder/
    plugin-jwks.json`` and cached.

    - The set is cached for ``ttl`` seconds (300, the endpoint's own max-age).
    - An unknown ``kid`` triggers a re-fetch (Minder rotated its key), at most
      once per ``min_refetch_interval`` seconds, so requests naming random
      kids can't turn into a flood of fetches.
    - When a re-fetch fails, the last good set stays usable for ``max_stale``
      seconds; with no usable set, :meth:`get` raises
      :class:`KeySetUnavailable`.
    - Only public OKP/Ed25519 keys whose ``kid`` is their RFC 7638 thumbprint
      are used. Redirects are not followed.
    """

    def __init__(
        self,
        minder_url: str,
        *,
        ttl: float = 300.0,
        min_refetch_interval: float = 30.0,
        max_stale: float = 3600.0,
        timeout: float = 5.0,
        client: Optional["httpx.AsyncClient"] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = origin_of(minder_url) + JWKS_PATH
        self._ttl = ttl
        self._min_refetch = min_refetch_interval
        self._max_stale = max_stale
        self._timeout = timeout
        self._client = client
        self._clock = clock
        self._keys: Dict[str, "Ed25519PublicKey"] = {}
        self._fetched_at: Optional[float] = None  # last successful fetch
        self._attempted_at: Optional[float] = None  # last attempt
        self._lock = asyncio.Lock()

    async def _fetch(self) -> Dict[str, "Ed25519PublicKey"]:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise ImportError(
                "fetching Minder's keys needs httpx: "
                "pip install 'minder-plugin-sdk[serve]'"
            ) from exc
        client = self._client or httpx.AsyncClient(trust_env=False)
        try:
            response = await client.get(
                self.url, timeout=self._timeout, follow_redirects=False
            )
        finally:
            if self._client is None:
                await client.aclose()
        if response.status_code != 200:
            raise ValueError(f"key set answered HTTP {response.status_code}")
        return _parse_jwks(response.json())

    async def _refresh(self) -> None:
        self._attempted_at = self._clock()
        try:
            keys = await self._fetch()
        except Exception as e:  # noqa: BLE001 - any failure leaves the old set
            logger.warning("could not fetch Minder's key set: %s", type(e).__name__)
            return
        self._keys = keys
        self._fetched_at = self._clock()

    def _age(self) -> Optional[float]:
        return None if self._fetched_at is None else self._clock() - self._fetched_at

    def _may_retry(self) -> bool:
        return (
            self._attempted_at is None
            or self._clock() - self._attempted_at >= self._min_refetch
        )

    async def get(self, kid: str) -> Optional["Ed25519PublicKey"]:
        """The public key for ``kid``, or None when Minder doesn't publish it."""
        async with self._lock:
            age = self._age()
            expired = age is None or age > self._ttl
            if (expired or kid not in self._keys) and self._may_retry():
                await self._refresh()
            age = self._age()
            if age is None or age > self._ttl + self._max_stale:
                raise KeySetUnavailable("Minder's key set is unavailable")
            return self._keys.get(kid)
