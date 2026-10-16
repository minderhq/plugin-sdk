"""t4: the RFC 9421 profile shared with Minder, keys, nonces and the key set.

``fixtures/rfc9421_t4_vectors.json`` is a copy of the Minder platform's
``tests/fixtures/rfc9421_t4_vectors.json``: the test vectors of the T4
signing profile, which both sides verify against. Keep it byte-identical to
the platform's copy except the ``description`` text; a signature mismatch here
means the SDK and Minder no longer interoperate.
"""

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

from minder_plugin_sdk import t4
from minder_plugin_sdk.t4 import (
    InMemoryNonceCache,
    InstallationKey,
    KeySetUnavailable,
    MinderKeySet,
    SignatureError,
    StaticKeySet,
)

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "rfc9421_t4_vectors.json").read_text(
        encoding="utf-8"
    )
)
KEY = VECTORS["key"]
CASES = {case["name"]: case for case in VECTORS["cases"]}
# The RFC 9421 Appendix B.1.4 test key the vectors use (a published test key).
TEST_SEED = KEY["seed_b64"]
AUTHORITY = "plugin.example"
NOW = 1_760_000_000


def run(coro):
    return asyncio.run(coro)


def sdk_key() -> InstallationKey:
    return InstallationKey.from_seed_b64(TEST_SEED)


def sdk_keys() -> StaticKeySet:
    return StaticKeySet({"keys": [KEY["public_jwk"]]})


def signed(
    *,
    method="POST",
    authority=AUTHORITY,
    path="/minder/v1/invoke",
    query="",
    body=b'{"kind":"tool"}',
    authorization=None,
    created=NOW,
    nonce="sdk-test-nonce-00001",
):
    headers = sdk_key().sign_request(
        method=method,
        authority=authority,
        path=path,
        query=query,
        body=body,
        authorization=authorization,
        created=created,
        nonce=nonce,
    )
    if authorization is not None:
        headers["Authorization"] = authorization
    return headers


def verify(
    headers,
    *,
    method="POST",
    authority=AUTHORITY,
    path="/minder/v1/invoke",
    query="",
    body=b'{"kind":"tool"}',
    now=NOW,
    cache=None,
    resolve_key=None,
    **kw,
):
    return run(
        t4.verify_request(
            method=method,
            authority=authority,
            path=path,
            query=query,
            headers=headers,
            body=body,
            resolve_key=resolve_key or sdk_keys().get,
            nonce_cache=(
                cache if cache is not None else InMemoryNonceCache(clock=lambda: now)
            ),
            now=now,
            **kw,
        )
    )


def reason(fn, *args, **kwargs):
    with pytest.raises(SignatureError) as info:
        fn(*args, **kwargs)
    return info.value.reason


# ── the profile, from the spec ───────────────────────────────────────────────


def test_signature_base_layout():
    """The exact base the profile defines (RFC 9421 section 2.5), written out
    by hand: component order, ``@authority`` normalised, ``@query`` as ``?``
    for an empty query, parameter order, no trailing newline."""
    headers = signed(
        authority="Plugin.EXAMPLE:443",
        body=b"{}",
        authorization="Bearer g",
    )
    digest = "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:"
    assert headers["Content-Digest"] == digest
    keyid = KEY["keyid"]
    params = (
        '("@method" "@authority" "@path" "@query" "content-digest" "authorization")'
        f';created={NOW};nonce="sdk-test-nonce-00001";keyid="{keyid}";alg="ed25519"'
    )
    assert headers["Signature-Input"] == f"sig1={params}"
    expected = (
        '"@method": POST\n'
        '"@authority": plugin.example\n'
        '"@path": /minder/v1/invoke\n'
        '"@query": ?\n'
        f'"content-digest": {digest}\n'
        '"authorization": Bearer g\n'
        f'"@signature-params": {params}'
    ).encode()
    base = t4.signature_base(
        method="POST",
        authority="plugin.example",
        path="/minder/v1/invoke",
        query="",
        headers={"content-digest": digest, "authorization": "Bearer g"},
        components=[
            "@method",
            "@authority",
            "@path",
            "@query",
            "content-digest",
            "authorization",
        ],
        signature_params=params,
    )
    assert base == expected
    signature = base64.b64decode(headers["Signature"][len("sig1=:") : -1])
    t4.public_key_from_jwk(KEY["public_jwk"]).verify(signature, expected)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("plugin.example", "plugin.example"),
        ("Plugin.Example:443", "plugin.example"),
        ("plugin.example:8443", "plugin.example:8443"),
        ("https://Plugin.example:443/x?y", "plugin.example"),
        ("http://localhost:80", "localhost"),
        ("http://localhost:8080", "localhost:8080"),
        ("[2001:DB8::1]:443", "[2001:db8::1]"),
    ],
)
def test_authority_normalisation(value, expected):
    assert t4.normalize_authority(value) == expected


@pytest.mark.parametrize("bad", ["", "a b", "u:p@host", "host/path", "host:99999"])
def test_authority_refusals(bad):
    with pytest.raises(ValueError):
        t4.normalize_authority(bad)


def test_query_component():
    assert t4.query_component("") == "?"
    assert t4.query_component("?") == "?"
    assert t4.query_component("a=1&b=%20") == "?a=1&b=%20"
    with pytest.raises(ValueError):
        t4.query_component("a=1 2")


def test_round_trip_and_query_coverage():
    headers = signed(query="x=1")
    verify(headers, query="x=1")
    assert reason(verify, headers, query="x=2") == "bad_signature"
    assert reason(verify, headers) == "bad_signature"  # query dropped


def test_another_authority_is_refused():
    headers = signed(authority="other-plugin.example")
    assert reason(verify, headers) == "bad_signature"
    verify(signed(authority="PLUGIN.example:443"))  # same authority, normalised


def test_profile_constants():
    assert t4.LABEL == "sig1" and t4.ALG == "ed25519"
    assert t4.DEFAULT_MAX_AGE_SECONDS == 300
    assert t4.DEFAULT_CLOCK_SKEW_SECONDS == 10
    assert t4.REQUIRED_COMPONENTS == (
        "@method",
        "@authority",
        "@path",
        "@query",
        "content-digest",
    )


def test_keyid_is_the_rfc7638_thumbprint():
    key = sdk_key()
    assert key.keyid == KEY["keyid"] == KEY["public_jwk"]["kid"]
    assert key.public_jwk() == KEY["public_jwk"]
    assert TEST_SEED not in repr(key)


# ── the shared vectors ───────────────────────────────────────────────────────


def vector_parts(case):
    """method, authority, path, query, body of a vector request."""
    request = case["request"]
    components = " ".join(VECTORS["profile"]["components"])
    if "@authority" not in components:
        pytest.fail(
            "fixtures/rfc9421_t4_vectors.json predates the @authority/@query "
            "profile: copy the platform's current vectors"
        )
    authority = request.get("authority") or case.get("params", {}).get("authority")
    query = request.get("query")
    url = request.get("url") or request.get("target_uri")
    if url:
        parts = urlsplit(url)
        authority = authority or t4.normalize_authority(url)
        query = parts.query if query is None else query
    if not authority:
        authority = request["headers"].get("Host")
    return (
        request["method"],
        authority,
        request["path"],
        query or "",
        request["body"].encode(),
    )


@pytest.mark.parametrize("name", sorted(CASES))
def test_signing_reproduces_the_vectors_byte_for_byte(name):
    case = CASES[name]
    method, authority, path, query, body = vector_parts(case)
    params, expected = case["params"], case["expected"]
    assert t4.content_digest(body) == expected["content_digest"]
    headers = sdk_key().sign_request(
        method=method,
        authority=authority,
        path=path,
        query=query,
        body=body,
        authorization=params["authorization"],
        created=params["created"],
        nonce=params["nonce"],
    )
    assert headers["Content-Digest"] == expected["content_digest"]
    assert headers["Signature-Input"] == expected["signature_input"]
    assert headers["Signature"] == expected["signature"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_vectors_verify(name):
    case = CASES[name]
    method, authority, path, query, body = vector_parts(case)
    verified = verify(
        case["request"]["headers"],
        method=method,
        authority=authority,
        path=path,
        query=query,
        body=body,
        now=case["params"]["created"],
    )
    assert verified.keyid == KEY["keyid"]
    assert verified.nonce == case["params"]["nonce"]
    # The same request against another plugin's authority fails.
    assert (
        reason(
            verify,
            case["request"]["headers"],
            method=method,
            authority="another-plugin.example",
            path=path,
            query=query,
            body=body,
            now=case["params"]["created"],
        )
        == "bad_signature"
    )


# ── refusals ─────────────────────────────────────────────────────────────────


def test_tampered_body_is_refused():
    assert reason(verify, signed(), body=b'{"kind":"action"}') == (
        "content_digest_mismatch"
    )


def test_tampered_path_and_method_are_refused():
    headers = signed()
    assert reason(verify, headers, path="/minder/v1/other") == "bad_signature"
    assert reason(verify, headers, method="PUT") == "bad_signature"


def test_digest_header_swapped_with_the_body_is_still_a_bad_signature():
    body = b"{}"
    headers = dict(signed(), **{"Content-Digest": t4.content_digest(body)})
    assert reason(verify, headers, body=body) == "bad_signature"


def test_tampered_authorization_is_refused():
    headers = signed(authorization="Bearer grant-1")
    verify(dict(headers), require_authorization=True)
    headers["Authorization"] = "Bearer grant-2"
    assert reason(verify, headers) == "bad_signature"


def test_authorization_present_but_not_covered_is_refused():
    headers = dict(signed(), Authorization="Bearer injected")
    assert reason(verify, headers) == "missing_component"
    assert reason(verify, signed(), require_authorization=True) == "missing_component"


def test_freshness_window_is_300_seconds_in_total():
    headers = signed()
    verify(headers, now=NOW + 300)  # at the edge
    assert reason(verify, headers, now=NOW + 301) == "signature_expired"
    verify(headers, now=NOW - 10)
    assert reason(verify, headers, now=NOW - 11) == "created_in_future"


def test_replayed_nonce_is_refused():
    cache = InMemoryNonceCache(clock=lambda: NOW)
    verify(signed(), cache=cache)
    assert reason(verify, signed(), cache=cache) == "nonce_replayed"


def test_nonce_is_remembered_until_created_plus_max_age_on_the_wall_clock():
    wall = [NOW + 300.0]
    cache = InMemoryNonceCache(clock=lambda: wall[0])
    verify(signed(), cache=cache, now=wall[0])
    # Still refused at the last instant the signature is fresh ...
    assert reason(verify, signed(), cache=cache, now=wall[0]) == "nonce_replayed"
    # ... and afterwards it is stale anyway.
    wall[0] += 1
    assert reason(verify, signed(), cache=cache, now=wall[0]) == "signature_expired"


def test_forged_request_does_not_burn_the_nonce():
    cache = InMemoryNonceCache(clock=lambda: NOW)
    assert reason(verify, signed(), path="/elsewhere", cache=cache) == "bad_signature"
    verify(signed(), cache=cache)


def test_unknown_key_is_refused():
    assert reason(verify, signed(), resolve_key=lambda kid: None) == "unknown_key"


def test_resolver_may_be_sync():
    public = t4.public_key_from_jwk(KEY["public_jwk"])
    verify(signed(), resolve_key=lambda kid: public)


def _replace_input(old, new):
    def mutate(headers):
        headers["Signature-Input"] = headers["Signature-Input"].replace(old, new)

    return mutate


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda h: h.pop("Signature"), "missing_signature"),
        (lambda h: h.pop("Signature-Input"), "missing_signature"),
        (
            lambda h: h.update({"Signature-Input": "sig1=(oops"}),
            "malformed_signature_input",
        ),
        (lambda h: h.update({"Signature": "sig1=:AAAA:"}), "malformed_signature"),
        (lambda h: h.update({"Signature": "sig2=:AAAA:"}), "malformed_signature"),
        (_replace_input("ed25519", "rsa-pss-sha512"), "unsupported_algorithm"),
        (_replace_input(' "content-digest"', ""), "missing_component"),
        (_replace_input('"@authority" ', ""), "missing_component"),
        (_replace_input(' "@query"', ""), "missing_component"),
        (_replace_input('"@path"', '"@target-uri"'), "unsupported_component"),
        (_replace_input(";alg=", ';tag="x";alg='), "unsupported_parameter"),
        (_replace_input(f";created={NOW}", ""), "missing_parameter"),
        (lambda h: h.pop("Content-Digest"), "content_digest_mismatch"),
    ],
)
def test_malformed_headers_are_refused(mutate, expected):
    headers = signed()
    mutate(headers)
    assert reason(verify, headers) == expected


def test_headers_are_case_insensitive_and_accept_pairs():
    verify([(k.upper(), v) for k, v in signed().items()])


def test_content_digest_matching():
    digest = t4.content_digest(b"abc")
    assert t4.content_digest_matches(digest, b"abc")
    assert t4.content_digest_matches(f"sha-512=:AAAA:, {digest}", b"abc")
    assert not t4.content_digest_matches(digest, b"abd")
    assert not t4.content_digest_matches("sha-512=:AAAA:", b"abc")
    assert not t4.content_digest_matches("garbage", b"abc")


def test_sign_request_validates_its_inputs():
    key = sdk_key()
    for kwargs in (
        {"path": "/a?b=c"},
        {"path": "/a b"},
        {"path": "/a", "nonce": "short"},
        {"path": "/a", "method": "P OST"},
        {"path": "/a", "authority": "a b"},
        {"path": "/a", "query": "a b"},
    ):
        args = {"method": "POST", "authority": AUTHORITY, **kwargs}
        with pytest.raises(ValueError):
            key.sign_request(**args)


# ── keys ─────────────────────────────────────────────────────────────────────


def test_seed_loading_never_echoes_the_value():
    for bad in ("not base64!", base64.b64encode(b"x" * 31).decode()):
        with pytest.raises(ValueError) as info:
            InstallationKey.from_seed_b64(bad)
        assert bad not in str(info.value)


def test_public_jwk_refusals():
    jwk = dict(KEY["public_jwk"])
    with pytest.raises(ValueError):
        t4.public_key_from_jwk(dict(jwk, d="secret"))
    with pytest.raises(ValueError):
        t4.public_key_from_jwk(dict(jwk, crv="X25519"))
    with pytest.raises(ValueError):
        t4.public_key_from_jwk(dict(jwk, x="short"))


def test_generated_key_round_trip():
    key = InstallationKey.generate()
    path = "/v1/plugin-callbacks/x"
    headers = key.sign_request(
        method="POST", authority="minder.example", path=path, body=b"{}"
    )
    keys = StaticKeySet({"keys": [key.public_jwk()]})
    run(
        t4.verify_request(
            method="POST",
            authority="minder.example",
            path=path,
            headers=headers,
            body=b"{}",
            resolve_key=keys.get,
            nonce_cache=InMemoryNonceCache(),
        )
    )


# ── nonce cache ──────────────────────────────────────────────────────────────


def test_nonce_cache_absolute_expiry_and_scope():
    now = [100.0]
    cache = InMemoryNonceCache(clock=lambda: now[0])
    assert run(cache.check_and_store("k", "n", 110))
    assert not run(cache.check_and_store("k", "n", 110))
    assert run(cache.check_and_store("other", "n", 110))
    now[0] = 110  # live up to and including expires_at
    assert not run(cache.check_and_store("k", "n", 110))
    now[0] = 111
    assert not run(cache.check_and_store("k", "late", 110))  # already expired
    assert run(cache.check_and_store("k", "n", 500))


def test_nonce_cache_fails_closed_when_full():
    now = [0.0]
    cache = InMemoryNonceCache(max_entries=2, clock=lambda: now[0])
    assert run(cache.check_and_store("k", "a", 10))
    assert run(cache.check_and_store("k", "b", 20))
    assert not run(cache.check_and_store("k", "c", 30))
    now[0] = 11
    assert run(cache.check_and_store("k", "c", 30))
    with pytest.raises(ValueError):
        InMemoryNonceCache(max_entries=0)


# ── Minder's key set ─────────────────────────────────────────────────────────


class JwksServer:
    def __init__(self, documents):
        self.documents = list(documents)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        document = self.documents[min(len(self.requests), len(self.documents)) - 1]
        if isinstance(document, int):
            return httpx.Response(document)
        return httpx.Response(200, json=document)


def key_set(server, now, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(server))
    return MinderKeySet(
        "https://minder.example/ignored/path", client=client, clock=lambda: now[0], **kw
    )


def test_key_set_url_and_https_rule():
    assert key_set(JwksServer([]), [0]).url == (
        "https://minder.example/.well-known/minder/plugin-jwks.json"
    )
    assert MinderKeySet("https://Minder.Example:443").url.startswith(
        "https://minder.example/"
    )
    MinderKeySet("http://127.0.0.1:8000")
    MinderKeySet("http://localhost:8000")
    for bad in (
        "http://minder.example",
        "ftp://minder.example",
        "https://u:p@m.example",
    ):
        with pytest.raises(ValueError):
            MinderKeySet(bad)


def test_key_set_caches_and_refetches_on_unknown_kid():
    other = InstallationKey.generate()
    server = JwksServer(
        [
            {"keys": [KEY["public_jwk"]]},
            {"keys": [KEY["public_jwk"], other.public_jwk()]},
        ]
    )
    now = [1000.0]
    keys = key_set(server, now)
    assert run(keys.get(KEY["keyid"])) is not None
    assert run(keys.get(KEY["keyid"])) is not None
    assert len(server.requests) == 1  # cached
    # A rotated-in key: refetched only after the minimum interval.
    assert run(keys.get(other.keyid)) is None
    assert len(server.requests) == 1
    now[0] += 31
    assert run(keys.get(other.keyid)) is not None
    assert len(server.requests) == 2
    # Random kids don't cause a fetch per request.
    for _ in range(5):
        assert run(keys.get("unknown-kid")) is None
    assert len(server.requests) == 2
    # TTL expiry refreshes.
    now[0] += 301
    run(keys.get(KEY["keyid"]))
    assert len(server.requests) == 3


def test_key_set_skips_keys_whose_kid_is_not_the_thumbprint():
    bad = dict(KEY["public_jwk"], kid="not-the-thumbprint")
    private = dict(InstallationKey.generate().public_jwk(), d="x")
    server = JwksServer([{"keys": [bad, private, "junk"]}])
    keys = key_set(server, [0.0])
    assert run(keys.get("not-the-thumbprint")) is None
    assert run(keys.get(KEY["keyid"])) is None


def test_key_set_unavailable_and_stale_use():
    now = [0.0]
    keys = key_set(JwksServer([503]), now)
    with pytest.raises(KeySetUnavailable):
        run(keys.get(KEY["keyid"]))

    server = JwksServer([{"keys": [KEY["public_jwk"]]}, 503])
    keys = key_set(server, now, max_stale=600)
    assert run(keys.get(KEY["keyid"])) is not None
    now[0] += 400  # expired; the refetch fails; the last set is still usable
    assert run(keys.get(KEY["keyid"])) is not None
    now[0] += 600
    with pytest.raises(KeySetUnavailable):
        run(keys.get(KEY["keyid"]))


def test_key_set_does_not_follow_redirects():
    def redirect(request):
        return httpx.Response(302, headers={"Location": "https://evil.example/jwks"})

    keys = key_set(redirect, [0.0])
    with pytest.raises(KeySetUnavailable):
        run(keys.get(KEY["keyid"]))


def test_key_set_unavailable_is_a_signature_error_with_its_own_reason():
    err = KeySetUnavailable()
    assert isinstance(err, SignatureError) and err.reason == "key_set_unavailable"


# ── packaging ────────────────────────────────────────────────────────────────

BLOCK_SERVE_DEPS = """
import sys

class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {"cryptography", "httpx", "starlette", "uvicorn"}:
            raise ImportError("blocked: " + name)

sys.meta_path.insert(0, Block())
import minder_plugin_sdk
from minder_plugin_sdk import cli, t4, t4_callbacks
assert t4.content_digest(b"").startswith("sha-256=:")
try:
    import minder_plugin_sdk.t4_server
except ImportError as exc:
    assert "[serve]" in str(exc), exc
else:
    raise AssertionError("t4_server imported without starlette")
assert cli.main(["serve", "x.py", "--minder-url", "https://m.example"]) == 2
print("ok")
"""


def test_base_package_imports_without_the_serve_extra():
    out = subprocess.run(
        [sys.executable, "-c", BLOCK_SERVE_DEPS],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().endswith("ok")
