"""t4_callbacks: the grant-callback PlatformContext. Minder is a MockTransport
that records each request; the signature is checked against the shared vector
and with the SDK's own verifier."""

import asyncio
import base64
import json
from pathlib import Path

import httpx
import pytest

from minder_plugin_sdk import (
    CapabilityDenied,
    CapabilityInvalid,
    CapabilityUnavailable,
    PlatformContext,
)
from minder_plugin_sdk.t4 import (
    InMemoryNonceCache,
    InstallationKey,
    StaticKeySet,
    verify_request,
)
from minder_plugin_sdk.t4_callbacks import CallbackPlatformContext

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "rfc9421_t4_vectors.json").read_text(
        encoding="utf-8"
    )
)
KEY = InstallationKey.from_seed_b64(VECTORS["key"]["seed_b64"])
MINDER = "https://minder.example"


def run(coro):
    return asyncio.run(coro)


class Recorder:
    def __init__(self, status=200, document=None, raw=None):
        self.status = status
        self.document = {"result": None} if document is None else document
        self.raw = raw
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if self.raw is not None:
            return httpx.Response(self.status, content=self.raw)
        return httpx.Response(self.status, json=self.document)


def context(recorder, **kw):
    options = {
        "callback_base": MINDER,
        "grant": "grant.opaque-token-0001",
        "key": KEY,
        "client": httpx.AsyncClient(transport=httpx.MockTransport(recorder)),
    }
    options.update(kw)
    return CallbackPlatformContext(**options)


def test_it_is_a_platform_context():
    assert isinstance(context(Recorder()), PlatformContext)


def test_callback_signature_matches_the_shared_vector():
    case = next(c for c in VECTORS["cases"] if c["name"] == "callback-with-grant")
    request, params, expected = case["request"], case["params"], case["expected"]
    ctx = CallbackPlatformContext(
        callback_base=request["origin"],
        grant=params["authorization"].removeprefix("Bearer "),
        key=KEY,
        sign_options={"created": params["created"], "nonce": params["nonce"]},
    )
    capability = request["target"].rsplit("/", 1)[1]
    sent_url, headers = ctx.signed_request(capability, request["body"].encode())
    assert sent_url == request["origin"] + request["target"]
    assert headers["Authorization"] == params["authorization"]
    assert headers["Content-Digest"] == expected["content_digest"]
    assert headers["Signature-Input"] == expected["signature_input"]
    assert headers["Signature"] == expected["signature"]


def test_callback_verifies_with_the_minder_authority_and_grant():
    recorder = Recorder(document={"result": "v"})
    assert run(context(recorder).secrets.get("K")) == "v"
    request = recorder.requests[0]
    assert str(request.url) == "https://minder.example/v1/plugin-callbacks/secrets.read"
    assert request.headers["authorization"] == "Bearer grant.opaque-token-0001"
    assert "@authority" in request.headers["signature-input"]
    keys = StaticKeySet({"keys": [KEY.public_jwk()]})
    run(
        verify_request(
            method="POST",
            authority="minder.example",
            path=request.url.path,
            query="",
            headers=request.headers,
            body=request.content,
            resolve_key=keys.get,
            nonce_cache=InMemoryNonceCache(),
            require_authorization=True,
        )
    )


def test_callback_base_path_and_default_port_are_handled():
    recorder = Recorder()
    run(
        context(recorder, callback_base="https://Minder.example:443/api/").secrets.get(
            "K"
        )
    )
    request = recorder.requests[0]
    assert request.url.path == "/api/v1/plugin-callbacks/secrets.read"
    assert request.url.host == "minder.example"


@pytest.mark.parametrize(
    "call, capability, body, result",
    [
        (lambda c: c.secrets.get("TOKEN"), "secrets.read", {"key": "TOKEN"}, None),
        (
            lambda c: c.plugins.invoke("weather", "forecast", city="Izmir"),
            "plugins.invoke",
            {"plugin": "weather", "action": "forecast", "kwargs": {"city": "Izmir"}},
            {"t": 21},
        ),
        (
            lambda c: c.documents.index("kb1", "a.txt", "hi", "text/plain"),
            "documents.index",
            {
                "kb_id": "kb1",
                "filename": "a.txt",
                "content_b64": base64.b64encode(b"hi").decode(),
                "content_type": "text/plain",
            },
            {"id": "d1"},
        ),
        (
            lambda c: c.timeseries.write("m,a=1 v=1 1\n\nm,a=2 v=2 2"),
            "timeseries.write",
            {"lines": ["m,a=1 v=1 1", "m,a=2 v=2 2"], "precision": "s"},
            2,
        ),
        (
            lambda c: c.timeseries.latest("m", "a", "1", fields=["v"]),
            "timeseries.latest",
            {"measurement": "m", "tag_key": "a", "tag_value": "1", "fields": ["v"]},
            {"time": "2026-01-01T00:00:00Z", "fields": {"v": 1}},
        ),
    ],
)
def test_each_capability_posts_its_body(call, capability, body, result):
    recorder = Recorder(document={"result": result})
    assert run(call(context(recorder))) == result
    request = recorder.requests[0]
    assert request.url.path == f"/v1/plugin-callbacks/{capability}"
    assert json.loads(request.content) == body


@pytest.mark.parametrize(
    "status, error",
    [
        (401, CapabilityDenied),
        (403, CapabilityDenied),
        (400, CapabilityInvalid),
        (422, CapabilityInvalid),
        (429, CapabilityUnavailable),
        (500, CapabilityUnavailable),
        (302, CapabilityUnavailable),
    ],
)
def test_status_mapping(status, error):
    with pytest.raises(error) as info:
        run(context(Recorder(status=status, document={"detail": "x"})).secrets.get("K"))
    assert info.value.capability == "secrets.read"
    assert "K" not in str(info.value).replace("secrets.read", "")


@pytest.mark.parametrize(
    "recorder",
    [
        Recorder(raw=b"not json"),
        Recorder(document={"nope": 1}),
        Recorder(document={"result": 5}),  # a secret must be a string
        Recorder(raw=b"x" * 2000),
    ],
)
def test_bad_answers_are_unavailable(recorder):
    with pytest.raises(CapabilityUnavailable):
        run(context(recorder, max_response_bytes=1000).secrets.get("K"))


def test_network_failure_is_unavailable():
    def fail(request):
        raise httpx.ConnectError("down")

    with pytest.raises(CapabilityUnavailable):
        run(context(fail).secrets.get("K"))


def test_deadline_passed_fails_fast():
    recorder = Recorder()
    ctx = context(recorder, deadline=10.0, clock=lambda: 11.0)
    with pytest.raises(CapabilityUnavailable):
        run(ctx.secrets.get("K"))
    assert recorder.requests == []


def test_no_key_is_unavailable_without_a_request():
    recorder = Recorder()
    with pytest.raises(CapabilityUnavailable):
        run(context(recorder, key=None).secrets.get("K"))
    assert recorder.requests == []


def test_telegraf_is_denied_locally():
    recorder = Recorder()
    ctx = context(recorder)
    for call in (
        ctx.telegraf.set_managed_region("x"),
        ctx.telegraf.clear_managed_region(),
        ctx.telegraf.reload(),
    ):
        with pytest.raises(CapabilityDenied):
            run(call)
    assert recorder.requests == []


def test_has():
    ctx = context(Recorder())
    assert ctx.has("secrets.read") and ctx.has("timeseries")
    assert not ctx.has("telegraf.reload") and not ctx.has("telegraf")
    ctx = context(Recorder(), granted=["secrets.read"])
    assert ctx.has("secrets.read") and not ctx.has("plugins.invoke")


def test_callback_base_must_be_https():
    with pytest.raises(ValueError):
        context(Recorder(), callback_base="http://minder.example")
    context(Recorder(), callback_base="http://127.0.0.1:8000")


def test_repr_hides_the_grant():
    assert "grant.opaque" not in repr(context(Recorder()))
