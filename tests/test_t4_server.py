"""t4_server: ``POST /minder/v1/invoke`` end to end, with requests signed the
way Minder signs them, and ``self.ctx`` callbacks answered by a stub Minder
that verifies the installation signature."""

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from minder_plugin_sdk import CapabilityDenied, PluginBase, PluginMetadata, cli
from minder_plugin_sdk.t4 import (
    InMemoryNonceCache,
    InstallationKey,
    StaticKeySet,
    new_nonce,
    verify_request,
)
from minder_plugin_sdk.t4_server import create_app, current_invocation

sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent / "examples" / "remote_echo")
)
from echo_plugin import RemoteEchoPlugin  # type: ignore  # noqa: E402

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "rfc9421_t4_vectors.json").read_text(
        encoding="utf-8"
    )
)
# Minder's signing key in these tests: the published RFC 9421 test key.
MINDER_KEY = InstallationKey.from_seed_b64(VECTORS["key"]["seed_b64"])
MINDER_KEYS = StaticKeySet({"keys": [MINDER_KEY.public_jwk()]})
INSTALLATION_KEY = InstallationKey.generate()
AUTHORITY = "plugin.example"
MINDER = "https://minder.example"


class Plugin(RemoteEchoPlugin):
    ACTIONS = frozenset(
        {"echo", "greeting", "slow", "boom", "denied", "weird", "whoami", "_hidden"}
    )

    async def slow(self):
        await asyncio.sleep(5)

    async def boom(self):
        raise RuntimeError("secret internal detail")

    async def denied(self):
        raise CapabilityDenied("secrets.read", "not granted")

    async def weird(self):
        return {"value": object()}

    async def whoami(self):
        inv = current_invocation()
        return {"tenant": inv.tenant_ref, "installation": inv.installation_id}

    async def _hidden(self):
        return "nope"


def envelope(**overrides):
    document = {
        "contract": "minder.t4/v1",
        "installation_id": "inst-1",
        "invocation_id": "inv-1",
        "kind": "tool",
        "target": "echo",
        "kwargs": {"text": "hello"},
        "deadline_ms": 2000,
        "grant": "grant.opaque-token-0001",
        "callback_base": MINDER,
        "tenant_ref": "t-ref",
        "owner_ref": "o-ref",
    }
    document.update(overrides)
    return json.dumps(document).encode()


def minder_headers(body, *, path="/minder/v1/invoke", method="POST", **kw):
    options = {"created": int(time.time()), "nonce": new_nonce(), **kw}
    authority = options.pop("authority", AUTHORITY)
    key = options.pop("key", MINDER_KEY)
    headers = key.sign_request(
        method=method, authority=authority, path=path, body=body, **options
    )
    headers["Content-Type"] = "application/json"
    return headers


class StubMinder:
    """Answers callbacks after verifying the installation signature."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []
        self.nonces = InMemoryNonceCache()

    async def __call__(self, request):
        body = await request.aread()
        keys = StaticKeySet({"keys": [INSTALLATION_KEY.public_jwk()]})
        verified = await verify_request(
            method=request.method,
            authority=request.url.netloc.decode(),
            path=request.url.path,
            query=request.url.query.decode(),
            headers=request.headers,
            body=body,
            resolve_key=keys.get,
            nonce_cache=self.nonces,
            require_authorization=True,
        )
        capability = request.url.path.rsplit("/", 1)[1]
        self.calls.append(
            {
                "capability": capability,
                "authorization": request.headers["authorization"],
                "body": json.loads(body),
                "keyid": verified.keyid,
            }
        )
        status, document = self.answers.get(capability, (200, {"result": None}))
        return httpx.Response(status, json=document)


def make_client(plugin=None, stub=None, **kw):
    stub = stub or StubMinder()
    http = httpx.AsyncClient(transport=httpx.MockTransport(stub))
    options = {
        "minder_url": MINDER,
        "installation_key": INSTALLATION_KEY,
        "installation_id": "inst-1",
        "key_set": MINDER_KEYS,
        "public_authority": AUTHORITY,
        "http_client": http,
    }
    options.update(kw)
    app = create_app(plugin or Plugin(), **options)
    return TestClient(app, base_url=f"https://{AUTHORITY}"), stub


@pytest.fixture
def client():
    test_client, _ = make_client()
    with test_client:
        yield test_client


def post(client, body, headers=None, path="/minder/v1/invoke"):
    return client.post(
        path,
        content=body,
        headers=headers if headers is not None else minder_headers(body),
    )


# ── the good path ────────────────────────────────────────────────────────────


def test_a_signed_tool_call_runs_the_tool(client):
    response = post(client, envelope())
    assert response.status_code == 200, response.text
    assert response.json() == {
        "ok": True,
        "invocation_id": "inv-1",
        "result": {"text": "hello"},
    }


def test_a_signed_action_call_and_the_invocation_info(client):
    body = envelope(kind="action", target="echo", kwargs={"text": "hi", "shout": True})
    assert post(client, body).json()["result"] == {"text": "HI"}
    body = envelope(kind="action", target="whoami", kwargs={}, invocation_id="inv-2")
    assert post(client, body).json()["result"] == {
        "tenant": "t-ref",
        "installation": "inst-1",
    }


def test_health_is_signed_too(client):
    headers = minder_headers(b"", path="/minder/v1/health", method="GET")
    response = client.get("/minder/v1/health", headers=headers)
    assert response.status_code == 200
    assert response.json()["result"] == {"healthy": True}
    assert client.get("/minder/v1/health").status_code == 401


def test_lifecycle_runs_register_initialize_and_shutdown():
    plugin = Plugin()
    test_client, _ = make_client(plugin)
    assert plugin.status == "registered"
    with test_client:
        assert plugin.status == "ready"
    assert plugin.status == "shutdown"


# ── signature refusals ───────────────────────────────────────────────────────


def refused(response, reason):
    assert response.status_code == 401, response.text
    error = response.json()["error"]
    assert error["code"] == "invalid_signature"
    assert error["reason"] == reason


def test_unsigned_request_is_refused(client):
    refused(client.post("/minder/v1/invoke", content=envelope()), "missing_signature")


def test_tampered_request_is_refused(client):
    body = envelope()
    headers = minder_headers(body)
    tampered = envelope(kwargs={"text": "evil"})
    refused(post(client, tampered, headers), "content_digest_mismatch")


def test_stale_request_is_refused(client):
    body = envelope()
    refused(
        post(client, body, minder_headers(body, created=int(time.time()) - 301)),
        "signature_expired",
    )


def test_replayed_request_is_refused(client):
    body = envelope()
    headers = minder_headers(body)
    assert post(client, body, headers).status_code == 200
    refused(post(client, body, headers), "nonce_replayed")


def test_unknown_kid_is_refused(client):
    body = envelope()
    refused(
        post(client, body, minder_headers(body, key=InstallationKey.generate())),
        "unknown_key",
    )


def test_request_signed_for_another_plugin_is_refused(client):
    body = envelope()
    headers = minder_headers(body, authority="other-plugin.example")
    refused(post(client, body, headers), "bad_signature")
    # Even when the attacker also sets Host to the other plugin's authority.
    headers["Host"] = "other-plugin.example"
    refused(post(client, body, headers), "bad_signature")


def test_query_is_covered(client):
    body = envelope()
    response = client.post(
        "/minder/v1/invoke?x=1", content=body, headers=minder_headers(body)
    )
    refused(response, "bad_signature")
    response = client.post(
        "/minder/v1/invoke?x=1", content=body, headers=minder_headers(body, query="x=1")
    )
    assert response.status_code == 200


def test_unknown_kid_refetches_minders_key_set():
    rotated = InstallationKey.generate()
    fetched = []

    def jwks(request):
        fetched.append(request.url.path)
        return httpx.Response(200, json={"keys": [rotated.public_jwk()]})

    from minder_plugin_sdk.t4 import MinderKeySet

    keys = MinderKeySet(
        MINDER, client=httpx.AsyncClient(transport=httpx.MockTransport(jwks))
    )
    test_client, _ = make_client(key_set=keys)
    with test_client:
        body = envelope()
        assert (
            post(test_client, body, minder_headers(body, key=rotated)).status_code
            == 200
        )
    assert fetched == ["/.well-known/minder/plugin-jwks.json"]


def test_key_set_unavailable_is_a_503():
    def down(request):
        return httpx.Response(503)

    from minder_plugin_sdk.t4 import MinderKeySet

    keys = MinderKeySet(
        MINDER, client=httpx.AsyncClient(transport=httpx.MockTransport(down))
    )
    test_client, _ = make_client(key_set=keys)
    with test_client:
        response = post(test_client, envelope())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "key_set_unavailable"


def test_path_prefix_is_part_of_the_signed_path():
    test_client, _ = make_client(path_prefix="/plugins/echo")
    with test_client:
        body = envelope()
        refused(post(test_client, body), "bad_signature")
        headers = minder_headers(body, path="/plugins/echo/minder/v1/invoke")
        assert post(test_client, body, headers).status_code == 200


@pytest.mark.parametrize(
    "missing",
    [
        {"public_authority": None},
        {"installation_id": None},
        {"public_authority": None, "installation_id": None},
        {"public_authority": "", "installation_id": ""},
    ],
)
def test_create_app_refuses_to_start_without_authority_or_installation(missing):
    with pytest.raises(ValueError) as info:
        make_client(**missing)
    assert "required" in str(info.value)


def test_cross_plugin_replay_is_refused():
    """The review's reproduction: a request Minder signed for plugin-a, sent to
    this server (plugin-b) with ``Host: plugin-a.example``. With the default
    (secure) configuration it is refused; the old Host-header fallback ran it."""
    body = envelope()
    headers = minder_headers(body, authority="plugin-a.example")
    headers["Host"] = "plugin-a.example"

    test_client, _ = make_client(public_authority="plugin-b.example")
    with test_client:
        refused(post(test_client, body, headers), "bad_signature")

    # Only the explicit development opt-in restores the Host fallback, loudly.
    test_client, _ = make_client(public_authority=None, insecure_host_authority=True)
    with test_client:
        assert post(test_client, body, headers).status_code == 200


def test_insecure_mode_logs_an_error(caplog):
    with caplog.at_level("ERROR", logger="minder_plugin_sdk.t4_server"):
        make_client(installation_id=None, insecure_host_authority=True)
    assert any("INSECURE" in r.getMessage() for r in caplog.records)


def test_public_authority_may_be_an_origin_url():
    test_client, _ = make_client(public_authority="https://Plugin.Example:443")
    with test_client:
        assert post(test_client, envelope()).status_code == 200
    with pytest.raises(ValueError):
        make_client(public_authority="https://plugin.example/path")
    with pytest.raises(ValueError):
        make_client(public_authority="plugin.example:0")


def test_wrong_installation_has_a_reason(client):
    response = post(client, envelope(installation_id="inst-2"))
    assert response.status_code == 403
    assert response.json()["error"]["reason"] == "installation_mismatch"


# ── envelope and dispatch errors ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "overrides, status, code",
    [
        ({"contract": "minder.t4/v0"}, 400, "unsupported_contract"),
        ({"kind": "collect"}, 400, "unsupported_kind"),
        ({"installation_id": "inst-2"}, 403, "wrong_installation"),
        ({"invocation_id": None}, 400, "invalid_envelope"),
        ({"kwargs": [1]}, 400, "invalid_envelope"),
        ({"deadline_ms": 0}, 400, "invalid_envelope"),
        ({"grant": "has space"}, 400, "invalid_envelope"),
        ({"callback_base": "https://elsewhere.example"}, 400, "invalid_envelope"),
        ({"callback_base": "http://minder.example"}, 400, "invalid_envelope"),
        ({"target": "nope"}, 404, "unknown_target"),
        ({"kind": "action", "target": "_hidden"}, 404, "unknown_target"),
        ({"kind": "action", "target": "register"}, 404, "unknown_target"),
        ({"kwargs": {"bogus": 1}}, 400, "invalid_arguments"),
        ({"kind": "action", "target": "boom", "kwargs": {}}, 500, "internal_error"),
        (
            {"kind": "action", "target": "weird", "kwargs": {}},
            500,
            "result_not_serializable",
        ),
        (
            {"kind": "action", "target": "denied", "kwargs": {}},
            424,
            "capability_denied",
        ),
        (
            {"kind": "action", "target": "slow", "kwargs": {}, "deadline_ms": 50},
            504,
            "deadline_exceeded",
        ),
    ],
)
def test_errors_map_to_clean_codes(client, overrides, status, code):
    response = post(client, envelope(**overrides))
    assert response.status_code == status, response.text
    document = response.json()
    assert document["ok"] is False
    assert document["error"]["code"] == code
    assert "Traceback" not in response.text
    assert "secret internal detail" not in response.text


def test_non_json_body_is_refused(client):
    body = b"not json"
    response = post(client, body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_envelope"


def test_oversized_body_is_refused():
    test_client, _ = make_client(max_body_bytes=100)
    with test_client:
        body = envelope(kwargs={"text": "x" * 200})
        response = post(test_client, body)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


# ── callbacks through self.ctx ───────────────────────────────────────────────


def test_ctx_callback_is_signed_and_carries_the_grant():
    stub = StubMinder({"secrets.read": (200, {"result": "merhaba"})})
    test_client, _ = make_client(stub=stub)
    with test_client:
        body = envelope(kind="action", target="greeting", kwargs={})
        response = post(test_client, body)
    assert response.json()["result"] == {"greeting": "merhaba", "source": "secret"}
    assert stub.calls == [
        {
            "capability": "secrets.read",
            "authorization": "Bearer grant.opaque-token-0001",
            "body": {"key": "GREETING"},
            "keyid": INSTALLATION_KEY.keyid,
        }
    ]


def test_ctx_callback_refusal_reaches_the_plugin_as_capability_denied():
    stub = StubMinder({"secrets.read": (403, {"detail": "grant expired"})})
    test_client, _ = make_client(stub=stub)
    with test_client:
        body = envelope(kind="action", target="greeting", kwargs={})
        result = post(test_client, body).json()["result"]
    assert result == {"greeting": "hello", "source": "default", "reason": "HTTP 403"}


def test_without_installation_key_ctx_is_unavailable():
    test_client, stub = make_client(installation_key=None)
    with test_client:
        body = envelope(kind="action", target="greeting", kwargs={})
        result = post(test_client, body).json()["result"]
    assert result["source"] == "default"
    assert result["reason"] == "no installation key configured"
    assert stub.calls == []


def test_without_a_grant_ctx_is_unbound(client):
    body = envelope(kind="action", target="greeting", kwargs={}, grant=None)
    result = post(client, body).json()["result"]
    assert result["source"] == "default"


# ── CLI ──────────────────────────────────────────────────────────────────────

EXAMPLE = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "remote_echo"
    / "echo_plugin.py"
)


def test_cli_serve_builds_the_app_and_runs_uvicorn(monkeypatch, capsys):
    import uvicorn

    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(app=app, **kw))
    monkeypatch.setenv("MINDER_PLUGIN_INSTALLATION_KEY", VECTORS["key"]["seed_b64"])
    code = cli.main(
        [
            "serve",
            str(EXAMPLE),
            "--minder-url",
            MINDER,
            "--public-authority",
            AUTHORITY,
            "--installation-id",
            "inst-1",
            "--port",
            "9000",
        ]
    )
    assert code == 0
    assert seen["port"] == 9000 and seen["host"] == "127.0.0.1"
    out = capsys.readouterr().out
    assert VECTORS["key"]["keyid"] in out
    assert VECTORS["key"]["seed_b64"] not in out


def test_cli_serve_refusals(monkeypatch, capsys):
    monkeypatch.delenv("MINDER_URL", raising=False)
    assert cli.main(["serve", str(EXAMPLE)]) == 2
    monkeypatch.setenv("MINDER_PLUGIN_INSTALLATION_KEY", "not-a-key")
    assert cli.main(["serve", str(EXAMPLE), "--minder-url", MINDER]) == 2
    assert "not-a-key" not in capsys.readouterr().out
    monkeypatch.delenv("MINDER_PLUGIN_INSTALLATION_KEY")
    secure = ["--public-authority", AUTHORITY, "--installation-id", "inst-1"]
    assert (
        cli.main(
            ["serve", str(EXAMPLE), "--minder-url", "http://minder.example", *secure]
        )
        == 2
    )
    # Without the public authority or the installation id it refuses to start.
    for drop in ("--public-authority", "--installation-id"):
        i = secure.index(drop)
        args = secure[:i] + secure[i + 2 :]
        capsys.readouterr()
        assert cli.main(["serve", str(EXAMPLE), "--minder-url", MINDER, *args]) == 2
        out = capsys.readouterr().out
        assert "required" in out and drop in out
        assert "--insecure-host-authority" in out
        assert "insecure_host_authority" not in out


def test_cli_serve_insecure_opt_in(monkeypatch):
    import uvicorn

    monkeypatch.delenv("MINDER_PLUGIN_INSTALLATION_KEY", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    args = ["serve", str(EXAMPLE), "--minder-url", MINDER, "--insecure-host-authority"]
    assert cli.main(args) == 0


def test_cli_serve_reads_authority_and_installation_from_the_environment(monkeypatch):
    import uvicorn

    monkeypatch.delenv("MINDER_PLUGIN_INSTALLATION_KEY", raising=False)
    monkeypatch.setenv("MINDER_PLUGIN_PUBLIC_AUTHORITY", AUTHORITY)
    monkeypatch.setenv("MINDER_PLUGIN_INSTALLATION_ID", "inst-1")
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    assert cli.main(["serve", str(EXAMPLE), "--minder-url", MINDER]) == 0


def test_example_passes_the_contract_checks():
    from minder_plugin_sdk import check_plugin
    from minder_plugin_sdk.source_rules import plugin_source_errors

    assert check_plugin(RemoteEchoPlugin()) == []
    assert plugin_source_errors(RemoteEchoPlugin()) == []


def test_plain_class_without_bind_context_is_served():
    class Plain:
        ACTIONS = frozenset({"ping"})

        async def register(self):
            return PluginMetadata(name="p", version="1", description="d", author="a")

        async def ping(self):
            return "pong"

    test_client, _ = make_client(Plain())
    with test_client:
        body = envelope(kind="action", target="ping", kwargs={})
        assert post(test_client, body).json()["result"] == "pong"


def test_concurrent_invocations_keep_their_own_context():
    seen = []

    class Recorder(PluginBase):
        ACTIONS = frozenset({"record"})

        async def register(self):
            return PluginMetadata(name="r", version="1", description="d", author="a")

        async def record(self, tag: str):
            await asyncio.sleep(0.01)
            seen.append((tag, current_invocation().grant, repr(self.ctx)))
            return tag

    plugin = Recorder()
    app = create_app(
        plugin,
        minder_url=MINDER,
        key_set=MINDER_KEYS,
        public_authority=AUTHORITY,
        installation_id="inst-1",
        installation_key=INSTALLATION_KEY,
    )

    async def main():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url=f"https://{AUTHORITY}"
        ) as http:

            async def one(i):
                body = envelope(
                    kind="action",
                    target="record",
                    kwargs={"tag": str(i)},
                    invocation_id=f"inv-{i}",
                    grant=f"grant-{i}",
                )
                response = await http.post(
                    "/minder/v1/invoke", content=body, headers=minder_headers(body)
                )
                return response.json()["result"]

            return await asyncio.gather(*(one(i) for i in range(5)))

    assert asyncio.run(main()) == [str(i) for i in range(5)]
    assert sorted((tag, grant) for tag, grant, _ in seen) == [
        (str(i), f"grant-{i}") for i in range(5)
    ]


# ── sync targets ─────────────────────────────────────────────────────────────


def test_blocking_sync_target_honours_the_deadline_and_frees_the_loop():
    """A sync action that blocks (time.sleep) must not ignore deadline_ms nor
    stall the event loop: it runs in a thread, the server answers 504 at the
    deadline, and other requests are served meanwhile."""

    class Blocking(RemoteEchoPlugin):
        ACTIONS = frozenset({"echo", "block", "add"})

        def block(self):
            time.sleep(0.6)
            return "late"

        def add(self, a: int, b: int):
            return a + b

    app = create_app(
        Blocking(),
        minder_url=MINDER,
        key_set=MINDER_KEYS,
        public_authority=AUTHORITY,
        installation_id="inst-1",
    )

    async def main():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url=f"https://{AUTHORITY}"
        ) as http:

            async def send(**overrides):
                body = envelope(kind="action", invocation_id=new_nonce(), **overrides)
                started = time.monotonic()
                response = await http.post(
                    "/minder/v1/invoke", content=body, headers=minder_headers(body)
                )
                return response, time.monotonic() - started

            slow = asyncio.ensure_future(
                send(target="block", kwargs={}, deadline_ms=100)
            )
            await asyncio.sleep(0.02)
            echo, echo_took = await send(target="echo", kwargs={"text": "hi"})
            blocked, blocked_took = await slow
            plain, _ = await send(target="add", kwargs={"a": 1, "b": 2})
            return echo, echo_took, blocked, blocked_took, plain

    echo, echo_took, blocked, blocked_took, plain = asyncio.run(main())
    assert blocked.status_code == 504
    assert blocked.json()["error"]["code"] == "deadline_exceeded"
    assert blocked_took < 0.5  # the deadline, not the 0.6 s sleep
    assert echo.status_code == 200 and echo_took < 0.3  # the loop stayed free
    assert plain.json()["result"] == 3  # sync targets still return normally
