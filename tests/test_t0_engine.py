"""The T0 declarative connector engine.

No test touches the network: upstream APIs are httpx mock transports routed by
the Host header (the engine connects to the pinned address, so the URL host is
an IP), and DNS is an injected resolver.
"""

import asyncio
import base64
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import httpx
import pytest

from minder_t0_engine import (
    DenialCounter,
    EgressDenied,
    Engine,
    Invocation,
    LimitExceeded,
    ManifestError,
    MappingError,
    ParamsError,
    SecretUnavailable,
    UpstreamError,
    load_manifest,
)
from minder_t0_engine import mapping as dmapping
from minder_t0_engine.egress import PluginEgress, RateLimiter
from minder_t0_engine.engine import NoSecrets, scrub

PUBLIC_IP = "93.184.216.34"
SECRET = "s3cr3t+/=key"
FIXED_NOW = datetime(2026, 10, 16, 9, 30, 15, 123456, tzinfo=timezone.utc)
FIXED_ISO = "2026-10-16T09:30:15.123456+00:00"


# ── helpers ──────────────────────────────────────────────────────────────


def manifest(spec: Optional[Dict[str, Any]] = None, name: str = "demo") -> Dict:
    """A minimal valid manifest; ``spec`` keys replace the defaults."""
    base_spec: Dict[str, Any] = {
        "runtime": {"kind": "declarative", "engine": 1},
        "display": {"label": "Demo", "category": "ai-tool"},
        "config_schema": [
            {"key": "LANG", "type": "string", "default": "en"},
            {"key": "API_TOKEN", "type": "string", "secret": True},
        ],
        "egress": [{"host": "api.example.com"}, {"host": "*.example.org"}],
        "bases": {"api": {"url": "https://api.example.com/v1"}},
        "tools": {
            "lookup": {
                "description": "Look something up.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "q": {"type": "string", "minLength": 1},
                        "limit": {"type": "integer", "default": 5},
                    },
                    "required": ["q"],
                },
                "steps": [
                    {
                        "name": "search",
                        "request": {
                            "base": "api",
                            "path": "/search",
                            "query": {"q": "{params.q}", "n": "{params.limit}"},
                        },
                    }
                ],
            }
        },
    }
    base_spec.update(spec or {})
    return {
        "apiVersion": "minder.dev/v1alpha1",
        "kind": "Plugin",
        "metadata": {"name": name, "version": "1.0.0", "stable_id": "plg_demo"},
        "spec": base_spec,
    }


def tool(steps: List[Dict], **extra: Any) -> Dict[str, Any]:
    op: Dict[str, Any] = {
        "description": "t",
        "parameters": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
        },
        "steps": steps,
    }
    op.update(extra)
    return op


class Upstream:
    """A mock upstream: ``routes[(host, path)]`` -> handler(request) or a
    static response. Records every request it receives."""

    def __init__(self) -> None:
        self.routes: Dict[tuple, Any] = {}
        self.requests: List[httpx.Request] = []

    def route(self, host: str, path: str, response: Any) -> None:
        self.routes[(host, path)] = response

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        # Routed on the raw (still percent-encoded) path.
        path = request.url.raw_path.split(b"?", 1)[0].decode("ascii")
        key = (request.headers["host"], path)
        handler = self.routes.get(key)
        if handler is None:
            return httpx.Response(404, json={"error": "no route"})
        if callable(handler):
            result = handler(request)
            if asyncio.iscoroutine(result):
                result = await result
            return result
        return handler

    def hosts(self) -> List[str]:
        return [r.headers["host"] for r in self.requests]


def resolver(mapping: Optional[Dict[str, Any]] = None, calls: Optional[list] = None):
    mapping = mapping or {}

    async def resolve(host: str, port: int) -> List[str]:
        if calls is not None:
            calls.append(host)
        value = mapping.get(host, PUBLIC_IP)
        if isinstance(value, Exception):
            raise value
        return [value] if isinstance(value, str) else list(value)

    return resolve


class Secrets:
    def __init__(self, values: Optional[Dict[str, str]] = None) -> None:
        self.values = values or {}
        self.reads: List[str] = []

    async def get(self, key: str) -> Optional[str]:
        self.reads.append(key)
        return self.values.get(key)


def engine(
    data: Dict,
    upstream: Upstream,
    dns: Optional[Callable] = None,
    denials: Optional[DenialCounter] = None,
    **kwargs: Any,
) -> Engine:
    return Engine(
        load_manifest(data),
        resolver=dns or resolver(),
        transport=httpx.MockTransport(upstream),
        denials=denials if denials is not None else DenialCounter(),
        **kwargs,
    )


def inv(config: Optional[Dict] = None, secrets: Optional[Dict] = None) -> Invocation:
    return Invocation(config=config or {}, secrets=Secrets(secrets))


# ── manifest validation ──────────────────────────────────────────────────


def test_valid_manifest_compiles_with_defaults():
    m = load_manifest(manifest())
    assert m.name == "demo" and m.stable_id == "plg_demo"
    assert set(m.tools) == {"lookup"} and m.tools["lookup"].read_only
    assert m.config_defaults == {"LANG": "en"}
    assert m.secret_config_keys == frozenset({"API_TOKEN"})
    assert m.limits.timeout_s == 10.0 and m.limits.max_concurrency == 4


@pytest.mark.parametrize(
    "host",
    [
        "postgres",  # a Docker service name (single label)
        "plugin-registry",
        "minder-api-gateway",  # a Minder container name
        "api-gateway",
        "localhost",
        "app.localhost",
        "metadata.google.internal",
        "vault.internal",
        "nas.local",
        "box.lan",
        "peer.ts.net",
        "10.0.0.1",
        "169.254.169.254",
        "127.0.0.1",
        "*.com",  # a wildcard over a whole TLD
        "api.*.example.com",
        "exa mple.com",
    ],
)
def test_internal_or_malformed_egress_hosts_are_refused(host):
    data = manifest({"egress": [{"host": host}]})
    with pytest.raises(ManifestError):
        load_manifest(data)


def test_base_must_be_on_a_declared_host_and_https():
    with pytest.raises(ManifestError, match="not in the declared egress"):
        load_manifest(manifest({"bases": {"api": {"url": "https://evil.example.net"}}}))
    with pytest.raises(ManifestError, match="plain http"):
        load_manifest(manifest({"bases": {"api": {"url": "http://api.example.com"}}}))
    ok = manifest(
        {
            "egress": [{"host": "api.example.com", "http": True}],
            "bases": {"api": {"url": "http://api.example.com"}},
        }
    )
    assert load_manifest(ok).bases["api"].scheme == "http"
    for bad in (
        "https://user:pw@api.example.com",
        "https://api.example.com/x?y=1",
        "ftp://api.example.com",
        "https://api.example.com/{params.q}",
    ):
        with pytest.raises(ManifestError):
            load_manifest(manifest({"bases": {"api": {"url": bad}}}))


def test_host_placeholders_are_whole_leading_labels_from_config():
    good = manifest({"bases": {"api": {"url": "https://{config.LANG}.example.org"}}})
    assert load_manifest(good)
    for url in (
        "https://{params.q}.example.org",  # only config feeds a host
        "https://x{config.LANG}.example.org",  # not a whole label
        "https://api.{config.LANG}.example.org",  # not leading
        "https://{config.LANG}.example.net",  # no matching suffix rule
        "https://{config.API_TOKEN}.example.org",  # a secret field
    ):
        with pytest.raises(ManifestError):
            load_manifest(manifest({"bases": {"api": {"url": url}}}))


@pytest.mark.parametrize(
    "template",
    [
        "{params.q | upper}",  # no expressions
        "{env.HOME}",  # unknown root
        "{secrets.API_TOKEN}",  # secrets are not a root
        "{config.API_TOKEN}",  # a secret config field
        "{config.NOPE}",  # undeclared
        "{params.nope}",  # undeclared
        "{steps.later.x}",  # not an earlier step
        "{item}",  # no foreach here
        "{params.q",  # unbalanced
    ],
)
def test_placeholders_are_dotted_references_only(template):
    data = manifest(
        {
            "tools": {
                "lookup": tool(
                    [
                        {
                            "name": "s",
                            "request": {
                                "base": "api",
                                "path": "/x",
                                "query": {"v": template},
                            },
                        }
                    ]
                )
            }
        }
    )
    with pytest.raises(ManifestError):
        load_manifest(data)


@pytest.mark.parametrize(
    "header", ["Authorization", "cookie", "Host", "X-Forwarded-For", "Bad Header"]
)
def test_reserved_headers_are_refused(header):
    step = {"name": "s", "request": {"base": "api", "headers": {header: "x"}}}
    with pytest.raises(ManifestError):
        load_manifest(manifest({"tools": {"lookup": tool([step])}}))


def test_auth_header_and_param_cannot_be_overridden():
    bases = {
        "api": {
            "url": "https://api.example.com",
            "auth": {"type": "api_key", "in": "query", "name": "key", "secret": "K"},
        }
    }
    step = {"name": "s", "request": {"base": "api", "query": {"key": "x"}}}
    with pytest.raises(ManifestError, match="auth parameter"):
        load_manifest(manifest({"bases": bases, "tools": {"lookup": tool([step])}}))
    bases["api"]["auth"] = {
        "type": "api_key",
        "in": "header",
        "name": "X-Key",
        "secret": "K",
    }
    step = {"name": "s", "request": {"base": "api", "headers": {"x-key": "x"}}}
    with pytest.raises(ManifestError, match="reserved"):
        load_manifest(manifest({"bases": bases, "tools": {"lookup": tool([step])}}))


@pytest.mark.parametrize(
    "auth",
    [
        {"type": "api_key", "secret": "K"},  # no name
        {"type": "bearer"},  # no secret
        {"type": "basic", "secret": "K"},
        {"type": "basic", "username_secret": "U"},
        {"type": "none", "secret": "K"},
        {"type": "bearer", "secret": "K", "in": "query"},
        {"type": "oauth2", "secret": "K"},
        {"type": "api_key", "secret": "bad key", "name": "k"},
    ],
)
def test_auth_shapes_are_validated(auth):
    bases = {"api": {"url": "https://api.example.com", "auth": auth}}
    with pytest.raises(ManifestError):
        load_manifest(manifest({"bases": bases}))


def test_bounds_are_enforced_at_load():
    step = {"name": "s", "request": {"base": "api"}}
    four = [dict(step, name=f"s{i}") for i in range(4)]
    with pytest.raises(ManifestError):
        load_manifest(manifest({"tools": {"lookup": tool(four)}}))
    big_fanout = [dict(step, foreach="params.q", max_items=21)]
    with pytest.raises(ManifestError):
        load_manifest(manifest({"tools": {"lookup": tool(big_fanout)}}))
    pages = [
        {
            "name": "s",
            "request": {
                "base": "api",
                "paginate": {"type": "link", "max_pages": 11},
            },
        }
    ]
    with pytest.raises(ManifestError):
        load_manifest(manifest({"tools": {"lookup": tool(pages)}}))
    with pytest.raises(ManifestError):
        load_manifest(manifest({"limits": {"max_response_bytes": 50 * 1024 * 1024}}))
    with pytest.raises(ManifestError):
        load_manifest(manifest({"limits": {"timeout_s": 120}}))


def test_operations_are_validated():
    step = {"name": "s", "request": {"base": "api"}}
    for spec in (
        {"tools": {"register": tool([step])}},  # shadows a lifecycle method
        {"tools": {"Bad-Name": tool([step])}},
        {"tools": {"a": tool([step])}, "actions": {"a": tool([step])}},
        {"tools": {"a": tool([step], parameters={"type": "string"})}},
        {
            "tools": {
                "a": tool(
                    [step],
                    parameters={
                        "type": "object",
                        "properties": {"x": {"$ref": "https://evil/x.json"}},
                    },
                )
            }
        },
        {
            "tools": {
                "a": tool([step], parameters={"type": "object", "minProperties": -1})
            }
        },
        {"tools": {"a": tool([step], output="steps.s[")}},  # bad JMESPath
        {"tools": {}, "actions": {}},  # nothing to expose
        {"tools": {"a": tool([dict(step, base="nope")])}},
        {"tools": {"a": tool([{"name": "s", "request": {"base": "nope"}}])}},
        {"tools": {"a": tool([dict(step, extra=1)])}},  # unknown field
    ):
        with pytest.raises(ManifestError):
            load_manifest(manifest(spec))


def test_schedule_measurement_must_be_declared():
    schedule = {
        "steps": [{"name": "s", "request": {"base": "api"}}],
        "measurement": "fx_rate",
        "points": "[]",
    }
    with pytest.raises(ManifestError, match="timeseries"):
        load_manifest(manifest({"schedule": schedule}))
    ok = load_manifest(
        manifest({"schedule": schedule, "timeseries": {"measurements": ["fx_rate"]}})
    )
    assert ok.schedule is not None and ok.schedule.measurement == "fx_rate"


# ── webhook trigger ──────────────────────────────────────────────


def _hook_action(**extra: Any) -> Dict[str, Any]:
    step = {
        "name": "push",
        "request": {
            "method": "POST",
            "base": "api",
            "path": "/events",
            "body": {"json": {"id": "{params.body.id}"}},
        },
    }
    params = {
        "type": "object",
        "properties": {
            "body": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            }
        },
        "required": ["body"],
    }
    op = {"description": "Ingest a webhook.", "parameters": params, "steps": [step]}
    return {**op, **extra}


def test_webhook_trigger_compiles():
    m = load_manifest(
        manifest(
            {
                "actions": {"ingest": _hook_action()},
                "webhook": {"action": "ingest", "secret": "HOOK_SECRET"},
            }
        )
    )
    assert m.webhook is not None
    assert (m.webhook.action, m.webhook.secret) == ("ingest", "HOOK_SECRET")
    assert load_manifest(manifest()).webhook is None


@pytest.mark.parametrize(
    "webhook, actions, match",
    [
        ({"action": "ingest"}, None, "secret"),  # no secret: never unsigned
        ({"action": "ingest", "secret": ""}, None, "secret name"),
        ({"action": "ingest", "secret": "bad name"}, None, "secret name"),
        ({"action": "lookup", "secret": "S"}, None, "declared action"),  # a tool
        ({"action": "nope", "secret": "S"}, None, "declared action"),
        (
            {"action": "ingest", "secret": "S"},
            {"ingest": _hook_action(admin_only=True)},
            "admin_only",
        ),
        (
            {"action": "ingest", "secret": "S"},
            {
                "ingest": _hook_action(
                    parameters={"type": "object"},
                    steps=[{"name": "s", "request": {"base": "api", "path": "/e"}}],
                )
            },
            "'body' parameter",
        ),
        ({"action": "ingest", "secret": "S", "path": "/x"}, None, "invalid"),
    ],
)
def test_webhook_trigger_is_validated_at_load(webhook, actions, match):
    spec = {"actions": actions or {"ingest": _hook_action()}, "webhook": webhook}
    with pytest.raises(ManifestError, match=match):
        load_manifest(manifest(spec))


async def test_webhook_action_maps_the_request_body():
    up = Upstream()
    up.route("api.example.com", "/v1/events", httpx.Response(200, json={"ok": 1}))
    data = manifest(
        {
            "actions": {"ingest": _hook_action()},
            "webhook": {"action": "ingest", "secret": "HOOK_SECRET"},
        }
    )
    # plugin-registry calls the action with the verified body as params.body.
    result = await engine(data, up).run_operation(
        "ingest", {"body": {"id": "evt_1"}}, inv()
    )
    assert result == {"ok": 1}
    (req,) = up.requests
    assert json.loads(req.content) == {"id": "evt_1"}


# ── requests, placeholders and pinning ───────────────────────────────────


async def test_request_is_pinned_to_the_resolved_address():
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(200, json={"hits": [1]}))
    calls: List[str] = []
    eng = engine(manifest(), up, dns=resolver(calls=calls))
    result = await eng.run_operation("lookup", {"q": "a&b=c"}, inv())
    assert result == {"hits": [1]}
    (req,) = up.requests
    assert req.url.host == PUBLIC_IP  # connected to the checked address
    assert req.headers["host"] == "api.example.com"  # Host stays the name
    assert req.extensions["sni_hostname"] == "api.example.com"  # and TLS SNI
    assert req.url.scheme == "https"
    assert dict(req.url.params) == {"q": "a&b=c", "n": "5"}  # default filled
    assert calls == ["api.example.com"]  # resolved once


async def test_values_are_encoded_per_url_component():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/page/..%2Fadmin%3Fx%3D1%23f",
        httpx.Response(200, json={"ok": 1}),
    )
    up.route("api.example.com", "/v1/page/%2E%2E", httpx.Response(200, json={"ok": 2}))
    steps = [
        {
            "name": "s",
            "request": {
                "base": "api",
                "path": "/page/{params.q}",
                "headers": {"X-Q": "{params.q}"},
            },
        }
    ]
    eng = engine(manifest({"tools": {"lookup": tool(steps)}}), up)
    assert await eng.run_operation("lookup", {"q": "../admin?x=1#f"}, inv()) == {
        "ok": 1
    }
    assert await eng.run_operation("lookup", {"q": ".."}, inv()) == {"ok": 2}
    with pytest.raises(MappingError, match="control characters"):
        await eng.run_operation("lookup", {"q": "x\r\nX-Evil: 1"}, inv())


async def test_host_label_from_config_is_validated_and_rechecked():
    up = Upstream()
    up.route("de.example.org", "/x", httpx.Response(200, json={"lang": "de"}))
    steps = [{"name": "s", "request": {"base": "wiki", "path": "/x"}}]
    data = manifest(
        {
            "bases": {"wiki": {"url": "https://{config.LANG}.example.org"}},
            "tools": {"lookup": tool(steps)},
        }
    )
    eng = engine(data, up)
    assert await eng.run_operation("lookup", {}, inv({"LANG": "DE"})) == {"lang": "de"}
    for evil in ("evil.com#", "a.b", "x/y", "", "-x"):
        with pytest.raises(MappingError):
            await eng.run_operation("lookup", {}, inv({"LANG": evil}))
    assert up.hosts() == ["de.example.org"]


def test_host_placeholder_fallback_is_a_validated_label():
    for url in (
        "https://{config.LANG|en}.example.org",
        "https://{ config.LANG | zh-yue }.example.org",
    ):
        assert load_manifest(manifest({"bases": {"api": {"url": url}}}))
    for url in (
        "https://{config.LANG|EN}.example.org",  # lower-case labels only
        "https://{config.LANG|}.example.org",  # empty
        "https://{config.LANG|evil.com}.example.org",  # a dot = another label
        "https://{config.LANG|-x}.example.org",
        "https://{config.LANG|a_b}.example.org",
        "https://{config.LANG|a|b}.example.org",
        "https://{config.LANG|x@evil}.example.org",
        "https://{config.LANG|x:1}.example.org",
        "https://{params.q|en}.example.org",  # still config only
        "https://{config.API_TOKEN|en}.example.org",  # still not a secret
        "https://{config.NOPE|en}.example.org",  # still declared keys only
        "https://{config.LANG|en}.example.net",  # still a declared suffix
    ):
        with pytest.raises(ManifestError):
            load_manifest(manifest({"bases": {"api": {"url": url}}}))
    # Outside a host a fallback is not a dotted reference.
    steps = [
        {"name": "s", "request": {"base": "api", "path": "/{params.q|x}"}},
    ]
    with pytest.raises(ManifestError):
        load_manifest(manifest({"tools": {"lookup": tool(steps)}}))


async def test_host_placeholder_fallback_replaces_invalid_config_values():
    up = Upstream()
    for host in ("de.example.org", "en.example.org", "fb.example.org"):
        up.route(host, "/x", httpx.Response(200, json={"host": host}))
    steps = [{"name": "s", "request": {"base": "wiki", "path": "/x"}}]
    data = manifest(
        {
            "config_schema": [
                {"key": "LANG", "type": "string", "default": "en"},
                {"key": "NODEF", "type": "string"},
                {"key": "API_TOKEN", "type": "string", "secret": True},
            ],
            "bases": {"wiki": {"url": "https://{config.LANG|fb}.example.org"}},
            "tools": {"lookup": tool(steps)},
        }
    )
    eng = engine(data, up)

    async def host(config: Dict[str, Any]) -> str:
        return (await eng.run_operation("lookup", {}, inv(config)))["host"]

    assert await host({"LANG": " DE "}) == "de.example.org"
    assert await host({}) == "en.example.org"  # the schema default
    for evil in (
        "en_US",
        "",
        "   ",
        None,
        True,
        ["de"],
        {"x": "de"},
        "evil.com",
        "evil.com#",
        "de.evil.com",
        "evil.com:443",
        "x:1",
        "user@evil.com",
        "user:pw@evil.com",
        "a/b",
        "-x",
        "x" * 64,
        "\u0435n",  # Cyrillic 'e'
        "de\r\nHost: evil.com",
    ):
        assert await host({"LANG": evil}) == "fb.example.org", evil
    # A missing key with no schema default also falls back.
    data["spec"]["bases"]["wiki"]["url"] = "https://{config.NODEF|fb}.example.org"
    result = await engine(data, up).run_operation("lookup", {}, inv())
    assert result["host"] == "fb.example.org"
    assert set(up.hosts()) == {"de.example.org", "en.example.org", "fb.example.org"}


async def test_host_placeholder_fallback_is_still_egress_checked():
    up = Upstream()
    up.route("fb.example.org", "/x", httpx.Response(200, json={}))
    steps = [{"name": "s", "request": {"base": "wiki", "path": "/x"}}]
    data = manifest(
        {
            "bases": {"wiki": {"url": "https://{config.LANG|fb}.example.org"}},
            "tools": {"lookup": tool(steps)},
        }
    )
    eng = engine(data, up, dns=resolver({"fb.example.org": "10.0.0.5"}))
    with pytest.raises(EgressDenied):
        await eng.run_operation("lookup", {}, inv({"LANG": "en_US"}))
    assert up.requests == []


async def test_optional_placeholders_drop_query_params_and_json_keys():
    up = Upstream()
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={})

    up.route("api.example.com", "/v1/items", handler)
    steps = [
        {
            "name": "s",
            "request": {
                "base": "api",
                "method": "POST",
                "path": "/items",
                "query": {"to": "{params.to}", "fixed": 3},
                "body": {
                    "json": {
                        "q": "{params.q}",
                        "n": "{params.n}",
                        "tag": "x-{params.q}",
                        "list": ["{params.to}", "a"],
                    }
                },
            },
        }
    ]
    op = tool(steps)
    op["parameters"]["properties"].update(
        {"to": {"type": "string"}, "n": {"type": "integer"}}
    )
    eng = engine(manifest({"tools": {"lookup": op}}), up)
    await eng.run_operation("lookup", {"q": "hi", "n": 3}, inv())
    assert seen["params"] == {"fixed": "3"}
    assert seen["body"] == {"q": "hi", "n": 3, "tag": "x-hi", "list": ["a"]}


async def test_params_are_validated_against_their_json_schema():
    eng = engine(manifest(), Upstream())
    with pytest.raises(ParamsError) as e:
        await eng.run_operation("lookup", {"limit": "five-secret-value"}, inv())
    assert isinstance(e.value, ValueError)  # the host maps it to invalid_argument
    assert "five-secret-value" not in str(e.value)
    with pytest.raises(ParamsError):
        await eng.run_operation("lookup", {"q": ""}, inv())
    with pytest.raises(ParamsError):
        await eng.run_operation("lookup", ["q"], inv())


def test_query_string_params_are_read_as_their_schema_type():
    """The registry's GET read route (the chat and functions tool
    path) passes every argument as a string."""
    data = manifest()
    data["spec"]["tools"]["lookup"]["parameters"]["properties"].update(
        {"amount": {"type": "number"}, "exact": {"type": "boolean"}}
    )
    op = load_manifest(data).operations["lookup"]
    values = Engine.validate_params(
        op, {"q": "7", "limit": "3", "amount": "2.5", "exact": "True"}
    )
    assert values == {"q": "7", "limit": 3, "amount": 2.5, "exact": True}
    for bad in ({"limit": "3.5"}, {"amount": "nan"}, {"exact": "yes"}):
        with pytest.raises(ParamsError):
            Engine.validate_params(op, {"q": "x", **bad})


# ── egress: the exit-criteria negatives ──────────────────────────────────


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.10",
        "127.0.0.1",  # loopback
        "::1",
        "169.254.169.254",  # cloud metadata
        "169.254.10.10",  # link-local
        "fe80::1",
        "fd00:ec2::254",
        "100.100.100.200",  # Alibaba metadata
        "100.64.0.1",  # CGNAT
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",  # NAT64 form of the metadata address
        "fd12:3456::1",  # ULA
        "224.0.0.1",  # multicast
        # nosec B104: test input (a non-global address the egress policy must
        # refuse), not a bind target
        "0.0.0.0",  # nosec B104
        ["93.184.216.34", "10.0.0.5"],  # one bad address taints the name
    ],
)
async def test_declared_host_resolving_to_a_non_global_address_is_refused(address):
    up = Upstream()
    denials = DenialCounter()
    eng = engine(
        manifest(), up, dns=resolver({"api.example.com": address}), denials=denials
    )
    with pytest.raises(EgressDenied, match="non-global address"):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    assert up.requests == []  # never connected
    assert denials.count("demo", "non-global address") == 1


@pytest.mark.parametrize(
    "location,reason",
    [
        ("https://evil.example.net/steal", "undeclared host"),
        ("https://api.example.com.evil.net/", "undeclared host"),
        ("https://example.org/", "undeclared host"),  # wildcard is not the apex
        ("http://plugin-registry:8001/internal", "undeclared host"),
        ("http://minder-postgres:5432/", "undeclared host"),
        ("https://169.254.169.254/latest/meta-data/", "ip literal"),
        ("http://[::ffff:169.254.169.254]/", "ip literal"),
        ("https://10.0.0.1/", "ip literal"),
        ("http://api.example.com/v1/plain", "http not declared"),  # downgrade
        ("ftp://api.example.com/file", "scheme"),
        ("https://user:pw@api.example.com/v1/x", "userinfo"),
    ],
)
async def test_redirect_hops_are_rechecked(location, reason, caplog):
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(302, headers={"location": location}),
    )
    denials = DenialCounter()
    eng = engine(manifest(), up, denials=denials)
    with caplog.at_level(logging.WARNING, "minder.plugin-runner.declarative"):
        with pytest.raises(EgressDenied) as e:
            await eng.run_operation("lookup", {"q": "x"}, inv())
    assert e.value.reason == reason
    assert up.hosts() == ["api.example.com"]  # the redirect target never reached
    assert denials.count("demo") == 1 and denials.snapshot() == {"demo": {reason: 1}}
    assert "plugin=demo" in caplog.text  # logged with the plugin name


async def test_redirect_to_a_declared_host_is_followed_without_headers_or_auth():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(302, headers={"location": "https://cdn.example.org/blob?a=1"}),
    )
    up.route("cdn.example.org", "/blob", httpx.Response(200, json={"from": "cdn"}))
    bases = {
        "api": {
            "url": "https://api.example.com/v1",
            "auth": {"type": "api_key", "in": "query", "name": "key", "secret": "K"},
        }
    }
    steps = [
        {
            "name": "search",
            "request": {"base": "api", "path": "/search", "headers": {"X-Trace": "1"}},
        }
    ]
    eng = engine(manifest({"bases": bases, "tools": {"lookup": tool(steps)}}), up)
    result = await eng.run_operation("lookup", {}, inv(secrets={"K": SECRET}))
    assert result == {"from": "cdn"}
    first, second = up.requests
    assert first.url.params["key"] == SECRET and first.headers["x-trace"] == "1"
    assert "key" not in second.url.params and "x-trace" not in second.headers
    assert second.url.host == PUBLIC_IP


async def test_too_many_redirects_is_a_limit():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(302, headers={"location": "/v1/search"}),
    )
    eng = engine(manifest(), up)
    with pytest.raises(LimitExceeded, match="redirects"):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    assert len(up.requests) == 6  # the first request plus five redirects


async def test_plugins_cannot_use_each_others_egress():
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(200, json={}))
    other = manifest(
        {
            "egress": [{"host": "api.other.net"}],
            "bases": {"api": {"url": "https://api.other.net"}},
        },
        name="other",
    )
    eng = engine(other, up)
    with pytest.raises(EgressDenied, match="undeclared host"):
        eng.egress.check_url(httpx.URL("https://api.example.com/v1/search"))


async def test_unresolvable_host_is_an_upstream_error_not_a_bypass():
    up = Upstream()
    eng = engine(manifest(), up, dns=resolver({"api.example.com": OSError("nxdomain")}))
    with pytest.raises(UpstreamError, match="resolve"):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    eng = engine(manifest(), up, dns=resolver({"api.example.com": []}))
    with pytest.raises(UpstreamError):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    assert up.requests == []


async def test_denial_hook_is_called_for_quarantine():
    seen: List[tuple] = []
    denials = DenialCounter(hook=lambda plugin, reason: seen.append((plugin, reason)))
    eng = engine(
        manifest(),
        Upstream(),
        dns=resolver({"api.example.com": "10.1.1.1"}),
        denials=denials,
    )
    with pytest.raises(EgressDenied):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    assert seen == [("demo", "non-global address")]


# ── limits ───────────────────────────────────────────────────────────────


async def test_response_size_is_capped():
    up = Upstream()
    big = b"[" + b"1," * 1500 + b"1]"
    up.route("api.example.com", "/v1/search", httpx.Response(200, content=big))
    eng = engine(manifest({"limits": {"max_response_bytes": 1024}}), up)
    with pytest.raises(LimitExceeded, match="response size"):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(200, content=b"[]", headers={"content-length": "999999"}),
    )
    with pytest.raises(LimitExceeded, match="response size"):
        await eng.run_operation("lookup", {"q": "x"}, inv())


async def test_request_time_is_capped():
    up = Upstream()

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={})

    up.route("api.example.com", "/v1/search", slow)
    eng = engine(manifest({"limits": {"timeout_s": 0.2}}), up)
    started = time.monotonic()
    with pytest.raises(LimitExceeded, match="time"):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    assert time.monotonic() - started < 2


async def test_rate_limit_is_per_plugin():
    now = [0.0]
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(200, json={}))
    m = load_manifest(manifest({"limits": {"rate_per_minute": 2}}))
    egress = PluginEgress(
        m,
        resolver=resolver(),
        transport=httpx.MockTransport(up),
        denials=DenialCounter(),
        clock=lambda: now[0],
    )
    eng = Engine(m, egress)
    await eng.run_operation("lookup", {"q": "x"}, inv())
    await eng.run_operation("lookup", {"q": "x"}, inv())
    with pytest.raises(LimitExceeded, match="rate"):
        await eng.run_operation("lookup", {"q": "x"}, inv())
    now[0] += 30.0  # one token back
    await eng.run_operation("lookup", {"q": "x"}, inv())
    assert len(up.requests) == 3


def test_rate_limiter_refills_up_to_capacity():
    now = [0.0]
    rl = RateLimiter(60, clock=lambda: now[0])
    assert all(rl.try_acquire() for _ in range(60)) and not rl.try_acquire()
    now[0] += 1000
    assert sum(rl.try_acquire() for _ in range(100)) == 60


async def test_concurrency_is_bounded_per_plugin():
    up = Upstream()
    state = {"now": 0, "max": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        state["now"] += 1
        state["max"] = max(state["max"], state["now"])
        await asyncio.sleep(0.02)
        state["now"] -= 1
        return httpx.Response(200, json={"id": request.url.path})

    up.route(
        "api.example.com", "/v1/search", httpx.Response(200, json=[1, 2, 3, 4, 5, 6])
    )
    for i in range(1, 7):
        up.route("api.example.com", f"/v1/item/{i}", handler)
    steps = [
        {"name": "search", "request": {"base": "api", "path": "/search"}},
        {
            "name": "items",
            "foreach": "steps.search",
            "request": {"base": "api", "path": "/item/{item}"},
        },
    ]
    eng = engine(
        manifest({"limits": {"max_concurrency": 2}, "tools": {"lookup": tool(steps)}}),
        up,
    )
    result = await eng.run_operation("lookup", {}, inv())
    assert len(result) == 6 and state["max"] == 2


# ── pagination ───────────────────────────────────────────────────────────


def paged(paginate: Dict[str, Any], select: Optional[str] = None) -> Dict:
    step: Dict[str, Any] = {
        "name": "list",
        "request": {"base": "api", "path": "/list", "paginate": paginate},
    }
    if select:
        step["select"] = select
    return manifest({"tools": {"lookup": tool([step])}})


async def test_cursor_pagination_follows_until_no_cursor():
    up = Upstream()
    pages = {None: ([1, 2], "c2"), "c2": ([3], "c3"), "c3": ([4], None)}

    def handler(request: httpx.Request) -> httpx.Response:
        items, nxt = pages[request.url.params.get("after")]
        return httpx.Response(200, json={"data": items, "meta": {"next": nxt}})

    up.route("api.example.com", "/v1/list", handler)
    data = paged(
        {"type": "cursor", "param": "after", "next": "meta.next", "items": "data"}
    )
    assert await engine(data, up).run_operation("lookup", {}, inv()) == [1, 2, 3, 4]
    assert len(up.requests) == 3


async def test_cursor_pagination_is_bounded_and_stops_on_a_repeated_cursor():
    up = Upstream()
    counter = {"n": 0}

    def endless(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        return httpx.Response(
            200, json={"data": [counter["n"]], "next": f"c{counter['n']}"}
        )

    up.route("api.example.com", "/v1/list", endless)
    data = paged(
        {
            "type": "cursor",
            "param": "c",
            "next": "next",
            "items": "data",
            "max_pages": 3,
        }
    )
    assert await engine(data, up).run_operation("lookup", {}, inv()) == [1, 2, 3]
    assert len(up.requests) == 3

    stuck = Upstream()
    stuck.route(
        "api.example.com",
        "/v1/list",
        httpx.Response(200, json={"data": [0], "next": "same"}),
    )
    data = paged(
        {
            "type": "cursor",
            "param": "c",
            "next": "next",
            "items": "data",
            "max_pages": 10,
        }
    )
    assert await engine(data, stuck).run_operation("lookup", {}, inv()) == [0, 0]
    assert len(stuck.requests) == 2


async def test_offset_pagination():
    up = Upstream()
    rows = list(range(5))

    def handler(request: httpx.Request) -> httpx.Response:
        off, lim = int(request.url.params["offset"]), int(request.url.params["limit"])
        return httpx.Response(200, json={"rows": rows[off : off + lim]})

    up.route("api.example.com", "/v1/list", handler)
    data = paged(
        {
            "type": "offset",
            "param": "offset",
            "size_param": "limit",
            "size": 2,
            "items": "rows",
        }
    )
    assert await engine(data, up).run_operation("lookup", {}, inv()) == rows
    assert [r.url.params["offset"] for r in up.requests] == ["0", "2", "4"]


async def test_page_pagination_and_select():
    up = Upstream()

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        items = [{"n": page * 10 + i} for i in range(2)] if page <= 2 else []
        return httpx.Response(200, json=items)

    up.route("api.example.com", "/v1/list", handler)
    data = paged({"type": "page", "param": "page"}, select="[].n")
    assert await engine(data, up).run_operation("lookup", {}, inv()) == [10, 11, 20, 21]
    assert [r.url.params["page"] for r in up.requests] == ["1", "2", "3"]


async def test_link_pagination_is_rechecked_against_egress():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/list",
        httpx.Response(
            200,
            json=[1],
            headers={"link": '<https://api.example.com/v1/list2?p=2>; rel="next"'},
        ),
    )
    up.route(
        "api.example.com",
        "/v1/list2",
        httpx.Response(
            200, json=[2], headers={"link": '<https://evil.example.net/p3>; rel="next"'}
        ),
    )
    data = paged({"type": "link"})
    denials = DenialCounter()
    with pytest.raises(EgressDenied, match="undeclared host"):
        await engine(data, up, denials=denials).run_operation("lookup", {}, inv())
    assert up.hosts() == ["api.example.com", "api.example.com"]
    assert up.requests[1].url.params["p"] == "2"
    assert denials.count("demo", "undeclared host") == 1

    up.route("api.example.com", "/v1/list2", httpx.Response(200, json=[2]))
    assert await engine(data, up).run_operation("lookup", {}, inv()) == [1, 2]


async def test_pagination_items_must_be_a_list():
    up = Upstream()
    up.route("api.example.com", "/v1/list", httpx.Response(200, json={"rows": "x"}))
    data = paged({"type": "page", "param": "page", "items": "rows"})
    with pytest.raises(MappingError):
        await engine(data, up).run_operation("lookup", {}, inv())


# ── fan-out and chaining ─────────────────────────────────────────────────


async def test_foreach_is_bounded_and_chains_results():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(
            200, json={"docs": [{"key": f"/works/W{i}"} for i in range(25)]}
        ),
    )

    def work(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"path": request.url.raw_path.decode()})

    for i in range(25):
        up.route("api.example.com", f"/v1/works/%2Fworks%2FW{i}", work)
    steps = [
        {"name": "search", "request": {"base": "api", "path": "/search"}},
        {
            "name": "works",
            "foreach": "steps.search.docs[].key",
            "max_items": 5,
            "request": {"base": "api", "path": "/works/{item}"},
            "select": "path",
        },
    ]
    eng = engine(
        manifest(
            {
                "tools": {
                    "lookup": tool(
                        steps, output="{n: length(steps.works), first: steps.works[0]}"
                    )
                }
            }
        ),
        up,
    )
    result = await eng.run_operation("lookup", {}, inv())
    assert result == {"n": 5, "first": "/v1/works/%2Fworks%2FW0"}
    assert len(up.requests) == 6  # one search and exactly max_items fetches


async def test_chained_step_reads_an_earlier_step_by_placeholder():
    up = Upstream()
    up.route("api.example.com", "/v1/token", httpx.Response(200, json={"id": "abc 1"}))
    up.route(
        "api.example.com", "/v1/detail/abc%201", httpx.Response(200, json={"ok": True})
    )
    steps = [
        {"name": "first", "request": {"base": "api", "path": "/token"}},
        {
            "name": "second",
            "request": {"base": "api", "path": "/detail/{steps.first.id}"},
        },
    ]
    eng = engine(manifest({"tools": {"lookup": tool(steps)}}), up)
    assert await eng.run_operation("lookup", {}, inv()) == {"ok": True}


async def test_a_failing_fanout_item_fails_the_step_and_cancels_the_rest():
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(200, json=[1, 2]))
    up.route("api.example.com", "/v1/item/1", httpx.Response(500))

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={})

    up.route("api.example.com", "/v1/item/2", slow)
    steps = [
        {"name": "search", "request": {"base": "api", "path": "/search"}},
        {
            "name": "items",
            "foreach": "steps.search",
            "request": {"base": "api", "path": "/item/{item}"},
        },
    ]
    eng = engine(manifest({"tools": {"lookup": tool(steps)}}), up)
    started = time.monotonic()
    with pytest.raises(UpstreamError) as e:
        await eng.run_operation("lookup", {}, inv())
    assert e.value.status == 500 and time.monotonic() - started < 2


# ── mapping ──────────────────────────────────────────────────────────────


async def test_jmespath_output_and_helper_functions():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/latest",
        httpx.Response(200, json={"base": "EUR", "rates": {"USD": 1.1, "TRY": 35.5}}),
    )
    steps = [{"name": "latest", "request": {"base": "api", "path": "/latest"}}]
    op = tool(
        steps,
        parameters={
            "type": "object",
            "properties": {"amount": {"type": "number"}, "to": {"type": "string"}},
        },
        output=(
            "{result: multiply(params.amount, steps.latest.rates.USD),"
            " to: upper(params.to), quotes: sort(entries(steps.latest.rates)[].key),"
            " parts: split('a, b,,c', ','), half: divide(`1`, `0`)}"
        ),
    )
    eng = engine(manifest({"tools": {"lookup": op}}), up)
    result = await eng.run_operation("lookup", {"amount": 10, "to": "usd"}, inv())
    assert result["result"] == pytest.approx(11.0)
    assert result["to"] == "USD" and result["quotes"] == ["TRY", "USD"]
    assert result["parts"] == ["a", "b", "c"] and result["half"] is None


ATOM = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <title>query</title>
  <entry>
    <id>http://arxiv.org/abs/1</id>
    <title> Paper One </title>
    <author><name>A</name></author>
    <author><name>B</name></author>
    <link href="http://arxiv.org/pdf/1" rel="related" type="application/pdf"/>
    <arxiv:primary_category term="cs.AI"/>
  </entry>
  <entry>
    <id>http://arxiv.org/abs/2</id>
    <title>Paper Two</title>
    <author><name>C</name></author>
  </entry>
</feed>"""


async def test_xml_responses_map_to_json():
    up = Upstream()
    up.route("api.example.com", "/v1/query", httpx.Response(200, content=ATOM))
    steps = [
        {
            "name": "feed",
            "request": {"base": "api", "path": "/query", "response": "xml"},
        }
    ]
    op = tool(
        steps,
        output=(
            "steps.feed.feed.entry[].{id: id, title: title,"
            ' authors: to_array(author)[].name, pdf: link."@href",'
            ' category: primary_category."@term"}'
        ),
    )
    eng = engine(manifest({"tools": {"lookup": op}}), up)
    assert await eng.run_operation("lookup", {}, inv()) == [
        {
            "id": "http://arxiv.org/abs/1",
            "title": "Paper One",
            "authors": ["A", "B"],
            "pdf": "http://arxiv.org/pdf/1",
            "category": "cs.AI",
        },
        {
            "id": "http://arxiv.org/abs/2",
            "title": "Paper Two",
            "authors": ["C"],
            "pdf": None,
            "category": None,
        },
    ]


def test_xml_is_parsed_safely():
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>'
    )
    with pytest.raises(UpstreamError):
        dmapping.xml_to_json(bomb)
    external = (
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        b"<x>&e;</x>"
    )
    with pytest.raises(UpstreamError):
        dmapping.xml_to_json(external)
    deep = b"<a>" * 100 + b"x" + b"</a>" * 100
    with pytest.raises(UpstreamError, match="deeply"):
        dmapping.xml_to_json(deep)
    with pytest.raises(UpstreamError):
        dmapping.xml_to_json(b"<not-closed>")
    assert dmapping.xml_to_json(b"<r a='1'>t<c>x</c></r>") == {
        "r": {"@a": "1", "c": "x", "#text": "t"}
    }


ATOM_NS = "http://www.w3.org/2005/Atom"
ARXIV_NS = "http://arxiv.org/schemas/atom"


def test_xml_namespaces_can_be_kept_as_uris_or_declared_prefixes():
    kept = dmapping.xml_to_json(ATOM, "keep")
    feed = kept[f"{{{ATOM_NS}}}feed"]
    assert len(feed[f"{{{ATOM_NS}}}entry"]) == 2
    assert feed[f"{{{ATOM_NS}}}entry"][0][f"{{{ARXIV_NS}}}primary_category"] == {
        "@term": "cs.AI"  # an attribute in no namespace stays bare
    }
    prefixed = dmapping.xml_to_json(ATOM, "keep", {ATOM_NS: "atom"})
    entry = prefixed["atom:feed"]["atom:entry"][0]
    assert entry["atom:title"] == "Paper One"
    assert f"{{{ARXIV_NS}}}primary_category" in entry  # undeclared URI stays {uri}
    # The same document in another default namespace has no atom:entry.
    other = ATOM.replace(ATOM_NS.encode(), b"urn:not-atom")
    assert "atom:feed" not in dmapping.xml_to_json(other, "keep", {ATOM_NS: "atom"})
    # The default still drops namespaces to local names.
    assert "entry" in dmapping.xml_to_json(ATOM)["feed"]
    attr = dmapping.xml_to_json(
        b'<r xmlns:x="urn:x" x:a="1" b="2"/>', "keep", {"urn:x": "x"}
    )
    assert attr == {"r": {"@x:a": "1", "@b": "2"}}


async def test_xml_namespaces_select_only_atom_entries_end_to_end():
    up = Upstream()
    other = ATOM.replace(ATOM_NS.encode(), b"urn:not-atom")
    up.route("api.example.com", "/v1/atom", httpx.Response(200, content=ATOM))
    up.route("api.example.com", "/v1/other", httpx.Response(200, content=other))
    steps = [
        {
            "name": "feed",
            "request": {
                "base": "api",
                "path": "/{params.q}",
                "response": "xml",
                "xml": {"namespaces": "keep", "prefixes": {"a": ATOM_NS}},
            },
        }
    ]
    op = tool(
        steps,
        output='length(to_array(values(steps.feed)[0]."a:entry" || `[]`))',
    )
    eng = engine(manifest({"tools": {"lookup": op}}), up)
    assert await eng.run_operation("lookup", {"q": "atom"}, inv()) == 2
    assert await eng.run_operation("lookup", {"q": "other"}, inv()) == 0


@pytest.mark.parametrize(
    "request_extra,match",
    [
        ({"xml": {"namespaces": "keep"}}, "only with 'response: xml'"),
        (
            {"response": "xml", "xml": {"prefixes": {"a": ATOM_NS}}},
            "only with 'namespaces: keep'",
        ),
        (
            {"response": "xml", "xml": {"namespaces": "keep", "prefixes": {"1a": "u"}}},
            "not a valid prefix",
        ),
        (
            {
                "response": "xml",
                "xml": {"namespaces": "keep", "prefixes": {"a": "u", "b": "u"}},
            },
            "distinct namespace URI",
        ),
        (
            {
                "response": "xml",
                "xml": {"namespaces": "keep", "prefixes": {"a": "u}x"}},
            },
            "distinct namespace URI",
        ),
        ({"response": "xml", "xml": {"namespaces": "strip"}}, "invalid"),
        ({"empty_body": "ignore"}, "invalid"),
        ({"method": "POST", "follow_redirects": True}, "GET/HEAD only"),
        ({"follow_redirects": "sometimes"}, "invalid"),
    ],
)
def test_request_options_are_validated_at_load(request_extra, match):
    data = manifest()
    data["spec"]["tools"]["lookup"]["steps"][0]["request"].update(request_extra)
    with pytest.raises(ManifestError, match=match):
        load_manifest(data)


def _fn(expr: str, data: Any = None) -> Any:
    return dmapping.search(dmapping.compile_expr(expr, "t"), data or {})


@pytest.mark.parametrize(
    "expr,expected",
    [
        ("substr('héllo', `1`)", "éllo"),
        ("substr('héllo', `1`, `3`)", "él"),
        ("substr('héllo', `-2`)", "lo"),
        ("substr('héllo', `0`, `-1`)", "héll"),
        ("substr('abc', `1.0`, `2.0`)", "b"),
        ("substr('abc', `5`)", ""),
        ("substr('abc', `2`, `1`)", ""),
        ("substr('abc', `-99999999999999999999999`)", "abc"),
        ("substr('abc', `0`, `99999999999999999999999`)", "abc"),
        ("substr('abc', `-1e300`, `1e300`)", "abc"),
        ("substr('', `0`, `10`)", ""),
        ("chars('añ😀')", ["a", "ñ", "😀"]),
        ("chars('')", []),
        ("words(' a\tb\r\n c d  ')", ["a", "b", "c", "d"]),
        ("join(' ', words('a \t b'))", "a b"),
    ],
)
def test_substr_chars_and_words(expr, expected):
    assert _fn(expr) == expected


def test_get_looks_up_a_computed_key():
    data = {"rates": {"USD": 1.1, "TRY": 0}, "to": " usd "}
    assert _fn("get(rates, upper(trim(to)))", data) == 1.1
    assert _fn("get(rates, 'TRY')", data) == 0
    assert _fn("get(rates, 'GBP')", data) is None
    for bad in ("get(to, 'x')", "get(rates, `1`)", "get(rates)"):
        with pytest.raises(MappingError):
            _fn(bad, data)


@pytest.mark.parametrize(
    "expr",
    [
        "substr('abc', `1.5`)",  # not an integer
        "substr('abc', `0`, `0.5`)",
        "substr('abc', `true`)",  # a bool is not a number
        "substr('abc', `0`, `false`)",
        "substr('abc', `0`, 'x')",
        "substr('abc', `0`, `null`)",
        "substr('abc')",  # arity
        "substr('abc', `0`, `1`, `2`)",
        "substr(`1`, `0`)",  # not a string
        "substr('abc', `1e400`)",  # infinity (JSON literal overflows)
        "chars(`5`)",
        "words(`null`)",
    ],
)
def test_substr_chars_and_words_refuse_bad_arguments(expr):
    with pytest.raises(MappingError):
        _fn(expr)


def test_chars_and_words_cap_their_output():
    long = "a" * (dmapping.MAX_LIST_ITEMS + 1)
    with pytest.raises(MappingError):
        _fn("chars(s)", {"s": long})
    assert len(_fn("chars(s)", {"s": long[:-1]})) == dmapping.MAX_LIST_ITEMS
    with pytest.raises(MappingError):
        _fn("words(s)", {"s": "a " * (dmapping.MAX_LIST_ITEMS + 1)})
    # substr never grows its input, whatever the indices.
    assert _fn("substr(s, `-99999999999`, `99999999999`)", {"s": long}) == long


def _lookup(**request_extra: Any) -> Dict:
    data = manifest()
    data["spec"]["tools"]["lookup"]["steps"][0]["request"].update(request_extra)
    data["spec"]["tools"]["lookup"]["error_output"] = "error"
    return data


@pytest.mark.parametrize("body", [b"", b"   ", b" \r\n\t "])
async def test_empty_body_is_null_by_default_or_a_parse_error_when_declared(body):
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(200, content=body))
    assert await engine(manifest(), up).run_operation("lookup", {"q": "x"}, inv()) is (
        None
    )
    eng = engine(_lookup(empty_body="error"), up)
    assert await eng.run_operation("lookup", {"q": "x"}, inv()) == {
        "kind": "parse",
        "status": None,
    }
    for fmt in ("text", "xml"):
        eng = engine(_lookup(empty_body="error", response=fmt), up)
        result = await eng.run_operation("lookup", {"q": "x"}, inv())
        assert result == {"kind": "parse", "status": None}
    # A non-empty body is unaffected.
    up.route("api.example.com", "/v1/search", httpx.Response(200, json=[1]))
    assert await engine(_lookup(empty_body="error"), up).run_operation(
        "lookup", {"q": "x"}, inv()
    ) == [1]


async def test_parse_errors_are_their_own_kind_and_never_echo_the_body():
    marker = "BODY-MARKER-7f3a"
    up = Upstream()
    eng = engine(_lookup(), up)
    xml_eng = engine(_lookup(response="xml"), up)
    for body in (f"<html>{marker}", f"{{'{marker}': 1", marker):
        up.route("api.example.com", "/v1/search", httpx.Response(200, text=body))
        for e in (eng, xml_eng):
            result = await e.run_operation("lookup", {"q": "x"}, inv())
            assert result == {"kind": "parse", "status": None}
        raw = engine(manifest(), up)
        with pytest.raises(UpstreamError) as err:  # still an UpstreamError
            await raw.run_operation("lookup", {"q": "x"}, inv())
        assert marker not in str(err.value) and err.value.status is None
    # Transport failures and statuses stay "upstream".
    up.route("api.example.com", "/v1/search", httpx.Response(502, text=marker))
    assert await eng.run_operation("lookup", {"q": "x"}, inv()) == {
        "kind": "upstream",
        "status": 502,
    }


async def test_follow_redirects_false_returns_the_redirect_as_a_status():
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(302, headers={"location": "/v1/moved"}),
    )
    up.route("api.example.com", "/v1/moved", httpx.Response(200, json={"ok": 1}))
    # Default: followed (GET), as before.
    assert await engine(manifest(), up).run_operation("lookup", {"q": "x"}, inv()) == {
        "ok": 1
    }
    up.requests.clear()
    eng = engine(_lookup(follow_redirects=False), up)
    assert await eng.run_operation("lookup", {"q": "x"}, inv()) == {
        "kind": "upstream",
        "status": 302,
    }
    assert [r.url.path for r in up.requests] == ["/v1/search"]  # never followed


@pytest.mark.parametrize(
    "location,reason",
    [
        ("https://evil.example.net/steal", "undeclared host"),
        ("https://169.254.169.254/latest/meta-data/", "ip literal"),
        ("http://api.example.com/v1/plain", "http not declared"),
    ],
)
async def test_explicit_follow_redirects_still_rechecks_every_hop(location, reason):
    up = Upstream()
    up.route(
        "api.example.com",
        "/v1/search",
        httpx.Response(302, headers={"location": location}),
    )
    data = manifest()
    data["spec"]["tools"]["lookup"]["steps"][0]["request"]["follow_redirects"] = True
    with pytest.raises(EgressDenied) as e:
        await engine(data, up).run_operation("lookup", {"q": "x"}, inv())
    assert e.value.reason == reason
    assert up.hosts() == ["api.example.com"]


async def test_on_error_stands_in_for_upstream_failures():
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(200, content=b"not json"))
    data = manifest()
    data["spec"]["tools"]["lookup"]["on_error"] = {"error": "lookup unavailable"}
    eng = engine(data, up)
    assert await eng.run_operation("lookup", {"q": "x"}, inv()) == {
        "error": "lookup unavailable"
    }
    up.route("api.example.com", "/v1/search", httpx.Response(503))
    assert await eng.run_operation("lookup", {"q": "x"}, inv()) == {
        "error": "lookup unavailable"
    }
    # A declared accept_status is a normal response.
    data["spec"]["tools"]["lookup"]["steps"][0]["request"]["accept_status"] = [404]
    data["spec"]["tools"]["lookup"]["output"] = "steps.search.error || 'found'"
    up.route(
        "api.example.com", "/v1/search", httpx.Response(404, json={"error": "none"})
    )
    assert await engine(data, up).run_operation("lookup", {"q": "x"}, inv()) == "none"


def test_error_output_must_be_jmespath():
    data = manifest()
    data["spec"]["tools"]["lookup"]["error_output"] = "{a: "
    with pytest.raises(ManifestError):
        load_manifest(data)


async def test_error_output_maps_params_config_and_the_error_class():
    up = Upstream()
    data = manifest()
    data["spec"]["tools"]["lookup"][
        "error_output"
    ] = "{q: params.q, lang: config.LANG, kind: error.kind, status: error.status}"
    eng = engine(data, up)
    for status in (404, 422, 500, 503):
        up.route("api.example.com", "/v1/search", httpx.Response(status))
        result = await eng.run_operation("lookup", {"q": " x "}, inv({"LANG": "tr"}))
        assert result == {
            "q": " x ",
            "lang": "tr",
            "kind": "upstream",
            "status": status,
        }

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    up.route("api.example.com", "/v1/search", down)
    assert await eng.run_operation("lookup", {"q": "x"}, inv()) == {
        "q": "x",
        "lang": "en",
        "kind": "upstream",
        "status": None,
    }
    up.route("api.example.com", "/v1/search", httpx.Response(200, content=b"<html>"))
    # A body that does not decode is a parse error, not a transport failure.
    assert (await eng.run_operation("lookup", {"q": "x"}, inv()))["kind"] == "parse"
    denied = engine(data, up, dns=resolver({"api.example.com": "127.0.0.1"}))
    assert (await denied.run_operation("lookup", {"q": "x"}, inv()))["kind"] == "egress"


async def test_error_output_null_falls_back_to_on_error_then_raises():
    up = Upstream()
    data = manifest()
    op = data["spec"]["tools"]["lookup"]
    op["error_output"] = (
        "error.status == `404` && {error: join('', ['no match for ', params.q])}"
        " || null"
    )
    up.route("api.example.com", "/v1/search", httpx.Response(404))
    assert await engine(data, up).run_operation("lookup", {"q": "x"}, inv()) == {
        "error": "no match for x"
    }
    up.route("api.example.com", "/v1/search", httpx.Response(500))
    with pytest.raises(UpstreamError):
        await engine(data, up).run_operation("lookup", {"q": "x"}, inv())
    op["on_error"] = {"error": "unavailable"}
    assert await engine(data, up).run_operation("lookup", {"q": "x"}, inv()) == {
        "error": "unavailable"
    }
    # An error_output that cannot be applied is treated as null.
    op["error_output"] = "multiply(params.q, `2`)"
    assert await engine(data, up).run_operation("lookup", {"q": "x"}, inv()) == {
        "error": "unavailable"
    }


async def test_error_output_cannot_read_responses_steps_or_secrets():
    up = Upstream()
    # The upstream reflects the request (auth included) in a failing body.
    up.route(
        "api.example.com",
        "/v1/echo",
        lambda r: httpx.Response(500, json=json.loads(echo(r).content)),
    )
    data = authed({"type": "bearer", "secret": "API_TOKEN"})
    op = data["spec"]["tools"]["lookup"]
    op["error_output"] = (
        "{all: @, steps: steps, body: steps.echo, response: response,"
        " secrets: secrets, auth: auth, q: params.q}"
    )
    eng = engine(data, up, clock=lambda: FIXED_NOW)
    result = await eng.run_operation(
        "lookup",
        {"q": SECRET},
        Invocation(
            {"API_TOKEN": SECRET, "LANG": "tr", "OTHER": "x"},
            Secrets({"API_TOKEN": SECRET}),
        ),
    )
    assert result == {
        "all": {
            "params": {"q": "[redacted]"},
            "config": {"LANG": "tr"},
            "error": {"kind": "upstream", "status": 500},
            "now": FIXED_ISO,
        },
        "steps": None,
        "body": None,
        "response": None,
        "secrets": None,
        "auth": None,
        "q": "[redacted]",
    }
    assert SECRET not in json.dumps(result)
    # Nothing an earlier step returned leaks either: step 1 succeeds, step 2
    # fails, and the error mapping still sees no step results.
    up.route("api.example.com", "/v1/ok", httpx.Response(200, json={"leak": "body"}))
    op["steps"] = [
        {"name": "first", "request": {"base": "api", "path": "/ok"}},
        {"name": "echo", "request": {"base": "api", "path": "/echo"}},
    ]
    op["error_output"] = "{all: @, first: steps.first}"
    result = await engine(data, up).run_operation(
        "lookup", {"q": "x"}, Invocation({}, Secrets({"API_TOKEN": SECRET}))
    )
    assert "leak" not in json.dumps(result) and result["first"] is None
    assert set(result["all"]) == {"params", "config", "error", "now"}


async def test_upstream_errors_carry_no_values():
    up = Upstream()
    up.route("api.example.com", "/v1/search", httpx.Response(500, text=SECRET))
    with pytest.raises(UpstreamError) as e:
        await engine(manifest(), up).run_operation("lookup", {"q": "needle"}, inv())
    assert e.value.status == 500
    assert SECRET not in str(e.value) and "needle" not in str(e.value)


# ── auth injection and secret non-leakage ────────────────────────────────


def authed(auth: Dict[str, Any], output: Optional[str] = None) -> Dict:
    steps = [{"name": "echo", "request": {"base": "api", "path": "/echo"}}]
    op = tool(steps, **({"output": output} if output else {}))
    return manifest(
        {
            "bases": {"api": {"url": "https://api.example.com/v1", "auth": auth}},
            "tools": {"lookup": op},
        }
    )


def echo(request: httpx.Request) -> httpx.Response:
    """An upstream that reflects everything it received (worst case)."""
    return httpx.Response(
        200,
        json={
            "url": str(request.url),
            "headers": dict(request.headers),
            "auth": request.headers.get("authorization"),
            "nested": {
                request.headers.get("x-key") or "k": [request.url.query.decode()]
            },
        },
    )


@pytest.mark.parametrize(
    "auth,check",
    [
        (
            {"type": "api_key", "in": "header", "name": "X-Key", "secret": "API_TOKEN"},
            lambda r: r.headers["x-key"] == SECRET,
        ),
        (
            {
                "type": "api_key",
                "in": "query",
                "name": "api_key",
                "secret": "API_TOKEN",
            },
            lambda r: r.url.params["api_key"] == SECRET,
        ),
        (
            {"type": "bearer", "secret": "API_TOKEN"},
            lambda r: r.headers["authorization"] == f"Bearer {SECRET}",
        ),
        (
            {
                "type": "basic",
                "username_secret": "USER",
                "password_secret": "API_TOKEN",
            },
            lambda r: r.headers["authorization"]
            == "Basic " + base64.b64encode(f"bob:{SECRET}".encode()).decode(),
        ),
    ],
)
async def test_auth_is_injected_and_never_reaches_the_output(auth, check, caplog):
    up = Upstream()
    up.route("api.example.com", "/v1/echo", echo)
    secrets = Secrets({"API_TOKEN": SECRET, "USER": "bob"})
    eng = engine(authed(auth), up)
    with caplog.at_level(logging.DEBUG):
        result = await eng.run_operation("lookup", {}, Invocation({}, secrets))
    (req,) = up.requests
    assert check(req)
    dumped = json.dumps(result)
    encoded = base64.b64encode(f"bob:{SECRET}".encode()).decode()
    for needle in (SECRET, "s3cr3t%2B%2F%3Dkey", "s3cr3t%2B/%3Dkey", encoded):
        assert needle not in dumped
    assert "[redacted]" in dumped
    # Not in any log either (httpx logs every request URL at INFO).
    for needle in (SECRET, "s3cr3t%2B%2F%3Dkey", "s3cr3t%2B/%3Dkey", encoded):
        assert needle not in caplog.text
    assert set(secrets.reads) <= {"API_TOKEN", "USER"}


async def test_secrets_are_not_in_the_mapping_context():
    up = Upstream()
    up.route("api.example.com", "/v1/echo", httpx.Response(200, json={}))
    auth = {"type": "bearer", "secret": "API_TOKEN"}
    eng = engine(authed(auth, output="{config: config, params: params}"), up)
    # Even when the admin's config payload carries the secret field, the
    # mapping context only has the declared non-secret keys.
    result = await eng.run_operation(
        "lookup",
        {},
        Invocation(
            {"API_TOKEN": SECRET, "LANG": "tr", "OTHER": "x"},
            Secrets({"API_TOKEN": SECRET}),
        ),
    )
    assert result == {"config": {"LANG": "tr"}, "params": {}}


async def test_missing_secret_fails_without_a_request():
    up = Upstream()
    up.route("api.example.com", "/v1/echo", echo)
    eng = engine(authed({"type": "bearer", "secret": "API_TOKEN"}), up)
    with pytest.raises(SecretUnavailable):
        await eng.run_operation("lookup", {}, Invocation({}, NoSecrets()))
    assert up.requests == []


async def test_secret_with_a_newline_is_refused():
    up = Upstream()
    eng = engine(
        authed({"type": "api_key", "in": "header", "name": "X-Key", "secret": "K"}), up
    )
    with pytest.raises(SecretUnavailable):
        await eng.run_operation("lookup", {}, inv(secrets={"K": "a\r\nX-Evil: 1"}))
    assert up.requests == []


def test_scrub_covers_keys_nested_values_and_encodings():
    value = {SECRET: ["x" + SECRET, {"k": "s3cr3t%2B%2F%3Dkey"}], "n": 1}
    out = scrub(value, [SECRET])
    assert SECRET not in json.dumps(out) and out["n"] == 1
    assert scrub({"a": "b"}, []) == {"a": "b"}


# ── the schedule trigger ─────────────────────────────────────────────────


def fx_manifest() -> Dict:
    return manifest(
        {
            "config_schema": [{"key": "FX_BASE", "type": "string", "default": "EUR"}],
            "egress": [{"host": "api.frankfurter.app"}],
            "bases": {"api": {"url": "https://api.frankfurter.app"}},
            "timeseries": {"measurements": ["fx_rate"]},
            "tools": {
                "convert": {
                    "description": "Convert an amount.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "amount": {"type": "number"},
                            "from_currency": {"type": "string"},
                            "to_currency": {"type": "string"},
                        },
                        "required": ["amount", "from_currency", "to_currency"],
                    },
                    "steps": [
                        {
                            "name": "rate",
                            "request": {
                                "base": "api",
                                "path": "/latest",
                                "query": {
                                    "from": "{params.from_currency}",
                                    "to": "{params.to_currency}",
                                },
                            },
                        }
                    ],
                    "output": (
                        "{amount: params.amount, from: upper(params.from_currency),"
                        " to: upper(params.to_currency), result: multiply(params.amount,"
                        " values(steps.rate.rates)[0])}"
                    ),
                    "on_error": {"error": "no rate"},
                }
            },
            "actions": {
                "refresh": {
                    "description": "Re-fetch the latest rates.",
                    "steps": [
                        {"name": "rate", "request": {"base": "api", "path": "/latest"}}
                    ],
                    "admin_only": True,
                }
            },
            "schedule": {
                "cron": "0 * * * *",
                "steps": [
                    {
                        "name": "latest",
                        "request": {
                            "base": "api",
                            "path": "/latest",
                            "query": {"from": "{config.FX_BASE}"},
                        },
                    }
                ],
                "measurement": "fx_rate",
                "points": (
                    'entries(steps.latest.rates)[].{tags: {base: `"EUR"`, quote: key},'
                    " fields: {rate: value}}"
                ),
            },
        },
        name="fxdemo",
    )


def fx_upstream() -> Upstream:
    up = Upstream()

    def latest(request: httpx.Request) -> httpx.Response:
        to = request.url.params.get("to")
        rates = {"USD": 1.1, "TRY": 35.5}
        return httpx.Response(
            200,
            json={
                "base": request.url.params.get("from"),
                "rates": {to: rates[to]} if to else rates,
            },
        )

    up.route("api.frankfurter.app", "/latest", latest)
    return up


async def test_schedule_maps_to_line_protocol():
    up = fx_upstream()
    lines = await engine(fx_manifest(), up).run_schedule(inv({"FX_BASE": "EUR"}))
    assert sorted(lines) == [
        "fx_rate,base=EUR,quote=TRY rate=35.5",
        "fx_rate,base=EUR,quote=USD rate=1.1",
    ]
    assert up.requests[0].url.params["from"] == "EUR"


# ── the clock, action writes and declared tags ───────────────────────────


class Sink:
    """A ``timeseries.write`` handle: records batches, returns their size,
    or raises / returns ``result`` when set."""

    def __init__(self, result: Any = None, error: Optional[Exception] = None):
        self.batches: List[List[str]] = []
        self.result = result
        self.error = error

    async def write(self, lines: Any, precision: str = "s") -> int:
        assert precision == "s"
        self.batches.append(list(lines))
        if self.error is not None:
            raise self.error
        return len(lines) if self.result is None else self.result


def fx_write_manifest(**refresh: Any) -> Dict:
    """fx_manifest() whose refresh action writes, like frankfurter's."""
    data = fx_manifest()
    data["spec"]["config_schema"].append({"key": "FX_SYMBOLS", "type": "string"})
    data["spec"]["actions"]["refresh"] = {
        "description": "Re-collect now.",
        "steps": [
            {
                "name": "latest",
                "request": {
                    "base": "api",
                    "path": "/latest",
                    "query": {"from": "{config.FX_BASE}"},
                },
            }
        ],
        "timeseries": {
            "measurement": "fx_rate",
            "points": (
                "entries(steps.latest.rates)[?type(value) == 'number']"
                ".{tags: {quote: key}, fields: {rate: multiply(value, `1.0`)}}"
            ),
            "tags": {"base": "upper(trim(config.FX_BASE))"},
        },
        "output": (
            "{base: upper(trim(config.FX_BASE)), rates: steps.latest.rates,"
            " influxdb_written: timeseries.written > `0`,"
            " points: timeseries.points, collected_at: now}"
        ),
        "admin_only": True,
        **refresh,
    }
    return data


async def test_now_is_the_invocation_start_in_utc():
    up = fx_upstream()
    data = fx_manifest()
    data["spec"]["tools"]["convert"]["output"] = "{at: now}"
    params = {"amount": 1, "from_currency": "EUR", "to_currency": "USD"}
    eng = engine(data, up, clock=lambda: FIXED_NOW)
    assert await eng.run_operation("convert", params, inv()) == {"at": FIXED_ISO}
    # A naive clock value is UTC; another zone is converted to UTC.
    naive = engine(data, up, clock=lambda: FIXED_NOW.replace(tzinfo=None))
    assert (await naive.run_operation("convert", params, inv()))["at"] == FIXED_ISO
    plus3 = FIXED_NOW.astimezone(timezone(timedelta(hours=3)))
    shifted = engine(data, up, clock=lambda: plus3)
    assert (await shifted.run_operation("convert", params, inv()))["at"] == FIXED_ISO
    # The default clock is the real one, aware and in UTC.
    real = (await engine(data, up).run_operation("convert", params, inv()))["at"]
    parsed = datetime.fromisoformat(real)
    assert parsed.utcoffset() == timedelta(0)
    assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 60


def test_now_is_not_a_placeholder_root():
    data = fx_manifest()
    data["spec"]["tools"]["convert"]["steps"][0]["request"]["query"]["at"] = "{now}"
    with pytest.raises(ManifestError, match="placeholder root"):
        load_manifest(data)


async def test_action_writes_its_declared_points_and_maps_the_count():
    up = fx_upstream()
    sink = Sink()
    eng = engine(fx_write_manifest(), up, clock=lambda: FIXED_NOW)
    result = await eng.run_operation(
        "refresh", {}, Invocation({"FX_BASE": " eur "}, NoSecrets(), sink)
    )
    assert result == {
        "base": "EUR",
        "rates": {"USD": 1.1, "TRY": 35.5},
        "influxdb_written": True,
        "points": 2,
        "collected_at": FIXED_ISO,
    }
    # Declared tags come first; ints are written as floats here.
    assert sink.batches == [
        [
            "fx_rate,base=EUR,quote=USD rate=1.1",
            "fx_rate,base=EUR,quote=TRY rate=35.5",
        ]
    ]
    assert up.requests[0].url.params["from"] == " eur "


async def test_action_write_without_a_sink_or_with_a_failing_one_is_zero(caplog):
    up = fx_upstream()
    eng = engine(fx_write_manifest(), up, clock=lambda: FIXED_NOW)
    no_sink = await eng.run_operation("refresh", {}, inv({"FX_BASE": "EUR"}))
    assert (no_sink["influxdb_written"], no_sink["points"]) == (False, 2)
    failing = Sink(error=RuntimeError("registry said no: EUR secret"))
    with caplog.at_level(logging.WARNING):
        result = await eng.run_operation(
            "refresh", {}, Invocation({"FX_BASE": "EUR"}, NoSecrets(), failing)
        )
    assert result["influxdb_written"] is False and result["rates"]
    assert "RuntimeError" in caplog.text and "registry said no" not in caplog.text
    for odd in (True, -3, "2", 0.5):
        sink = Sink(result=odd)
        out = await eng.run_operation(
            "refresh", {}, Invocation({"FX_BASE": "EUR"}, NoSecrets(), sink)
        )
        assert out["influxdb_written"] is False, odd
    # No points: nothing is sent at all.
    empty = fx_write_manifest()
    empty["spec"]["actions"]["refresh"]["timeseries"]["points"] = "`[]`"
    sink = Sink()
    out = await engine(empty, up).run_operation(
        "refresh", {}, Invocation({"FX_BASE": "EUR"}, NoSecrets(), sink)
    )
    assert (out["points"], out["influxdb_written"], sink.batches) == (0, False, [])


@pytest.mark.parametrize(
    "where, change, match",
    [
        # Only an action that is not read-only may write.
        ("tools", {"read_only": True}, "only a non-read-only action"),
        ("actions", {"read_only": True}, "only a non-read-only action"),
        # The measurement must be one the plugin declares (its TIMESERIES).
        (
            "actions",
            {"timeseries": {"measurement": "cpu", "points": "`[]`"}},
            "must be listed in spec.timeseries",
        ),
        # Platform-owned and malformed tag keys are refused.
        (
            "actions",
            {
                "timeseries": {
                    "measurement": "fx_rate",
                    "points": "`[]`",
                    "tags": {"owner_id": "config.FX_BASE"},
                }
            },
            "not an allowed tag key",
        ),
        (
            "actions",
            {
                "timeseries": {
                    "measurement": "fx_rate",
                    "points": "`[]`",
                    "tags": {"plugin": "config.FX_BASE"},
                }
            },
            "not an allowed tag key",
        ),
        (
            "actions",
            {
                "timeseries": {
                    "measurement": "fx_rate",
                    "points": "`[]`",
                    "tags": {"a b": "config.FX_BASE"},
                }
            },
            "not an allowed tag key",
        ),
        (
            "actions",
            {
                "timeseries": {
                    "measurement": "fx_rate",
                    "points": "`[]`",
                    "tags": {"base": "config.["},
                }
            },
            "invalid JMESPath",
        ),
    ],
)
def test_action_writes_are_validated_at_load(where, change, match):
    data = fx_write_manifest(**({} if where == "tools" else change))
    if where == "tools":
        op = data["spec"]["tools"]["convert"]
        op["timeseries"] = data["spec"]["actions"]["refresh"]["timeseries"]
        op.update(change)
    with pytest.raises(ManifestError, match=match):
        load_manifest(data)


def test_a_tool_may_not_write_even_if_not_read_only():
    data = fx_write_manifest()
    op = data["spec"]["tools"]["convert"]
    op["timeseries"] = data["spec"]["actions"]["refresh"]["timeseries"]
    op["read_only"] = False
    with pytest.raises(ManifestError, match="only a non-read-only action"):
        load_manifest(data)


def test_a_manifest_without_timeseries_cannot_write():
    data = fx_write_manifest()
    del data["spec"]["timeseries"]
    del data["spec"]["schedule"]
    with pytest.raises(ManifestError, match="must be listed in spec.timeseries"):
        load_manifest(data)


async def test_points_cannot_name_another_measurement():
    up = fx_upstream()
    data = fx_write_manifest()
    data["spec"]["actions"]["refresh"]["timeseries"]["points"] = (
        "entries(steps.latest.rates)[].{measurement: 'cpu', name: 'cpu',"
        " tags: {quote: key}, fields: {rate: value}}"
    )
    sink = Sink()
    await engine(data, up).run_operation(
        "refresh", {}, Invocation({"FX_BASE": "EUR"}, NoSecrets(), sink)
    )
    assert sink.batches and all(line.startswith("fx_rate,") for line in sink.batches[0])


@pytest.mark.parametrize(
    "value",
    [
        "EUR\nevil,owner_id=victim rate=1",
        "EUR\r\nx",
        "EUR\\",
        "EU\\,R",
        "EUR\x00",
        "EUR\t",
        "",
        "x" * 257,
    ],
)
async def test_tag_injection_through_config_is_refused(value):
    up = fx_upstream()
    sink = Sink()
    data = fx_write_manifest()
    data["spec"]["actions"]["refresh"]["timeseries"]["tags"] = {
        "base": "config.FX_BASE"
    }
    eng = engine(data, up)
    with pytest.raises(MappingError, match="tag 'base'"):
        await eng.run_operation(
            "refresh", {}, Invocation({"FX_BASE": value}, NoSecrets(), sink)
        )
    assert sink.batches == []
    # The schedule's declared tags are checked the same way.
    sched = fx_manifest()
    sched["spec"]["schedule"]["tags"] = {"base": "config.FX_BASE"}
    with pytest.raises(MappingError):
        await engine(sched, up).run_schedule(inv({"FX_BASE": value}))


async def test_tag_separators_are_escaped_and_null_tags_left_out():
    up = fx_upstream()
    data = fx_write_manifest()
    tags = data["spec"]["actions"]["refresh"]["timeseries"]["tags"]
    tags.update({"base": "config.FX_BASE", "src": "config.FX_SYMBOLS"})
    sink = Sink()
    await engine(data, up).run_operation(
        "refresh", {}, Invocation({"FX_BASE": "E,U R=x"}, NoSecrets(), sink)
    )
    assert sink.batches[0][0] == "fx_rate,base=E\\,U\\ R\\=x,quote=USD rate=1.1"
    for bad in ({"a": 1}, ["EUR"]):
        with pytest.raises(MappingError, match="scalar"):
            await engine(data, up).run_operation(
                "refresh", {}, Invocation({"FX_BASE": bad}, NoSecrets(), Sink())
            )


async def test_point_tags_from_the_upstream_are_checked_too():
    up = Upstream()
    up.route(
        "api.frankfurter.app",
        "/latest",
        httpx.Response(200, json={"rates": {"US\nD": 1.0}}),
    )
    sink = Sink()
    with pytest.raises(MappingError, match="point tag"):
        await engine(fx_write_manifest(), up).run_operation(
            "refresh", {}, Invocation({"FX_BASE": "EUR"}, NoSecrets(), sink)
        )
    assert sink.batches == []


async def test_a_failed_write_mapping_reaches_error_output_with_now():
    up = fx_upstream()
    data = fx_write_manifest(
        error_output=(
            "{base: config.FX_BASE, rates: `{}`, influxdb_written: `false`,"
            " collected_at: now, kind: error.kind}"
        )
    )
    data["spec"]["actions"]["refresh"]["timeseries"]["tags"] = {
        "base": "config.FX_BASE"
    }
    sink = Sink()
    result = await engine(data, up, clock=lambda: FIXED_NOW).run_operation(
        "refresh", {}, Invocation({"FX_BASE": "E\nUR"}, NoSecrets(), sink)
    )
    assert result == {
        "base": "E\nUR",
        "rates": {},
        "influxdb_written": False,
        "collected_at": FIXED_ISO,
        "kind": "mapping",
    }
    assert sink.batches == []


async def test_schedule_declared_tags_come_first_and_win():
    up = fx_upstream()
    data = fx_manifest()
    data["spec"]["schedule"]["tags"] = {"base": "config.FX_BASE"}
    lines = await engine(data, up).run_schedule(inv({"FX_BASE": "TRY"}))
    # The points' own base="EUR" is overridden by the declared tag.
    assert lines == [
        "fx_rate,base=TRY,quote=USD rate=1.1",
        "fx_rate,base=TRY,quote=TRY rate=35.5",
    ]


def fx_vars_manifest() -> Dict:
    data = fx_manifest()
    op = data["spec"]["tools"]["convert"]
    op["vars"] = {
        "frm": "upper(trim(params.from_currency))",
        "to": "upper(trim(params.to_currency))",
        "none": "params.missing",
    }
    op["steps"][0]["when"] = "vars.frm != vars.to"
    op["steps"][0]["request"]["query"] = {
        "from": "{vars.frm}",
        "to": "{vars.to}",
        "x": "{vars.none}",
    }
    op["output"] = "{frm: vars.frm, to: vars.to, rate: steps.rate}"
    return data


async def test_vars_are_mapped_from_params_and_feed_placeholders():
    up = fx_upstream()
    eng = engine(fx_vars_manifest(), up)
    result = await eng.run_operation(
        "convert", {"amount": 1, "from_currency": " eur ", "to_currency": "usd"}, inv()
    )
    assert result["frm"] == "EUR" and result["to"] == "USD"
    assert result["rate"]["rates"] == {"USD": 1.1}
    params = up.requests[0].url.params
    # Encoded like any query value; a null var drops an optional parameter.
    assert (params["from"], params["to"], "x" in params) == ("EUR", "USD", False)


async def test_a_falsy_when_skips_the_step_without_a_request():
    up = fx_upstream()
    eng = engine(fx_vars_manifest(), up)
    result = await eng.run_operation(
        "convert", {"amount": 1, "from_currency": "eur", "to_currency": " EUR"}, inv()
    )
    assert result == {"frm": "EUR", "to": "EUR", "rate": None}
    assert up.requests == []


@pytest.mark.parametrize(
    "value, runs",
    [(None, False), (False, False), ("", False), ([], False), ({}, False)]
    + [(0, True), ("x", True), (True, True), ([0], True)],
)
async def test_when_uses_jmespath_truthiness(value, runs):
    up = fx_upstream()
    data = fx_manifest()
    step = data["spec"]["tools"]["convert"]["steps"][0]
    step["when"] = f"`{json.dumps(value)}`"
    data["spec"]["tools"]["convert"]["output"] = "steps.rate"
    params = {"amount": 1, "from_currency": "EUR", "to_currency": "USD"}
    await engine(data, up).run_operation("convert", params, inv())
    assert bool(up.requests) is runs


def test_vars_are_validated_at_load():
    data = fx_vars_manifest()
    data["spec"]["tools"]["convert"]["steps"][0]["request"]["query"][
        "y"
    ] = "{vars.undeclared}"
    with pytest.raises(ManifestError, match="not a declared var"):
        load_manifest(data)
    data = fx_vars_manifest()
    data["spec"]["tools"]["convert"]["vars"]["Bad-Name"] = "params.amount"
    with pytest.raises(ManifestError, match="not a valid var name"):
        load_manifest(data)
    data = fx_vars_manifest()
    data["spec"]["tools"]["convert"]["vars"]["bad"] = "params.["
    with pytest.raises(ManifestError, match="invalid JMESPath"):
        load_manifest(data)
    data = fx_vars_manifest()
    data["spec"]["tools"]["convert"]["steps"][0]["when"] = "params.["
    with pytest.raises(ManifestError, match="invalid JMESPath"):
        load_manifest(data)
    # Another operation's vars are not in scope, and a host stays config-only.
    data = fx_vars_manifest()
    data["spec"]["actions"]["refresh"]["steps"][0]["request"]["query"] = {
        "from": "{vars.frm}"
    }
    with pytest.raises(ManifestError, match="not a declared var"):
        load_manifest(data)
    data = fx_vars_manifest()
    data["spec"]["bases"]["api"]["url"] = "https://{vars.frm}.frankfurter.app"
    with pytest.raises(ManifestError):
        load_manifest(data)


async def test_vars_cannot_read_steps_or_secrets():
    up = fx_upstream()
    data = fx_vars_manifest()
    data["spec"]["config_schema"].append({"key": "API_TOKEN", "secret": True})
    data["spec"]["tools"]["convert"]["vars"]["seen"] = "{steps: steps, config: config}"
    data["spec"]["tools"]["convert"]["output"] = "vars.seen"
    result = await engine(data, up).run_operation(
        "convert",
        {"amount": 1, "from_currency": "EUR", "to_currency": "USD"},
        inv({"API_TOKEN": SECRET}, {"API_TOKEN": SECRET}),
    )
    assert result == {"steps": None, "config": {"FX_BASE": "EUR"}}


async def test_a_failing_var_reaches_error_output():
    up = fx_upstream()
    data = fx_vars_manifest()
    data["spec"]["tools"]["convert"]["vars"]["frm"] = "upper(params.amount)"
    data["spec"]["tools"]["convert"]["error_output"] = "{kind: error.kind}"
    result = await engine(data, up).run_operation(
        "convert", {"amount": 1, "from_currency": "EUR", "to_currency": "USD"}, inv()
    )
    assert result == {"kind": "mapping"} and up.requests == []


async def test_schedule_vars_feed_its_request():
    up = fx_upstream()
    data = fx_manifest()
    sched = data["spec"]["schedule"]
    sched["vars"] = {"base": "upper(trim(config.FX_BASE || 'EUR'))"}
    sched["steps"][0]["request"]["query"] = {"from": "{vars.base}"}
    sched["tags"] = {"base": "vars.base"}
    lines = await engine(data, up).run_schedule(inv({"FX_BASE": " try "}))
    assert up.requests[0].url.params["from"] == "TRY"
    assert lines[0] == "fx_rate,base=TRY,quote=USD rate=1.1"
