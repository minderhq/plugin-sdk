"""safe_http: address classification, host allowlists, URL checks, IP pinning,
per-hop redirect re-checks, credential stripping and the body cap. DNS is
stubbed and HTTP goes through httpx.MockTransport, so no network is used."""

import asyncio

import httpx
import pytest

from minder_plugin_sdk import UnsafeURLError
from minder_plugin_sdk import safe_http
from minder_plugin_sdk.safe_http import (
    check_url,
    host_allowed,
    is_public_address,
    safe_request,
)

DNS = {
    "public.example": ["93.184.216.34"],
    "other.example": ["93.184.216.35"],
    "v6.example": ["2606:2800:220:1:248:1893:25c8:1946"],
    "internal.example": ["10.0.0.5"],
    "mixed.example": ["93.184.216.34", "127.0.0.1"],
    "metadata.example": ["169.254.169.254"],
}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    async def resolve(host, port):
        if host not in DNS:
            raise OSError("nxdomain")
        return DNS[host]

    monkeypatch.setattr(safe_http, "_resolve", resolve)


def run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize(
    "ip, public",
    [
        ("93.184.216.34", True),
        ("2606:2800:220:1:248:1893:25c8:1946", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("fd00::1", False),
        ("fe80::1", False),
        ("::ffff:127.0.0.1", False),
        ("::ffff:93.184.216.34", True),
        ("64:ff9b::7f00:1", False),  # NAT64 → 127.0.0.1
        ("2002:a00:1::", False),  # 6to4 → 10.0.0.1
    ],
)
def test_is_public_address(ip, public):
    assert is_public_address(ip) is public


def test_host_allowed():
    pats = ["api.example.com", "*.example.org"]
    assert host_allowed("api.example.com", pats)
    assert host_allowed("API.example.com.", pats)
    assert host_allowed("a.b.example.org", pats)
    assert not host_allowed("example.org", pats)  # wildcard excludes the apex
    assert not host_allowed("evilexample.org", pats)
    assert not host_allowed("example.com", pats)


@pytest.mark.parametrize(
    "url, fragment",
    [
        ("ftp://public.example/x", "scheme 'ftp'"),
        ("file:///etc/passwd", "scheme 'file'"),
        ("http:///nohost", "no host"),
        ("http://user:pw@public.example/", "embedded credentials"),
        ("http://public.example:99999/", "invalid port"),
        ("http://internal.example/", "non-public"),
        ("http://mixed.example/", "non-public"),
        ("http://metadata.example/latest/meta-data", "non-public"),
        ("http://127.0.0.1/", "non-public"),
        ("http://[::1]/", "non-public"),
        ("http://unknown.example/", "cannot resolve"),
    ],
)
def test_check_url_refuses(url, fragment):
    with pytest.raises(UnsafeURLError, match=fragment):
        run(check_url(url))


def test_check_url_allowlist_and_keywords():
    assert run(check_url("https://public.example/x")) == (
        "public.example",
        "93.184.216.34",
    )
    with pytest.raises(UnsafeURLError, match="not in the allowed hosts"):
        run(check_url("https://public.example/", ["api.example.com"]))
    # an EGRESS keyword string means "no host allowlist"
    assert run(check_url("https://public.example/", "public"))[0] == "public.example"
    assert run(check_url("http://93.184.216.34/"))[1] == "93.184.216.34"


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_request_is_pinned_to_the_checked_address():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    async def go():
        async with _client(handler) as c:
            return await safe_request(
                "GET", "https://public.example/a?q=1", client=c, params={"p": "2"}
            )

    resp = run(go())
    assert resp.is_success and resp.json() == {"ok": True}
    assert resp.url == "https://public.example/a?q=1"
    req = seen[0]
    assert req.url.host == "93.184.216.34"
    assert req.headers["host"] == "public.example"
    assert req.extensions["sni_hostname"] == "public.example"
    assert req.url.params["p"] == "2"


def test_ipv6_pin():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text="hi")

    async def go():
        async with _client(handler) as c:
            return await safe_request("GET", "http://v6.example/", client=c)

    assert run(go()).text == "hi"
    assert seen[0].url.host == "2606:2800:220:1:248:1893:25c8:1946"
    assert "sni_hostname" not in seen[0].extensions  # plain http


def test_redirect_hops_are_rechecked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://internal.example/"})

    async def go():
        async with _client(handler) as c:
            return await safe_request("GET", "http://public.example/", client=c)

    with pytest.raises(UnsafeURLError, match="non-public"):
        run(go())


def test_redirect_followed_and_credentials_stripped_cross_host():
    seen = []

    def handler(request):
        seen.append(request)
        if request.headers["host"] == "public.example":
            return httpx.Response(301, headers={"location": "http://other.example/z"})
        return httpx.Response(200, text="done")

    async def go():
        async with _client(handler) as c:
            return await safe_request(
                "GET",
                "http://public.example/",
                client=c,
                headers={"Authorization": "Bearer t", "X-Keep": "1"},
            )

    resp = run(go())
    assert resp.text == "done" and resp.url == "http://other.example/z"
    assert seen[0].headers["authorization"] == "Bearer t"
    assert "authorization" not in seen[1].headers
    assert seen[1].headers["x-keep"] == "1"
    assert seen[1].url.host == "93.184.216.35"


def test_redirect_limit():
    def handler(request):
        return httpx.Response(302, headers={"location": "/again"})

    async def go():
        async with _client(handler) as c:
            return await safe_request(
                "GET", "http://public.example/", client=c, max_redirects=2
            )

    with pytest.raises(UnsafeURLError, match="more than 2 redirects"):
        run(go())


def test_post_does_not_follow_redirects():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://internal.example/"})

    async def go():
        async with _client(handler) as c:
            return await safe_request(
                "POST", "http://public.example/", client=c, json_body={"a": 1}
            )

    assert run(go()).status_code == 302


@pytest.mark.parametrize("declared", [True, False])
def test_body_cap(declared):
    body = b"x" * 2048

    async def chunks():
        yield body[:1024]
        yield body[1024:]

    def handler(request):
        if declared:
            return httpx.Response(200, content=body)
        return httpx.Response(200, content=chunks())  # no content-length

    async def go():
        async with _client(handler) as c:
            return await safe_request(
                "GET", "http://public.example/", client=c, max_bytes=1500
            )

    with pytest.raises(UnsafeURLError, match="exceeds 1500 bytes"):
        run(go())


def test_owned_client_refuses_before_any_connection():
    # no client passed: the URL check fails before a connection is attempted
    with pytest.raises(UnsafeURLError):
        run(safe_request("GET", "http://internal.example/"))
