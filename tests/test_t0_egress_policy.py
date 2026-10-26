"""egress_policy: save-time URL rules and the request-time
resolve-and-vet check. DNS is always mocked (``resolve_host``)."""

import pytest

from minder_t0_engine import egress_policy as ep
from minder_t0_engine.egress_policy import (
    EgressPolicyError,
    address_refused,
    assert_public_destination,
    validate_outbound_base_url,
)

# Refused in every mode: loopback, link-local/metadata, unspecified, multicast.
ALWAYS_REFUSED = [
    "http://127.0.0.1:8000/v1",
    "http://127.1.2.3/v1",
    "http://localhost:11434/v1",
    "http://api.localhost/v1",
    "http://[::1]:8000/v1",
    "http://169.254.169.254/latest/meta-data",
    "http://169.254.1.1/",
    "http://[fe80::1]/",
    "http://[fd00:ec2::254]/",
    "http://100.100.100.200/",
    "http://metadata.google.internal/computeMetadata/v1",
    "http://0.0.0.0:8005/",
    "http://0.1.2.3/",
    "http://[::]/",
    "http://224.0.0.1/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://2130706433/",  # 127.0.0.1 as a decimal integer
    "http://0x7f.1/",
    "http://[64:ff9b::7f00:1]/",  # NAT64 wrapping 127.0.0.1
    "http://[fe80::1%25eth0]:8000/",  # zone-scoped IPv6 literal
    "http://[2606:4700::1%25eth0]/",
    "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 wrapping 169.254.169.254
    # RFC 8215 local-use NAT64: low32 reads 8.8.8.8, but a /48 translator
    # maps it to 10.0.1.0 -- the whole /48 is refused.
    "http://[64:ff9b:1:a00:1:0:808:808]/",
    "http://ollama-router:11434/",
    # Minder's own services, refused even for a self-host is_local row.
    "http://minder-postgres:5432/",
    "http://minder-redis:6379/",
    "http://minder-api-gateway.example/",
    "http://postgres:5432/",
    "http://redis:6379/",
    "http://neo4j:7474/",
    "http://rabbitmq:15672/",
    "http://qdrant:6333/",
    "http://minio:9000/",
    "http://api-gateway:8000/",
]

# Refused unless allow_private (self-host + is_local).
PRIVATE = [
    "http://10.0.0.5:8000/v1",
    "http://172.16.0.1/v1",
    "http://192.168.1.50:11434/v1",
    "http://100.64.0.1/v1",
    "http://[fd00::1]/v1",
    "http://[::ffff:10.0.0.1]/v1",
    "http://vllm:8000/v1",  # single-label: a tenant's own compose service
    "http://ollama:11434/v1",  # the platform Ollama (inference) is allowed
    "http://minder-ollama:11434/v1",
    "http://host.docker.internal:8000/v1",  # Docker Desktop host: allowed
    "http://[64:ff9b::a00:1]/v1",  # NAT64 wrapping 10.0.0.1
    "http://gpu-box.lan:11434/v1",
    "http://node.tail1234.ts.net/v1",
]

PUBLIC = [
    "https://api.openai.com/v1",
    "https://api.z.ai/api/paas/v4",
    "https://openrouter.ai/api/v1",
    "http://8.8.8.8:8080/v1",
    "https://[2606:4700:4700::1111]/v1",
    "HTTPS://API.OPENAI.COM./v1",
]

MALFORMED = [
    "ftp://api.openai.com/v1",
    "file:///etc/passwd",
    "gopher://example.com/",
    "https://user:pass@api.openai.com/v1",
    "https://x-access-token:tok@api.openai.com/v1",
    "https://api.openai.com\\@evil.com/",
    "https://api.openai.com%40evil.com/",
    "https:///v1",
    "https://",
    "api.openai.com/v1",
    "http://[abc",
    "http://api.openai.com:0/",
    "http://api.openai.com:99999/",
    "http://api.openai.com:x/",
    "http://api.open ai.com/",
    "http://api.openai.com/\nHost: evil",
    "",
    "http://a..b/",
]


@pytest.mark.parametrize("allow_private", [False, True])
@pytest.mark.parametrize("url", ALWAYS_REFUSED + MALFORMED)
def test_always_refused(url, allow_private):
    with pytest.raises(EgressPolicyError):
        validate_outbound_base_url(url, allow_private=allow_private)


@pytest.mark.parametrize("url", PRIVATE)
def test_private_refused_unless_allowed(url):
    with pytest.raises(EgressPolicyError):
        validate_outbound_base_url(url, allow_private=False)
    assert validate_outbound_base_url(url, allow_private=True).host


@pytest.mark.parametrize("allow_private", [False, True])
@pytest.mark.parametrize("url", PUBLIC)
def test_public_allowed(url, allow_private):
    out = validate_outbound_base_url(url, allow_private=allow_private)
    assert out.scheme in ("http", "https")
    assert out.host == out.host.lower() and not out.host.endswith(".")


def test_normalized_fields():
    out = validate_outbound_base_url(
        "  HTTPS://API.OpenAI.com/v1  ", allow_private=False
    )
    assert (out.url, out.scheme, out.host, out.port) == (
        "HTTPS://API.OpenAI.com/v1",
        "https",
        "api.openai.com",
        443,
    )
    assert validate_outbound_base_url("http://8.8.8.8", allow_private=False).port == 80


def test_error_text_never_echoes_the_url():
    secret = "sk-SECRET123"
    with pytest.raises(EgressPolicyError) as e:
        validate_outbound_base_url(
            f"https://u:{secret}@169.254.169.254/", allow_private=False
        )
    assert secret not in str(e.value) and "169.254" not in str(e.value)


@pytest.mark.parametrize(
    "addr,private_ok,public_ok",
    [
        ("8.8.8.8", True, True),
        ("10.1.2.3", True, False),
        ("100.64.1.1", True, False),
        ("fd12::1", True, False),
        ("127.0.0.1", False, False),
        ("169.254.169.254", False, False),
        ("fd00:ec2::254", False, False),
        ("::", False, False),
        ("2002:7f00:1::", False, False),  # 6to4 wrapping 127.0.0.1
        ("64:ff9b::7f00:1", False, False),  # NAT64 wrapping 127.0.0.1
        ("64:ff9b::808:808", True, True),  # NAT64 wrapping 8.8.8.8
        ("64:ff9b:1:a00:1:0:808:808", False, False),  # local-use NAT64 /48
        ("64:ff9b:1::808:808", False, False),
        # Explicit tables, same answer on Python 3.12.3 and 3.13.
        ("::ffff:10.0.0.1", True, False),  # v4-mapped: judged as 10.0.0.1
        ("::ffff:8.8.8.8", True, True),
        ("2002:808:808::1", True, True),  # 6to4 wrapping 8.8.8.8
        ("2002:a00:1::1", True, False),  # 6to4 wrapping 10.0.0.1
        ("2001:0:4136:e378::1", False, False),  # Teredo
        ("::127.0.0.1", False, False),  # IPv4-compatible (deprecated)
        ("::1", False, False),
        ("fe80::1", False, False),
        ("ff02::1", False, False),
        ("2001:db8::1", True, False),  # documentation
        ("255.255.255.255", False, False),
        ("240.0.0.1", False, False),
        ("224.0.0.251", False, False),
        ("192.0.2.1", True, False),  # documentation
        ("2606:4700:4700::1111", True, True),
        ("::ffff:0:10.0.0.1", False, False),  # IPv4-translated (inside ::/8)
        ("100.100.100.200", False, False),
        ("168.63.129.16", False, False),
        ("0.1.2.3", False, False),
        ("100::1", False, False),
        ("fec0::1", False, False),
        ("198.18.0.1", True, False),
        ("198.51.100.1", True, False),
        ("203.0.113.1", True, False),
        ("192.0.0.1", True, False),
        ("192.88.99.1", True, False),  # 6to4 relay anycast: private-only
        ("2002:c058:6301::", True, False),  # 6to4 wrapping 192.88.99.1
        ("3fff::1", True, False),
        ("2001:2::1", True, False),
        ("2001:10::1", True, False),
        ("2001:20::1", True, False),
        ("5f00::1", True, False),
        ("not-an-ip", False, False),
    ],
)
def test_address_refused(addr, private_ok, public_ok):
    assert address_refused(addr, allow_private=True) is not private_ok
    assert address_refused(addr, allow_private=False) is not public_ok


def _resolver(mapping):
    async def fake(host, port):
        value = mapping[host]
        if isinstance(value, Exception):
            raise value
        return value

    return fake


@pytest.mark.asyncio
async def test_resolution_all_public_returns_addresses(monkeypatch):
    monkeypatch.setattr(
        ep, "resolve_host", _resolver({"api.example.com": ["1.1.1.1", "2606::1"]})
    )
    got = await assert_public_destination("api.example.com", allow_private=False)
    assert got == ["1.1.1.1", "2606::1"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer", [["1.1.1.1", "10.0.0.1"], ["169.254.169.254"], ["::1"], []]
)
async def test_resolution_any_bad_record_is_refused(monkeypatch, answer):
    monkeypatch.setattr(ep, "resolve_host", _resolver({"api.example.com": answer}))
    with pytest.raises(EgressPolicyError):
        await assert_public_destination("api.example.com", allow_private=False)


@pytest.mark.asyncio
async def test_resolution_private_allowed_only_with_allow_private(monkeypatch):
    monkeypatch.setattr(ep, "resolve_host", _resolver({"gpu.lan": ["192.168.1.9"]}))
    with pytest.raises(EgressPolicyError):
        await assert_public_destination("gpu.lan", allow_private=False)
    assert await assert_public_destination("gpu.lan", allow_private=True) == [
        "192.168.1.9"
    ]


@pytest.mark.asyncio
async def test_metadata_refused_even_with_allow_private(monkeypatch):
    monkeypatch.setattr(
        ep, "resolve_host", _resolver({"evil.example.com": ["169.254.169.254"]})
    )
    with pytest.raises(EgressPolicyError):
        await assert_public_destination("evil.example.com", allow_private=True)


@pytest.mark.asyncio
async def test_resolution_error_fails_closed_with_the_same_text(monkeypatch):
    monkeypatch.setattr(
        ep, "resolve_host", _resolver({"nx.example.com": OSError("NXDOMAIN")})
    )
    with pytest.raises(EgressPolicyError) as e:
        await assert_public_destination("nx.example.com", allow_private=False)
    assert str(e.value) == ep.REFUSED_DESTINATION


@pytest.mark.asyncio
async def test_ip_literal_is_not_resolved(monkeypatch):
    async def boom(host, port):  # pragma: no cover - must not be called
        raise AssertionError("resolved an IP literal")

    monkeypatch.setattr(ep, "resolve_host", boom)
    assert await assert_public_destination("8.8.8.8", allow_private=False) == [
        "8.8.8.8"
    ]
    with pytest.raises(EgressPolicyError):
        await assert_public_destination("10.0.0.1", allow_private=False)


@pytest.mark.parametrize(
    "host,refused",
    [
        ("localhost", True),
        ("api.localhost", True),
        ("metadata.google.internal", True),
        ("127.0.0.1", True),
        ("[::1]", True),
        ("169.254.169.254", True),
        ("64:ff9b::a9fe:a9fe", True),
        ("fe80::1%eth0", True),
        ("2130706433", True),
        ("", True),
        # the floor only: private ranges and platform names are left to callers
        ("minder-influxdb", False),
        ("influxdb", False),
        ("10.0.0.5", False),
        ("api.example.com", False),
    ],
)
def test_host_always_refused(host, refused):
    assert ep.host_always_refused(host) is refused
