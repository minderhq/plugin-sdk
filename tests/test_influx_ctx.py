"""influx helpers with a platform context: a bound context that grants the
time-series capability routes through ``ctx.timeseries`` and never contacts
InfluxDB; no context / the unbound context / no grant keeps the direct path."""

import asyncio
import re
from datetime import date

import httpx
import pytest

from minder_plugin_sdk import (
    UNBOUND_CONTEXT,
    FakePlatformContext,
    latest_influx_date,
    write_history,
)
from minder_plugin_sdk.context import (
    CAP_TIMESERIES_LATEST,
    CAP_TIMESERIES_WRITE,
    HOST_CAPABILITIES,
    PlatformContext,
)

SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
CFG = {"host": "influx", "port": 8086, "token": "t", "bucket": "b", "org": "o"}
GRANTED = {"timeseries.*"}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def no_influx(monkeypatch):
    """Fail the test if anything opens an HTTP client."""

    class _Forbidden:
        def __init__(self, *a, **k):
            raise AssertionError("InfluxDB must not be contacted")

    monkeypatch.setattr(httpx, "AsyncClient", _Forbidden)


def _capturing_client(capture, payload=None):
    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None, params=None, content=None):
            capture.append({"url": url, "content": content, "json": json})
            return _Resp()

    return _Client


def _write(ctx, cfg=None, points=((1700000000, 1.5), (1700086400, 2.5))):
    return _run(
        write_history(
            http_timeout=1.0,
            cfg=cfg,
            safe_pattern=SAFE,
            measurement="m",
            tag_key="code",
            tag_value="AAA",
            field_name="price",
            points=list(points),
            ctx=ctx,
        )
    )


def _latest(ctx, cfg=None, tag_value="AAA"):
    return _run(
        latest_influx_date(
            http_timeout=1.0,
            cfg=cfg,
            safe_pattern=SAFE,
            measurement="m",
            tag_key="code",
            tag_value=tag_value,
            ctx=ctx,
        )
    )


# ── protocol ─────────────────────────────────────────────────────────────────
def test_timeseries_is_part_of_the_context_protocol():
    assert CAP_TIMESERIES_WRITE == "timeseries.write"
    assert CAP_TIMESERIES_LATEST == "timeseries.latest"
    assert {CAP_TIMESERIES_WRITE, CAP_TIMESERIES_LATEST} <= HOST_CAPABILITIES
    assert isinstance(FakePlatformContext(), PlatformContext)
    assert isinstance(UNBOUND_CONTEXT, PlatformContext)


def test_unbound_timeseries_raises_unavailable():
    from minder_plugin_sdk import CapabilityUnavailable

    with pytest.raises(CapabilityUnavailable):
        _run(UNBOUND_CONTEXT.timeseries.write("m v=1"))
    with pytest.raises(CapabilityUnavailable):
        _run(UNBOUND_CONTEXT.timeseries.latest("m", "code", "AAA"))


def test_fake_for_plugin_grants_timeseries_when_declared():
    class _P:
        TIMESERIES = {"measurements": ["m"]}

    assert FakePlatformContext.for_plugin(_P()).has(CAP_TIMESERIES_WRITE)

    class _Q(_P):
        TIMESERIES = None

    assert not FakePlatformContext.for_plugin(_Q()).has(CAP_TIMESERIES_WRITE)


def test_fake_latest_with_fields():
    ctx = FakePlatformContext(
        timeseries_latest={
            ("m", "code", "AAA"): {"time": "2024-01-02T00:00:00Z", "fields": {"v": 1}}
        }
    )
    got = _run(ctx.timeseries.latest("m", "code", "AAA", fields=["v", "w"]))
    assert got == {"time": "2024-01-02T00:00:00Z", "fields": {"v": 1, "w": None}}
    assert _run(ctx.timeseries.latest("m", "code", "AAA")) == "2024-01-02T00:00:00Z"
    assert _run(ctx.timeseries.latest("m", "code", "BBB")) is None


# ── bound + granted: through ctx.timeseries, never InfluxDB ──────────────────
def test_write_history_routes_through_ctx(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)
    # cfg present too: the context still wins, InfluxDB is not contacted
    assert _write(ctx, cfg=CFG) == 2
    assert ctx.timeseries_lines == [
        "m,code=AAA price=1.5 1700000000",
        "m,code=AAA price=2.5 1700086400",
    ]
    (call,) = ctx.called(CAP_TIMESERIES_WRITE)
    assert call.args == {"lines": 2, "precision": "s"}


def test_write_history_through_ctx_needs_no_cfg(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)
    assert _write(ctx, cfg=None) == 2


def test_write_history_through_ctx_drops_non_finite(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)
    assert _write(ctx, points=[(1, float("nan")), (2, 3.0)]) == 1
    assert ctx.timeseries_lines == ["m,code=AAA price=3.0 2"]


def test_write_history_through_ctx_guards_still_apply(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)
    assert _write(ctx, points=[]) == 0
    assert (
        _run(
            write_history(
                http_timeout=1.0,
                cfg=None,
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="bad tag",
                field_name="price",
                points=[(1, 1.0)],
                ctx=ctx,
            )
        )
        == 0
    )
    assert ctx.calls == []


@pytest.mark.parametrize("failure", ["denied", "unavailable"])
def test_write_history_through_ctx_never_raises(no_influx, failure):
    ctx = FakePlatformContext(grants=GRANTED, **{failure: [CAP_TIMESERIES_WRITE]})
    # has() is False for a denied/unavailable capability -> falls back, and
    # with no cfg the fallback writes nothing
    assert _write(ctx) == 0


def test_write_history_through_ctx_swallows_call_errors(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)

    async def boom(lines, precision="s"):
        raise RuntimeError("platform down")

    ctx.timeseries.write = boom  # type: ignore[method-assign]
    assert _write(ctx, cfg=CFG) == 0


def test_latest_influx_date_routes_through_ctx(no_influx):
    ctx = FakePlatformContext(
        grants=GRANTED,
        timeseries_latest={("m", "code", "AAA"): "2024-03-05T00:00:00Z"},
    )
    assert _latest(ctx, cfg=CFG) == date(2024, 3, 5)
    (call,) = ctx.called(CAP_TIMESERIES_LATEST)
    assert call.args["measurement"] == "m"
    assert call.args["tag_key"] == "code"
    assert call.args["tag_value"] == "AAA"


def test_latest_influx_date_through_ctx_empty_series(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)
    assert _latest(ctx) is None


def test_latest_influx_date_through_ctx_accepts_point_shape(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)

    async def latest(measurement, tag_key, tag_value, fields=None):
        return {"time": "2024-03-06T12:00:00", "fields": {}}

    ctx.timeseries.latest = latest  # type: ignore[method-assign]
    assert _latest(ctx) == date(2024, 3, 6)


def test_latest_influx_date_through_ctx_never_raises(no_influx):
    ctx = FakePlatformContext(grants=GRANTED)

    async def boom(*a, **k):
        raise RuntimeError("platform down")

    ctx.timeseries.latest = boom  # type: ignore[method-assign]
    assert _latest(ctx) is None
    ok = FakePlatformContext(
        grants=GRANTED, timeseries_latest={("m", "code", "AAA"): "not a date"}
    )
    assert _latest(ok) is None
    assert _latest(ok, tag_value="bad tag") is None


# ── unbound / not granted: the direct InfluxDB path, unchanged ───────────────
@pytest.mark.parametrize(
    "ctx",
    [None, UNBOUND_CONTEXT, "ungranted"],
    ids=["no-ctx", "unbound", "ungranted"],
)
def test_write_history_falls_back_to_influx(monkeypatch, ctx):
    if ctx == "ungranted":
        ctx = FakePlatformContext(grants={"secrets.read"})
    posted: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _capturing_client(posted))
    assert _write(ctx, cfg=CFG) == 2
    (req,) = posted
    assert req["url"] == "http://influx:8086/api/v2/write"
    assert req["content"].splitlines()[0] == "m,code=AAA price=1.5 1700000000"
    if isinstance(ctx, FakePlatformContext):
        assert ctx.called(CAP_TIMESERIES_WRITE) == []
    # and without cfg the fallback is still "sink off"
    assert _write(ctx, cfg=None) == 0


@pytest.mark.parametrize(
    "ctx",
    [None, UNBOUND_CONTEXT, "ungranted"],
    ids=["no-ctx", "unbound", "ungranted"],
)
def test_latest_influx_date_falls_back_to_influx(monkeypatch, ctx):
    if ctx == "ungranted":
        ctx = FakePlatformContext(grants={"secrets.read"})
    posted: list = []
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        _capturing_client(posted, payload=[{"t": "2024-01-02T00:00:00Z"}]),
    )
    assert _latest(ctx, cfg=CFG) == date(2024, 1, 2)
    (req,) = posted
    assert req["url"] == "http://influx:8086/api/v3/query_sql"
    if isinstance(ctx, FakePlatformContext):
        assert ctx.called(CAP_TIMESERIES_LATEST) == []
    assert _latest(ctx, cfg=None) is None
