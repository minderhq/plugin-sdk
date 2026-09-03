"""influx helpers: the guard paths and the never-raise guarantee.

These run without a live InfluxDB — the guard branches return early, and the
"unreachable host" cases exercise the try/except that keeps a failed InfluxDB
call from ever crashing a plugin's collection loop.
"""

import asyncio
import re
from datetime import date

import httpx
import pytest

from minder_plugin_sdk import influx, latest_influx_date, write_history

SAFE = re.compile(r"^[A-Za-z0-9._-]+$")

CFG = {"host": "influx", "port": 8086, "token": "t", "bucket": "b", "org": "o"}


def _run(coro):
    return asyncio.run(coro)


def _fake_client(payload, *, capture=None):
    """Patch-in for httpx.AsyncClient that returns `payload` from .json() and,
    if `capture` is given, records the POST body into it."""

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
            if capture is not None:
                capture["url"] = url
                capture["content"] = content
                capture["json"] = json
            return _Resp()

    return _Client


def test_exports_are_wired():
    # re-exported at the top level and on the module
    assert latest_influx_date is influx.latest_influx_date
    assert write_history is influx.write_history


def test_latest_influx_date_no_cfg():
    assert (
        _run(
            latest_influx_date(
                http_timeout=1.0,
                cfg=None,
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="AAA",
            )
        )
        is None
    )


def test_latest_influx_date_unsafe_tag():
    # an unsafe tag value never reaches the network
    assert (
        _run(
            latest_influx_date(
                http_timeout=1.0,
                cfg={"host": "unused"},
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="bad code!",
            )
        )
        is None
    )


def test_write_history_off_or_empty():
    # no cfg -> 0, and empty points -> 0
    assert (
        _run(
            write_history(
                http_timeout=1.0,
                cfg=None,
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="AAA",
                field_name="price",
                points=[(1, 2.0)],
            )
        )
        == 0
    )
    assert (
        _run(
            write_history(
                http_timeout=1.0,
                cfg={"host": "unused"},
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="AAA",
                field_name="price",
                points=[],
            )
        )
        == 0
    )


def test_write_history_unsafe_tag():
    assert (
        _run(
            write_history(
                http_timeout=1.0,
                cfg={"host": "unused"},
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="bad!",
                field_name="price",
                points=[(1, 2.0)],
            )
        )
        == 0
    )


def test_never_raises_on_unreachable_influx():
    # cfg + safe value + an unreachable host: the call must degrade to None/0,
    # not propagate the connection error.
    cfg = {"host": "127.0.0.1", "port": 9, "token": "t", "bucket": "b", "org": "o"}
    assert (
        _run(
            latest_influx_date(
                http_timeout=0.5,
                cfg=cfg,
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="AAA",
            )
        )
        is None
    )
    assert (
        _run(
            write_history(
                http_timeout=0.5,
                cfg=cfg,
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="AAA",
                field_name="price",
                points=[(1, 2.0)],
            )
        )
        == 0
    )


# ── HTTP success paths (mocked httpx) ────────────────────────────────────────
def test_latest_influx_date_parses_iso_timestamp(monkeypatch):
    monkeypatch.setattr(
        httpx, "AsyncClient", _fake_client([{"t": "2021-01-05T00:00:00Z"}])
    )
    got = _run(
        latest_influx_date(
            http_timeout=1.0,
            cfg=CFG,
            safe_pattern=SAFE,
            measurement="m",
            tag_key="code",
            tag_value="AAA",
        )
    )
    assert got == date(2021, 1, 5)  # 'Z' stripped, date() extracted


@pytest.mark.parametrize(
    "payload",
    [
        [],  # empty result set
        [{"t": None}],  # null timestamp
        [{"nope": 1}],  # missing 't'
        ["not-a-dict"],  # unexpected row shape
        {"error": "boom"},  # a non-list 200 body
        [{"t": "not-a-date"}],  # present but unparseable → ValueError → None
    ],
)
def test_latest_influx_date_none_on_odd_shapes(monkeypatch, payload):
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(payload))
    assert (
        _run(
            latest_influx_date(
                http_timeout=1.0,
                cfg=CFG,
                safe_pattern=SAFE,
                measurement="m",
                tag_key="code",
                tag_value="AAA",
            )
        )
        is None
    )


def test_write_history_writes_line_protocol_and_counts(monkeypatch):
    cap = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, capture=cap))
    n = _run(
        write_history(
            http_timeout=1.0,
            cfg=CFG,
            safe_pattern=SAFE,
            measurement="price_hist",
            tag_key="symbol",
            tag_value="BTC-USD",
            field_name="close",
            points=[(100, 1.5), (200, 2.5)],
        )
    )
    assert n == 2  # returns the number of points written
    assert cap["url"].endswith("/api/v2/write")
    assert cap["content"] == (
        "price_hist,symbol=BTC-USD close=1.5 100\n"
        "price_hist,symbol=BTC-USD close=2.5 200"
    )
