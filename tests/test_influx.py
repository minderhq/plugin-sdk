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

from minder_plugin_sdk import (
    escape_tag,
    influx,
    latest_influx_date,
    line_protocol,
    write_history,
)

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


# ── escape_tag / line_protocol builders ──────────────────────────────────────
def test_escape_tag_escapes_comma_equals_space_only():
    assert escape_tag("a,b=c d") == "a\\,b\\=c\\ d"
    assert escape_tag("owner/repo") == "owner/repo"  # slash is legal, untouched
    assert escape_tag("plain") == "plain"


def test_line_protocol_formats_int_float_bool_and_drops_none():
    line = line_protocol(
        "m",
        {"host": "a b"},  # tag with a space → escaped
        {"i": 5, "f": 1.5, "b": True, "gone": None},
        ts=100,
    )
    assert line == "m,host=a\\ b i=5i,f=1.5,b=true 100"


def test_line_protocol_quotes_string_fields():
    assert line_protocol("m", {}, {"s": 'he said "hi"'}) == 'm s="he said \\"hi\\""'


def test_line_protocol_empty_when_all_fields_none():
    assert line_protocol("m", {"t": "x"}, {"a": None, "b": None}) == ""


def test_line_protocol_omits_timestamp_when_not_given():
    assert line_protocol("m", {"t": "x"}, {"v": 3}) == "m,t=x v=3i"


def test_line_protocol_matches_hand_rolled_github_line():
    # the exact shape the github plugin emits, now via the shared builder
    line = line_protocol(
        "github_repo",
        {"repo": "owner/repo"},
        {"stars": 5, "forks": 2, "open_issues": 1},
    )
    assert line == "github_repo,repo=owner/repo stars=5i,forks=2i,open_issues=1i"


def test_line_protocol_escapes_measurement():
    assert line_protocol("a b,c", {"t": "x"}, {"v": 1}) == "a\\ b\\,c,t=x v=1i"


def test_line_protocol_drops_nan_and_inf_fields():
    assert line_protocol("m", {"t": "x"}, {"a": float("nan"), "b": 2}) == "m,t=x b=2i"
    assert line_protocol("m", {"t": "x"}, {"a": float("inf")}) == ""


def test_latest_influx_date_guard_uses_fullmatch(monkeypatch):
    # a caller pattern that isn't end-anchored must NOT let an injection prefix pass
    loose = re.compile(r"[A-Za-z0-9]+")
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client([{"t": "2021-01-01"}]))
    got = _run(
        latest_influx_date(
            http_timeout=1.0,
            cfg=CFG,
            safe_pattern=loose,
            measurement="m",
            tag_key="s",
            tag_value="AAA'; DROP TABLE x",
        )
    )
    assert got is None  # blocked by fullmatch (was allowed by prefix .match)


def test_write_history_skips_nan_point_not_whole_batch(monkeypatch):
    cap = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client({}, capture=cap))
    n = _run(
        write_history(
            http_timeout=1.0,
            cfg=CFG,
            safe_pattern=SAFE,
            measurement="fund",
            tag_key="code",
            tag_value="YAC",
            field_name="price",
            points=[(100, 1.5), (200, float("nan")), (300, 2.5)],
        )
    )
    assert n == 2  # the nan point is dropped, the other two still written
    assert "nan" not in cap["content"] and cap["content"].count("\n") == 1


def test_write_history_drops_non_finite_points():
    # cfg + points are present, but every value is non-finite, so line_protocol
    # drops them all -> no lines -> 0 (one bad point can't 400 the whole batch).
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
                points=[(1, float("nan")), (2, float("inf"))],
            )
        )
        == 0
    )
