"""influx helpers: the guard paths and the never-raise guarantee.

These run without a live InfluxDB — the guard branches return early, and the
"unreachable host" cases exercise the try/except that keeps a failed InfluxDB
call from ever crashing a plugin's collection loop.
"""

import asyncio
import re

from minder_plugin_sdk import influx, latest_influx_date, write_history

SAFE = re.compile(r"^[A-Za-z0-9._-]+$")


def _run(coro):
    return asyncio.run(coro)


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
