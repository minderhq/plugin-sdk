"""InfluxDB write / resume helpers for per-tag daily time-series plugins.

Plugins that backfill one numeric value per day per symbol/code/id into
InfluxDB (price history, fund NAV, …) share the same resume-then-write logic;
only the measurement name, tag key, and field name differ. These two helpers
factor that out — a plugin keeps a thin wrapper that fills in its own
measurement/tag/field and delegates here.

Both helpers take an optional ``ctx`` (pass ``self.ctx``). When that platform
context grants the time-series capability (the plugin declares ``TIMESERIES``),
the helpers go through ``ctx.timeseries`` and never contact InfluxDB: a plugin
hosted out of process has no store credentials and cannot reach it. Otherwise
(no ``ctx``, the unbound context, or no grant) they talk to InfluxDB directly
with ``cfg``, exactly as before.

Both helpers **never raise**: a failed InfluxDB or platform call degrades to "no
resume point" / "nothing written", never a crash that would abort the plugin's
whole collection loop.
"""

from __future__ import annotations

import logging
import math
from datetime import date, datetime
from re import Pattern
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .context import (
    CAP_TIMESERIES_LATEST,
    CAP_TIMESERIES_WRITE,
    PlatformContext,
    TimeseriesAPI,
)

logger = logging.getLogger(__name__)

_TAG_ESCAPES = ((",", "\\,"), ("=", "\\="), (" ", "\\ "))


def escape_tag(value: str) -> str:
    """Escape a value for an InfluxDB line-protocol **tag key or value**: comma,
    equals and space must be backslash-escaped or they corrupt the tag set — a
    config-sourced tag (a feed name, a location, an ``owner/repo``) can contain
    any of them. Backslash itself is NOT escaped; it is the escape character."""
    for ch, rep in _TAG_ESCAPES:
        value = value.replace(ch, rep)
    return value


def _format_field(value: Any) -> Optional[str]:
    """Format one field value for line protocol, or ``None`` to drop it. Ints get
    the ``i`` suffix (InfluxDB integer), floats stay bare, bools become
    true/false, strings are quoted; ``None`` is dropped so a missing reading just
    omits that field. bool is checked before int (bool is an int subclass)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return f"{value}i"
    if isinstance(value, float):
        # nan/inf are not valid line protocol — drop rather than 400 the whole batch
        return repr(value) if math.isfinite(value) else None
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def line_protocol(
    measurement: str,
    tags: Mapping[str, Any],
    fields: Mapping[str, Any],
    ts: Optional[int] = None,
) -> str:
    """Build ONE InfluxDB line-protocol line — tags escaped, int/float/bool/str
    fields formatted, ``None`` fields dropped. Returns ``""`` when no field
    survives (an all-empty reading is not a valid point). Centralises the escaping
    every hand-rolled writer needs (news/weather/github), so a tag carrying a
    comma or equals can't silently corrupt the series."""
    tag_str = "".join(
        f",{escape_tag(str(k))}={escape_tag(str(v))}" for k, v in tags.items()
    )
    parts = []
    for k, v in fields.items():
        formatted = _format_field(v)
        if formatted is not None:
            parts.append(f"{escape_tag(str(k))}={formatted}")
    if not parts:
        return ""
    meas = str(measurement).replace(",", "\\,").replace(" ", "\\ ")
    line = f"{meas}{tag_str} {','.join(parts)}"
    if ts is not None:
        line += f" {ts}"
    return line


def _timeseries(
    ctx: Optional[PlatformContext], capability: str
) -> Optional[TimeseriesAPI]:
    """``ctx.timeseries`` when ``ctx`` is bound and grants ``capability``, else
    ``None`` (the caller falls back to direct InfluxDB). The unbound context's
    ``has()`` is always ``False``, so it falls back too."""
    if ctx is None:
        return None
    try:
        granted = ctx.has(capability)
    except Exception:
        return None
    return getattr(ctx, "timeseries", None) if granted else None


def _parse_day(t: Any) -> Optional[date]:
    if not t:
        return None
    try:
        return datetime.fromisoformat(str(t).replace("Z", "")).date()
    except ValueError:
        return None


async def latest_influx_date(
    *,
    http_timeout: float,
    cfg: Optional[Dict[str, Any]],
    safe_pattern: Pattern[str],
    measurement: str,
    tag_key: str,
    tag_value: str,
    ctx: Optional[PlatformContext] = None,
) -> Optional[date]:
    """Latest day already stored for ``tag_value``, or ``None`` if
    empty/unavailable. Through ``ctx.timeseries.latest`` when ``ctx`` grants
    ``timeseries.latest`` (``cfg`` is then unused), else an InfluxDB v3 SQL
    query. Never raises — a resume-query failure degrades to "no resume point"
    (the caller backfills from scratch)."""
    api = _timeseries(ctx, CAP_TIMESERIES_LATEST)
    if api is None and not cfg:
        return None
    if not safe_pattern.fullmatch(tag_value):
        logger.warning(f"Skipping influx resume for unsafe {tag_key}: {tag_value!r}")
        return None
    if api is not None:
        try:
            latest = await api.latest(measurement, tag_key, tag_value)
        except Exception as e:
            logger.warning(
                f"Time-series resume query failed for {tag_value}: "
                f"{type(e).__name__}"
            )
            return None
        if isinstance(latest, dict):
            latest = latest.get("time")
        return _parse_day(latest)

    import httpx  # lazy: keep `import minder_plugin_sdk` working without httpx

    if not cfg:  # narrows the type; already checked above
        return None
    host, port = cfg.get("host", "minder-influxdb"), cfg.get("port", 8086)
    db = cfg.get("bucket", "minder-metrics")
    q = f"SELECT max(time) AS t FROM {measurement} WHERE {tag_key} = '{tag_value}'"
    try:
        async with httpx.AsyncClient(timeout=http_timeout) as client:
            resp = await client.post(
                f"http://{host}:{port}/api/v3/query_sql",
                json={"db": db, "q": q, "format": "json"},
                headers={"Authorization": f"Token {cfg.get('token', '')}"},
            )
            resp.raise_for_status()
            rows: Any = resp.json() or []
    except Exception as e:
        logger.warning(
            f"InfluxDB resume query failed for {tag_value}: {type(e).__name__}"
        )
        return None
    # `rows` is assumed to be a bare JSON array of row objects; a differently
    # shaped 200 body (an error/status object, or array-encoded rows) would
    # otherwise raise here and abort every remaining tag in the caller's loop.
    t = (
        rows[0].get("t")
        if isinstance(rows, list) and rows and isinstance(rows[0], dict)
        else None
    )
    return _parse_day(t)


async def write_history(
    *,
    http_timeout: float,
    cfg: Optional[Dict[str, Any]],
    safe_pattern: Pattern[str],
    measurement: str,
    tag_key: str,
    tag_value: str,
    field_name: str,
    points: List[Tuple[int, float]],
    ctx: Optional[PlatformContext] = None,
) -> int:
    """Write ``[(ts, value)]`` (``ts`` in seconds) under ``field_name``; return
    the count written (0 if the sink is off/unconfigured, ``points`` is empty, or
    the write fails). Through ``ctx.timeseries.write`` when ``ctx`` grants
    ``timeseries.write`` (``cfg`` is then unused), else straight to InfluxDB."""
    if not points:
        return 0
    api = _timeseries(ctx, CAP_TIMESERIES_WRITE)
    if api is None and not cfg:
        return 0
    if not safe_pattern.fullmatch(tag_value):
        logger.warning(f"Skipping influx write for unsafe {tag_key}: {tag_value!r}")
        return 0
    # Build each point through line_protocol: it escapes the measurement / tag /
    # field key and DROPS a non-finite (nan/inf) value — one bad point can no
    # longer 400 the whole batch and stall an incremental resume.
    lines = [
        ln
        for ts, value in points
        if (
            ln := line_protocol(
                measurement, {tag_key: tag_value}, {field_name: value}, ts
            )
        )
    ]
    if not lines:
        return 0
    if api is not None:
        try:
            return int(await api.write(lines, precision="s"))
        except Exception as e:
            logger.warning(
                f"Time-series write failed for {tag_value}: {type(e).__name__}"
            )
            return 0

    import httpx  # lazy: keep `import minder_plugin_sdk` working without httpx

    if not cfg:  # narrows the type; already checked above
        return 0
    host, port = cfg.get("host", "minder-influxdb"), cfg.get("port", 8086)
    org, bucket = cfg.get("org", "minder"), cfg.get("bucket", "minder-metrics")
    try:
        async with httpx.AsyncClient(timeout=http_timeout) as client:
            resp = await client.post(
                f"http://{host}:{port}/api/v2/write",
                params={"org": org, "bucket": bucket, "precision": "s"},
                headers={"Authorization": f"Token {cfg.get('token', '')}"},
                content="\n".join(lines),
            )
            resp.raise_for_status()
        return len(lines)
    except Exception as e:
        logger.warning(f"InfluxDB write failed for {tag_value}: {type(e).__name__}")
        return 0
