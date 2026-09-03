"""InfluxDB write / resume helpers for per-tag daily time-series plugins.

Plugins that backfill one numeric value per day per symbol/code/id into
InfluxDB (price history, fund NAV, …) share the same resume-then-write logic;
only the measurement name, tag key, and field name differ. These two helpers
factor that out — a plugin keeps a thin wrapper that fills in its own
measurement/tag/field and delegates here.

Both helpers **never raise**: a failed InfluxDB call degrades to "no resume
point" / "nothing written", never a crash that would abort the plugin's whole
collection loop.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from re import Pattern
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


async def latest_influx_date(
    *,
    http_timeout: float,
    cfg: Optional[Dict[str, Any]],
    safe_pattern: Pattern[str],
    measurement: str,
    tag_key: str,
    tag_value: str,
) -> Optional[date]:
    """Latest day already stored for ``tag_value`` (InfluxDB v3 SQL query), or
    ``None`` if empty/unavailable. Never raises — a resume-query failure
    degrades to "no resume point" (the caller backfills from scratch)."""
    import httpx  # lazy: keep `import minder_plugin_sdk` working without httpx

    if not cfg:
        return None
    if not safe_pattern.match(tag_value):
        logger.warning(f"Skipping influx resume for unsafe {tag_key}: {tag_value!r}")
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
    if not t:
        return None
    try:
        return datetime.fromisoformat(str(t).replace("Z", "")).date()
    except ValueError:
        return None


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
) -> int:
    """Write ``[(ts, value)]`` to InfluxDB under ``field_name``; return the count
    written (0 if the sink is off/unconfigured, ``points`` is empty, or the
    write fails)."""
    import httpx  # lazy: keep `import minder_plugin_sdk` working without httpx

    if not (cfg and points):
        return 0
    if not safe_pattern.match(tag_value):
        logger.warning(f"Skipping influx write for unsafe {tag_key}: {tag_value!r}")
        return 0
    host, port = cfg.get("host", "minder-influxdb"), cfg.get("port", 8086)
    org, bucket = cfg.get("org", "minder"), cfg.get("bucket", "minder-metrics")
    lines = "\n".join(
        f"{measurement},{tag_key}={tag_value} {field_name}={value} {ts}"
        for ts, value in points
    )
    try:
        async with httpx.AsyncClient(timeout=http_timeout) as client:
            resp = await client.post(
                f"http://{host}:{port}/api/v2/write",
                params={"org": org, "bucket": bucket, "precision": "s"},
                headers={"Authorization": f"Token {cfg.get('token', '')}"},
                content=lines,
            )
            resp.raise_for_status()
        return len(points)
    except Exception as e:
        logger.warning(f"InfluxDB write failed for {tag_value}: {type(e).__name__}")
        return 0
