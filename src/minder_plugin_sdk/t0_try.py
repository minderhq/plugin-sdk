"""``minder-plugin try``: run one operation of a T0 manifest locally.

It uses the same engine (``minder_t0_engine``) and the same egress rules as
Minder's declarative runner, so the output an author sees here is what the
runner produces.

- **Live:** real DNS and real upstream calls, under the manifest's egress rules.
- ``--record DIR``: live, and every upstream response is saved to ``DIR``.
- ``--replay DIR``: no network at all. Responses come from ``DIR``; a request
  that was not recorded fails. Host, scheme, path and redirect rules still
  apply. DNS is not used, so address checks (private / metadata IPs) are
  only exercised in live and record mode.

Needs the ``t0`` extra: ``pip install 'minder-plugin-sdk[t0]'``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

# A public address (example.com) that replay never connects to; it only lets
# the egress address check and IP pinning proceed offline.
_REPLAY_ADDRESS = "93.184.215.14"

# Hop-by-hop and encoding headers would not match the stored (already decoded)
# body on replay; cookies are never stored.
_DROPPED_HEADERS = frozenset(
    {
        "content-encoding",
        "transfer-encoding",
        "content-length",
        "connection",
        "set-cookie",
    }
)


def _key(method: str, host: str, target: str) -> str:
    raw = f"{method.upper()} {host.lower()} {target}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _load_manifest_file(path: Path) -> Mapping[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
    else:
        import yaml  # the yaml extra; a T0 manifest is usually YAML

        data = yaml.safe_load(text)
    if not isinstance(data, Mapping):
        raise ValueError(f"{path}: a manifest must be a mapping")
    return data


class _Secrets:
    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    async def get(self, key: str) -> Optional[str]:
        return self._values.get(key)


def _transport(mode: str, directory: Optional[Path]) -> Any:
    import httpx

    def target(request: "httpx.Request") -> str:
        return request.url.raw_path.decode("ascii")

    def host(request: "httpx.Request") -> str:
        return str(request.headers.get("host", request.url.host))

    if mode == "replay":
        assert directory is not None

        async def serve(request: "httpx.Request") -> "httpx.Response":
            path = (
                directory
                / f"{_key(request.method, host(request), target(request))}.json"
            )
            if not path.is_file():
                raise RuntimeError(
                    f"not recorded: {request.method} {host(request)}{target(request)}"
                )
            rec = json.loads(path.read_text(encoding="utf-8"))
            return httpx.Response(
                rec["status"],
                headers=rec["headers"],
                content=base64.b64decode(rec["body_b64"]),
            )

        return httpx.MockTransport(serve)

    real = httpx.AsyncHTTPTransport()
    if mode != "record":
        return real
    assert directory is not None
    out_dir: Path = directory
    out_dir.mkdir(parents=True, exist_ok=True)

    class _Recording(httpx.AsyncBaseTransport):
        async def handle_async_request(
            self, request: "httpx.Request"
        ) -> "httpx.Response":
            response = await real.handle_async_request(request)
            body = await response.aread()
            kept: List[Tuple[str, str]] = [
                (k, v)
                for k, v in response.headers.multi_items()
                if k.lower() not in _DROPPED_HEADERS
            ]
            rec = {
                "request": {
                    "method": request.method,
                    "host": host(request),
                    "target": target(request),
                },
                "status": response.status_code,
                "headers": [list(h) for h in kept],
                "body_b64": base64.b64encode(body).decode("ascii"),
            }
            name = _key(request.method, host(request), target(request))
            (out_dir / f"{name}.json").write_text(
                json.dumps(rec, indent=2, sort_keys=True), encoding="utf-8"
            )
            return httpx.Response(
                response.status_code,
                headers=kept,
                content=body,
                request=request,
            )

        async def aclose(self) -> None:
            await real.aclose()

    return _Recording()


async def run_try(
    manifest_path: Path,
    operation: str,
    params: Mapping[str, Any],
    config: Mapping[str, Any],
    secrets: Mapping[str, str],
    record: Optional[Path] = None,
    replay: Optional[Path] = None,
) -> Any:
    """Run one operation and return its mapped output."""
    from minder_t0_engine import Engine, Invocation, load_manifest

    manifest = load_manifest(_load_manifest_file(manifest_path))
    mode = "replay" if replay else "record" if record else "live"
    options: Dict[str, Any] = {"transport": _transport(mode, replay or record)}
    if mode == "replay":

        async def resolver(_host: str, _port: int) -> List[str]:
            return [_REPLAY_ADDRESS]

        options["resolver"] = resolver
    engine = Engine(manifest, **options)
    inv = Invocation(config=dict(config), secrets=_Secrets(secrets))
    return await engine.run_operation(operation, dict(params), inv)


def cmd_try(args: Any) -> int:
    try:
        params = json.loads(args.args) if args.args else {}
        config = json.loads(args.config) if args.config else {}
    except json.JSONDecodeError as exc:
        print(f"FAIL --args/--config must be JSON: {exc}")
        return 2
    secrets: Dict[str, str] = {}
    for item in args.secret or []:
        key, sep, value = item.partition("=")
        if not sep:
            print(f"FAIL --secret expects KEY=VALUE, got {item!r}")
            return 2
        secrets[key] = value
    try:
        result = asyncio.run(
            run_try(
                Path(args.manifest),
                args.operation,
                params,
                config,
                secrets,
                record=Path(args.record) if args.record else None,
                replay=Path(args.replay) if args.replay else None,
            )
        )
    except ImportError as exc:
        print(f"FAIL {exc}. Install the t0 extra: pip install 'minder-plugin-sdk[t0]'")
        return 2
    except Exception as exc:  # the engine's own errors carry a safe message
        print(f"FAIL {type(exc).__name__}: {exc}")
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0
