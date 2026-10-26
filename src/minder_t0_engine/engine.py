"""The T0 connector engine: runs a compiled declarative manifest.

One :class:`Engine` per plugin. Each call (a tool, an action, or the schedule
trigger) runs in its own :class:`_Run`, which holds that invocation's config,
its secrets and its request budget, and is dropped when the call returns: the
engine keeps no tenant data between invocations. Secrets come only from the
invocation's :class:`SecretSource` (the plugin's per-tenant secrets, read
under the invocation's grant) and only into the auth the manifest declares;
they are never in the context placeholders and mappings read, and every
output is scrubbed of them before it leaves the engine.

An operation's declared ``vars`` (JMESPath over its params, config and
``now``) are evaluated before its steps; placeholders and mappings read them
as ``vars.<name>`` (a null one drops an optional query parameter). A step's
``when`` that is falsy skips it: no request, a null result.

Mappings also see ``now``: the invocation's start as an ISO-8601 UTC string,
read once per invocation from the engine's clock (injectable for tests). An
action that declares ``timeseries`` writes its points through the
invocation's sink (the bound ``timeseries.write`` handle) before its output
is mapped, and the output sees ``timeseries: {measurement, points,
written}``. The schedule's collect (:meth:`Engine.run_collect`) does the same:
its result is that object, or its declared ``output`` mapped over the same
context; its ``error_output`` stands in for a failure like an operation's.
"""

import asyncio
import base64
import copy
import logging
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
)
from urllib.parse import quote, quote_plus

import httpx
from jmespath.parser import ParsedResult
from minder_plugin_sdk import line_protocol

from .egress import AuthInjection, Fetched, PluginEgress
from .errors import (
    EgressDenied,
    EngineError,
    LimitExceeded,
    MappingError,
    ParamsError,
    ParseError,
    SecretUnavailable,
    UpstreamError,
)
from .mapping import parse_body, search
from .model import (
    MAX_ITEMS,
    MAX_POINTS,
    MAX_REQUESTS_PER_INVOCATION,
    Base,
    DeclarativeManifest,
    Operation,
    Request,
    Step,
    TimeseriesWrite,
    Vars,
)
from .placeholders import (
    FORM,
    HEADER,
    HOST_LABEL,
    MISSING,
    PATH,
    QUERY,
    Template,
    render,
    render_json,
)

logger = logging.getLogger("minder.plugin-runner.declarative")

REDACTED = "[redacted]"

#: Failures an operation's ``error_output`` / ``on_error`` stand in for.
_RECOVERABLE = (UpstreamError, EgressDenied, LimitExceeded, MappingError)

#: The registry's own cap on a tag value (core/timeseries_capability.py).
MAX_TAG_LENGTH = 256
#: Characters no tag key or value may hold: a line break would start another
#: point, a backslash would escape the next separator, other control
#: characters are refused by the registry's parser.
_TAG_UNSAFE = re.compile(r"[\x00-\x1f\x7f\\]")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _falsy(value: Any) -> bool:
    """JMESPath falsiness: null, false, and an empty string, list or object
    (a number, 0 included, is true)."""
    return value is None or value is False or value in ("", [], {})


def _vars(variables: Vars, ctx: Dict[str, Any]) -> None:
    """Evaluate an operation's declared ``vars`` over its params, config and
    ``now`` (not over each other or any step) into ``ctx["vars"]``."""
    base = {k: ctx[k] for k in ("params", "config", "now") if k in ctx}
    ctx["vars"] = {name: search(expr, base) for name, expr in variables}


def _tag_text(value: Any, what: str) -> str:
    """A tag key or value as line-protocol text, or MappingError: a scalar,
    non-empty, at most :data:`MAX_TAG_LENGTH` characters, without control
    characters or a backslash (``,``, ``=`` and space are escaped later)."""
    if not isinstance(value, (str, int, float, bool)):
        raise MappingError(f"{what} must be a scalar value")
    text = str(value)
    if not text or len(text) > MAX_TAG_LENGTH or _TAG_UNSAFE.search(text):
        raise MappingError(
            f"{what} must be 1-{MAX_TAG_LENGTH} characters, without control "
            "characters or a backslash"
        )
    return text


def error_view(e: BaseException) -> Dict[str, Any]:
    """What an ``error_output`` mapping may know about a failure: its class
    and, for an upstream HTTP status, the status code. Never a message, a URL
    or a response body. ``parse`` is a body that did not decode as declared;
    ``upstream`` a transport error (status null) or a non-accepted status."""
    if isinstance(e, ParseError):
        return {"kind": "parse", "status": None}
    if isinstance(e, UpstreamError):
        return {"kind": "upstream", "status": e.status}
    if isinstance(e, EgressDenied):
        return {"kind": "egress", "status": None}
    if isinstance(e, LimitExceeded):
        return {"kind": "limit", "status": None}
    return {"kind": "mapping", "status": None}


class SecretSource(Protocol):
    """The plugin's secrets for the invoking tenant and owner."""

    async def get(self, key: str) -> Optional[str]: ...


class NoSecrets:
    async def get(self, key: str) -> Optional[str]:
        return None


class TimeseriesSink(Protocol):
    """The plugin's ``timeseries.write`` handle (scoped by the registry to its
    declared measurements, under the invocation's grant); returns the count
    written."""

    async def write(self, lines: Any, precision: str = "s") -> int: ...


@dataclass
class Invocation:
    """What one call runs with. Built per call; never stored by the engine.
    ``timeseries`` is where an action's points go (none: nothing written)."""

    config: Mapping[str, Any]
    secrets: SecretSource
    timeseries: Optional[TimeseriesSink] = None


def scrub(value: Any, secrets: Iterable[str]) -> Any:
    """``value`` with every occurrence of a secret (raw, URL-encoded or
    form-encoded) replaced by ``[redacted]``, in strings and object keys."""
    needles = set()
    for secret in secrets:
        if secret:
            needles.update({secret, quote(secret, safe=""), quote_plus(secret)})
    if not needles:
        return value
    ordered = sorted(needles, key=len, reverse=True)

    def _str(s: str) -> str:
        for needle in ordered:
            if needle in s:
                s = s.replace(needle, REDACTED)
        return s

    def _walk(v: Any, depth: int) -> Any:
        if depth > 200:
            raise MappingError("output nested too deeply")
        if isinstance(v, str):
            return _str(v)
        if isinstance(v, list):
            return [_walk(x, depth + 1) for x in v]
        if isinstance(v, dict):
            return {_str(str(k)): _walk(x, depth + 1) for k, x in v.items()}
        return v

    return _walk(value, 0)


def _link_next(headers: httpx.Headers) -> Optional[str]:
    link = headers.get("link")
    if not link:
        return None
    links = httpx.Response(200, headers={"link": link}).links
    nxt = links.get("next") or {}
    url = nxt.get("url")
    return url if isinstance(url, str) and url else None


class _Run:
    """One invocation: its secrets, its request budget, its context."""

    def __init__(self, engine: "Engine", inv: Invocation) -> None:
        self.engine = engine
        self.manifest = engine.manifest
        self.inv = inv
        self.config = engine.config_view(inv.config)
        self._secrets: Dict[str, str] = {}
        self._derived: List[str] = []
        self.requests = 0
        self.now = engine.now()

    # ── secrets ──────────────────────────────────────────────────────────
    async def secret(self, key: str) -> str:
        if key not in self._secrets:
            value = await self.inv.secrets.get(key)
            if not isinstance(value, str) or not value:
                raise SecretUnavailable(key)
            self._secrets[key] = value
        return self._secrets[key]

    def scrub(self, value: Any) -> Any:
        return scrub(value, [*self._secrets.values(), *self._derived])

    async def auth_for(
        self, base: Base, origin: Tuple[str, str, int]
    ) -> Optional[AuthInjection]:
        a = base.auth
        if a.type == "none":
            return None
        inj = AuthInjection(origin=origin)
        if a.type == "api_key":
            assert a.secret is not None and a.name is not None
            value = await self.secret(a.secret)
            if a.location == "query":
                inj.query[a.name] = value
            else:
                inj.headers[a.name] = value
        elif a.type == "bearer":
            assert a.secret is not None
            inj.headers["Authorization"] = f"Bearer {await self.secret(a.secret)}"
        else:  # basic
            assert a.username_secret is not None and a.password_secret is not None
            user = await self.secret(a.username_secret)
            password = await self.secret(a.password_secret)
            token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            self._derived.append(token)
            inj.headers["Authorization"] = f"Basic {token}"
        for value in inj.headers.values():
            if any(c in value for c in "\r\n\x00"):
                raise SecretUnavailable(a.secret or a.username_secret or "")
        return inj

    # ── requests ─────────────────────────────────────────────────────────
    def _url(
        self, req: Request, ctx: Mapping[str, Any]
    ) -> Tuple[httpx.URL, Tuple[str, str, int]]:
        base = req.base
        labels = []
        for label in base.host_labels:
            rendered = render(label, ctx, HOST_LABEL)
            assert rendered is not None
            labels.append(rendered)
        host = ".".join(labels)
        path = render(req.path, ctx, PATH) or ""
        port = f":{base.port}" if base.port else ""
        try:
            url = httpx.URL(f"{base.scheme}://{host}{port}{base.path}{path}")
        except (httpx.InvalidURL, ValueError):
            raise MappingError("request URL is invalid") from None
        default = 443 if base.scheme == "https" else 80
        return url, (base.scheme, host, base.port or default)

    @staticmethod
    def _pairs(
        pairs: Iterable[Tuple[str, Template]], ctx: Mapping[str, Any], component: str
    ) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for key, template in pairs:
            value = render(template, ctx, component)
            if value is not None:
                out[key] = value
        return out

    def _json(self, value: Any, ctx: Mapping[str, Any]) -> Any:
        if isinstance(value, Template):
            return render_json(value, ctx)
        if isinstance(value, list):
            return [v for v in (self._json(x, ctx) for x in value) if v is not MISSING]
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                rendered = self._json(v, ctx)
                if rendered is not MISSING:
                    out[k] = rendered
            return out
        return value

    async def _fetch(
        self,
        req: Request,
        url: httpx.URL,
        query: Dict[str, str],
        headers: Dict[str, str],
        json_body: Any,
        form: Optional[Dict[str, str]],
        auth: Optional[AuthInjection],
    ) -> Tuple[Any, Fetched]:
        self.requests += 1
        if self.requests > MAX_REQUESTS_PER_INVOCATION:
            raise LimitExceeded("requests per invocation")
        fetched = await self.engine.egress.fetch(
            req.method,
            url,
            params=query,
            headers=headers,
            json=json_body,
            has_json=req.has_json,
            data=form,
            auth=auth,
            follow_redirects=req.follow_redirects,
        )
        if not (200 <= fetched.status < 300 or fetched.status in req.accept_status):
            raise UpstreamError("unexpected status", fetched.status)
        if req.method == "HEAD":
            return None, fetched
        body = parse_body(
            fetched.content,
            req.response,
            fetched.encoding,
            empty_body=req.empty_body,
            namespaces=req.xml_namespaces,
            prefixes=dict(req.xml_prefixes),
        )
        return body, fetched

    async def request(self, step: Step, ctx: Mapping[str, Any]) -> Any:
        req = step.request
        url, origin = self._url(req, ctx)
        query = self._pairs(req.query, ctx, QUERY)
        headers = self._pairs(req.headers, ctx, HEADER)
        json_body = self._json(req.json_body, ctx) if req.has_json else None
        form = self._pairs(req.form, ctx, FORM) if req.form else None
        auth = await self.auth_for(req.base, origin)
        if req.paginate is None:
            data, _ = await self._fetch(req, url, query, headers, json_body, form, auth)
        else:
            data = await self._paginate(req, url, query, headers, json_body, form, auth)
        return search(step.select, data) if step.select is not None else data

    async def _paginate(
        self,
        req: Request,
        url: httpx.URL,
        query: Dict[str, str],
        headers: Dict[str, str],
        json_body: Any,
        form: Optional[Dict[str, str]],
        auth: Optional[AuthInjection],
    ) -> List[Any]:
        p = req.paginate
        assert p is not None
        collected: List[Any] = []
        cursor: Any = None
        seen: set[str] = set()
        page_url = url
        for page in range(p.max_pages):
            q = dict(query)
            if p.type == "cursor" and cursor is not None:
                assert p.param is not None
                q[p.param] = str(cursor)
            elif p.type == "offset":
                assert p.param and p.size_param and p.size
                q[p.param] = str(p.start + page * p.size)
                q[p.size_param] = str(p.size)
            elif p.type == "page":
                assert p.param is not None
                q[p.param] = str(p.start + page)
                if p.size_param and p.size:
                    q[p.size_param] = str(p.size)
            elif p.type == "link" and page > 0:
                q = {}  # the next link carries its own query
            body, fetched = await self._fetch(
                req, page_url, q, headers, json_body, form, auth
            )
            items = search(p.items, body) if p.items is not None else body
            if items is None:
                items = []
            if not isinstance(items, list):
                raise MappingError("pagination 'items' is not a list")
            collected.extend(items)
            if len(collected) >= MAX_ITEMS:
                return collected[:MAX_ITEMS]
            if p.type == "cursor":
                assert p.next is not None
                nxt = search(p.next, body)
                if nxt in (None, "", False) or not isinstance(nxt, (str, int, float)):
                    break
                if str(nxt) in seen:
                    break  # a server repeating its cursor
                seen.add(str(nxt))
                cursor = nxt
            elif p.type == "offset":
                if len(items) < (p.size or 0):
                    break
            elif p.type == "page":
                if not items or (p.size and len(items) < p.size):
                    break
            else:  # link
                nxt_url = _link_next(fetched.headers)
                if nxt_url is None:
                    break
                try:
                    page_url = fetched.url.join(nxt_url)
                except (httpx.InvalidURL, ValueError):
                    raise UpstreamError("invalid next link") from None
        return collected

    async def step(self, step: Step, ctx: Dict[str, Any]) -> Any:
        if step.when is not None and _falsy(search(step.when, ctx)):
            return None  # skipped: no request
        if step.foreach is None:
            return await self.request(step, ctx)
        items = search(step.foreach, ctx)
        if items is None:
            items = []
        if not isinstance(items, list):
            raise MappingError(f"step {step.name!r}: 'foreach' is not a list")
        tasks = [
            asyncio.ensure_future(self.request(step, {**ctx, "item": item}))
            for item in items[: step.max_items]
        ]
        try:
            return list(await asyncio.gather(*tasks))
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def steps(self, steps: Iterable[Step], ctx: Dict[str, Any]) -> Any:
        last: Any = None
        for step in steps:
            last = await self.step(step, ctx)
            ctx["steps"][step.name] = last
        return last


_INTEGER_TEXT = re.compile(r"-?\d+")


def _from_query_string(text: str, kind: Any) -> Any:
    """A tool called through the registry's GET read route (the chat and
    functions path) gets every argument as a query string, so a string is
    read as the scalar its schema declares. Text that does not parse
    stays a string, and the schema check refuses it."""
    lowered = text.strip().lower()
    if kind == "integer" and _INTEGER_TEXT.fullmatch(lowered):
        return int(lowered)
    if kind == "number":
        try:
            number = float(lowered)
        except ValueError:
            return text
        return number if math.isfinite(number) else text
    if kind == "boolean" and lowered in ("true", "false"):
        return lowered == "true"
    return text


class Engine:
    """Runs one plugin's tools, actions and schedule."""

    def __init__(
        self,
        manifest: DeclarativeManifest,
        egress: Optional[PluginEgress] = None,
        clock: Optional[Callable[[], datetime]] = None,
        **egress_options: Any,
    ) -> None:
        self.manifest = manifest
        self.egress = egress or PluginEgress(manifest, **egress_options)
        self._clock = clock or _utc_now

    def now(self) -> str:
        """The clock as ISO-8601 UTC (``datetime.isoformat()``, ``+00:00``);
        a naive clock value is taken as UTC."""
        moment = self._clock()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()

    def config_view(self, config: Mapping[str, Any]) -> Dict[str, Any]:
        """The config placeholders and mappings see: declared, non-secret
        keys only, over the schema defaults."""
        view = dict(self.manifest.config_defaults)
        declared = {e["key"] for e in self.manifest.config_schema}
        for key, value in (config or {}).items():
            if key in declared and key not in self.manifest.secret_config_keys:
                view[key] = value
        return view

    @staticmethod
    def validate_params(op: Operation, params: Any) -> Dict[str, Any]:
        if not isinstance(params, Mapping):
            raise ParamsError("parameters must be an object")
        values = dict(params)
        for name, prop in (op.parameters.get("properties") or {}).items():
            if not isinstance(prop, dict):
                continue
            if name not in values and "default" in prop:
                values[name] = copy.deepcopy(prop["default"])
            elif isinstance(values.get(name), str):
                values[name] = _from_query_string(values[name], prop.get("type"))
        errors = sorted(op.validator.iter_errors(values), key=lambda e: list(e.path))
        if errors:
            # The keyword and the location only: jsonschema's own message
            # quotes the offending value.
            first = errors[0]
            where = ".".join(str(p) for p in first.path) or "(root)"
            raise ParamsError(
                f"invalid parameters for {op.name}: {where} fails '{first.validator}'"
            )
        return values

    async def run_operation(self, name: str, params: Any, inv: Invocation) -> Any:
        op = self.manifest.operations.get(name)
        if op is None:
            raise EngineError(f"unknown operation {name!r}")
        values = self.validate_params(op, params)
        run = _Run(self, inv)
        ctx: Dict[str, Any] = {
            "params": values,
            "config": run.config,
            "steps": {},
            "now": run.now,
        }
        try:
            if op.vars:
                _vars(op.vars, ctx)
            last = await run.steps(op.steps, ctx)
            if op.timeseries is not None:
                lines = self._lines(op.timeseries, ctx, run)
                ctx["timeseries"] = {
                    "measurement": op.timeseries.measurement,
                    "points": len(lines),
                    "written": await self._write(inv, lines, name),
                }
            result = search(op.output, ctx) if op.output is not None else last
        except _RECOVERABLE as e:
            fallback = self._on_error(op, values, run, e)
            if fallback is MISSING:
                raise
            logger.warning(
                "T0 %s.%s failed (%s); returning its error value",
                self.manifest.name,
                name,
                e,
            )
            return fallback
        return run.scrub(result)

    @staticmethod
    def _on_error(
        op: Operation, values: Dict[str, Any], run: "_Run", e: BaseException
    ) -> Any:
        """The value a failed operation returns instead of raising, or MISSING.

        ``error_output`` is evaluated over a fresh context holding only the
        validated params, the non-secret config view, ``now`` and
        :func:`error_view`: no step results (so no upstream body), no
        secrets. When it yields null (or cannot be applied) the fixed
        ``on_error`` value is used, if any."""
        if op.error_output is not None:
            mapped = Engine._error_output(op.error_output, values, run, e)
            if mapped is not MISSING:
                return mapped
        if op.on_error is not None:
            return copy.deepcopy(op.on_error)
        return MISSING

    @staticmethod
    def _error_output(
        expr: ParsedResult, values: Dict[str, Any], run: "_Run", e: BaseException
    ) -> Any:
        """``expr`` over a fresh context holding only ``values`` (the
        validated params), the non-secret config view, ``now`` and
        :func:`error_view`, scrubbed; MISSING when it yields null or cannot
        be applied."""
        ctx = {
            "params": copy.deepcopy(values),
            "config": copy.deepcopy(run.config),
            "now": run.now,
            "error": error_view(e),
        }
        try:
            mapped = search(expr, ctx)
        except MappingError:
            mapped = None
        return MISSING if mapped is None else run.scrub(mapped)

    async def run_schedule(self, inv: Invocation) -> List[str]:
        """Run the schedule's steps and map them to line-protocol lines for
        ``timeseries.write`` (scrubbed like any output)."""
        schedule = self.manifest.schedule
        if schedule is None:
            return []
        run = _Run(self, inv)
        ctx: Dict[str, Any] = {"config": run.config, "steps": {}, "now": run.now}
        if schedule.vars:
            _vars(schedule.vars, ctx)
        await run.steps(schedule.steps, ctx)
        return self._lines(schedule.write, ctx, run)

    async def run_collect(self, inv: Invocation) -> Any:
        """The schedule trigger: run its steps, write its points through the
        invocation's sink (none: nothing written) and return
        ``{measurement, points, written}``, or the schedule's ``output``
        mapped over the action context (``params`` empty) with that object
        as ``timeseries``. On a failure the schedule's ``error_output`` (over
        params, config, ``now`` and the error only), when declared and not
        null, is returned instead of raising."""
        schedule = self.manifest.schedule
        if schedule is None:
            return {}
        run = _Run(self, inv)
        ctx: Dict[str, Any] = {
            "params": {},
            "config": run.config,
            "steps": {},
            "now": run.now,
        }
        try:
            if schedule.vars:
                _vars(schedule.vars, ctx)
            await run.steps(schedule.steps, ctx)
            lines = self._lines(schedule.write, ctx, run)
            written: Any = 0
            if lines and inv.timeseries is not None:
                # Unlike an action's write, a failed collect write raises.
                written = await inv.timeseries.write(lines, "s")
            summary = {
                "measurement": schedule.measurement,
                "points": len(lines),
                "written": written,
            }
            if schedule.output is None:
                return summary
            ctx["timeseries"] = summary
            return run.scrub(search(schedule.output, ctx))
        except _RECOVERABLE as e:
            if schedule.error_output is None:
                raise
            fallback = self._error_output(schedule.error_output, {}, run, e)
            if fallback is MISSING:
                raise
            logger.warning(
                "T0 %s collect failed (%s); returning its error value",
                self.manifest.name,
                e,
            )
            return fallback

    @staticmethod
    def _lines(write: TimeseriesWrite, ctx: Mapping[str, Any], run: _Run) -> List[str]:
        """``write``'s points over ``ctx`` as line-protocol lines (scrubbed).
        The measurement is the declared one; points cannot name another."""
        declared: Dict[str, str] = {}
        for key, expr in write.tags:
            value = search(expr, ctx)
            if value is not None:  # a null tag is left out
                declared[key] = _tag_text(value, f"tag {key!r}")
        points = search(write.points, ctx)
        if points is None:
            return []
        if not isinstance(points, list):
            raise MappingError("'points' is not a list")
        lines: List[str] = []
        for point in points[:MAX_POINTS]:
            if not isinstance(point, dict) or not isinstance(point.get("fields"), dict):
                raise MappingError("a point needs a 'fields' object")
            tags = point.get("tags") or {}
            if not isinstance(tags, dict) or not all(
                isinstance(v, (str, int, float, bool)) for v in tags.values()
            ):
                raise MappingError("point 'tags' must be scalar values")
            # Declared tags first (in declared order), then the point's own.
            merged = dict(declared)
            for k, v in tags.items():
                if k not in declared:
                    key = _tag_text(k, "a point tag key")
                    merged[key] = _tag_text(v, "a point tag value")
            fields = {
                k: v
                for k, v in point["fields"].items()
                if isinstance(v, (str, int, float, bool))
            }
            ts = point.get("time")
            if ts is not None and (isinstance(ts, bool) or not isinstance(ts, int)):
                raise MappingError("point 'time' must be epoch seconds")
            line = line_protocol(write.measurement, merged, fields, ts)
            if line:
                lines.append(line)
        return list(run.scrub(lines))

    async def _write(self, inv: Invocation, lines: List[str], name: str) -> int:
        """Write an action's lines through the invocation's sink; the count
        written. No sink, no lines, or a failed write (logged by class only,
        as code plugins do) is 0: the action still returns its output."""
        if not lines or inv.timeseries is None:
            return 0
        try:
            written = await inv.timeseries.write(lines, "s")
        except Exception as e:  # CancelledError is not an Exception
            logger.warning(
                "T0 %s.%s time-series write failed (%s)",
                self.manifest.name,
                name,
                type(e).__name__,
            )
            return 0
        if isinstance(written, bool) or not isinstance(written, int):
            return 0
        return max(written, 0)
