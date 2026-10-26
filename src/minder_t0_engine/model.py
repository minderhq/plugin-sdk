"""The declarative (T0) manifest, v1.

:func:`load_manifest` validates a parsed manifest (a dict, from YAML or JSON)
and compiles it: placeholders are parsed, JMESPath expressions compiled, JSON
Schemas checked, and every base URL checked statically against the plugin's
own egress declaration. Anything invalid is refused at load with a
:class:`ManifestError`; nothing is guessed. The SDK's schema for the unified
manifest mirrors this model.

Shape (YAML)::

    apiVersion: minder.dev/v1alpha1
    kind: Plugin
    metadata: {name: frankfurter, version: 1.0.0, description: ..., author: ...}
    spec:
      runtime: {kind: declarative, engine: 1}
      display: {label: ..., summary: ..., logo: ..., color: ..., category: ...}
      config_schema: [{key: FX_BASE, type: string, default: EUR}]
      egress:
        - host: api.frankfurter.app       # an exact host
        - host: "*.wikipedia.org"          # any subdomain (not the apex)
          http: false                      # plain http only when declared
      bases:
        api:
          url: https://api.frankfurter.app
          auth: {type: api_key, in: header, name: X-Api-Key, secret: FX_KEY}
        wiki:                              # a leading host label from config,
          url: "https://{config.WIKI_LANG|en}.wikipedia.org"  # 'en' if invalid
      limits: {timeout_s: 10, max_response_bytes: 2097152,
               max_concurrency: 4, rate_per_minute: 120}
      timeseries: {measurements: [fx_rate]}
      tools:                               # AI tools (and actions)
        convert:
          description: ...
          parameters: {type: object, properties: {...}, required: [...]}
          effect: read                     # optional, tools only: read|write|
                                           # send|destructive (tool effect class)
          vars:                            # JMESPath over {params, config, now}
            frm: upper(trim(params.from_currency))
            to: upper(trim(params.to_currency))
          steps:                           # 1-3 chained steps
            - name: rate
              when: vars.frm != vars.to    # falsy: skipped, null, no request
              request:
                base: api
                path: /latest
                query: {from: "{vars.frm}", to: "{vars.to}"}
                # optional: follow_redirects (GET/HEAD default true),
                # empty_body: null|error, and for response: xml
                # xml: {namespaces: drop|keep, prefixes: {atom: <uri>}}
              select: rates                # JMESPath over the response
          output: "{result: multiply(params.amount, values(steps.rate)[0])}"
          # On a failure: error_output (JMESPath over {params, config, error}
          # only; never a response or a secret) and, where it yields null,
          # the fixed on_error value.
          error_output: >-
            error.status == `404` && {error: join('', ['no rate for ',
            params.from_currency])} || null
          on_error: {error: rate unavailable}
      actions:                             # same shape, not exposed as AI tools
        refresh:
          description: ...
          steps: [...]
          # An action (never a tool, never read_only) may write points with
          # the schedule's block; the output context then holds 'timeseries'
          # ({measurement, points, written}). Every mapping also sees 'now'
          # (the invocation's start, ISO-8601 UTC).
          timeseries:
            measurement: fx_rate
            points: "entries(steps.latest.rates)[].{tags: {quote: key}, fields: {rate: value}}"
            tags: {base: "upper(config.FX_BASE)"}  # JMESPath over the root
          output: "{rates: steps.latest.rates, written: timeseries.written, at: now}"
      schedule:                            # the collect trigger
        cron: "0 * * * *"
        steps: [...]
        measurement: fx_rate
        points: "entries(steps.latest.rates)[].{tags: {quote: key}, fields: {rate: value}}"
        tags: {base: "config.FX_BASE"}     # merged into every point
        # optional: the collect result (default {measurement, points,
        # written}) over the action context, and error_output (over
        # {params, config, now, error} only) in place of raising
        output: "{base: vars.base, written: timeseries.written, at: now}"
        error_output: "{base: config.FX_BASE, written: `0`, error: error.kind}"
      webhook:                             # inbound webhook trigger
        action: ingest                     # a declared action (not admin-only)
                                           # with a 'body' parameter
        secret: HOOK_SECRET                # required: the per-tenant HMAC key
        # plugin-registry verifies the HMAC before anything runs, then calls
        # the action with {body: <the JSON request body>} as its params, so
        # its mappings see params.body. A webhook without a secret is refused.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Literal, Mapping, Optional, Tuple, Union

from jmespath.parser import ParsedResult
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .egress_policy import EgressPolicyError, check_host

from .errors import ManifestError
from .mapping import compile_expr
from .placeholders import Part, Ref, Template, literal_text
from .placeholders import parse as parse_template

# ── engine hard caps (a manifest may only lower them) ───────────────────
MAX_STEPS = 3
MAX_FANOUT = 20
MAX_PAGES = 10
MAX_PAGE_SIZE = 1000
MAX_ITEMS = 1000
MAX_REQUESTS_PER_INVOCATION = 60
MAX_REDIRECTS = 5
MAX_TIMEOUT_S = 30.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_CONCURRENCY = 8
MAX_RATE_PER_MINUTE = 600
MAX_OPERATIONS = 32
MAX_EGRESS_RULES = 32
MAX_BASES = 16
MAX_POINTS = 5000
MAX_VARS = 16

API_VERSION = "minder.dev/v1alpha1"
ENGINE_VERSION = 1

_OP_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PLUGIN_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_CONFIG_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_XML_PREFIX = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,31}$")
_MEASUREMENT = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TAG_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")
_CRON = re.compile(r"^[0-9*/,\-]+( [0-9*/,\-]+){4}$")
_BASE_URL = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?P<host>[^/:?#@]+)"
    r"(?::(?P<port>[0-9]{1,5}))?(?P<path>/[^?#]*)?$"
)

#: Header names a manifest may not set: the engine owns auth and framing.
RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
    }
)

#: Names the generated plugin class already uses; no tool/action may shadow
#: one (they become methods of that class).
RESERVED_OPERATION_NAMES = frozenset(
    {
        "register",
        "initialize",
        "shutdown",
        "health_check",
        "collect_data",
        "analyze",
        "apply_config",
        "bind_context",
        "bind_timeseries",
        "schedule",
        "handle_webhook",
        "connect",
        "panels",
        "manifest",
        "engine",
    }
)


#: Tag keys the platform owns: plugin-registry forces them on every point
#: (D3.3a), so a manifest may not declare them.
RESERVED_TAG_KEYS = frozenset({"owner_id", "plugin"})


# ── pydantic shape ───────────────────────────────────────────────────────


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EgressRuleModel(_Model):
    host: str = Field(min_length=1, max_length=253)
    http: bool = False


class AuthModel(_Model):
    type: Literal["none", "api_key", "bearer", "basic"] = "none"
    secret: Optional[str] = None
    in_: Literal["header", "query"] = Field("header", alias="in")
    name: Optional[str] = None
    username_secret: Optional[str] = None
    password_secret: Optional[str] = None


class BaseModel_(_Model):
    url: str = Field(min_length=1, max_length=2048)
    auth: AuthModel = Field(default_factory=AuthModel)  # type: ignore[arg-type]


class PaginationModel(_Model):
    type: Literal["cursor", "offset", "page", "link"]
    max_pages: int = Field(5, ge=1, le=MAX_PAGES)
    items: Optional[str] = None
    param: Optional[str] = None
    next: Optional[str] = None
    size_param: Optional[str] = None
    size: Optional[int] = Field(None, ge=1, le=MAX_PAGE_SIZE)
    start: Optional[int] = Field(None, ge=0)


class BodyModel(_Model):
    json_: Optional[Any] = Field(None, alias="json")
    form: Optional[Dict[str, Union[str, int, float, bool]]] = None


Scalar = Union[str, int, float, bool]


class XmlModel(_Model):
    namespaces: Literal["drop", "keep"] = "drop"
    prefixes: Dict[str, str] = Field(default_factory=dict, max_length=16)


class RequestModel(_Model):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] = "GET"
    base: str
    path: str = Field("", max_length=2048)
    query: Dict[str, Scalar] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[BodyModel] = None
    response: Literal["json", "xml", "text"] = "json"
    xml: Optional[XmlModel] = None
    empty_body: Literal["null", "error"] = "null"
    follow_redirects: Optional[bool] = None
    paginate: Optional[PaginationModel] = None
    accept_status: List[int] = Field(default_factory=list)


class StepModel(_Model):
    name: str
    request: RequestModel
    when: Optional[str] = None
    foreach: Optional[str] = None
    max_items: int = Field(10, ge=1, le=MAX_FANOUT)
    select: Optional[str] = None


class TimeseriesWriteModel(_Model):
    measurement: str
    points: str
    tags: Dict[str, str] = Field(default_factory=dict, max_length=16)


class OperationModel(_Model):
    description: str = Field(min_length=1, max_length=2000)
    parameters: Dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}}
    )
    vars: Dict[str, str] = Field(default_factory=dict, max_length=MAX_VARS)
    steps: List[StepModel] = Field(min_length=1, max_length=MAX_STEPS)
    output: Optional[str] = None
    on_error: Optional[Any] = None
    error_output: Optional[str] = None
    read_only: Optional[bool] = None
    admin_only: bool = False
    timeseries: Optional[TimeseriesWriteModel] = None
    effect: Optional[Literal["read", "write", "send", "destructive"]] = None


class ScheduleModel(_Model):
    cron: Optional[str] = None
    vars: Dict[str, str] = Field(default_factory=dict, max_length=MAX_VARS)
    steps: List[StepModel] = Field(min_length=1, max_length=MAX_STEPS)
    measurement: str
    points: str
    tags: Dict[str, str] = Field(default_factory=dict, max_length=16)
    output: Optional[str] = None
    error_output: Optional[str] = None


class WebhookModel(_Model):
    action: str
    secret: str


class TimeseriesModel(_Model):
    measurements: List[str] = Field(min_length=1, max_length=16)


class LimitsModel(_Model):
    timeout_s: float = Field(10.0, gt=0, le=MAX_TIMEOUT_S)
    max_response_bytes: int = Field(2 * 1024 * 1024, ge=1024, le=MAX_RESPONSE_BYTES)
    max_concurrency: int = Field(4, ge=1, le=MAX_CONCURRENCY)
    rate_per_minute: int = Field(120, ge=1, le=MAX_RATE_PER_MINUTE)


class RuntimeModel(_Model):
    kind: Literal["declarative"]
    engine: Literal[1] = 1


class SpecModel(_Model):
    runtime: RuntimeModel
    display: Optional[Dict[str, Any]] = None
    config_schema: List[Dict[str, Any]] = Field(default_factory=list)
    egress: List[EgressRuleModel] = Field(min_length=1, max_length=MAX_EGRESS_RULES)
    bases: Dict[str, BaseModel_] = Field(min_length=1, max_length=MAX_BASES)
    limits: LimitsModel = Field(default_factory=LimitsModel)  # type: ignore[arg-type]
    timeseries: Optional[TimeseriesModel] = None
    tools: Dict[str, OperationModel] = Field(default_factory=dict)
    actions: Dict[str, OperationModel] = Field(default_factory=dict)
    schedule: Optional[ScheduleModel] = None
    webhook: Optional[WebhookModel] = None


class MetadataModel(_Model):
    name: str
    version: str = Field(min_length=1, max_length=64)
    description: str = Field("", max_length=2000)
    author: str = Field("", max_length=200)
    stable_id: Optional[str] = Field(None, max_length=128)


class ManifestModel(_Model):
    apiVersion: Literal["minder.dev/v1alpha1"]
    kind: Literal["Plugin"]
    metadata: MetadataModel
    spec: SpecModel


# ── compiled form ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EgressRule:
    """One declared destination: ``host`` exact, or ``suffix`` for any
    subdomain of it (``*.example.com`` matches ``a.example.com``, never
    ``example.com`` itself)."""

    pattern: str
    host: Optional[str]
    suffix: Optional[str]
    http: bool

    def matches(self, host: str) -> bool:
        if self.host is not None:
            return host == self.host
        assert self.suffix is not None
        return host.endswith("." + self.suffix) and len(host) > len(self.suffix) + 1


@dataclass(frozen=True)
class Auth:
    type: str
    location: str = "header"
    name: Optional[str] = None
    secret: Optional[str] = None
    username_secret: Optional[str] = None
    password_secret: Optional[str] = None

    @property
    def secret_keys(self) -> Tuple[str, ...]:
        return tuple(
            k
            for k in (self.secret, self.username_secret, self.password_secret)
            if k is not None
        )


@dataclass(frozen=True)
class Base:
    name: str
    scheme: str
    host_labels: Tuple[Template, ...]
    port: Optional[int]
    path: str
    auth: Auth


@dataclass(frozen=True)
class Pagination:
    type: str
    max_pages: int
    items: Optional[ParsedResult]
    param: Optional[str]
    next: Optional[ParsedResult]
    size_param: Optional[str]
    size: Optional[int]
    start: int


@dataclass(frozen=True)
class Request:
    method: str
    base: Base
    path: Template
    query: Tuple[Tuple[str, Template], ...]
    headers: Tuple[Tuple[str, Template], ...]
    json_body: Any
    has_json: bool
    form: Tuple[Tuple[str, Template], ...]
    response: str
    paginate: Optional[Pagination]
    accept_status: FrozenSet[int]
    #: Follow 3xx redirects (each hop re-checked). GET/HEAD only.
    follow_redirects: bool = True
    #: "error": an empty or whitespace-only body is a ParseError, not null.
    empty_body: str = "null"
    #: XML namespaces: "drop" (local names) or "keep".
    xml_namespaces: str = "drop"
    #: With "keep": namespace URI -> prefix, as ((uri, prefix), ...).
    xml_prefixes: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Step:
    name: str
    request: Request
    foreach: Optional[ParsedResult]
    max_items: int
    select: Optional[ParsedResult]
    #: JMESPath over the context; a falsy result skips the step (its result
    #: is null and no request is made).
    when: Optional[ParsedResult] = None


#: Declared values: (name, JMESPath over {params, config, now}), in order.
Vars = Tuple[Tuple[str, ParsedResult], ...]


@dataclass(frozen=True)
class TimeseriesWrite:
    """Points to write. ``points`` (JMESPath over the context) yields
    ``[{tags, fields, time?}]``; each ``tags`` expression is evaluated once
    over the context root and merged into every point, over the point's own
    tag of that name. The measurement is fixed, and one the plugin declares."""

    measurement: str
    points: ParsedResult
    tags: Tuple[Tuple[str, ParsedResult], ...] = ()


@dataclass(frozen=True)
class Operation:
    name: str
    kind: str  # "tool" or "action"
    description: str
    parameters: Dict[str, Any]
    validator: Any
    steps: Tuple[Step, ...]
    output: Optional[ParsedResult]
    on_error: Any
    error_output: Optional[ParsedResult]
    read_only: bool
    admin_only: bool
    #: An action's time-series write, run after its steps.
    timeseries: Optional[TimeseriesWrite] = None
    vars: Vars = ()
    #: A tool's declared effect class, served with its AI tool so the
    #: registry's tool-effect analysis sees the declaration.
    effect: Optional[str] = None


@dataclass(frozen=True)
class Schedule:
    cron: Optional[str]
    steps: Tuple[Step, ...]
    write: TimeseriesWrite
    vars: Vars = ()
    #: The collect result: JMESPath over {params (empty), config, vars,
    #: steps, now, timeseries: {measurement, points, written}}. None: the
    #: ``timeseries`` object itself.
    output: Optional[ParsedResult] = None
    #: On a failure: JMESPath over {params (empty), config, now, error} only;
    #: a null result (or none declared) re-raises.
    error_output: Optional[ParsedResult] = None

    @property
    def measurement(self) -> str:
        return self.write.measurement

    @property
    def points(self) -> ParsedResult:
        return self.write.points


@dataclass(frozen=True)
class Webhook:
    """The inbound webhook trigger: plugin-registry verifies the request's
    HMAC with the tenant's ``secret`` and only then runs ``action``."""

    action: str
    secret: str


@dataclass(frozen=True)
class Limits:
    timeout_s: float
    max_response_bytes: int
    max_concurrency: int
    rate_per_minute: int


@dataclass(frozen=True)
class DeclarativeManifest:
    """A validated, compiled T0 manifest."""

    name: str
    version: str
    description: str
    author: str
    stable_id: Optional[str]
    display: Optional[Dict[str, Any]]
    config_schema: List[Dict[str, Any]]
    config_defaults: Dict[str, Any]
    secret_config_keys: FrozenSet[str]
    egress: Tuple[EgressRule, ...]
    bases: Dict[str, Base]
    limits: Limits
    measurements: Tuple[str, ...]
    tools: Dict[str, Operation]
    actions: Dict[str, Operation]
    schedule: Optional[Schedule]
    raw: Dict[str, Any] = field(repr=False, compare=False)
    webhook: Optional[Webhook] = None

    @property
    def operations(self) -> Dict[str, Operation]:
        return {**self.tools, **self.actions}

    @property
    def secret_keys(self) -> FrozenSet[str]:
        """Every per-tenant secret the engine may inject (auth only)."""
        return frozenset(k for b in self.bases.values() for k in b.auth.secret_keys)

    def rule_for(self, host: str) -> Optional[EgressRule]:
        for rule in self.egress:
            if rule.matches(host):
                return rule
        return None


# ── compilation ──────────────────────────────────────────────────────────


def _egress_rule(raw: EgressRuleModel, where: str) -> EgressRule:
    pattern = raw.host.strip().lower().rstrip(".")
    wildcard = pattern.startswith("*.")
    name = pattern[2:] if wildcard else pattern
    if "*" in name:
        raise ManifestError(f"{where}: only a leading '*.' wildcard is allowed")
    labels = name.split(".")
    if not all(_DNS_LABEL.match(label) for label in labels):
        raise ManifestError(f"{where}: {pattern!r} is not a DNS host name")
    if all(label.isdigit() for label in labels):
        raise ManifestError(f"{where}: IP addresses cannot be declared, use a name")
    if wildcard and len(labels) < 2:
        raise ManifestError(f"{where}: a wildcard needs at least a registrable domain")
    try:
        # The platform's own rules: no single-label (Docker service) names,
        # no .internal/.local/..., no Minder service names, no localhost or
        # metadata names.
        check_host(name, allow_private=False)
    except EgressPolicyError:
        raise ManifestError(
            f"{where}: {pattern!r} is an internal or reserved host name"
        ) from None
    return EgressRule(
        pattern=pattern,
        host=None if wildcard else name,
        suffix=name if wildcard else None,
        http=raw.http,
    )


def _auth(raw: AuthModel, where: str) -> Auth:
    t = raw.type
    names = {"secret": raw.secret, "username_secret": raw.username_secret}
    names["password_secret"] = raw.password_secret
    for key, value in names.items():
        if value is not None and not _CONFIG_KEY.match(value):
            raise ManifestError(f"{where}.{key}: not a valid secret name")
    if t == "none":
        if any(names.values()) or raw.name:
            raise ManifestError(f"{where}: auth type 'none' takes no other fields")
        return Auth("none")
    if t in ("api_key", "bearer"):
        if not raw.secret or raw.username_secret or raw.password_secret:
            raise ManifestError(f"{where}: {t} auth needs exactly 'secret'")
    if t == "api_key":
        if not raw.name:
            raise ManifestError(f"{where}: api_key auth needs 'name'")
        pattern = _HEADER_NAME if raw.in_ == "header" else _PARAM_NAME
        if not pattern.match(raw.name):
            raise ManifestError(f"{where}.name: not a valid {raw.in_} name")
        if raw.in_ == "header" and raw.name.lower() in RESERVED_HEADERS - {
            "authorization"
        }:
            raise ManifestError(f"{where}.name: {raw.name!r} is a reserved header")
        return Auth("api_key", raw.in_, raw.name, raw.secret)
    if t == "bearer":
        if raw.name or raw.in_ != "header":
            raise ManifestError(
                f"{where}: bearer auth is always the Authorization header"
            )
        return Auth("bearer", "header", "Authorization", raw.secret)
    # basic
    if raw.secret or not raw.username_secret or not raw.password_secret:
        raise ManifestError(
            f"{where}: basic auth needs 'username_secret' and 'password_secret'"
        )
    if raw.name or raw.in_ != "header":
        raise ManifestError(f"{where}: basic auth is always the Authorization header")
    return Auth(
        "basic",
        "header",
        "Authorization",
        username_secret=raw.username_secret,
        password_secret=raw.password_secret,
    )


class _Scope:
    """What placeholders may reference at one point of the manifest."""

    def __init__(
        self,
        config_keys: FrozenSet[str],
        secret_config: FrozenSet[str],
        params: Optional[FrozenSet[str]],
        steps: FrozenSet[str] = frozenset(),
        item: bool = False,
        vars: FrozenSet[str] = frozenset(),
    ) -> None:
        self.config_keys = config_keys
        self.secret_config = secret_config
        self.params = params
        self.steps = steps
        self.item = item
        self.vars = vars

    def check(self, template: Template, where: str) -> Template:
        for ref in template.refs:
            root, rest = ref.root, ref.path[1:]
            if root == "config":
                if not rest or rest[0] not in self.config_keys:
                    raise ManifestError(
                        f"{where}: {{{ref}}} is not a declared config key"
                    )
                if rest[0] in self.secret_config:
                    raise ManifestError(
                        f"{where}: {{{ref}}} is a secret config field; secrets "
                        "are injected only through 'auth'"
                    )
            elif root == "params":
                if self.params is None:
                    raise ManifestError(f"{where}: no parameters here ({{{ref}}})")
                if not rest or rest[0] not in self.params:
                    raise ManifestError(
                        f"{where}: {{{ref}}} is not a declared parameter"
                    )
            elif root == "steps":
                if not rest or rest[0] not in self.steps:
                    raise ManifestError(f"{where}: {{{ref}}} is not an earlier step")
            elif root == "item" and not self.item:
                raise ManifestError(
                    f"{where}: {{{ref}}} is only valid in a foreach step"
                )
            elif root == "vars" and (not rest or rest[0] not in self.vars):
                raise ManifestError(f"{where}: {{{ref}}} is not a declared var")
        return template


def _base(
    name: str, raw: BaseModel_, rules: Tuple[EgressRule, ...], scope: _Scope
) -> Base:
    where = f"spec.bases.{name}"
    m = _BASE_URL.match(raw.url.strip())
    if not m:
        raise ManifestError(
            f"{where}.url: must be scheme://host[:port][/path], without "
            "credentials, query or fragment"
        )
    scheme = m.group("scheme").lower()
    if scheme not in ("http", "https"):
        raise ManifestError(f"{where}.url: scheme must be https (or declared http)")
    port = int(m.group("port")) if m.group("port") else None
    if port is not None and not 1 <= port <= 65535:
        raise ManifestError(f"{where}.url: invalid port")
    path = (m.group("path") or "").rstrip("/")
    if "{" in path or "}" in path:
        raise ManifestError(f"{where}.url: placeholders go in a request's path")
    host_t = parse_template(m.group("host"), f"{where}.url", allow_default=True)
    raw_labels: List[List[Part]] = [[]]
    for part in host_t.parts:
        if isinstance(part, Ref):
            raw_labels[-1].append(part)
            continue
        pieces = part.split(".")
        raw_labels[-1].append(pieces[0])
        for piece in pieces[1:]:
            raw_labels.append([piece])
    labels: List[Template] = []
    templated = 0
    for i, raw_label in enumerate(raw_labels):
        parts = [p for p in raw_label if p != ""]
        if len(parts) == 1 and isinstance(parts[0], str):
            label = parts[0].lower()
            if not _DNS_LABEL.match(label):
                raise ManifestError(f"{where}.url: invalid host label {label!r}")
            labels.append(Template((label,)))
            continue
        if len(parts) != 1 or not isinstance(parts[0], Ref):
            raise ManifestError(
                f"{where}.url: a host placeholder must be a whole label"
            )
        ref = parts[0]
        if ref.root != "config":
            raise ManifestError(f"{where}.url: host placeholders come from config")
        if templated != i:
            raise ManifestError(
                f"{where}.url: host placeholders must be the leading label(s)"
            )
        tmpl = Template((ref,))
        scope.check(tmpl, f"{where}.url")
        templated += 1
        labels.append(tmpl)
    literal = ".".join(t.literal() for t in labels[templated:])
    if templated == len(labels):
        raise ManifestError(f"{where}.url: the host needs a literal domain")
    if templated == 0:
        rule = next((r for r in rules if r.matches(literal)), None)
    else:
        rule = next(
            (
                r
                for r in rules
                if r.suffix is not None
                and (literal == r.suffix or literal.endswith("." + r.suffix))
            ),
            None,
        )
    if rule is None:
        raise ManifestError(f"{where}.url: host is not in the declared egress")
    if scheme == "http" and not rule.http:
        raise ManifestError(
            f"{where}.url: plain http needs 'http: true' on its egress entry"
        )
    return Base(
        name=name,
        scheme=scheme,
        host_labels=tuple(labels),
        port=port,
        path=path,
        auth=_auth(raw.auth, f"{where}.auth"),
    )


def _pagination(raw: PaginationModel, where: str) -> Pagination:
    t = raw.type
    if t == "cursor" and not (raw.param and raw.next):
        raise ManifestError(f"{where}: cursor pagination needs 'param' and 'next'")
    if t == "offset" and not (raw.param and raw.size_param and raw.size):
        raise ManifestError(
            f"{where}: offset pagination needs 'param', 'size_param' and 'size'"
        )
    if t == "page" and not raw.param:
        raise ManifestError(f"{where}: page pagination needs 'param'")
    if t == "page" and bool(raw.size_param) != bool(raw.size):
        raise ManifestError(f"{where}: 'size_param' and 'size' go together")
    if t == "link" and (raw.param or raw.next or raw.size_param):
        raise ManifestError(f"{where}: link pagination follows the Link header only")
    if t != "cursor" and raw.next:
        raise ManifestError(f"{where}: 'next' is for cursor pagination")
    for key in ("param", "size_param"):
        value = getattr(raw, key)
        if value is not None and not _PARAM_NAME.match(value):
            raise ManifestError(f"{where}.{key}: not a valid query parameter name")
    return Pagination(
        type=t,
        max_pages=raw.max_pages,
        items=compile_expr(raw.items, f"{where}.items") if raw.items else None,
        param=raw.param,
        next=compile_expr(raw.next, f"{where}.next") if raw.next else None,
        size_param=raw.size_param,
        size=raw.size,
        start=raw.start if raw.start is not None else (1 if t == "page" else 0),
    )


def _json_templates(value: Any, where: str, scope: _Scope, depth: int = 0) -> Any:
    if depth > 16:
        raise ManifestError(f"{where}: JSON body nested too deeply")
    if isinstance(value, str):
        return scope.check(parse_template(value, where), where)
    if isinstance(value, list):
        return [_json_templates(v, where, scope, depth + 1) for v in value]
    if isinstance(value, dict):
        return {
            str(k): _json_templates(v, f"{where}.{k}", scope, depth + 1)
            for k, v in value.items()
        }
    return value


def _request(
    raw: RequestModel, where: str, bases: Dict[str, Base], scope: _Scope
) -> Request:
    base = bases.get(raw.base)
    if base is None:
        raise ManifestError(f"{where}.base: {raw.base!r} is not a declared base")
    path = raw.path
    if path and not path.startswith("/"):
        raise ManifestError(f"{where}.path: must start with '/'")
    if "?" in path or "#" in path:
        raise ManifestError(f"{where}.path: use 'query', not '?' in the path")
    path_t = scope.check(parse_template(path, f"{where}.path"), f"{where}.path")
    auth = base.auth
    query: List[Tuple[str, Template]] = []
    for key, value in raw.query.items():
        if not _PARAM_NAME.match(key):
            raise ManifestError(f"{where}.query: {key!r} is not a valid name")
        if auth.type == "api_key" and auth.location == "query" and key == auth.name:
            raise ManifestError(f"{where}.query: {key!r} is the auth parameter")
        text = value if isinstance(value, str) else literal_text(value)
        query.append(
            (key, scope.check(parse_template(text, f"{where}.query.{key}"), where))
        )
    headers: List[Tuple[str, Template]] = []
    for name, value in raw.headers.items():
        if not _HEADER_NAME.match(name):
            raise ManifestError(f"{where}.headers: {name!r} is not a valid header")
        lowered = name.lower()
        if lowered in RESERVED_HEADERS or (
            auth.type == "api_key"
            and auth.location == "header"
            and lowered == (auth.name or "").lower()
        ):
            raise ManifestError(f"{where}.headers: {name!r} is reserved")
        headers.append(
            (name, scope.check(parse_template(value, f"{where}.headers.{name}"), where))
        )
    json_body: Any = None
    has_json = False
    form: List[Tuple[str, Template]] = []
    if raw.body is not None:
        has_json = raw.body.json_ is not None
        if has_json == (raw.body.form is not None):
            raise ManifestError(f"{where}.body: exactly one of 'json' or 'form'")
        if raw.method in ("GET", "HEAD"):
            raise ManifestError(f"{where}.body: {raw.method} takes no body")
        if has_json:
            json_body = _json_templates(raw.body.json_, f"{where}.body.json", scope)
        else:
            for key, value in (raw.body.form or {}).items():
                text = value if isinstance(value, str) else literal_text(value)
                form.append(
                    (
                        key,
                        scope.check(
                            parse_template(text, f"{where}.body.form.{key}"), where
                        ),
                    )
                )
    for status in raw.accept_status:
        if not 400 <= status <= 599:
            raise ManifestError(f"{where}.accept_status: only 4xx/5xx statuses")
    # Redirects are followed by default for GET/HEAD only: a request body is
    # never replayed to another location.
    follows = raw.method in ("GET", "HEAD")
    if raw.follow_redirects and not follows:
        raise ManifestError(f"{where}.follow_redirects: GET/HEAD only")
    if raw.follow_redirects is not None:
        follows = raw.follow_redirects
    xml_prefixes = _xml_prefixes(raw, where)
    return Request(
        method=raw.method,
        base=base,
        path=path_t,
        query=tuple(query),
        headers=tuple(headers),
        json_body=json_body,
        has_json=has_json,
        form=tuple(form),
        response=raw.response,
        paginate=(
            _pagination(raw.paginate, f"{where}.paginate") if raw.paginate else None
        ),
        accept_status=frozenset(raw.accept_status),
        follow_redirects=follows,
        empty_body=raw.empty_body,
        xml_namespaces=raw.xml.namespaces if raw.xml else "drop",
        xml_prefixes=xml_prefixes,
    )


def _xml_prefixes(raw: RequestModel, where: str) -> Tuple[Tuple[str, str], ...]:
    """The ``xml`` option, checked: only on an XML response; ``prefixes``
    (prefix -> namespace URI) only with ``namespaces: keep``, each prefix a
    plain name and each URI declared once. Returned as (uri, prefix) pairs."""
    if raw.xml is None:
        return ()
    if raw.response != "xml":
        raise ManifestError(f"{where}.xml: only with 'response: xml'")
    if raw.xml.prefixes and raw.xml.namespaces != "keep":
        raise ManifestError(f"{where}.xml.prefixes: only with 'namespaces: keep'")
    pairs: List[Tuple[str, str]] = []
    seen = set()
    for prefix, uri in raw.xml.prefixes.items():
        if not _XML_PREFIX.match(prefix):
            raise ManifestError(
                f"{where}.xml.prefixes: {prefix!r} is not a valid prefix"
            )
        if not uri or len(uri) > 1024 or any(c in uri for c in "{}") or uri in seen:
            raise ManifestError(
                f"{where}.xml.prefixes.{prefix}: needs a distinct namespace URI"
            )
        seen.add(uri)
        pairs.append((uri, prefix))
    return tuple(pairs)


def _steps(
    raws: List[StepModel],
    where: str,
    bases: Dict[str, Base],
    scope: _Scope,
) -> Tuple[Step, ...]:
    seen: List[str] = []
    out: List[Step] = []
    for i, raw in enumerate(raws):
        w = f"{where}.steps[{i}]"
        if not _OP_NAME.match(raw.name) or raw.name in seen:
            raise ManifestError(f"{w}.name: must be a unique lower-case identifier")
        step_scope = _Scope(
            scope.config_keys,
            scope.secret_config,
            scope.params,
            steps=frozenset(seen),
            item=raw.foreach is not None,
            vars=scope.vars,
        )
        out.append(
            Step(
                name=raw.name,
                request=_request(raw.request, f"{w}.request", bases, step_scope),
                foreach=(
                    compile_expr(raw.foreach, f"{w}.foreach")
                    if raw.foreach is not None
                    else None
                ),
                max_items=raw.max_items,
                select=(
                    compile_expr(raw.select, f"{w}.select")
                    if raw.select is not None
                    else None
                ),
                when=(
                    compile_expr(raw.when, f"{w}.when")
                    if raw.when is not None
                    else None
                ),
            )
        )
        seen.append(raw.name)
    return tuple(out)


def _check_refs(schema: Any, where: str, depth: int = 0) -> None:
    if depth > 32:
        raise ManifestError(f"{where}: schema nested too deeply")
    if isinstance(schema, dict):
        ref = schema.get("$ref")
        if ref is not None and (not isinstance(ref, str) or not ref.startswith("#")):
            raise ManifestError(f"{where}: only local '$ref's are allowed")
        for value in schema.values():
            _check_refs(value, where, depth + 1)
    elif isinstance(schema, list):
        for value in schema:
            _check_refs(value, where, depth + 1)


def _vars(raw: Mapping[str, str], where: str) -> Vars:
    out: List[Tuple[str, ParsedResult]] = []
    for name, expr in raw.items():
        if not _OP_NAME.match(name):
            raise ManifestError(f"{where}.vars: {name!r} is not a valid var name")
        out.append((name, compile_expr(expr, f"{where}.vars.{name}")))
    return tuple(out)


def _timeseries_write(
    measurement: str,
    points: str,
    tags: Mapping[str, str],
    measurements: Tuple[str, ...],
    where: str,
) -> TimeseriesWrite:
    if measurement not in measurements:
        raise ManifestError(f"{where}.measurement: must be listed in spec.timeseries")
    compiled: List[Tuple[str, ParsedResult]] = []
    for key, expr in tags.items():
        if not _TAG_KEY.match(key) or key in RESERVED_TAG_KEYS:
            raise ManifestError(f"{where}.tags: {key!r} is not an allowed tag key")
        compiled.append((key, compile_expr(expr, f"{where}.tags.{key}")))
    return TimeseriesWrite(
        measurement=measurement,
        points=compile_expr(points, f"{where}.points"),
        tags=tuple(compiled),
    )


def _operation(
    name: str,
    kind: str,
    raw: OperationModel,
    bases: Dict[str, Base],
    config_keys: FrozenSet[str],
    secret_config: FrozenSet[str],
    measurements: Tuple[str, ...] = (),
) -> Operation:
    where = f"spec.{kind}s.{name}"
    if not _OP_NAME.match(name) or name in RESERVED_OPERATION_NAMES:
        raise ManifestError(f"{where}: not a valid (or a reserved) operation name")
    schema = raw.parameters
    if schema.get("type") != "object":
        raise ManifestError(f"{where}.parameters: must be a JSON Schema of type object")
    _check_refs(schema, f"{where}.parameters")
    try:
        Draft7Validator.check_schema(schema)
    except SchemaError as e:
        raise ManifestError(
            f"{where}.parameters: invalid JSON Schema ({e.message[:200]})"
        ) from None
    props = schema.get("properties") or {}
    if not isinstance(props, dict):
        raise ManifestError(f"{where}.parameters.properties: must be an object")
    variables = _vars(raw.vars, where)
    scope = _Scope(
        config_keys,
        secret_config,
        frozenset(props),
        vars=frozenset(n for n, _ in variables),
    )
    read_only = raw.read_only if raw.read_only is not None else kind == "tool"
    if raw.effect is not None and kind != "tool":
        raise ManifestError(f"{where}.effect: only an AI tool declares an effect")
    if raw.effect == "read" and not read_only:
        raise ManifestError(f"{where}.effect: a read tool must be read_only")
    timeseries: Optional[TimeseriesWrite] = None
    if raw.timeseries is not None:
        # A write is a side effect: never from an AI tool or a read-only action.
        if kind != "action" or read_only:
            raise ManifestError(
                f"{where}.timeseries: only a non-read-only action may write"
            )
        ts = raw.timeseries
        timeseries = _timeseries_write(
            ts.measurement, ts.points, ts.tags, measurements, f"{where}.timeseries"
        )
    return Operation(
        name=name,
        kind=kind,
        description=raw.description,
        parameters=schema,
        validator=Draft7Validator(schema),
        steps=_steps(raw.steps, where, bases, scope),
        output=(
            compile_expr(raw.output, f"{where}.output")
            if raw.output is not None
            else None
        ),
        on_error=raw.on_error,
        error_output=(
            compile_expr(raw.error_output, f"{where}.error_output")
            if raw.error_output is not None
            else None
        ),
        read_only=read_only,
        admin_only=raw.admin_only,
        timeseries=timeseries,
        vars=variables,
        effect=raw.effect,
    )


def _config_schema(
    fields: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], FrozenSet[str]]:
    defaults: Dict[str, Any] = {}
    secret: set[str] = set()
    seen: set[str] = set()
    for i, entry in enumerate(fields):
        key = entry.get("key")
        if not isinstance(key, str) or not _CONFIG_KEY.match(key) or key in seen:
            raise ManifestError(f"spec.config_schema[{i}].key: a unique config key")
        seen.add(key)
        if entry.get("secret") or entry.get("type") in ("secret", "password"):
            secret.add(key)
        elif "default" in entry:
            defaults[key] = entry["default"]
    return defaults, frozenset(secret)


def _format_validation(e: ValidationError) -> str:
    parts = []
    for err in e.errors()[:5]:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        parts.append(f"{loc}: {err.get('msg')}")
    return "; ".join(parts)


def load_manifest(data: Mapping[str, Any]) -> DeclarativeManifest:
    """Validate and compile a declarative manifest; raises ManifestError."""
    if not isinstance(data, Mapping):
        raise ManifestError("a manifest must be a mapping")
    try:
        model = ManifestModel.model_validate(dict(data))
    except ValidationError as e:
        raise ManifestError(f"invalid manifest: {_format_validation(e)}") from None
    meta, spec = model.metadata, model.spec
    if not _PLUGIN_NAME.match(meta.name):
        raise ManifestError("metadata.name: lower-case letters, digits, '_' or '-'")
    rules = tuple(
        _egress_rule(r, f"spec.egress[{i}]") for i, r in enumerate(spec.egress)
    )
    defaults, secret_config = _config_schema(spec.config_schema)
    config_keys = frozenset(e["key"] for e in spec.config_schema)
    base_scope = _Scope(config_keys, secret_config, None)
    bases: Dict[str, Base] = {}
    for name, raw_base in spec.bases.items():
        if not _OP_NAME.match(name):
            raise ManifestError(f"spec.bases.{name}: not a valid base name")
        bases[name] = _base(name, raw_base, rules, base_scope)
    measurements: Tuple[str, ...] = ()
    if spec.timeseries is not None:
        for m in spec.timeseries.measurements:
            if not _MEASUREMENT.match(m):
                raise ManifestError(f"spec.timeseries: {m!r} is not a measurement name")
        measurements = tuple(spec.timeseries.measurements)
    if len(spec.tools) + len(spec.actions) > MAX_OPERATIONS:
        raise ManifestError(f"spec: at most {MAX_OPERATIONS} tools and actions")
    clash = set(spec.tools) & set(spec.actions)
    if clash:
        raise ManifestError(f"spec: {sorted(clash)} is both a tool and an action")
    tools = {
        n: _operation(n, "tool", op, bases, config_keys, secret_config, measurements)
        for n, op in spec.tools.items()
    }
    actions = {
        n: _operation(n, "action", op, bases, config_keys, secret_config, measurements)
        for n, op in spec.actions.items()
    }
    if not tools and not actions and spec.schedule is None:
        raise ManifestError("spec: declare at least one tool, action or schedule")
    schedule: Optional[Schedule] = None
    if spec.schedule is not None:
        raw_s = spec.schedule
        write = _timeseries_write(
            raw_s.measurement, raw_s.points, raw_s.tags, measurements, "spec.schedule"
        )
        if raw_s.cron is not None and not _CRON.match(raw_s.cron.strip()):
            raise ManifestError("spec.schedule.cron: a five-field cron expression")
        schedule_vars = _vars(raw_s.vars, "spec.schedule")
        schedule = Schedule(
            cron=raw_s.cron.strip() if raw_s.cron else None,
            steps=_steps(
                raw_s.steps,
                "spec.schedule",
                bases,
                _Scope(
                    config_keys,
                    secret_config,
                    None,
                    vars=frozenset(n for n, _ in schedule_vars),
                ),
            ),
            vars=schedule_vars,
            write=write,
            output=(
                compile_expr(raw_s.output, "spec.schedule.output")
                if raw_s.output is not None
                else None
            ),
            error_output=(
                compile_expr(raw_s.error_output, "spec.schedule.error_output")
                if raw_s.error_output is not None
                else None
            ),
        )
    webhook: Optional[Webhook] = None
    if spec.webhook is not None:
        raw_w = spec.webhook
        target = actions.get(raw_w.action)
        if target is None or target.admin_only:
            # No caller role reaches a webhook, so never an admin-only action.
            raise ManifestError(
                "spec.webhook.action: a declared action that is not admin_only"
            )
        if not _CONFIG_KEY.match(raw_w.secret):
            raise ManifestError("spec.webhook.secret: not a valid secret name")
        if "body" not in target.parameters.get("properties", {}):
            # The request body arrives as params.body, validated by its schema.
            raise ManifestError(
                "spec.webhook.action: the action must declare a 'body' parameter"
            )
        webhook = Webhook(action=raw_w.action, secret=raw_w.secret)
    return DeclarativeManifest(
        name=meta.name,
        version=meta.version,
        description=meta.description,
        author=meta.author,
        stable_id=meta.stable_id,
        display=dict(spec.display) if spec.display is not None else None,
        config_schema=[dict(e) for e in spec.config_schema],
        config_defaults=defaults,
        secret_config_keys=secret_config,
        egress=rules,
        bases=bases,
        limits=Limits(
            timeout_s=spec.limits.timeout_s,
            max_response_bytes=spec.limits.max_response_bytes,
            max_concurrency=spec.limits.max_concurrency,
            rate_per_minute=spec.limits.rate_per_minute,
        ),
        measurements=measurements,
        tools=tools,
        actions=actions,
        schedule=schedule,
        raw=dict(data),
        webhook=webhook,
    )
