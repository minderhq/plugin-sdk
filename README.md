# Minder Plugin SDK

The authoring contract for **Minder** module plugins — the `Plugin` lifecycle,
`PluginMetadata`, the optional extension points (config, actions, AI tools), the
manifest JSON Schema, and a complete worked reference plugin.

> Minder is a self-hostable, local-first AI platform (RAG + knowledge graph +
> local LLMs) extended by **plugins**. Plugins are **manifest-based and run no
> arbitrary uploaded code** — new actions are fixed, reviewed handlers. This repo
> is everything a third party needs to write one; the core platform is
> documented at [minderhq.github.io/docs](https://minderhq.github.io/docs/).

Licensed under **Apache-2.0**.

Full docs: the [plugin authoring guide](https://minderhq.github.io/docs/plugins/authoring/),
the [contract reference](https://minderhq.github.io/docs/plugins/contract/), and
[manifest plugins](https://minderhq.github.io/docs/plugins/manifest/) on the docs site.

## Install

```bash
pip install minder-plugin-sdk        # once published
# or, from source:
pip install "git+https://github.com/minderhq/plugin-sdk"
```

## The contract in 30 seconds

A module plugin is a **class** the registry duck-types by the presence of
`register()`. Inheriting `Plugin` is optional — it's a `runtime_checkable`
`Protocol` for editor/mypy checks.

```python
from minder_plugin_sdk import PluginMetadata, Plugin

class MyPlugin:                      # no inheritance required
    async def register(self) -> PluginMetadata:
        return PluginMetadata(
            name="my-plugin", version="1.0.0",
            description="what it does", author="you",
        )
    async def initialize(self) -> None: ...
    async def health_check(self) -> dict:
        return {"healthy": True}     # ← MUST return {"healthy": <bool>}
    async def collect_data(self) -> dict: ...   # hourly, or manual /collect
    async def analyze(self) -> dict: ...        # /analysis
    async def shutdown(self) -> None: ...
```

The registry drives this lifecycle: `register()` → `initialize()` →
`health_check()` (60s loop) → `collect_data()` (hourly or on demand) →
`analyze()` → `shutdown()`.

## Optional extension points (class attributes)

| Attribute | What it does |
|-----------|--------------|
| `CONFIG_SCHEMA` | Makes the plugin configurable over the API (`GET/PUT /v1/plugins/<name>/config`) — no container env + restart. The registry resolves `default → env → persisted` and calls `apply_config(effective)`. |
| `ACTIONS` (+ `READ_ONLY_ACTIONS`) | A `frozenset` of method names invokable via `POST /v1/plugins/<name>/actions/<method>` (JWT-gated). Only listed names are reachable. |
| `AI_TOOLS` | Advertise Ollama / OpenAI function-calling tools (`{name, description, parameters, action}`), aggregated at `GET /v1/plugins/ai/tools`. |
| `DISPLAY` | Branding for the plugin's card in the client: `{label, summary, logo, color, category}`. `logo` is a lucide icon name. |
| `REQUIRES` | What the plugin needs from the platform: `{services, optional_services, bundles}`. Lets the platform refuse to enable a plugin whose services are missing, offer to enable the bundles it needs, and show requirements on its card. Names are checked against `KNOWN_SERVICES` / `KNOWN_BUNDLES`. |

## Plugin-driven UI (the plugin owns its presentation)

Every plugin's config needs are different — a long value wants a `textarea`, a
city wants autocomplete from a source, a flag wants a toggle. So the **plugin
self-describes** how each field renders, and the **trusted client** draws it with
its own components. Plugins never ship HTML/templates — that would be an injection
vector and break the "no arbitrary code" guarantee; presentation is **declarative**.

Add these optional keys to any `CONFIG_SCHEMA` field:

| Key | Purpose |
|-----|---------|
| `widget` | `text` · `textarea` · `number` · `toggle` · `select` · `multiselect` · `secret` · `autocomplete` (default: inferred from `type`) |
| `placeholder`, `rows` | input hint; textarea height |
| `options` | static `[{value, label}]` for a select |
| `options_action` | name of a **READ_ONLY action** returning `[{value, label}]` → a **dynamic** autocomplete (e.g. a city search). Reuses `ACTIONS`. |
| `min` / `max` / `step` | numeric bounds |
| `required`, `group` | validation; section grouping |

A field with none of these renders as a plain input, so existing schemas keep
working. See [`examples/weather_plugin.py`](examples/weather_plugin.py): a
`textarea` for locations, a `toggle` for the sink, and a `WEATHER_DEFAULT_CITY`
**autocomplete** backed by a `search_cities` read-only action — plus a `DISPLAY`
logo. (Client + registry wiring is tracked in Minder core.)

## Gotchas (read these)

- **`health_check()` must return `{"healthy": <bool>, ...}`.** Monitoring reads
  `health["healthy"]`; anything else marks the plugin unhealthy.
- **The loader picks the class** by `__all__` if present, else the first class that
  defines `register`. Export exactly the plugin class via `__all__`.
- **Only `ACTIONS` names are reachable** over HTTP — nothing else on the instance.
  Reads go through `/collect` + `/analysis`; `ACTIONS` is for state changes.
- **Backend config is injected** by the registry into `self.config`: `redis`,
  `influxdb` and, when available, `database`. There is **no** `postgres` or
  `qdrant` key — read what you need from `self.config` and don't hard-wire hosts.
  Don't read `POSTGRES_*` (or other platform credentials) from the environment
  either.
- **`config["database"]` is a least-privilege Postgres handle**, not the
  platform's database credentials:

  ```python
  {"host": ..., "port": ..., "user": "minder_plugins", "password": ...,
   "database": ..., "schema": "plugin_data"}
  ```

  - The role only has its own schema (`plugin_data`) and has **no access to
    platform tables**.
  - Its `search_path` is pinned to `plugin_data`, so an unqualified
    `CREATE TABLE` lands there, owned by the plugin. `schema` is passed
    explicitly too, so you can schema-qualify your own DDL.
  - **The key may be missing.** If the operator hasn't configured the plugin
    database role, no `database` key is injected at all. Use
    `self.config.get("database")` and degrade gracefully (disable the feature
    or report it in `health_check()`) instead of raising `KeyError`.

## Platform context (contract v2)

Plugins may run in a separate process from the platform (out-of-process
execution). That process holds **no platform credentials** and cannot reach
platform services directly, so a plugin asks the platform for what it needs
through **`self.ctx`**, the platform context. The platform checks every call
against a grant for the current invocation: this plugin, the invoking
tenant/owner, and the capabilities the plugin declared. The same plugin code
works whether it runs in-process or out-of-process.

Contract v2 is **opt-in and additive**. A plugin that declares none of the
attributes below is a contract-v1 plugin and keeps working unchanged.

```python
from minder_plugin_sdk import (
    CapabilityDenied, CapabilityUnavailable, PluginBase, PluginMetadata,
)
from minder_plugin_sdk.safe_http import safe_request


class CrawlerPlugin(PluginBase):
    CONTRACT_VERSION = 2                 # "I use self.ctx"
    EGRESS = "public"                    # or "lan", or ["api.example.com", "*.example.org"]
    REQUIRES = {"bundles": ["rag"]}      # documents.index needs the rag bundle
    ACTIONS = frozenset({"ingest"})

    async def register(self) -> PluginMetadata:
        return PluginMetadata(name="crawler", version="1.0.0",
                              description="Index a web page", author="you")

    async def ingest(self, url: str, kb_id: str) -> dict:
        page = await safe_request("GET", url)          # SSRF-guarded fetch
        return await self.ctx.documents.index(
            kb_id, "page.html", page.content, "text/html")

    async def health_check(self) -> dict:
        # Optional features: switch on what is granted, degrade otherwise.
        return {"healthy": self.status == "ready",
                "indexing": self.ctx.has("documents.index")}
```

**What `self.ctx` offers** (every call is `async`):

| Call | Capability | Notes |
|------|------------|-------|
| `await ctx.secrets.get(key)` | `secrets.read` | This plugin's own secret for the invoking tenant, or `None` if unset. |
| `await ctx.plugins.invoke(plugin, action, **kw)` | `plugins.invoke` | Only along a declared `PluginMetadata.dependencies` edge. |
| `await ctx.documents.index(kb_id, filename, content, content_type)` | `documents.index` | Uploads on behalf of the invoking user. |
| `await ctx.telegraf.set_managed_region(toml)` / `clear_managed_region()` / `reload(force=False)` | `telegraf.*` | Only for plugins with `MANAGES = ["telegraf"]`. The platform validates the TOML (allowlisted inputs, size caps) and writes it atomically. |
| `await ctx.timeseries.write(lines, precision="s")` / `latest(measurement, tag_key, tag_value, fields=None)` | `timeseries.*` | Only for plugins that declare `TIMESERIES`, and only for the declared measurements. The platform sets the owner and plugin tags. `latest` returns the newest timestamp (or `None`), or `{"time", "fields"}` when `fields` is given. The `write_history` / `latest_influx_date` helpers use it when you pass `ctx=self.ctx`. |
| `ctx.has(capability)` | — | Whether a capability is granted (`"telegraf"` matches any `telegraf.*`). |

**Errors** (all subclasses of `PluginError`; messages name the capability and a
reason, never the secret or payload):

- `CapabilityDenied`: not granted for this invocation (undeclared, wrong
  owner/tenant, expired, undeclared plugin edge). Retrying won't help.
- `CapabilityUnavailable`: cannot be served right now. This is also what an
  **unbound** context raises (a contract-v1 host, or a test without a fake), so
  catch it to degrade cleanly.
- `CapabilityInvalid`: the platform rejected the arguments.

**Binding.** The host calls `plugin.bind_context(ctx)` when it loads the
plugin. `PluginBase` implements it; a plain duck-typed class can define its own
`bind_context(self, ctx)` and store `self.ctx`. Before binding,
`PluginBase.ctx` is `UNBOUND_CONTEXT`.

**Declarations** (optional class attributes, checked by `check_plugin`):

| Attribute | Shape | Meaning |
|-----------|-------|---------|
| `CONTRACT_VERSION` | `int` (default `1`) | `2` = uses `self.ctx`. A host refuses a plugin that declares a newer version than it supports, and `check_plugin` flags versions above `SUPPORTED_CONTRACT_VERSION`. |
| `MANAGES` | `list[str]` | Platform-managed sidecars the plugin configures through `ctx.<name>.*` (currently `"telegraf"`). Requires `CONTRACT_VERSION = 2`. |
| `EGRESS` | `"public"`, `"lan"`, or a list of host patterns | Where the plugin connects. Patterns are hostnames (`"api.example.com"`) or one-level wildcards (`"*.example.com"`); no scheme, port, path or IP. |
| `TIMESERIES` | `{"measurements": [...]}` | The time-series measurements the plugin writes and reads through `ctx.timeseries` (grants `timeseries.*`). |

**Rules for plugin code** (enforced by `check_plugin` / `minder-plugin validate`):

- **Don't read platform secrets from the environment.** `os.environ[...]`,
  `os.environ.get(...)` and `os.getenv(...)` of platform-credential names are
  flagged: `JWT_SECRET`, `NEO4J_AUTH`, `POSTGRES_PASSWORD`, `DB_*`, `REDIS_*`,
  anything ending in `_TOKEN`, `_SECRET` or `_PASSWORD`, and so on. Keys
  declared in your own `CONFIG_SCHEMA` are your configuration and are allowed;
  use `"secret": True` there, or `ctx.secrets.get(...)`.
- **Don't import platform internals** (`core.*`). Talk to the platform only
  through this SDK.
- **Return JSON-serialisable results** from actions and lifecycle methods; they
  may cross a process boundary.
- **Don't share memory between plugins.** Use `ctx.plugins.invoke(...)` along a
  declared dependency instead of reaching into another plugin's instance.

These checks are a **lint, not a security boundary**. The scan is syntactic
and best-effort (names built at runtime aren't seen), so the rules still apply
where the checker can't look. The actual protection comes from the platform:
plugin code runs isolated, with no platform credentials and no route to
platform services, and every `self.ctx` call is checked against the
invocation's grant.

### `safe_http`: outbound HTTP for URLs you don't control

`minder_plugin_sdk.safe_http.safe_request(method, url, ...)` applies the
platform's egress rules in the plugin. Use it for any configured or
user-supplied URL. It needs `httpx`; the rest of the SDK stays dependency-free.

- Allows `http`/`https` only, and refuses URLs with embedded credentials.
- Resolves the host and refuses it if **any** address is non-public. That
  covers loopback, private, link-local and cloud metadata, CGNAT, multicast,
  reserved ranges, and IPv4 embedded in IPv6.
- Pins the connection to the checked address. TLS is still verified against the
  hostname.
- Follows redirects only for `GET`/`HEAD` and re-checks **every** hop. A
  redirect to another origin (scheme, host or port) drops **all** your
  headers, and an `https` → `http` downgrade is refused.
- Opens a fresh connection per hop, so a pinned connection is never reused for
  another host.
- Caps the body (`max_bytes`, default 10 MiB) and the number of redirects
  (default 5). `timeout` (default 30 s) bounds the whole call; past it,
  `TimeoutError` is raised.
- The `client=` parameter exists for tests (mock transports); leave it unset in
  plugin code.
- Takes `allowed_hosts=` (e.g. your `EGRESS` list) to also restrict which hosts
  may be contacted.
- `check_url(url)` gives you the check alone.

### Testing with `FakePlatformContext`

```python
import asyncio
from minder_plugin_sdk import CapabilityDenied, FakePlatformContext, run_lifecycle

def test_ingest_indexes_the_page():
    ctx = FakePlatformContext(grants={"documents.index"})
    plugin = CrawlerPlugin()
    plugin.bind_context(ctx)
    ...
    assert ctx.indexed[0]["kb_id"] == "kb1"

def test_secret_denied():
    ctx = FakePlatformContext(secrets={"API_TOKEN": "t"}, grants=set())
    # ctx.secrets.get(...) now raises CapabilityDenied
    out = asyncio.run(run_lifecycle(MyPlugin(), ctx=ctx))   # binds ctx after register()
```

`FakePlatformContext` takes these options:

- `secrets`: the secret values.
- `grants`: the granted capabilities. `None`, the default, grants everything,
  which is more than the platform would. `FakePlatformContext.for_plugin(plugin,
  dependencies=[...])` starts from what the plugin's declarations would be
  granted instead (`secrets.read`; `plugins.invoke` with dependencies;
  `documents.index` with the `rag` bundle; `telegraf.*` with
  `MANAGES = ["telegraf"]`).
- `denied` / `unavailable`: capabilities that always raise.
- `invoke_results`: `{(plugin, action): value or callable}`.
- `telegraf_validator`: a callable that raises `CapabilityInvalid` to simulate a
  rejected region.
- `timeseries_latest`: `{(measurement, tag_key, tag_value): point}` answers for
  `ctx.timeseries.latest` (an ISO timestamp, or `{"time", "fields"}`).

It records every call in `ctx.calls` with identifying arguments only (secret
*keys*, never values; kwarg *names* for invokes; see
`ctx.called("secrets.read")`), and keeps side effects in `ctx.indexed`,
`ctx.telegraf_region`, `ctx.telegraf_reloads` and `ctx.timeseries_lines`.

## Worked example

[`examples/weather_plugin.py`](examples/weather_plugin.py) is a complete,
self-contained plugin that uses **every** part of the contract: the full
lifecycle, `CONFIG_SCHEMA` + `apply_config`, `ACTIONS` + `READ_ONLY_ACTIONS`, and
an `AI_TOOLS` function-calling tool. Depends only on `httpx` + this SDK.

## Manifest plugins (data-ingestion)

A separate, declarative mechanism for `webhook → store-vector` ingestion — a YAML
manifest that supplies **parameters only** (no code). Its JSON Schema (draft-07)
is [`src/minder_plugin_sdk/schemas/manifest.schema.json`](src/minder_plugin_sdk/schemas/manifest.schema.json). This is the
**installable, runtime** shape most **third-party** integrations should use rather
than an in-process code plugin — see
[`docs/plugins/webhook-vs-code-plugin.md`](docs/plugins/webhook-vs-code-plugin.md)
for which shape to pick. Reach for a manifest when you just need to pipe a webhook
into the vector store; add a small `handle_webhook` handler
([`examples/webhook_plugin.py`](examples/webhook_plugin.py)) only when a payload
needs reshaping first.

## Scaling to any plugin (RFC 0001)

Thousands of plugin types can't fit a fixed lifecycle + a closed widget enum — and
the answer is **not** plugin-supplied code (that breaks the no-arbitrary-code
guarantee). Instead variety comes from **data + trusted primitives**:

- **Config is JSON Schema + UI Schema.** `resolve_config_schema(plugin)` returns a
  standard JSON Schema (nested objects, arrays, enums, formats, conditionals,
  validation) plus UI hints. The simple `CONFIG_SCHEMA` list is compiled to this,
  so simple plugins stay one-liners while the platform always speaks JSON Schema.
- **Widgets are a client-side registry**, resolved by name with a default
  fallback — a plugin can ask for a widget that doesn't exist yet and degrade
  gracefully; new rich widgets are added to the trusted client, never shipped as
  plugin code.
- **Capabilities, not one lifecycle.** `capabilities(plugin)` reports what a
  plugin implements (data-source, ai-tools, actions, webhook-ingest, scheduler,
  connection, ui-panel…) — an open vocabulary; unknown capabilities are ignored.
- **Versioned** (`api_version` / `API_VERSION`) so the contract evolves without
  breaking older plugins.

Full design: [`docs/rfc/0001-extensible-plugin-contract.md`](docs/rfc/0001-extensible-plugin-contract.md).

## SDK toolkit

The SDK is more than the contract — it ships the batteries a plugin author needs:

| Import | What |
|--------|------|
| `PluginBase` | Optional base class — sensible defaults for the whole lifecycle + the standard config flow, so a data-source plugin is just `register` + `collect_data`. |
| `check_plugin(p)` / `run_lifecycle(p, ctx=None)` | Test helpers: contract violations as a list; drive the full lifecycle in a test (optionally with a bound context). |
| `FakePlatformContext` | In-memory platform context (contract v2) for unit tests: secrets, grants/denials, recorded calls. |
| `safe_http.safe_request` / `check_url` | SSRF-guarded outbound HTTP (needs `httpx`). |
| `resolve_config_schema` / `resolve_effective_config` / `validate_config` | Compile config to JSON Schema, resolve default→env→persisted, validate values. |
| `build_tool_definitions` / `ai_tool_errors` | Turn `AI_TOOLS` into OpenAI/Ollama tool defs; validate they map to actions. |
| `load_manifest` / `validate_manifest` | Parse + validate a `webhook → store-vector` manifest (bundled JSON Schema). |
| `capabilities(p)` + `DataSource` / `Scheduler` / `WebhookHandler` / … | Introspect + type-check per-capability interfaces. |

### CLI

```bash
minder-plugin scaffold my-plugin        # generate a working skeleton
minder-plugin validate my_plugin.py     # (or a manifest.yaml) → contract check
minder-plugin inspect  my_plugin.py     # capabilities + compiled config/UI schema + tools
```

### Examples

- [`weather_plugin.py`](examples/weather_plugin.py) — the full reference (config UI, actions, AI tool, DISPLAY).
- [`minimal_plugin.py`](examples/minimal_plugin.py) — the smallest data source (`PluginBase`).
- [`ai_tool_plugin.py`](examples/ai_tool_plugin.py) — an AI-tool-only plugin.
- [`discord_manifest.yaml`](examples/discord_manifest.yaml) — a manifest plugin.
- [`webhook_manifest.yaml`](examples/webhook_manifest.yaml) — a manifest + webhook plugin (the installable third-party shape).
- [`webhook_plugin.py`](examples/webhook_plugin.py) — a `handle_webhook` handler stub (request/response contract).

## Develop

```bash
pip install -e ".[dev,examples]"
pytest && black --check src tests examples && flake8 src tests examples && mypy src
```

## Contributing a plugin

Community plugins are catalogued at
[`minderhq/plugins`](https://github.com/minderhq/plugins). Scaffold a new one from
[`minderhq/plugin-template`](https://github.com/minderhq/plugin-template) (compiles
against this SDK). Design and roadmap discussion lives in
[Discussions](https://github.com/minderhq/plugin-sdk/discussions).
