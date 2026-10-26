# Changelog

All notable changes to `minder-plugin-sdk`. Pre-1.0: the contract may still
evolve; changes are additive and backwards-compatible where possible.

## [Unreleased]

### `minder_t0_engine` and `minder-plugin try`
- New package `minder_t0_engine`: the T0 declarative connector engine that
  Minder's declarative runner uses (manifest model, placeholders, JMESPath /
  XML mapping, pagination, per-plugin egress with IP pinning, and the shared
  egress policy). Install with the new `t0` extra.
- New `minder-plugin try MANIFEST OPERATION`: runs one tool or action with
  that engine and prints the mapped output. `--record DIR` saves upstream
  responses; `--replay DIR` runs offline from them.

### Manifest schemas
The bundled schemas are now the single source of the manifest contract; Minder
validates against the same files.
- `manifest.schema.json` gains the `schedule` and `poll` triggers and the
  `http-request` and `plugin-action` actions, which Minder already runs. A
  `webhook` trigger now requires `secretRef` (Minder refuses an unsigned
  webhook), `/t0/` webhook paths are reserved, and a `store-vector` text
  template may not be empty. The schema has an `$id`:
  `https://minderhq.github.io/docs/schemas/manifest.v1alpha1.json`.
- New `declarative-manifest.schema.json` for declarative connectors
  (`spec.runtime.kind: declarative`), `$id`
  `https://minderhq.github.io/docs/schemas/declarative-manifest.v1alpha1.json`.
  It covers the runtime, egress, bases and auth, limits, time series, tools,
  actions, the schedule and the signed webhook. Unknown fields are refused.
- `validate_manifest` and `minder-plugin validate` pick the schema from
  `spec.runtime.kind`; `minder-plugin validate` also reads `.json` manifests.
  New `declarative_manifest_schema()` and `is_declarative_manifest()`.
- Tests validate the catalog's declarative manifests against the schema.

### Tool effect classes
Additive; a tool without the new fields still loads (warning only).
- `AI_TOOLS` entries may declare `effect` (`read` / `write` / `send` /
  `destructive`), `idempotent`, per-argument `sensitivity` (`recipient`, `url`,
  `amount`, `free_text`, `bound:<attr>`; or a tool-level `sensitivities` map)
  and egress `hosts`. Minder uses them to decide which tool calls need user
  approval. New `tool_effects` module with `Effect`, `EFFECTS`, `AIToolSpec`
  and `SENSITIVITIES`.
- `check_plugin` fails on invalid values. New `check_plugin_warnings` /
  `ai_tool_warnings` report a tool without `effect` and a declaration that the
  tool's name, method or arguments contradict (e.g. `read` with a recipient
  argument). `minder-plugin validate` prints them as `WARN` lines and still
  passes.
- `mcp_annotations` / `tool_annotations` map an effect to MCP tool annotations
  (`readOnlyHint`, `destructiveHint`, `openWorldHint`, `idempotentHint`).
- `build_tool_definitions` leaves the per-argument `sensitivity` out of the
  parameters it hands to the model.
- The examples declare `effect`.

### Platform context (contract v2)
Additive; plugins that declare none of the new attributes are contract-v1
plugins and keep working unchanged. This is groundwork for running plugins out
of process, where plugin code holds no platform credentials.
- `context`: the `PlatformContext` protocol a plugin reaches through `self.ctx`.
  It provides `secrets.get`, `plugins.invoke`, `documents.index`,
  `telegraf.set_managed_region` / `clear_managed_region` / `reload(force)`, and
  `has(capability)`. Capability names are `HOST_CAPABILITIES`, and name
  matching is `capability_granted`.
- `PluginBase.bind_context(ctx)` hook and `PluginBase.ctx`, which defaults to
  `UNBOUND_CONTEXT`. Its calls raise `CapabilityUnavailable` and `has()` is
  `False`, so unbound plugins degrade cleanly.
- `errors`: `CapabilityError` with `CapabilityDenied`, `CapabilityUnavailable`
  and `CapabilityInvalid` (all `PluginError`s; messages never carry secrets or
  payloads), plus `UnsafeURLError`.
- `declarations`: optional `CONTRACT_VERSION` (`SUPPORTED_CONTRACT_VERSION = 2`),
  `MANAGES`, `EGRESS` (`"public"` / `"lan"` / host patterns) and `TIMESERIES`
  (declared only), with `declaration_errors` / `contract_version`.
- `safe_http`: `safe_request` / `check_url`, SSRF-guarded outbound HTTP. It
  refuses non-public addresses, pins the checked IP on a fresh connection per
  hop, re-checks each redirect hop, drops caller headers on a cross-origin
  redirect, refuses `https` → `http` downgrades, caps the body and bounds the
  whole call by `timeout`. It needs `httpx` (optional).
- `check_plugin` now also checks:
  - the contract-v2 declarations, refusing a `CONTRACT_VERSION` newer than
    supported;
  - `os.environ` / `os.getenv` reads of platform-secret names (aliases
    included), except keys the plugin declares in its own `CONFIG_SCHEMA`
    (`source_rules`);
  - imports of platform internals (`core.*`), including literal
    `importlib.import_module` / `__import__` calls.

  The scan covers every module of a packaged plugin. It is a lint, not a
  security boundary.

  Existing plugins that read such names directly from the environment now
  fail validation. Move them to `CONFIG_SCHEMA` or `ctx.secrets`.
- `harness.FakePlatformContext` gives plugin unit tests configurable secrets,
  grants, denials and unavailability, plugin-invoke results, and recorded calls.
  `FakePlatformContext.for_plugin(...)` derives grants from the plugin's
  declarations.
  `run_lifecycle(plugin, ctx=...)` binds a context.
- `minder-plugin inspect` reports `contract_version`, `manages`, `egress` and
  `timeseries`.
- Rules for plugin authors: return JSON-serialisable results, and don't share
  memory between plugins.

### Remote (T4) plugins
New optional extra `serve` (starlette, uvicorn, cryptography, httpx). The base
package stays dependency-free, because these packages are imported only when
used.
- `t4` signs and verifies one RFC 9421 HTTP Message Signatures profile, used in
  both directions.
  - The profile is Ed25519 over `@method`, `@authority`, `@path`, `@query`,
    `content-digest` and, when present, `authorization`. The parameters are
    `created`, `nonce`, `keyid` (the RFC 7638 thumbprint) and `alg`. Bodies
    get an RFC 9530 `Content-Digest`.
  - A signature is fresh while `now - created <= 300` and
    `created - now <= 10`.
  - Nonce replay goes through a pluggable `NonceCache`, which expires entries
    at the wall-clock time `created + 300 + 10`.
  - `MinderKeySet` fetches and caches Minder's
    `/.well-known/minder/plugin-jwks.json`, refetching on an unknown `keyid`
    with a rate limit.
  - `InstallationKey` signs callbacks.
  - `normalize_authority` refuses non-ASCII input before lowercasing and an
    empty label anywhere in the host (`a..b`, `.a.b`, `a.b..`); one trailing
    dot is still dropped.
  - `require_ascii_origin` returns the canonical `scheme://authority` of an
    origin whose host is already ASCII: LDH labels, well-formed IDNA
    A-labels (`xn--`), canonical dotted-decimal IPv4 or an IPv6 literal. It
    refuses a Unicode host, `_` or `%` in the host, a `0x` hexadecimal label
    anywhere (and any host that ends in a number but isn't canonical IPv4),
    and an `xn--` label that is malformed or fails a conservative subset of
    the IDNA2008 rules (no leading combining mark, no default-ignorable or
    filler code points, no mixed bidi direction, scripts among Latin,
    Cyrillic and Greek, or digit sets). It is not full IDNA2008. It is for
    pinning an origin once.
- `t4_server.create_app` and `minder-plugin serve` wrap a plugin as an ASGI
  app.
  - It serves a signed `POST /minder/v1/invoke` (envelope `kind`, `target`,
    `kwargs`, `deadline_ms`) and `GET /minder/v1/health`.
  - It checks `@authority` against the configured `--public-authority`, and
    the envelope's `installation_id` against `--installation-id`. Both are
    required; `--insecure-host-authority` (local development only) is the one
    opt-out.
  - Sync targets run in a worker thread, so `deadline_ms` applies to them
    and they don't stall the event loop.
  - Errors are JSON with stable codes and no tracebacks.
  - `current_invocation()` exposes the invocation.
- `t4_callbacks.CallbackPlatformContext` is `self.ctx` for remote plugins.
  - Each call is a `POST <callback_base>/v1/plugin-callbacks/<capability>`,
    sent with the grant as bearer and signed with the installation key.
  - Errors map to `CapabilityDenied`, `CapabilityInvalid` and
    `CapabilityUnavailable`.
  - `telegraf.*` is denied locally.
- `examples/remote_echo` and the guide
  `docs/t4/verifying-minder-signatures.md`, for authors in other languages.

### Platform time-series capability
- `context`: `ctx.timeseries` (`TimeseriesAPI`) with `write(lines,
  precision="s")` and `latest(measurement, tag_key, tag_value, fields=None)`,
  capabilities `timeseries.write` / `timeseries.latest` (`CAP_TIMESERIES_*`,
  now in `HOST_CAPABILITIES`). Granted to plugins that declare `TIMESERIES`;
  the platform limits them to the declared measurements and sets the owner and
  plugin tags. The unbound context raises `CapabilityUnavailable`.
- `write_history` / `latest_influx_date` take an optional `ctx=` (pass
  `self.ctx`). When that context grants `timeseries.*`, they go through
  `ctx.timeseries` and never contact InfluxDB (`cfg` is unused), so they work
  for a plugin hosted out of process. Without a context, with the unbound
  context, or without the grant they keep the direct InfluxDB path unchanged.
  Both still never raise.
- `FakePlatformContext`: `ctx.timeseries`, with `timeseries_latest` answers and
  the written lines in `timeseries_lines`; `for_plugin` grants `timeseries.*`
  when the plugin declares `TIMESERIES`.

### Examples & docs
- Webhook-mode plugin example: `examples/webhook_manifest.yaml` (the installable
  manifest + webhook shape) and `examples/webhook_plugin.py` (a `handle_webhook`
  handler stub documenting the request/response contract).
- `docs/plugins/webhook-vs-code-plugin.md` — steers third-party authors to the
  manifest + webhook shape vs. the in-process code-plugin shape (when to use
  which). Mirrors the runtime-plugin-loading ADR (Recommendation point 2).
- README: the registry injects `config["database"]` (a least-privilege role
  confined to the `plugin_data` schema, absent unless configured), not
  `config["postgres"]`/`config["qdrant"]` (#41).

## [0.1.0] — 2026-09-06

Initial SDK. (Note: v0.1.1–v0.1.4 were interim tags used during active
development and have been retired — this repo isn't incrementing routine
releases until the SDK's scope is actually finished, at which point normal
versioning resumes. Everything those tags contained is included here.)

### Contract
- `Plugin` Protocol + `PluginMetadata` (with `api_version`) — the lifecycle the
  registry drives; duck-typed on `register`.
- Extension points: `CONFIG_SCHEMA`, `ACTIONS` / `READ_ONLY_ACTIONS`, `AI_TOOLS`,
  `DISPLAY` (branding), `REQUIRES` (services/bundles the plugin needs), and
  per-field UI presentation keys (`widget`, `options_action`, `placeholder`,
  `rows`, `group`, …).

### Extensibility (RFC 0001)
- **Config as JSON Schema + UI Schema**: `resolve_config_schema`,
  `fields_to_json_schema` (compiles the flat list), `resolve_effective_config`
  (default→env→persisted), `validate_config` / `config_errors`.
- **Capabilities**: `capabilities()` + `KNOWN_CAPABILITIES` and the per-capability
  protocols `DataSource` / `Scheduler` / `WebhookHandler` / `ConnectionProvider` /
  `UIPanelProvider`. Open vocabulary, graceful degradation.
- Widget/format vocabularies (`WIDGETS`, `FORMATS`) — open, client-resolved.
- **Requirements**: `requirements()` / `requirement_errors()` +
  `KNOWN_SERVICES` / `KNOWN_BUNDLES` — a plugin declares the services and bundles
  it needs; validated names catch typos.

### Toolkit
- `PluginBase` convenience base class.
- `harness`: `check_plugin`, `run_lifecycle`.
- `ai_tools`: `build_tool_definitions`, `ai_tool_errors`.
- `manifest`: `load_manifest`, `validate_manifest`, bundled `manifest.schema.json`.
- `errors`: `PluginError`, `ConfigError`, `ManifestError`.
- **CLI** `minder-plugin`: `scaffold`, `validate`, `inspect`.

### Examples
- `weather` (full reference), `minimal` (`PluginBase`), `ai_tool`, and a
  `discord_manifest.yaml`.
