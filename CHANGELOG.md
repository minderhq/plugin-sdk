# Changelog

All notable changes to `minder-plugin-sdk`. Pre-1.0: the contract may still
evolve; changes are additive and backwards-compatible where possible.

## [Unreleased]

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
  refuses non-public addresses, pins the checked IP, re-checks each redirect
  hop and caps the body. It needs `httpx` (optional).
- `check_plugin` now also checks:
  - the contract-v2 declarations, refusing a `CONTRACT_VERSION` newer than
    supported;
  - `os.environ` / `os.getenv` reads of platform-secret names, except keys the
    plugin declares in its own `CONFIG_SCHEMA` (`source_rules`);
  - imports of platform internals (`core.*`).

  Existing plugins that read such names directly from the environment now
  fail validation. Move them to `CONFIG_SCHEMA` or `ctx.secrets`.
- `harness.FakePlatformContext` gives plugin unit tests configurable secrets,
  grants, denials and unavailability, plugin-invoke results, and recorded calls.
  `run_lifecycle(plugin, ctx=...)` binds a context.
- `minder-plugin inspect` reports `contract_version`, `manages`, `egress` and
  `timeseries`.
- Rules for plugin authors: return JSON-serialisable results, and don't share
  memory between plugins.

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
