# Changelog

All notable changes to `minder-plugin-sdk`. Pre-1.0: the contract may still
evolve; changes are additive and backwards-compatible where possible.

## [0.1.0] — unreleased

Initial SDK.

### Contract
- `Plugin` Protocol + `PluginMetadata` (with `api_version`) — the lifecycle the
  registry drives; duck-typed on `register`.
- Extension points: `CONFIG_SCHEMA`, `ACTIONS` / `READ_ONLY_ACTIONS`, `AI_TOOLS`,
  `DISPLAY` (branding), and per-field UI presentation keys (`widget`,
  `options_action`, `placeholder`, `rows`, `group`, …).

### Extensibility (RFC 0001)
- **Config as JSON Schema + UI Schema**: `resolve_config_schema`,
  `fields_to_json_schema` (compiles the flat list), `resolve_effective_config`
  (default→env→persisted), `validate_config` / `config_errors`.
- **Capabilities**: `capabilities()` + `KNOWN_CAPABILITIES` and the per-capability
  protocols `DataSource` / `Scheduler` / `WebhookHandler` / `ConnectionProvider` /
  `UIPanelProvider`. Open vocabulary, graceful degradation.
- Widget/format vocabularies (`WIDGETS`, `FORMATS`) — open, client-resolved.

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
