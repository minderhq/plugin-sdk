# Minder Plugin SDK

The authoring contract for **Minder** module plugins — the `Plugin` lifecycle,
`PluginMetadata`, the optional extension points (config, actions, AI tools), the
manifest JSON Schema, and a complete worked reference plugin.

> Minder is a self-hostable, local-first AI platform (RAG + knowledge graph +
> local LLMs) extended by **plugins**. Plugins are **manifest-based and run no
> arbitrary uploaded code** — new actions are fixed, reviewed handlers. This repo
> is everything a third party needs to write one; the core platform lives at
> [`minderhq/minder`](https://github.com/minderhq/minder).

Licensed under **Apache-2.0**.

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

## Gotchas (read these)

- **`health_check()` must return `{"healthy": <bool>, ...}`.** Monitoring reads
  `health["healthy"]`; anything else marks the plugin unhealthy.
- **The loader picks the class** by `__all__` if present, else the first class that
  defines `register`. Export exactly the plugin class via `__all__`.
- **Only `ACTIONS` names are reachable** over HTTP — nothing else on the instance.
  Reads go through `/collect` + `/analysis`; `ACTIONS` is for state changes.
- **Storage config is injected** by the registry as `config["<backend>"]` (e.g.
  `config["influxdb"]`, `config["postgres"]`, `config["qdrant"]`) — read it from
  `self.config`, don't hard-wire hosts.

## Worked example

[`examples/weather_plugin.py`](examples/weather_plugin.py) is a complete,
self-contained plugin that uses **every** part of the contract: the full
lifecycle, `CONFIG_SCHEMA` + `apply_config`, `ACTIONS` + `READ_ONLY_ACTIONS`, and
an `AI_TOOLS` function-calling tool. Depends only on `httpx` + this SDK.

## Manifest plugins (data-ingestion)

A separate, declarative mechanism for `webhook → store-vector` ingestion — a YAML
manifest that supplies **parameters only** (no code). Its JSON Schema (draft-07)
is [`schema/manifest.schema.json`](schema/manifest.schema.json). Most plugins are
module plugins (above); reach for a manifest when you just need to pipe a webhook
into the vector store.

## Develop

```bash
pip install -e ".[dev,examples]"
pytest && black --check src tests examples && flake8 src tests examples && mypy src
```

## Contributing a plugin

Community plugins are catalogued at
[`minderhq/plugins`](https://github.com/minderhq/plugins). Scaffold a new one from
[`minderhq/plugin-template`](https://github.com/minderhq/plugin-template) (compiles
against this SDK). Design and roadmap discussion lives on the
[Minder tracker](https://github.com/minderhq/minder/issues).
