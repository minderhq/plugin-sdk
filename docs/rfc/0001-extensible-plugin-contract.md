# RFC 0001 — An extensible plugin contract that scales to thousands of plugin types

> Status: **Draft** · Tracks: [minderhq/minder#1263](https://github.com/minderhq/minder/issues/1263)
>
> The problem, stated plainly: **every plugin's needs are different, and there
> could be thousands of types.** A fixed lifecycle + a flat `CONFIG_SCHEMA` with a
> closed `widget` enum (SDK v0.2) handles the common 80% and breaks on the long
> tail. This RFC defines a contract that stays **open to unbounded variety** while
> keeping the platform's hard rule: **no arbitrary code, no plugin-supplied HTML.**

## The core tension

Extensibility usually buys variety with one of two costs, both unacceptable here:

1. **A growing closed enum** (`widget: text|textarea|toggle|…`). Every new need =
   an SDK change + a client change. It never catches up with the long tail.
2. **Plugin-supplied code / markup** (a plugin ships React/HTML/JS). Infinite
   variety, but it's arbitrary code execution and an XSS surface — it violates
   Minder's "manifest-based, no uploaded code" guarantee by construction.

The resolution: **variety must come from DATA and a growing set of trusted,
first-party primitives — never from plugin-executed code.** Four mechanisms, all
declarative and safe, cover the space:

## 1. Config as JSON Schema + UI Schema (not a bespoke flat list)

Replace the flat `CONFIG_SCHEMA` list with **standard JSON Schema** for the data
shape and a separate **UI Schema** for rendering hints. This is the proven pattern
(react-jsonschema-form, Kubernetes CRDs, Grafana, VS Code settings, Backstage).

- **JSON Schema is infinitely expressive for DATA:** nested objects, **arrays**
  (repeatable groups — a list of locations, a set of credentials), `enum`,
  `format` (`uri`/`email`/`date-time`/`duration` + custom `geo-point`/`cron`),
  **conditionals** (`if/then`, `dependentSchemas`), `$ref`, validation
  (`minLength`, `pattern`, `minimum`…). A plugin that needs a repeatable
  key-value list, a nested OAuth credential object, or a field that appears only
  when another is set, expresses it in schema — no SDK change.
- **UI Schema carries presentation:** `ui:widget`, `ui:options`, `ui:order`,
  `ui:group`, `ui:help`, `ui:optionsAction` (dynamic autocomplete), `ui:hidden`.
- The v0.2 flat list becomes **sugar**: a helper compiles it to JSON Schema +
  UI Schema, so simple plugins stay one-liners while everything is JSON Schema
  underneath.

## 2. An extensible, trusted widget registry (client-side)

Even JSON Schema needs custom widgets for the tail (a map picker, color, cron
builder, code editor, table). The safe way: the **client** ships a **registry**
mapping `format` / `ui:widget` → a trusted React component. A plugin **references
a widget by name**; it never provides the implementation.

- New rich widgets are added by **growing the client registry** (a community PR to
  the client), not by shipping plugin code.
- **Graceful degradation is mandatory:** an unknown `ui:widget` or `format` falls
  back to the sensible default for its JSON type (a `string` → text input with the
  schema's validation still applied). Unknown is never an error.

## 3. Capabilities, not one fixed lifecycle

`collect_data`/`analyze` is a *data-source* shape. Real plugins are also event
ingestors, AI tools, enrichers, actuators, schedulers, connection/OAuth
providers, dashboard-panel contributors… A single lifecycle can't model them.

Adopt **capability negotiation** (the VS Code `contributes` / LSP / K8s model): a
plugin **declares the capabilities it implements** from an **open vocabulary**;
each capability is a small, independently-versioned interface; the platform only
drives what's declared.

```
capabilities = ["config", "data-source", "ai-tools", "actions",
                "webhook-ingest", "scheduler", "connection", "ui-panel", …]
```

- Old plugins (few capabilities) and new hosts coexist; an **unknown capability is
  ignored, never fatal**.
- A plugin implements only the interfaces for capabilities it declares — no
  need to stub `collect_data` if you're a pure AI-tool plugin.

## 4. Generic, data-driven surfaces for novel UI

When a plugin needs to *show* something that isn't a config form, it does NOT ship
a view. It exposes **data + actions** in known shapes, and the client renders with
**generic safe primitives** selected by declarative hints — a table, a chart, a
timeline, a key-value card, a form (à la Grafana panels / Backstage cards). The
plugin says "render this dataset as a table with these columns"; the trusted
client draws it.

## Versioning & forward-compatibility

- Every plugin declares an **`apiVersion`** (`minder.dev/v1`). The contract can add
  capabilities and widgets without breaking existing plugins.
- **Negotiation + graceful degradation everywhere:** unknown capability → not
  invoked; unknown widget/format → default; unknown UI hint → ignored. The system
  never crashes on something newer or older than it knows.

## What this means concretely for the SDK

| v0.2 (today) | v1 (this RFC) |
|--------------|---------------|
| flat `CONFIG_SCHEMA` list | **JSON Schema + UI Schema**; the flat list is compiled sugar |
| closed `widget` enum in the SDK | open `ui:widget` names resolved by a **client registry**, default fallback |
| fixed lifecycle only | **declared `capabilities`**, each a small interface |
| implicit versioning | explicit **`apiVersion`** + negotiation |
| — | **graceful degradation** is a documented, tested guarantee |

Back-compat: v0.2 plugins keep working (the flat list compiles to schema; the
default capability set is inferred from the methods/attrs present).

## Rollout

1. **SDK (this repo):** add `apiVersion`, a `capabilities()` introspector, JSON
   Schema config support (`CONFIG_JSONSCHEMA` + `UI_SCHEMA`) with a
   `fields_to_json_schema()` compiler from the flat list, and document the widget
   registry + degradation contract. (v0.3 — begins here.)
2. **plugin-registry:** serve `apiVersion` + capabilities + the compiled JSON
   Schema/UI Schema via `GET /v1/plugins/<name>/config`; drive only declared
   capabilities.
3. **client:** a JSON-Schema form renderer with a widget registry + graceful
   fallback; generic data surfaces (table/chart/kv) for `ui-panel` capabilities.

The north star: **a plugin author declares intent in data; the trusted platform
supplies the behavior and the pixels.** That's how you get thousands of plugin
types with zero arbitrary code.
