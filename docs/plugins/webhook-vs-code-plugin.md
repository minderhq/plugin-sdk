# Webhook plugin vs. code plugin — which shape should I write?

Minder plugins come in two shapes. Picking the right one first saves a rewrite,
so this guide is the decision, up front, with a worked example of each.

> **Short version:** if you are a **third party** integrating an external system,
> reach for the **manifest + webhook** shape. Write a **code plugin**
> only when you need Python logic. Code plugins are reviewed and merged into the
> catalog by pull request. Both shapes run isolated, out of process, in a
> `plugin-runner`, and **no user-uploaded code runs**.

## The two shapes

### 1. Manifest + webhook (declarative — the third-party default)

A YAML **manifest** declares an inbound webhook path and where each delivery
should go. Minder exposes the path, verifies the shared secret, and pipes the
payload into the vector store. It runs **no plugin code**,
and the plugin **installs at runtime** — nothing to build, review, or redeploy in
Minder itself.

- Example manifest: [`examples/webhook_manifest.yaml`](../../examples/webhook_manifest.yaml)
- Validate it: `minder-plugin validate examples/webhook_manifest.yaml`
- Schema: [`src/minder_plugin_sdk/schemas/manifest.schema.json`](../../src/minder_plugin_sdk/schemas/manifest.schema.json)

When the declarative `store-vector` mapping isn't enough — a payload has to be
reshaped before it is stored — add a small, reviewed `handle_webhook` handler
(the `webhook-ingest` capability). That handler stub, with the exact
request/response contract, is [`examples/webhook_plugin.py`](../../examples/webhook_plugin.py):

| Direction | Shape |
|-----------|-------|
| **request** (Minder → handler) | the parsed JSON body of the inbound webhook, as a `dict`. Minder verifies the secret named by `spec.trigger.webhook.secretRef` **before** calling. |
| **response** (handler → Minder) | the record to store — `{"text": <str>, "metadata": <dict>}`, matching `spec.action.store.input`. Return `{}` to acknowledge but store nothing. |

### 2. In-process code plugin (first-party only)

A Python **class** the registry loads and drives through a lifecycle
(`register → initialize → health_check → collect_data → analyze → shutdown`),
hosted by a `plugin-runner`. It can poll a source on a schedule, expose
configurable settings and HTTP-invokable actions, and advertise AI tools.

Because this is Python code, it is **reviewed and merged into the catalog by
pull request** — it is not something a user uploads and Minder executes. It runs
isolated, out of process, in a `plugin-runner`. AI tools declare an `effect`, and
write/send/destructive ones pause for user approval. The
full reference is [`examples/weather_plugin.py`](../../examples/weather_plugin.py);
the smallest one is [`examples/minimal_plugin.py`](../../examples/minimal_plugin.py).

## Choose by answering these

| If your integration… | use |
|----------------------|-----|
| receives events from an external system over HTTP | **manifest + webhook** |
| just needs to land those events in the vector store | **manifest + webhook** (declarative only) |
| needs to reshape a payload before storing it | **manifest + webhook** with a `handle_webhook` handler |
| is installed at runtime as data, with no Python to review | **manifest + webhook** |
| must poll a source on a schedule or needs custom Python logic | **code plugin** |
| exposes configurable settings, actions, or AI tools | **code plugin** |
| is reviewed Python merged into the catalog by pull request | **code plugin** |

When in doubt as a third party, start with the manifest. You can always add a
`handle_webhook` handler later without changing the install shape.

## See also

- [`README.md`](../../README.md) — the contract in 30 seconds and the toolkit.
- [`docs/rfc/0001-extensible-plugin-contract.md`](../rfc/0001-extensible-plugin-contract.md)
  — the capability model (`webhook-ingest`, `data-source`, …).
- [`minderhq/plugin-template`](https://github.com/minderhq/plugin-template) — scaffold
  a new plugin. (A matching webhook-flavored template is a good follow-up there.)
