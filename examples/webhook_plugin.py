"""A webhook-mode plugin — the installable *manifest + webhook* shape.

Most third-party integrations should reach for THIS shape rather than an
in-process code plugin (see ``weather_plugin.py``). A webhook plugin ships a
declarative manifest (``examples/webhook_manifest.yaml``) that tells Minder to
expose an inbound webhook path and pipe each POST into the vector store — nothing
is compiled into the platform and it installs at runtime. See
``docs/plugins/webhook-vs-code-plugin.md`` for when to use which shape.

When the manifest's declarative ``store-vector`` mapping isn't enough — a payload
needs reshaping before it is stored — a plugin MAY add a small, reviewed
``handle_webhook`` handler (the ``webhook-ingest`` capability). This example is
that handler stub; it documents the request → response contract:

  request  (Minder → handler): the parsed JSON body of the inbound webhook, as a
           ``dict``. Minder verifies the shared secret named by the manifest's
           ``spec.trigger.webhook.secretRef`` *before* calling the handler.
  response (handler → Minder): the record to store —
           ``{"text": <str>, "metadata": <dict>}`` — matching the manifest's
           ``spec.action.store.input`` shape. Return ``{}`` to acknowledge the
           delivery but store nothing (e.g. an event type you don't ingest).

Depends only on the SDK (stdlib): Minder owns the HTTP listener and secret
verification, so the plugin ships no web framework — it only shapes the payload.
"""

from typing import Any, Dict

from minder_plugin_sdk import PluginBase, PluginMetadata

__all__ = ["IssueWebhookPlugin"]


class IssueWebhookPlugin(PluginBase):
    """Normalize an inbound issue-tracker webhook into a storable record."""

    # Declared explicitly so the platform drives only this capability (see
    # capabilities.py). It is also inferred from the ``handle_webhook`` method.
    CAPABILITIES = ["webhook-ingest"]

    async def register(self) -> PluginMetadata:
        return PluginMetadata(
            name="issue-webhook",
            version="1.0.0",
            description="Ingest issue-tracker webhooks into the vector store.",
            author="you",
            capabilities=["webhook-ingest"],
        )

    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Shape one inbound webhook POST into a ``{text, metadata}`` record.

        ``payload`` is the already-parsed JSON body; the return value is what
        Minder stores (or ``{}`` to store nothing). Keep this pure and defensive
        — never trust the shape of an externally-supplied payload.
        """
        issue = payload.get("issue")
        if not isinstance(issue, dict):
            # Not an event we ingest (e.g. a ping) — acknowledge, store nothing.
            return {}
        title = str(issue.get("title") or "").strip()
        body = str(issue.get("body") or "").strip()
        if not title and not body:
            return {}
        return {
            "text": f"{title}\n\n{body}".strip(),
            "metadata": {
                "number": issue.get("number"),
                "state": issue.get("state"),
                "action": payload.get("action"),
            },
        }
