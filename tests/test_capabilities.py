"""Tests for capability negotiation: an explicit CAPABILITIES override, and the
inference path that derives capabilities from the attributes/methods present
(so existing plugins get sensible capabilities for free).
"""

from minder_plugin_sdk.capabilities import capabilities


def test_explicit_capabilities_override_wins():
    class P:
        CAPABILITIES = ["config", "something-custom"]
        # would otherwise infer data-source, but the explicit list wins verbatim

        async def collect_data(self):
            return {}

    assert capabilities(P()) == {"config", "something-custom"}


def test_infers_config_and_data_source_and_tools_and_actions():
    class P:
        CONFIG_SCHEMA = [{"key": "X", "type": "string"}]
        AI_TOOLS = [{"name": "t", "action": "act"}]
        ACTIONS = frozenset({"act"})

        async def collect_data(self):
            return {}

    assert capabilities(P()) == {"config", "data-source", "ai-tools", "actions"}


def test_infers_config_from_jsonschema_variant():
    class P:
        CONFIG_JSONSCHEMA = {"type": "object"}

    assert capabilities(P()) == {"config"}


def test_infers_extended_capabilities_from_methods():
    # covers the webhook-ingest / scheduler / connection / ui-panel branches
    class P:
        async def handle_webhook(self, payload):
            return {}

        def schedule(self):
            return "0 * * * *"

        async def connect(self, credentials):
            return {}

        def panels(self):
            return []

    assert capabilities(P()) == {
        "webhook-ingest",
        "scheduler",
        "connection",
        "ui-panel",
    }


def test_empty_plugin_has_no_capabilities():
    class P:
        pass

    assert capabilities(P()) == set()
