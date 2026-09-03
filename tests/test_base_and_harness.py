"""Cover PluginBase defaults and the harness branches not hit by the contract
tests: the sync-value _await fall-through, the missing-register short-circuit,
and the options_action → READ_ONLY validation.
"""

import asyncio

from minder_plugin_sdk import PluginBase, PluginMetadata
from minder_plugin_sdk.harness import _await, check_plugin


# ── PluginBase defaults ──────────────────────────────────────────────────────
def test_pluginbase_default_methods():
    p = PluginBase()
    assert asyncio.run(p.collect_data()) == {}
    assert asyncio.run(p.analyze()) == {"message": "no data collected yet"}
    # health is False pre-init (status "registered"), True once initialize() ran
    assert asyncio.run(p.health_check()) == {"healthy": False}
    asyncio.run(p.initialize())
    assert asyncio.run(p.health_check()) == {"healthy": True}


def test_pluginbase_analyze_returns_last_when_present():
    p = PluginBase()
    p._last = {"some": "data"}
    assert asyncio.run(p.analyze()) == {"some": "data"}


# ── harness._await ───────────────────────────────────────────────────────────
def test_await_returns_sync_values_unchanged():
    assert _await(42) == 42  # not awaitable → returned as-is


def test_check_plugin_accepts_a_sync_register():
    # register() need not be async — _await handles a plain return value too
    class P:
        def register(self):
            return PluginMetadata(
                name="s", version="1.0.0", description="d", author="a"
            )

    assert check_plugin(P()) == []


# ── harness.check_plugin branches ────────────────────────────────────────────
def test_check_plugin_flags_missing_register():
    class NotAPlugin:
        pass

    problems = check_plugin(NotAPlugin())
    assert problems == ["missing register() — the registry loads on its presence"]


def test_check_plugin_flags_options_action_not_read_only():
    class P:
        ACTIONS = frozenset({"refresh"})
        READ_ONLY_ACTIONS = frozenset()  # refresh is NOT read-only
        CONFIG_SCHEMA = [
            {
                "key": "CHOICE",
                "type": "string",
                "default": "",
                "options_action": "refresh",
            }
        ]

        async def register(self):
            return PluginMetadata(
                name="p", version="1.0.0", description="d", author="a"
            )

    problems = check_plugin(P())
    assert any("is not a READ_ONLY action" in p for p in problems)
