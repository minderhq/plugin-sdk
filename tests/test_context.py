"""The platform context (contract v2): the unbound default, PluginBase's
bind_context hook, capability-name matching and the capability errors."""

import asyncio

import pytest

from minder_plugin_sdk import (
    UNBOUND_CONTEXT,
    CapabilityDenied,
    CapabilityError,
    CapabilityInvalid,
    CapabilityUnavailable,
    FakePlatformContext,
    PlatformContext,
    PluginBase,
    PluginError,
    capability_granted,
)


def test_unbound_context_conforms_and_has_nothing():
    assert isinstance(UNBOUND_CONTEXT, PlatformContext)
    assert UNBOUND_CONTEXT.has("secrets.read") is False
    assert UNBOUND_CONTEXT.has("telegraf") is False


@pytest.mark.parametrize(
    "call, capability",
    [
        (lambda c: c.secrets.get("K"), "secrets.read"),
        (lambda c: c.plugins.invoke("telegraf", "status", x=1), "plugins.invoke"),
        (
            lambda c: c.documents.index("kb", "a.txt", b"x", "text/plain"),
            "documents.index",
        ),
        (lambda c: c.telegraf.set_managed_region("[x]"), "telegraf.set_managed_region"),
        (lambda c: c.telegraf.clear_managed_region(), "telegraf.clear_managed_region"),
        (lambda c: c.telegraf.reload(force=True), "telegraf.reload"),
    ],
)
def test_unbound_calls_raise_unavailable(call, capability):
    with pytest.raises(CapabilityUnavailable) as exc:
        asyncio.run(call(UNBOUND_CONTEXT))
    assert exc.value.capability == capability
    assert "no platform context is bound" in str(exc.value)


class _P(PluginBase):
    async def register(self):  # pragma: no cover - not driven here
        raise NotImplementedError


def test_pluginbase_defaults_to_unbound_and_binds():
    p = _P()
    assert p.ctx is UNBOUND_CONTEXT
    fake = FakePlatformContext()
    p.bind_context(fake)
    assert p.ctx is fake
    # binding is per instance, not class-wide
    assert _P().ctx is UNBOUND_CONTEXT


def test_ctx_exists_even_without_super_init():
    class NoSuper(PluginBase):
        def __init__(self):  # deliberately skips PluginBase.__init__
            pass

    assert NoSuper().ctx is UNBOUND_CONTEXT


def test_plugin_degrades_cleanly_when_unbound():
    class Degrading(PluginBase):
        async def token(self):
            try:
                return await self.ctx.secrets.get("API_TOKEN")
            except CapabilityUnavailable:
                return None

    assert asyncio.run(Degrading().token()) is None


@pytest.mark.parametrize(
    "granted, wanted, expected",
    [
        ({"secrets.read"}, "secrets.read", True),
        ({"secrets.read"}, "plugins.invoke", False),
        ({"telegraf"}, "telegraf.reload", True),
        ({"telegraf.*"}, "telegraf.set_managed_region", True),
        ({"telegraf.reload"}, "telegraf", True),
        ({"telegraf.reload"}, "telegraf.set_managed_region", False),
        (set(), "secrets.read", False),
        ({"secrets.read"}, "secrets", True),
    ],
)
def test_capability_granted(granted, wanted, expected):
    assert capability_granted(granted, wanted) is expected


@pytest.mark.parametrize(
    "cls, verb",
    [
        (CapabilityDenied, "denied"),
        (CapabilityUnavailable, "unavailable"),
        (CapabilityInvalid, "rejected an invalid request"),
    ],
)
def test_capability_errors_are_plugin_errors_with_clear_messages(cls, verb):
    err = cls("secrets.read", "not granted")
    assert isinstance(err, CapabilityError)
    assert isinstance(err, PluginError)
    assert str(err) == f"platform capability 'secrets.read' {verb}: not granted"
    assert err.capability == "secrets.read"
    assert err.reason == "not granted"
    assert str(cls("plugins.invoke")) == f"platform capability 'plugins.invoke' {verb}"
