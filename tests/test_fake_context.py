"""harness.FakePlatformContext: configurable secrets, grants / denials /
unavailability, plugin-invoke results, recorded calls, and run_lifecycle(ctx=)."""

import asyncio

import pytest

from minder_plugin_sdk import (
    CapabilityDenied,
    CapabilityInvalid,
    CapabilityUnavailable,
    FakePlatformContext,
    PlatformContext,
    PluginBase,
    PluginMetadata,
    run_lifecycle,
)


def run(coro):
    return asyncio.run(coro)


def test_fake_conforms_to_protocol():
    assert isinstance(FakePlatformContext(), PlatformContext)


def test_secrets_get_and_missing_key():
    ctx = FakePlatformContext(secrets={"API_TOKEN": "s3cr3t"})
    assert run(ctx.secrets.get("API_TOKEN")) == "s3cr3t"
    assert run(ctx.secrets.get("NOPE")) is None
    # recorded by key only; the value never lands in the call log
    assert [c.args for c in ctx.called("secrets.read")] == [
        {"key": "API_TOKEN"},
        {"key": "NOPE"},
    ]
    assert "s3cr3t" not in repr(ctx.calls)


def test_default_grants_everything():
    ctx = FakePlatformContext()
    assert ctx.has("secrets.read") and ctx.has("telegraf.reload")


def test_ungranted_call_is_denied_and_recorded():
    ctx = FakePlatformContext(
        secrets={"K": "zz-secret-value"}, grants={"documents.index"}
    )
    assert ctx.has("documents.index") and not ctx.has("secrets.read")
    with pytest.raises(CapabilityDenied) as exc:
        run(ctx.secrets.get("K"))
    assert "zz-secret-value" not in str(exc.value)
    assert len(ctx.called("secrets.read")) == 1


def test_explicit_denial_and_unavailability_override_grants():
    ctx = FakePlatformContext(denied={"telegraf"}, unavailable={"documents.index"})
    assert not ctx.has("telegraf.reload")
    assert not ctx.has("documents.index")
    with pytest.raises(CapabilityDenied):
        run(ctx.telegraf.reload())
    with pytest.raises(CapabilityUnavailable):
        run(ctx.documents.index("kb", "a.txt", "hi", "text/plain"))


def test_plugins_invoke_values_callables_and_unknown_targets():
    async def async_handler(**kw):
        return {"async": kw}

    ctx = FakePlatformContext(
        invoke_results={
            ("telegraf", "status"): {"running": True},
            ("telegraf", "add_target"): lambda **kw: {"added": kw["host"]},
            ("telegraf", "slow"): async_handler,
        }
    )
    assert run(ctx.plugins.invoke("telegraf", "status")) == {"running": True}
    assert run(ctx.plugins.invoke("telegraf", "add_target", host="h")) == {"added": "h"}
    assert run(ctx.plugins.invoke("telegraf", "slow", a=1)) == {"async": {"a": 1}}
    with pytest.raises(CapabilityInvalid):
        run(ctx.plugins.invoke("telegraf", "missing"))
    assert ctx.called("plugins.invoke")[1].args == {
        "plugin": "telegraf",
        "action": "add_target",
        "host": "h",
    }


def test_documents_index_records_the_document():
    ctx = FakePlatformContext()
    out = run(ctx.documents.index("kb1", "page.html", b"<p>x</p>", "text/html"))
    assert out == {
        "document_id": "fake-doc-1",
        "kb_id": "kb1",
        "filename": "page.html",
        "content_type": "text/html",
    }
    assert ctx.indexed[0]["content"] == b"<p>x</p>"


def test_telegraf_region_lifecycle_and_validator():
    def validator(toml):
        if "inputs.exec" in toml:
            raise CapabilityInvalid("telegraf.set_managed_region", "inputs.exec")

    ctx = FakePlatformContext(telegraf_validator=validator)
    run(ctx.telegraf.set_managed_region("[[inputs.ping]]\nurls=['h']\n"))
    assert ctx.telegraf_region.startswith("[[inputs.ping]]")
    with pytest.raises(CapabilityInvalid):
        run(ctx.telegraf.set_managed_region("[[inputs.exec]]"))
    assert ctx.telegraf_region.startswith("[[inputs.ping]]")  # unchanged
    run(ctx.telegraf.reload(force=True))
    run(ctx.telegraf.clear_managed_region())
    assert ctx.telegraf_region == ""
    assert ctx.telegraf_reloads == [True]


class ContextPlugin(PluginBase):
    CONTRACT_VERSION = 2

    async def register(self):
        return PluginMetadata(name="ctx", version="1.0.0", description="d", author="a")

    async def collect_data(self):
        token = await self.ctx.secrets.get("API_TOKEN")
        self._last = {"have_token": token is not None}
        return self._last


def test_run_lifecycle_binds_the_context():
    ctx = FakePlatformContext(secrets={"API_TOKEN": "t"})
    out = run(run_lifecycle(ContextPlugin(), ctx=ctx))
    assert out["collect_data"] == {"have_token": True}
    assert ctx.called("secrets.read")


def test_run_lifecycle_without_ctx_leaves_plugin_unbound():
    with pytest.raises(CapabilityUnavailable):
        run(run_lifecycle(ContextPlugin()))


def test_run_lifecycle_ctx_ignored_for_plugins_without_hook():
    class Plain:
        async def register(self):
            return PluginMetadata(name="p", version="1", description="d", author="a")

    out = run(run_lifecycle(Plain(), ctx=FakePlatformContext()))
    assert out["metadata"].name == "p"
