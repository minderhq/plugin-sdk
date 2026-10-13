"""Contract-v2 declarations: CONTRACT_VERSION, MANAGES, EGRESS, TIMESERIES —
shape checks, check_plugin integration, and contract-v1 compatibility."""

import pytest

from minder_plugin_sdk import (
    SUPPORTED_CONTRACT_VERSION,
    PluginBase,
    PluginMetadata,
    check_plugin,
    contract_version,
    declaration_errors,
)
from minder_plugin_sdk.declarations import is_host_pattern


def plugin(**attrs):
    async def register(self):
        return PluginMetadata(name="p", version="1.0.0", description="d", author="a")

    return type("P", (PluginBase,), {"register": register, **attrs})()


def test_v1_plugin_without_declarations_is_unchanged():
    p = plugin()
    assert contract_version(p) == 1
    assert declaration_errors(p) == []
    assert check_plugin(p) == []


def test_full_v2_plugin_is_valid():
    p = plugin(
        CONTRACT_VERSION=2,
        MANAGES=["telegraf"],
        EGRESS=["api.example.com", "*.example.org"],
        TIMESERIES={"measurements": ["net_latency", "net.up"]},
    )
    assert SUPPORTED_CONTRACT_VERSION == 2
    assert contract_version(p) == 2
    assert check_plugin(p) == []


@pytest.mark.parametrize("keyword", ["public", "lan"])
def test_egress_keywords(keyword):
    assert declaration_errors(plugin(EGRESS=keyword)) == []


@pytest.mark.parametrize(
    "attrs, fragment",
    [
        ({"CONTRACT_VERSION": 3}, "newer than this SDK supports (max 2)"),
        ({"CONTRACT_VERSION": 0}, "must be >= 1"),
        ({"CONTRACT_VERSION": "2"}, "must be an int"),
        ({"CONTRACT_VERSION": True}, "must be an int"),
        ({"CONTRACT_VERSION": 2, "MANAGES": "telegraf"}, "MANAGES must be a list"),
        ({"CONTRACT_VERSION": 2, "MANAGES": ["docker"]}, "unknown service 'docker'"),
        ({"MANAGES": ["telegraf"]}, "MANAGES requires CONTRACT_VERSION = 2"),
        ({"EGRESS": "anywhere"}, "EGRESS must be one of"),
        ({"EGRESS": 42}, "got int"),
        ({"EGRESS": ["https://api.example.com"]}, "is not a host pattern"),
        ({"EGRESS": ["api.example.com:443"]}, "is not a host pattern"),
        ({"EGRESS": ["10.0.0.1"]}, "is not a host pattern"),
        ({"EGRESS": ["*"]}, "is not a host pattern"),
        ({"TIMESERIES": ["m"]}, "TIMESERIES must be a dict"),
        ({"TIMESERIES": {"tables": []}}, "unknown key 'tables'"),
        ({"TIMESERIES": {"measurements": "m"}}, "must be a list of names"),
        ({"TIMESERIES": {"measurements": ["a b"]}}, "is not a valid name"),
    ],
)
def test_bad_declarations_are_flagged(attrs, fragment):
    errors = declaration_errors(plugin(**attrs))
    assert any(fragment in e for e in errors), errors
    # and check_plugin surfaces them
    assert any(fragment in e for e in check_plugin(plugin(**attrs)))


def test_contract_version_falls_back_to_1_for_garbage():
    assert contract_version(plugin(CONTRACT_VERSION="x")) == 1


@pytest.mark.parametrize(
    "value, ok",
    [
        ("api.example.com", True),
        ("*.example.com", True),
        ("localhost", True),
        ("API.example.com", False),
        ("*.*.example.com", False),
        ("-bad.example.com", False),
        ("1.2.3.4", False),
        ("", False),
        (None, False),
    ],
)
def test_is_host_pattern(value, ok):
    assert is_host_pattern(value) is ok
