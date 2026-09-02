"""Plugins declare the services / bundles they need (REQUIRES)."""

import sys
from pathlib import Path

from minder_plugin_sdk import (
    KNOWN_BUNDLES,
    KNOWN_SERVICES,
    check_plugin,
    requirement_errors,
    requirements,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))


def test_requirements_normalizes():
    class P:
        REQUIRES = {"services": ["qdrant"], "bundles": ["rag"]}

    req = requirements(P())
    assert req == {
        "services": ["qdrant"],
        "optional_services": [],  # filled in even when omitted
        "bundles": ["rag"],
    }


def test_no_requires_is_valid_and_empty():
    class P:
        pass

    assert requirements(P()) == {
        "services": [],
        "optional_services": [],
        "bundles": [],
    }
    assert requirement_errors(P()) == []


def test_requirement_errors_flag_typos_and_bad_shape():
    class Typo:
        REQUIRES = {"services": ["postgresql"], "bundles": ["raggg"]}

    errs = " ".join(requirement_errors(Typo()))
    assert "postgresql" in errs  # unknown service caught
    assert "raggg" in errs  # unknown bundle caught

    class BadShape:
        REQUIRES = ["influxdb"]  # must be a dict

    assert requirement_errors(BadShape())

    class BadKey:
        REQUIRES = {"servcies": ["influxdb"]}  # typo'd key

    assert any("unknown key" in e for e in requirement_errors(BadKey()))


def test_weather_example_requires_influxdb_and_check_plugin_agrees():
    from weather_plugin import WeatherPlugin  # type: ignore

    assert requirements(WeatherPlugin())["services"] == ["influxdb"]
    # a real, known service → check_plugin stays clean
    assert check_plugin(WeatherPlugin()) == []


def test_vocabularies_are_populated():
    assert {"postgres", "qdrant", "influxdb"} <= KNOWN_SERVICES
    assert {"core", "rag", "monitoring"} <= KNOWN_BUNDLES
