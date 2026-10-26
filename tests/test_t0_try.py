"""``minder-plugin try``: replayed runs of real catalog manifests, and the
egress rules that still apply offline."""

import base64
import json
from pathlib import Path

import pytest

from minder_plugin_sdk.cli import main
from minder_plugin_sdk.t0_try import _key, run_try

FIXTURES = Path(__file__).parent / "fixtures" / "t0"
CASES = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(CASES))
async def test_replay_reproduces_the_recorded_output(name):
    case = CASES[name]
    result = await run_try(
        FIXTURES / name / "manifest.yml",
        case["operation"],
        case["args"],
        {},
        {},
        replay=FIXTURES / name / "recorded",
    )
    expected = json.loads((FIXTURES / name / "expected.json").read_text("utf-8"))
    assert json.loads(json.dumps(result, default=str)) == expected


def test_cli_prints_the_mapped_output(capsys):
    case = CASES["frankfurter"]
    rc = main(
        [
            "try",
            str(FIXTURES / "frankfurter" / "manifest.yml"),
            case["operation"],
            "--args",
            json.dumps(case["args"]),
            "--replay",
            str(FIXTURES / "frankfurter" / "recorded"),
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out == json.loads((FIXTURES / "frankfurter" / "expected.json").read_text())


def test_cli_rejects_bad_json_args(capsys):
    rc = main(
        [
            "try",
            str(FIXTURES / "frankfurter" / "manifest.yml"),
            "convert",
            "--args",
            "{",
        ]
    )
    assert rc == 2
    assert "must be JSON" in capsys.readouterr().out


async def test_unrecorded_request_fails_offline(tmp_path):
    case = CASES["frankfurter"]
    with pytest.raises(Exception) as exc:
        await run_try(
            FIXTURES / "frankfurter" / "manifest.yml",
            case["operation"],
            case["args"],
            {},
            {},
            replay=tmp_path,
        )
    assert "not recorded" in str(exc.value) or "transport error" in str(exc.value)


async def test_redirect_to_an_undeclared_host_is_refused_offline(tmp_path):
    """A recorded 302 to a host the manifest doesn't declare is never followed:
    the engine reports the operation's error value, as the runner does, and
    no request reaches the other host (replay would fail on it)."""
    case = CASES["frankfurter"]
    src = FIXTURES / "frankfurter" / "recorded"
    original = json.loads(next(src.glob("*.json")).read_text("utf-8"))
    req = original["request"]
    redirect = {
        "request": req,
        "status": 302,
        "headers": [["location", "https://evil.example.com/steal"]],
        "body_b64": base64.b64encode(b"").decode("ascii"),
    }
    name = _key(req["method"], req["host"], req["target"])
    (tmp_path / f"{name}.json").write_text(json.dumps(redirect), encoding="utf-8")
    result = await run_try(
        FIXTURES / "frankfurter" / "manifest.yml",
        case["operation"],
        case["args"],
        {},
        {},
        replay=tmp_path,
    )
    assert "error" in result
    assert "result" not in result
