"""Tests for the light config validator + env coercion edge cases: the
constraint branches (type / minimum / minLength / maxLength / pattern) config
authors actually hit, and the _coerce fall-throughs that leave a bad value
unchanged so validation surfaces it.
"""

from minder_plugin_sdk.schema import _coerce, config_errors


def _schema(prop):
    return {"type": "object", "properties": {"f": prop}}


# ── config_errors constraint branches ────────────────────────────────────────
def test_type_mismatch_reported():
    errs = config_errors(_schema({"type": "integer"}), {"f": "not-an-int"})
    assert errs == ["f: expected integer, got str"]


def test_integer_field_rejects_bool():
    errs = config_errors(_schema({"type": "integer"}), {"f": True})
    assert errs == ["f: expected integer, got boolean"]


def test_minimum_and_maximum():
    assert config_errors(_schema({"type": "integer", "minimum": 5}), {"f": 3}) == [
        "f: 3 < minimum 5"
    ]
    assert config_errors(_schema({"type": "integer", "maximum": 5}), {"f": 9}) == [
        "f: 9 > maximum 5"
    ]


def test_min_and_max_length():
    assert config_errors(_schema({"type": "string", "minLength": 3}), {"f": "ab"}) == [
        "f: shorter than minLength 3"
    ]
    assert config_errors(
        _schema({"type": "string", "maxLength": 2}), {"f": "abcd"}
    ) == ["f: longer than maxLength 2"]


def test_pattern_mismatch():
    errs = config_errors(
        _schema({"type": "string", "pattern": "^[a-z]+$"}), {"f": "ABC"}
    )
    assert errs == ["f: does not match pattern '^[a-z]+$'"]


def test_enum_and_unknown_key_and_required():
    assert config_errors(_schema({"enum": ["a", "b"]}), {"f": "c"}) == [
        "f: 'c' is not one of ['a', 'b']"
    ]
    assert config_errors(_schema({"type": "string"}), {"other": "x"}) == [
        "other: unknown config key"
    ]
    assert config_errors(
        {"required": ["f"], "properties": {"f": {"type": "string"}}}, {}
    ) == ["f: required"]


def test_valid_values_have_no_errors():
    schema = {
        "type": "object",
        "properties": {
            "n": {"type": "integer", "minimum": 0, "maximum": 10},
            "s": {"type": "string", "minLength": 1, "pattern": "^[a-z]+$"},
        },
    }
    assert config_errors(schema, {"n": 5, "s": "abc"}) == []


# ── _coerce fall-throughs ────────────────────────────────────────────────────
def test_coerce_passes_non_strings_through():
    assert _coerce(5, "integer") == 5  # already typed, not a str → unchanged


def test_coerce_bool_unrecognized_token_returned_verbatim():
    # not in the true/false vocab → returned as-is so validation can flag it
    assert _coerce("maybe", "boolean") == "maybe"


def test_coerce_bad_integer_and_number_returned_verbatim():
    assert _coerce("abc", "integer") == "abc"
    assert _coerce("not-a-float", "number") == "not-a-float"


def test_coerce_happy_paths():
    assert _coerce("true", "boolean") is True
    assert _coerce("off", "boolean") is False
    assert _coerce("42", "integer") == 42
    assert _coerce("3.5", "number") == 3.5
