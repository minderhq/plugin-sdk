"""env-sourced config is coerced to the declared type.

Env values are always strings; a bool/int/number field must not keep a string
(``"false"`` is truthy!). A value that can't be coerced is left unchanged so
``validate_config`` surfaces it.
"""

from minder_plugin_sdk import resolve_effective_config


class _P:
    CONFIG_SCHEMA = [
        {"key": "ENABLED", "type": "bool", "default": True},
        {"key": "COUNT", "type": "int", "default": 3},
        {"key": "RATE", "type": "float", "default": 1.0},
        {"key": "NAME", "type": "string", "default": "x"},
    ]


def test_env_bool_int_number_are_coerced():
    cfg = resolve_effective_config(
        _P(),
        env={"ENABLED": "false", "COUNT": "5", "RATE": "1.5", "NAME": "y"},
    )
    assert cfg["ENABLED"] is False
    assert cfg["COUNT"] == 5 and isinstance(cfg["COUNT"], int)
    assert cfg["RATE"] == 1.5 and isinstance(cfg["RATE"], float)
    assert cfg["NAME"] == "y"


def test_env_truthy_bool_variants():
    cfg = resolve_effective_config(_P(), env={"ENABLED": "on"})
    assert cfg["ENABLED"] is True


def test_env_bad_number_left_as_string_for_validation():
    cfg = resolve_effective_config(_P(), env={"COUNT": "notanint"})
    assert cfg["COUNT"] == "notanint"  # unchanged → validate_config flags it


def test_persisted_and_default_untouched():
    # a persisted (already-typed) value wins and is not re-coerced
    cfg = resolve_effective_config(_P(), persisted={"ENABLED": True})
    assert cfg["ENABLED"] is True
    # default when nothing overrides it
    assert resolve_effective_config(_P())["COUNT"] == 3
