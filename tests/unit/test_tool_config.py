"""Tests for per-integration configuration: `ToolConfig`, passthrough, and parsing (ADR §8.5)."""

from __future__ import annotations

import pytest

from linceo.core.policy import PolicyConfigurationError
from linceo.core.tool_config import (
    ToolConfig,
    parse_tool_configs,
    parse_tool_defaults,
    render_passthrough_flags,
    resolve_tool_config,
)

# --- render_passthrough_flags -------------------------------------------------


def test_string_value_becomes_flag_and_value_tokens() -> None:
    assert render_passthrough_flags({"redact": "20"}) == ("--redact", "20")


def test_int_and_float_values_are_stringified() -> None:
    assert render_passthrough_flags({"max-target-megabytes": 5}) == ("--max-target-megabytes", "5")
    assert render_passthrough_flags({"threshold": 2.5}) == ("--threshold", "2.5")


def test_bool_true_emits_the_flag_alone() -> None:
    assert render_passthrough_flags({"verbose": True}) == ("--verbose",)


def test_bool_false_omits_the_flag_entirely() -> None:
    assert render_passthrough_flags({"verbose": False}) == ()


def test_tuple_value_repeats_the_flag_once_per_item_in_order() -> None:
    assert render_passthrough_flags({"enable-rule": ("a", "b", "c")}) == (
        "--enable-rule",
        "a",
        "--enable-rule",
        "b",
        "--enable-rule",
        "c",
    )


def test_a_single_value_never_expands_into_more_than_its_own_tokens() -> None:
    """The anti-injection guarantee (ADR §8.5): a value that *looks* like several arguments

    (spaces, extra flags) is still exactly one token — never split, never reinterpreted.
    """
    argv = render_passthrough_flags({"report-template": "a; --evil-flag /etc/passwd"})

    assert argv == ("--report-template", "a; --evil-flag /etc/passwd")
    assert len(argv) == 2


def test_multiple_entries_render_in_declared_order() -> None:
    passthrough = {"a": "1", "b": "2", "c": "3"}

    assert render_passthrough_flags(passthrough) == ("--a", "1", "--b", "2", "--c", "3")


def test_custom_prefix_is_honored() -> None:
    assert render_passthrough_flags({"depth": 3}, prefix="-") == ("-depth", "3")


@pytest.mark.parametrize("bad_key", ["has space", "-leading-dash", "", "trailing space "])
def test_a_key_that_does_not_look_like_a_flag_name_raises_value_error(bad_key: str) -> None:
    with pytest.raises(ValueError, match="not a valid flag name"):
        render_passthrough_flags({bad_key: "x"})


# --- parse_tool_configs --------------------------------------------------------


def test_no_tools_table_at_all_returns_an_empty_mapping() -> None:
    assert parse_tool_configs({}) == {}


def test_tools_not_a_table_is_a_policy_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="tools must be a table"):
        parse_tool_configs({"tools": "oops"})


def test_one_tool_entry_not_a_table_is_a_policy_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match=r"tools\.gitleaks must be a table"):
        parse_tool_configs({"tools": {"gitleaks": "oops"}})


def test_an_empty_tool_table_produces_the_all_default_tool_config() -> None:
    configs = parse_tool_configs({"tools": {"gitleaks": {}}})

    assert configs == {"gitleaks": ToolConfig()}


def test_every_level_1_field_parses_into_its_typed_value() -> None:
    configs = parse_tool_configs(
        {
            "tools": {
                "gitleaks": {
                    "exclude_paths": ["vendor/", "*.min.js"],
                    "scan_history": False,
                    "custom_rules_path": "/etc/linceo/gitleaks.toml",
                    "timeout": 120,
                }
            }
        }
    )

    assert configs["gitleaks"] == ToolConfig(
        exclude_paths=("vendor/", "*.min.js"),
        scan_history=False,
        custom_rules_path="/etc/linceo/gitleaks.toml",
        timeout=120.0,
    )


def test_multiple_tools_parse_independently() -> None:
    configs = parse_tool_configs(
        {
            "tools": {
                "gitleaks": {"scan_history": False},
                "trivy": {"timeout": 30},
            }
        }
    )

    assert configs["gitleaks"] == ToolConfig(scan_history=False)
    assert configs["trivy"] == ToolConfig(timeout=30.0)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("exclude_paths", "not-a-list", "exclude_paths must be a list of strings"),
        ("exclude_paths", [1, 2], "exclude_paths must be a list of strings"),
        ("scan_history", "yes", "scan_history must be a boolean"),
        ("custom_rules_path", 123, "custom_rules_path must be a string"),
        ("timeout", "soon", "timeout must be a number of seconds"),
        ("timeout", True, "timeout must be a number of seconds"),
        ("timeout", 0, "timeout must be positive"),
        ("timeout", -5, "timeout must be positive"),
    ],
)
def test_an_invalid_level_1_field_is_a_policy_configuration_error(
    field: str, value: object, match: str
) -> None:
    with pytest.raises(PolicyConfigurationError, match=match):
        parse_tool_configs({"tools": {"gitleaks": {field: value}}})


def test_unrecognized_keys_become_passthrough() -> None:
    configs = parse_tool_configs(
        {
            "tools": {
                "gitleaks": {
                    "redact": 50,
                    "no-color": True,
                    "enable-rule": ["a", "b"],
                }
            }
        }
    )

    assert configs["gitleaks"] == ToolConfig(
        passthrough={"redact": 50, "no-color": True, "enable-rule": ("a", "b")}
    )


def test_level_1_keys_never_leak_into_passthrough() -> None:
    configs = parse_tool_configs({"tools": {"gitleaks": {"scan_history": True, "redact": 50}}})

    assert configs["gitleaks"].passthrough == {"redact": 50}


@pytest.mark.parametrize(
    "value",
    [
        {"nested": "table"},
        [1, "mixed"],
        [{"nested": True}],
        None,
    ],
)
def test_a_passthrough_value_outside_the_allowed_shapes_is_a_policy_configuration_error(
    value: object,
) -> None:
    with pytest.raises(PolicyConfigurationError, match="must be a string, number, boolean"):
        parse_tool_configs({"tools": {"gitleaks": {"weird": value}}})


# --- parse_tool_defaults -------------------------------------------------------


def test_no_tool_defaults_table_returns_the_all_default_tool_config() -> None:
    assert parse_tool_defaults({}) == ToolConfig()


def test_tool_defaults_not_a_table_is_a_policy_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="tool_defaults must be a table"):
        parse_tool_defaults({"tool_defaults": "oops"})


def test_tool_defaults_parses_the_same_level_1_fields_as_a_per_tool_block() -> None:
    defaults = parse_tool_defaults(
        {
            "tool_defaults": {
                "exclude_paths": ["node_modules/", ".venv/"],
                "scan_history": True,
                "custom_rules_path": "/etc/linceo/shared-rules.toml",
                "timeout": 90,
            }
        }
    )

    assert defaults == ToolConfig(
        exclude_paths=("node_modules/", ".venv/"),
        scan_history=True,
        custom_rules_path="/etc/linceo/shared-rules.toml",
        timeout=90.0,
    )


def test_tool_defaults_rejects_a_field_that_is_not_one_of_the_four_level_1_fields() -> None:
    """`[tool_defaults]` never carries passthrough — a raw flag name has no meaning shared

    across tools (ADR §8.5), so even a syntactically valid passthrough-shaped value here is
    still rejected, with a hint pointing at `[tools.<name>]` instead.
    """
    with pytest.raises(PolicyConfigurationError, match=r"\[tools\.<name>\] instead"):
        parse_tool_defaults({"tool_defaults": {"redact": 50}})


def test_tool_defaults_reuses_level_1_field_validation() -> None:
    with pytest.raises(PolicyConfigurationError, match=r"tool_defaults\.timeout must be positive"):
        parse_tool_defaults({"tool_defaults": {"timeout": -1}})


# --- resolve_tool_config --------------------------------------------------------


def test_resolve_falls_back_to_defaults_field_by_field_when_override_sets_nothing() -> None:
    defaults = ToolConfig(exclude_paths=("node_modules/",), scan_history=True, timeout=60.0)

    resolved = resolve_tool_config(defaults=defaults, override=ToolConfig())

    assert resolved == defaults


def test_resolve_lets_override_win_field_by_field_without_losing_the_rest_of_defaults() -> None:
    """The motivating case: a shared exclude_paths default, one tool overriding only timeout."""
    defaults = ToolConfig(exclude_paths=("node_modules/",), scan_history=True, timeout=60.0)
    override = ToolConfig(timeout=10.0)

    resolved = resolve_tool_config(defaults=defaults, override=override)

    assert resolved.exclude_paths == ("node_modules/",)  # inherited from defaults
    assert resolved.scan_history is True  # inherited from defaults
    assert resolved.timeout == 10.0  # overridden


def test_resolve_lets_an_explicit_empty_exclude_paths_override_a_non_empty_default() -> None:
    """`None` (never mentioned) and `()` (explicitly empty) are distinct at this layer."""
    defaults = ToolConfig(exclude_paths=("node_modules/",))
    override = ToolConfig(exclude_paths=())

    resolved = resolve_tool_config(defaults=defaults, override=override)

    assert resolved.exclude_paths == ()


def test_resolve_never_merges_passthrough_it_is_always_the_overrides() -> None:
    defaults = ToolConfig()  # tool_defaults never carries passthrough in practice
    override = ToolConfig(passthrough={"redact": 50})

    resolved = resolve_tool_config(defaults=defaults, override=override)

    assert resolved.passthrough == {"redact": 50}
