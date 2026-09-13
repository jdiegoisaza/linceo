"""Tests for configuration resolution and the ADR §5/R5 precedence chain."""

from __future__ import annotations

from pathlib import Path

import pytest

from linceo.core.config import (
    Config,
    ConfigurationError,
    candidate_config_paths,
    load_config,
)
from linceo.core.severity import Severity


def test_candidate_paths_use_explicit_config_path_when_given() -> None:
    candidates = candidate_config_paths(
        explicit_config_path="/somewhere/custom.toml", workspace_path="/ws"
    )

    assert candidates == ("/somewhere/custom.toml",)


def test_candidate_paths_fall_back_to_the_conventional_workspace_path() -> None:
    candidates = candidate_config_paths(explicit_config_path=None, workspace_path="/ws")

    assert candidates == ("/ws/.devsecops/config.toml",)


def test_explicit_config_path_inside_the_package_directory_is_rejected(tmp_path: Path) -> None:
    """The R5 verification the ADR itself describes: no candidate may point inside the package."""
    package_root = tmp_path / "installed-package"
    package_root.mkdir()
    workspace_path = tmp_path / "client-repo"
    workspace_path.mkdir()

    with pytest.raises(ConfigurationError, match="installed package directory"):
        load_config(
            explicit_config_path=str(package_root / "config.toml"),
            workspace_path=str(workspace_path),
            package_root=str(package_root),
        )


def test_conventional_workspace_path_inside_the_package_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """A workspace nested inside the package would make even the conventional path unsafe."""
    package_root = tmp_path / "installed-package"
    package_root.mkdir()
    workspace_inside_package = package_root / "vendored-client-repo"
    workspace_inside_package.mkdir()

    with pytest.raises(ConfigurationError, match="installed package directory"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(workspace_inside_package),
            package_root=str(package_root),
        )


def test_load_config_with_nothing_provided_returns_defaults(tmp_path: Path) -> None:
    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert config == Config()


def test_load_config_reads_the_conventional_workspace_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "high"\ncontinue_on_tool_error = true\n')

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert config.fail_on is Severity.HIGH
    assert config.continue_on_tool_error is True


def test_load_config_reads_an_explicit_config_path(tmp_path: Path) -> None:
    custom_path = tmp_path / "custom.toml"
    custom_path.write_text("baseline_max_horizon_days = 30\n")

    config = load_config(
        explicit_config_path=str(custom_path),
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert config.baseline_max_horizon_days == 30


def test_env_var_overrides_the_config_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "high"\n')

    config = load_config(
        env={"LINCEO_FAIL_ON": "critical"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert config.fail_on is Severity.CRITICAL


def test_cli_override_wins_over_env_and_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "high"\n')

    config = load_config(
        cli_overrides={"fail_on": "none"},
        env={"LINCEO_FAIL_ON": "critical"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert config.fail_on is None


def test_fail_on_none_string_resolves_to_none_threshold(tmp_path: Path) -> None:
    config = load_config(
        cli_overrides={"fail_on": "NONE"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert config.fail_on is None


def test_invalid_fail_on_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="fail_on"):
        load_config(
            cli_overrides={"fail_on": "extremely-bad"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
        )


def test_boolean_field_accepts_true_and_false_strings_via_cli_override(tmp_path: Path) -> None:
    enabled = load_config(
        cli_overrides={"strict_normalization": "true"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )
    disabled = load_config(
        cli_overrides={"strict_normalization": "false"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert enabled.strict_normalization is True
    assert disabled.strict_normalization is False


def test_unknown_cli_override_field_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="unknown configuration field"):
        load_config(
            cli_overrides={"bogus_field": "x"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
        )


def test_invalid_boolean_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="continue_on_tool_error"):
        load_config(
            cli_overrides={"continue_on_tool_error": "maybe"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
        )


def test_invalid_integer_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="baseline_max_horizon_days"):
        load_config(
            cli_overrides={"baseline_max_horizon_days": "soon"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
        )


def test_malformed_toml_file_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("this is not [ valid toml")

    with pytest.raises(ConfigurationError, match="not valid TOML"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
        )


def test_unknown_field_in_config_file_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('typo_field = "oops"\n')

    with pytest.raises(ConfigurationError, match="unknown field"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
        )
