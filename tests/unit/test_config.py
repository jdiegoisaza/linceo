"""Tests for configuration resolution and the ADR §5/R5 precedence chain."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from linceo.core.config import (
    Config,
    ConfigurationError,
    candidate_config_paths,
    load_config,
)
from linceo.core.policy import ConfigLayer
from linceo.core.severity import Severity
from linceo.core.tool_config import ToolConfig

TODAY = date(2026, 9, 13)


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
            today=TODAY,
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
            today=TODAY,
        )


def test_load_config_with_nothing_provided_returns_defaults(tmp_path: Path) -> None:
    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
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
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds == {Severity.CRITICAL: 0, Severity.HIGH: 0}
    assert config.threshold_resolution.source is ConfigLayer.FILE
    assert config.continue_on_tool_error is True


def test_load_config_reads_an_explicit_config_path(tmp_path: Path) -> None:
    custom_path = tmp_path / "custom.toml"
    custom_path.write_text("max_expiry_horizon_days = 30\n")

    config = load_config(
        explicit_config_path=str(custom_path),
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.max_expiry_horizon_days == 30


def test_env_var_overrides_the_config_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "high"\n')

    config = load_config(
        env={"LINCEO_FAIL_ON": "critical"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds == {Severity.CRITICAL: 0}
    assert config.threshold_resolution.source is ConfigLayer.ENV


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
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds == {}
    assert config.threshold_resolution.source is ConfigLayer.CLI


def test_fail_on_none_string_resolves_to_no_thresholds(tmp_path: Path) -> None:
    config = load_config(
        cli_overrides={"fail_on": "NONE"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds == {}


def test_invalid_fail_on_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="fail_on"):
        load_config(
            cli_overrides={"fail_on": "extremely-bad"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_fail_on_info_is_a_configuration_error(tmp_path: Path) -> None:
    """ADR §6: INFO never blocks the gate under any threshold configuration."""
    with pytest.raises(ConfigurationError, match="INFO"):
        load_config(
            cli_overrides={"fail_on": "info"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_boolean_field_accepts_true_and_false_strings_via_cli_override(tmp_path: Path) -> None:
    enabled = load_config(
        cli_overrides={"strict_normalization": "true"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )
    disabled = load_config(
        cli_overrides={"strict_normalization": "false"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
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
            today=TODAY,
        )


def test_invalid_boolean_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="continue_on_tool_error"):
        load_config(
            cli_overrides={"continue_on_tool_error": "maybe"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_invalid_integer_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="max_expiry_horizon_days"):
        load_config(
            cli_overrides={"max_expiry_horizon_days": "soon"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
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
            today=TODAY,
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
            today=TODAY,
        )


def test_unsupported_schema_version_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("version = 2\n")

    with pytest.raises(ConfigurationError, match="schema version"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_negative_max_expiry_horizon_days_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="max_expiry_horizon_days"):
        load_config(
            cli_overrides={"max_expiry_horizon_days": "-1"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_negative_report_max_rows_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="max_rows"):
        load_config(
            cli_overrides={"report_max_rows": "-1"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_report_max_rows_from_the_nested_report_table(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[report]\nmax_rows = 5\n")

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.report_max_rows == 5


def test_report_max_rows_cli_override_wins_over_the_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[report]\nmax_rows = 5\n")

    config = load_config(
        cli_overrides={"report_max_rows": "50"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.report_max_rows == 50


def test_report_table_not_a_table_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('report = "oops"\n')

    with pytest.raises(ConfigurationError, match="'report' must be a table"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_env_var_sets_a_generic_scalar_field(tmp_path: Path) -> None:
    config = load_config(
        env={"LINCEO_CONTINUE_ON_TOOL_ERROR": "true"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.continue_on_tool_error is True


def test_report_table_with_an_unknown_field_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[report]\nbogus = 1\n")

    with pytest.raises(ConfigurationError, match="unknown field"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


# --- thresholds table and its interaction with fail_on (ADR §8.1) ------------


def test_thresholds_table_alone_becomes_the_effective_thresholds(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[thresholds]\ncritical = 0\nhigh = 5\n")

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds == {Severity.CRITICAL: 0, Severity.HIGH: 5}
    assert config.threshold_resolution.source is ConfigLayer.FILE
    assert config.threshold_resolution.superseded is None


def test_cli_fail_on_replaces_the_file_thresholds_table_entirely(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[thresholds]\ncritical = 0\nhigh = 5\nmedium = 25\n")

    config = load_config(
        cli_overrides={"fail_on": "high"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    resolution = config.threshold_resolution
    assert resolution.thresholds == {Severity.CRITICAL: 0, Severity.HIGH: 0}
    assert resolution.source is ConfigLayer.CLI
    assert resolution.fail_on is Severity.HIGH
    assert resolution.superseded == {Severity.CRITICAL: 0, Severity.HIGH: 5, Severity.MEDIUM: 25}
    assert resolution.superseded_from is not None
    assert resolution.superseded_from.endswith("config.toml")


def test_env_fail_on_also_replaces_the_file_thresholds_table(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[thresholds]\nhigh = 5\n")

    config = load_config(
        env={"LINCEO_FAIL_ON": "critical"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    resolution = config.threshold_resolution
    assert resolution.source is ConfigLayer.ENV
    assert resolution.superseded == {Severity.HIGH: 5}


def test_no_override_and_no_thresholds_table_falls_back_to_the_files_flat_fail_on(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "high"\n')

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds == {Severity.CRITICAL: 0, Severity.HIGH: 0}
    assert config.threshold_resolution.superseded is None


def test_thresholds_table_wins_over_a_flat_fail_on_in_the_same_file_without_announcing_an_override(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "critical"\n[thresholds]\nhigh = 5\n')

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    resolution = config.threshold_resolution
    assert resolution.thresholds == {Severity.HIGH: 5}
    assert resolution.source is ConfigLayer.FILE
    assert resolution.superseded is None


def test_thresholds_table_naming_info_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[thresholds]\ninfo = 0\n")

    with pytest.raises(ConfigurationError, match="INFO"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


# --- exclusions and tool skips loaded through the same file (ADR §8.2) -------


def test_exclusions_load_through_the_config_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[[exclusions]]\n"
        'fingerprint = "v1:abc"\n'
        'reason = "Synthetic credential in the parser test corpus"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-11-30\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    [exclusion] = config.policy.exclusions
    assert exclusion.fingerprint == "v1:abc"
    assert exclusion.owner == "team-atlas"
    assert exclusion.expires_at == date(2026, 11, 30)


def test_exclusion_beyond_the_horizon_is_a_configuration_error_at_load_time(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[[exclusions]]\n"
        'fingerprint = "v1:abc"\n'
        'reason = "adoption"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2099-01-01\n"
    )

    with pytest.raises(ConfigurationError, match="horizon"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_tool_skips_load_through_the_config_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[[skipped_tools]]\n"
        'tool = "gitleaks"\n'
        'reason = "Rollout paused while the team triages the initial backlog"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-10-01\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    [tool_skip] = config.policy.tool_skips
    assert tool_skip.tool == "gitleaks"
    assert tool_skip.expires_at == date(2026, 10, 1)


# --- per-integration configuration loaded through the same file (ADR §8.5) ---


def test_tool_configs_load_through_the_config_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[tools.gitleaks]\n"
        "scan_history = false\n"
        'custom_rules_path = ".gitleaks-custom.toml"\n'
        "timeout = 120\n"
        "redact = 50\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.tool_configs["gitleaks"] == ToolConfig(
        scan_history=False,
        custom_rules_path=".gitleaks-custom.toml",
        timeout=120.0,
        passthrough={"redact": 50},
    )


def test_no_tools_table_means_no_configured_tools(tmp_path: Path) -> None:
    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.tool_configs == {}


def test_an_invalid_tool_config_field_is_a_configuration_error_at_load_time(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[tools.gitleaks]\ntimeout = -5\n")

    with pytest.raises(ConfigurationError, match="timeout must be positive"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )
