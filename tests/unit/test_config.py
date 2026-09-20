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
    resolve_local_document,
)
from linceo.core.findings import Category
from linceo.core.policy import ConfigLayer
from linceo.core.remote_policy import PolicySourceState, PolicySourceStatus
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


# --- per-category thresholds and their interaction with fail_on (ADR §8.1) ---


def test_category_threshold_table_is_used_for_that_category_only(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[thresholds]\nhigh = 5\n\n"
        "[thresholds.secrets]\ncritical = 0\nhigh = 0\n\n"
        "[thresholds.sca]\nhigh = 5\nmedium = 25\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    resolution = config.threshold_resolution
    assert resolution.thresholds == {Severity.HIGH: 5}
    assert resolution.category_thresholds == {
        Category.SECRETS: {Severity.CRITICAL: 0, Severity.HIGH: 0},
        Category.SCA: {Severity.HIGH: 5, Severity.MEDIUM: 25},
    }
    assert resolution.thresholds_for(Category.SECRETS) == {Severity.CRITICAL: 0, Severity.HIGH: 0}
    assert resolution.thresholds_for(Category.SCA) == {Severity.HIGH: 5, Severity.MEDIUM: 25}


def test_a_category_with_its_own_table_never_falls_back_to_the_default(tmp_path: Path) -> None:
    """A category's own table replaces the default entirely — never merges field by field."""
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[thresholds]\nmedium = 25\n\n[thresholds.secrets]\nhigh = 0\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds_for(Category.SECRETS) == {Severity.HIGH: 0}


def test_a_category_without_its_own_table_falls_back_to_the_default(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[thresholds]\nmedium = 25\n\n[thresholds.secrets]\nhigh = 0\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.threshold_resolution.thresholds_for(Category.SCA) == {Severity.MEDIUM: 25}


def test_cli_fail_on_replaces_every_category_table_too(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[thresholds]\nmedium = 25\n\n[thresholds.secrets]\nhigh = 0\n"
    )

    config = load_config(
        cli_overrides={"fail_on": "high"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    resolution = config.threshold_resolution
    assert resolution.source is ConfigLayer.CLI
    assert resolution.category_thresholds == {}
    assert resolution.superseded == {Severity.MEDIUM: 25}
    assert resolution.superseded_category_thresholds == {Category.SECRETS: {Severity.HIGH: 0}}
    assert resolution.thresholds_for(Category.SECRETS) == {Severity.CRITICAL: 0, Severity.HIGH: 0}
    assert resolution.thresholds_for(Category.SCA) == {Severity.CRITICAL: 0, Severity.HIGH: 0}


def test_only_category_tables_declared_still_wins_over_a_flat_file_fail_on(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        'fail_on = "critical"\n[thresholds.secrets]\nhigh = 0\n'
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    resolution = config.threshold_resolution
    assert resolution.source is ConfigLayer.FILE
    assert resolution.superseded is None
    assert resolution.superseded_category_thresholds == {}
    assert resolution.thresholds_for(Category.SECRETS) == {Severity.HIGH: 0}
    assert resolution.thresholds_for(Category.SCA) == {}


def test_unknown_category_under_thresholds_is_a_configuration_error(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[thresholds.bogus]\nhigh = 0\n")

    with pytest.raises(ConfigurationError, match="unknown category"):
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


def test_tool_defaults_loads_through_the_config_file(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        '[tool_defaults]\nexclude_paths = ["node_modules/", ".venv/"]\nscan_history = true\n'
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.tool_defaults == ToolConfig(
        exclude_paths=("node_modules/", ".venv/"), scan_history=True
    )


def test_no_tool_defaults_table_means_the_all_default_tool_config(tmp_path: Path) -> None:
    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config.tool_defaults == ToolConfig()


def test_a_level_1_field_at_the_document_root_is_a_configuration_error_with_a_specific_hint(
    tmp_path: Path,
) -> None:
    """ "unknown field" alone doesn't say *where* exclude_paths actually belongs (ADR §8.5)."""
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('exclude_paths = ["node_modules/"]\n')

    with pytest.raises(ConfigurationError, match=r"\[tool_defaults\].*\[tools\.<name>\]"):
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )


def test_an_unrelated_unknown_root_field_gets_no_level_1_hint(tmp_path: Path) -> None:
    """The hint only fires for an actual level 1 field name — not for every typo."""
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('typo_field = "oops"\n')

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path / "package"),
            today=TODAY,
        )

    assert "tool_defaults" not in str(exc_info.value)


# --- remote policy resolution (ADR R2, §8.4) ----------------------------------


def test_resolve_local_document_returns_the_same_document_load_config_would_use(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('fail_on = "high"\n')

    file_path, document = resolve_local_document(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
    )

    assert file_path.endswith("config.toml")
    assert document == {"fail_on": "high"}


def test_a_remote_policy_table_in_the_local_file_is_not_an_unknown_field(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('[remote_policy]\nrepository = "security-baseline"\n')

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
    )

    assert config == Config()


def test_remote_document_thresholds_replace_the_local_files_own(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[thresholds]\nhigh = 5\n")

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
        remote_document={"thresholds": {"critical": 0}},
    )

    assert config.threshold_resolution.thresholds == {Severity.CRITICAL: 0}
    assert config.threshold_resolution.source is ConfigLayer.FILE


def test_remote_document_never_touches_local_exclusions(tmp_path: Path) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "[[exclusions]]\n"
        'fingerprint = "v1:abc"\n'
        'reason = "local team decision"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-11-30\n"
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
        remote_document={"thresholds": {"critical": 0}},
    )

    [exclusion] = config.policy.exclusions
    assert exclusion.fingerprint == "v1:abc"


def test_a_governed_key_the_remote_document_is_silent_on_falls_back_to_the_local_file(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / ".devsecops"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text('[tool_defaults]\nexclude_paths = ["node_modules/"]\n')

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
        remote_document={"thresholds": {"critical": 0}},
    )

    assert config.tool_defaults == ToolConfig(exclude_paths=("node_modules/",))


def test_policy_source_status_is_carried_onto_the_resolved_config(tmp_path: Path) -> None:
    status = PolicySourceStatus(
        repository="security-baseline",
        path="policy.toml",
        state=PolicySourceState.FRESH,
        fetched_at=None,
        age_days=0,
        stale=False,
    )

    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=TODAY,
        policy_source=status,
    )

    assert config.policy_source is status
