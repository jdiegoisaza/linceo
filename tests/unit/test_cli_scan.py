"""Tests for `linceo scan secrets` (ADR §8, §10): the CLI wired end to end.

Every scenario here runs through `typer.testing.CliRunner`, and none of
them needs a real `gitleaks` binary — `SubprocessToolExecutor` is replaced
with `linceo.testing.FakeToolExecutor` (ADR §11), the same double the
engine's own tests use, so these stay `tests/unit/` tests (no real tool
binary required) even though they exercise the CLI end to end.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from linceo.cli.main import EXIT_USAGE_ERROR, app
from linceo.core.exit_codes import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_GATE_FAILED,
    EXIT_OK,
    EXIT_TOOL_EXECUTION_FAILED,
)
from linceo.core.fingerprint import secret_fingerprint
from linceo.core.ports import FetchedPolicy, ProcessResult
from linceo.core.remote_policy import RemotePolicyFetchError
from linceo.testing import FakePolicySource, FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
#: Recorded once and reused by every scenario that needs `detect_version` to succeed —
#: the exact version value never matters to these tests, only that one is available.
_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
)


def _git(*args: str, cwd: Path) -> None:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    (path / "app.py").write_text("print('hi')\n")
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", "initial commit", cwd=path)
    return path


def _stub_executor_factory(recordings: Mapping[tuple[str, ...], ProcessResult]) -> object:
    def factory() -> FakeToolExecutor:
        return FakeToolExecutor(recordings=dict(recordings))

    return factory


def test_missing_gitleaks_binary_prints_actionable_hint_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo)])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "gitleaks binary not found on PATH" in result.output
    assert "install gitleaks" in result.output.lower()


def test_a_finding_at_or_above_fail_on_exits_with_gate_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--fail-on", "high"])

    assert result.exit_code == EXIT_GATE_FAILED
    assert "aws-access-token" in result.output
    assert "Gate: FAILED" in result.output
    assert "1 HIGH exceeds the maximum allowed of 0" in result.output


def test_a_clean_run_with_fail_on_exits_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--fail-on", "high"])

    assert result.exit_code == EXIT_OK
    assert "PASSED" in result.output


def test_default_fail_on_none_never_blocks_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo)])

    assert result.exit_code == EXIT_OK
    assert "not enforced" in result.output


def test_json_format_renders_the_canonical_lossless_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--format", "json", "--fail-on", "high"]
    )

    payload = json.loads(result.output)
    assert payload["findings"][0]["rule_id"] == "aws-access-token"
    assert payload["verdict"]["passed"] is False


def test_sarif_format_renders_a_sarif_2_1_0_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--format", "sarif", "--fail-on", "high"]
    )

    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    [run] = payload["runs"]
    assert run["tool"]["driver"]["name"] == "gitleaks"
    [sarif_result] = run["results"]
    assert sarif_result["ruleId"] == "aws-access-token"


def test_dry_run_prints_the_command_without_running_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No recording at all: `detect_version` falls back to a placeholder version
    # silently, and dry-run output never depends on it in the first place.
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(app, ["scan", "secrets", "--path", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "gitleaks detect --source" in result.output
    assert str(tmp_path.resolve()) in result.output


def test_a_path_that_is_not_a_git_repository_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    result = runner.invoke(app, ["scan", "secrets", "--path", str(not_a_repo)])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Configuration error" in result.output


def test_a_malformed_config_file_is_a_configuration_error(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "widgets")
    bad_config = tmp_path / "bad.toml"
    bad_config.write_text("this is not [ valid toml")

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(bad_config)]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Configuration error" in result.output


def test_strict_normalization_flag_is_wired_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--strict-normalization"])

    assert result.exit_code == EXIT_OK


def test_ambiguous_exclusion_fingerprint_at_run_time_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "many_findings.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )
    expires_at = (date.today() + timedelta(days=30)).isoformat()
    config_path = tmp_path / "policy.toml"
    config_path.write_text(
        "[[exclusions]]\n"
        'fingerprint = "v1:"\n'  # matches every one of the three findings
        'reason = "Synthetic credential in the parser test fixture"\n'
        'owner = "team-atlas"\n'
        f"expires_at = {expires_at}\n"
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path)]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "ambiguous" in result.output


def test_fail_on_info_is_rejected_before_it_ever_reaches_the_engine(tmp_path: Path) -> None:
    """ADR §6: INFO never blocks the gate under any threshold configuration."""
    repo = _init_repo(tmp_path / "widgets")

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--fail-on", "info"])

    assert result.exit_code == EXIT_USAGE_ERROR


def test_max_rows_truncates_the_console_table_but_not_the_json_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "many_findings.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    console_result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--max-rows", "1"])
    json_result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--format", "json", "--max-rows", "1"]
    )

    assert "showing 1 of 3" in console_result.output
    payload = json.loads(json_result.output)
    assert len(payload["findings"]) == 3


def test_policy_file_exclusion_suppresses_a_finding_and_it_no_longer_fails_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )
    # `one_finding.json`'s single entry, reduced to the fingerprint
    # `GitleaksIntegration` + `normalize_finding` compute for it: same rule,
    # path, and secret hash the fixture carries (secret value from
    # `tests/unit/fixtures/gitleaks/README.md`, a synthetic test value).
    secret_hash = hashlib.sha256(b"AKIAQPFM3ZXVJ7HKQZ2A").hexdigest()
    fingerprint = secret_fingerprint(
        rule_id="aws-access-token", path="config.py", secret_hash=secret_hash
    )
    expires_at = (date.today() + timedelta(days=30)).isoformat()
    config_path = tmp_path / "policy.toml"
    config_path.write_text(
        "[[exclusions]]\n"
        f'fingerprint = "{fingerprint}"\n'
        'reason = "Synthetic credential in the parser test fixture"\n'
        'owner = "team-atlas"\n'
        f"expires_at = {expires_at}\n"
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "secrets",
            "--path",
            str(repo),
            "--fail-on",
            "high",
            "--config",
            str(config_path),
        ],
    )

    assert "Suppressed by policy: 1" in result.output
    assert result.exit_code == EXIT_OK


def test_remote_policy_thresholds_govern_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR R2, §8.4: a fetched remote document's `[thresholds]` replaces the local file's own."""
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )
    monkeypatch.setenv("LINCEO_POLICY_CACHE_DIR", str(tmp_path / "policy-cache"))
    monkeypatch.setattr(
        "linceo.cli.scan.AzureDevOpsPolicySource",
        lambda **_kwargs: FakePolicySource(
            outcome=FetchedPolicy(content="[thresholds]\nhigh = 0\n")
        ),
    )
    config_path = tmp_path / "policy.toml"
    # No `--fail-on`, and the local file declares no gate of its own either — the
    # remote document's `[thresholds]` is the only thing that turns the gate on.
    config_path.write_text('[remote_policy]\nrepository = "security-baseline"\n')

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path)]
    )

    assert result.exit_code == EXIT_GATE_FAILED
    assert "Remote policy: security-baseline/policy.toml — fetched fresh this run" in result.output
    assert "Gate: FAILED" in result.output


def test_remote_policy_fetch_failure_degrades_to_the_local_document_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR §5, §8.4: a failed fetch with no cache never fails the run — it warns and continues."""
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("gitleaks", "version"): _VERSION_RESULT,
                ("gitleaks", "detect"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )
    monkeypatch.setenv("LINCEO_POLICY_CACHE_DIR", str(tmp_path / "policy-cache"))
    monkeypatch.setattr(
        "linceo.cli.scan.AzureDevOpsPolicySource",
        lambda **_kwargs: FakePolicySource(outcome=RemotePolicyFetchError("401 unauthorized")),
    )
    config_path = tmp_path / "policy.toml"
    config_path.write_text('[remote_policy]\nrepository = "security-baseline"\n')

    result = runner.invoke(
        app,
        [
            "scan",
            "secrets",
            "--path",
            str(repo),
            "--config",
            str(config_path),
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == EXIT_OK
    assert "WARN: unreachable and no cached copy (401 unauthorized)" in result.output


def test_continue_on_tool_error_overrides_a_missing_binary_to_exit_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`engine.run`'s own missing-binary handling (ADR §5) is what prints the actionable
    hint, via `ToolExecution.message` (ADR §1 checkpoint) — it never hard-exits on its own,
    precisely so `--continue-on-tool-error` still governs the exit code, exactly as it
    would for any other tool execution failure."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--continue-on-tool-error"]
    )

    assert result.exit_code == EXIT_OK
    assert "gitleaks binary not found on PATH" in result.output


# --- per-integration configuration (ADR §8.5) --------------------------------


def test_dry_run_reflects_a_scan_history_false_tool_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--dry-run` shows the *effective* argv — level 1 config included, not just the base one."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text("[tools.gitleaks]\nscan_history = false\n")

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "--no-git" in result.output


def test_dry_run_reflects_tool_defaults_merged_with_a_per_tool_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`[tool_defaults]` applies even without gitleaks' own block declaring the field, and

    `[tools.gitleaks]` overrides it field by field for the one it does declare (ADR §8.5)."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text(
        "[tool_defaults]\n"
        "scan_history = false\n"
        "\n"
        "[tools.gitleaks]\n"
        'custom_rules_path = ".gitleaks-custom.toml"\n'
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "--no-git" in result.output  # inherited from [tool_defaults]
    assert "--config .gitleaks-custom.toml" in result.output  # from [tools.gitleaks]


def test_dry_run_shows_the_per_tool_override_winning_over_tool_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text(
        "[tool_defaults]\nscan_history = false\n\n[tools.gitleaks]\nscan_history = true\n"
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "--no-git" not in result.output


def test_dry_run_reflects_passthrough_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text("[tools.gitleaks]\nredact = 25\n")

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "--redact 25" in result.output


def test_dry_run_reports_an_unsupported_tool_config_as_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """gitleaks has no flag for `exclude_paths` — ADR §8.5's "say so explicitly" rule."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text('[tools.gitleaks]\nexclude_paths = ["vendor/"]\n')

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Configuration error" in result.output
    assert "no command-line flag" in result.output


def test_an_unsupported_tool_config_on_a_real_run_never_invokes_the_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rejection happens before any tool runs (ADR §8.4/§8.5) — code 2, not code 3."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory({("gitleaks", "version"): _VERSION_RESULT}),
    )
    config_path = tmp_path / "policy.toml"
    config_path.write_text('[tools.gitleaks]\nexclude_paths = ["vendor/"]\n')

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--config", str(config_path)]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Configuration error" in result.output
