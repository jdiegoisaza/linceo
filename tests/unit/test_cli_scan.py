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

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.cli.main import EXIT_USAGE_ERROR, app
from linceo.core.exit_codes import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_GATE_FAILED,
    EXIT_OK,
    EXIT_TOOL_EXECUTION_FAILED,
)
from linceo.core.fingerprint import secret_fingerprint
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"


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


def _stub_executor_factory(recordings: Mapping[str, ProcessResult]) -> object:
    def factory() -> FakeToolExecutor:
        return FakeToolExecutor(recordings=dict(recordings))

    return factory


def _stub_detect_version(monkeypatch: pytest.MonkeyPatch, version: str = "8.30.1") -> None:
    """Bypass version detection entirely, independent of whatever executor is in play.

    `FakeToolExecutor` records one `ProcessResult` per binary name, not per
    distinct invocation — it cannot tell `gitleaks version` apart from
    `gitleaks detect ...` against the same recording. Patching
    `detect_version` directly sidesteps that rather than fighting it.
    """
    monkeypatch.setattr(
        GitleaksIntegration, "detect_version", staticmethod(lambda _executor: version)
    )


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
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
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
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
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
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
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
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
            }
        ),
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--format", "json", "--fail-on", "high"]
    )

    payload = json.loads(result.output)
    assert payload["findings"][0]["rule_id"] == "aws-access-token"
    assert payload["verdict"]["passed"] is False


def test_dry_run_prints_the_command_without_running_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_detect_version(monkeypatch)

    result = runner.invoke(app, ["scan", "secrets", "--path", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "gitleaks detect --source" in result.output
    assert str(tmp_path.resolve()) in result.output


def test_a_path_that_is_not_a_git_repository_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_detect_version(monkeypatch)
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
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
            }
        ),
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--strict-normalization"])

    assert result.exit_code == EXIT_OK


def test_ambiguous_exclusion_fingerprint_at_run_time_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "many_findings.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
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


def test_fail_on_info_is_rejected_before_it_ever_reaches_the_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR §6: INFO never blocks the gate under any threshold configuration."""
    repo = _init_repo(tmp_path / "widgets")
    _stub_detect_version(monkeypatch)

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--fail-on", "info"])

    assert result.exit_code == EXIT_USAGE_ERROR


def test_max_rows_truncates_the_console_table_but_not_the_json_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "many_findings.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
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
    _stub_detect_version(monkeypatch)
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                "gitleaks": ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                )
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


def test_continue_on_tool_error_overrides_a_missing_binary_to_exit_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLI's missing-binary preflight only prints an actionable hint (ADR R4) — it
    never hard-exits on its own, precisely so `--continue-on-tool-error` still governs the
    exit code via `engine.run`'s own missing-binary handling, exactly as it would for any
    other tool execution failure (ADR §5)."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--continue-on-tool-error"]
    )

    assert result.exit_code == EXIT_OK
    assert "gitleaks binary not found on PATH" in result.output
