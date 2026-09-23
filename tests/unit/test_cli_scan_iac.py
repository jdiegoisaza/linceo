"""Tests for `linceo scan iac` (ADR §8, §10): the CLI wired end to end.

Mirrors `tests/unit/test_cli_scan_sca.py` (the `sca` command): every
scenario runs through `typer.testing.CliRunner`, and none of them needs a
real `checkov` binary — `SubprocessToolExecutor` is replaced with
`linceo.testing.FakeToolExecutor` (ADR §11).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from linceo.cli.main import app
from linceo.core.exit_codes import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_GATE_FAILED,
    EXIT_OK,
    EXIT_TOOL_EXECUTION_FAILED,
)
from linceo.core.fingerprint import iac_fingerprint
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "checkov"
_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="3.3.19\n", stderr="", started_at=_NOW, finished_at=_NOW
)


def _git(*args: str, cwd: Path) -> None:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    (path / "main.tf").write_text('resource "aws_s3_bucket" "logs" {\n  bucket = "x"\n}\n')
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", "initial commit", cwd=path)
    return path


def _stub_executor_factory(recordings: Mapping[tuple[str, ...], ProcessResult]) -> object:
    def factory() -> FakeToolExecutor:
        return FakeToolExecutor(recordings=dict(recordings))

    return factory


def test_missing_checkov_binary_prints_actionable_hint_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(app, ["scan", "iac", "--path", str(repo)])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "checkov binary not found on PATH" in result.output
    assert "install checkov" in result.output.lower()


def test_a_finding_at_or_above_fail_on_exits_with_gate_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("checkov", "--version"): _VERSION_RESULT,
                ("checkov", "-d"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    # checkov's own default severity for an iac finding with no native signal
    # is MEDIUM (severity_map.toml's [defaults.iac]) — `--fail-on medium`,
    # not `high`, is what actually breaches the gate for it.
    result = runner.invoke(app, ["scan", "iac", "--path", str(repo), "--fail-on", "medium"])

    assert result.exit_code == EXIT_GATE_FAILED
    assert "CKV2_AWS_61" in result.output
    assert "Gate: FAILED" in result.output


def test_a_clean_run_with_fail_on_exits_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("checkov", "--version"): _VERSION_RESULT,
                ("checkov", "-d"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "iac", "--path", str(repo), "--fail-on", "high"])

    assert result.exit_code == EXIT_OK
    assert "PASSED" in result.output


def test_json_format_renders_the_canonical_lossless_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("checkov", "--version"): _VERSION_RESULT,
                ("checkov", "-d"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(
        app, ["scan", "iac", "--path", str(repo), "--format", "json", "--fail-on", "medium"]
    )

    payload = json.loads(result.output)
    assert payload["findings"][0]["rule_id"] == "CKV2_AWS_61"
    assert payload["findings"][0]["resource"] == "aws_s3_bucket.logs"
    assert payload["verdict"]["passed"] is False


def test_dry_run_prints_the_command_without_running_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(app, ["scan", "iac", "--path", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "checkov -d" in result.output
    assert "--skip-framework" in result.output
    assert "secrets" in result.output  # excluded framework, named explicitly (ADR §10)
    assert str(tmp_path.resolve()) in result.output


def test_exclude_paths_is_wired_through_to_skip_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text('[tool_defaults]\nexclude_paths = [".terraform/"]\n')

    result = runner.invoke(
        app, ["scan", "iac", "--path", str(tmp_path), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "--skip-path .terraform/" in result.output


def test_scan_history_on_checkov_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An IaC directory scan has no notion of history to switch between (ADR §8.5)."""
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text("[tools.checkov]\nscan_history = true\n")

    result = runner.invoke(
        app, ["scan", "iac", "--path", str(tmp_path), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "no notion of scan history" in result.output


def test_policy_file_exclusion_suppresses_a_finding_and_it_no_longer_fails_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("checkov", "--version"): _VERSION_RESULT,
                ("checkov", "-d"): ProcessResult(
                    exit_code=1, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )
    # `one_finding.json`'s single entry, reduced to the fingerprint
    # `CheckovIntegration` + `normalize_finding` compute for it: same rule,
    # path, and resource the fixture carries.
    fingerprint = iac_fingerprint(
        rule_id="CKV2_AWS_61", path="main.tf", resource="aws_s3_bucket.logs"
    )
    expires_at = (date.today() + timedelta(days=30)).isoformat()
    config_path = tmp_path / "policy.toml"
    config_path.write_text(
        "[[exclusions]]\n"
        f'fingerprint = "{fingerprint}"\n'
        'reason = "Accepted risk, tracked separately"\n'
        'owner = "team-atlas"\n'
        f"expires_at = {expires_at}\n"
    )

    result = runner.invoke(
        app,
        ["scan", "iac", "--path", str(repo), "--fail-on", "medium", "--config", str(config_path)],
    )

    assert "Suppressed by policy: 1" in result.output
    assert result.exit_code == EXIT_OK
