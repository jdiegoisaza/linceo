"""Tests for `linceo scan sca` (ADR §8, §10): the CLI wired end to end.

Mirrors `tests/unit/test_cli_scan.py` (the `secrets` command): every
scenario runs through `typer.testing.CliRunner`, and none of them needs a
real `trivy` binary — `SubprocessToolExecutor` is replaced with
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
from linceo.core.fingerprint import sca_fingerprint
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
#: Recorded once and reused by every scenario that needs `detect_version` and
#: `detect_data_sources` to succeed — captured, real `trivy version --format json` shape.
_VERSION_JSON_RESULT = ProcessResult(
    exit_code=0,
    stdout='{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
    '"NextUpdate":"2026-09-15T01:15:36.636778479Z",'
    '"UpdatedAt":"2026-09-14T01:15:36.63677888Z",'
    '"DownloadedAt":"2026-09-14T04:17:21.725730573Z"}}',
    stderr="",
    started_at=_NOW,
    finished_at=_NOW,
)


def _git(*args: str, cwd: Path) -> None:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    (path / "requirements.txt").write_text("certifi==2015.4.28\n")
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", "initial commit", cwd=path)
    return path


def _stub_executor_factory(recordings: Mapping[tuple[str, ...], ProcessResult]) -> object:
    def factory() -> FakeToolExecutor:
        return FakeToolExecutor(recordings=dict(recordings))

    return factory


def test_missing_trivy_binary_prints_actionable_hint_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(app, ["scan", "sca", "--path", str(repo)])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "trivy binary not found on PATH" in result.output
    assert "install trivy" in result.output.lower()


def test_a_finding_at_or_above_fail_on_exits_with_gate_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "one_finding.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("trivy", "version", "--format", "json"): _VERSION_JSON_RESULT,
                ("trivy", "fs"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "sca", "--path", str(repo), "--fail-on", "high"])

    assert result.exit_code == EXIT_GATE_FAILED
    assert "CVE-2023-37920" in result.output
    assert "Gate: FAILED" in result.output
    assert "1 HIGH exceeds the maximum allowed of 0" in result.output


def test_a_clean_run_with_fail_on_exits_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path / "widgets")
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("trivy", "version", "--format", "json"): _VERSION_JSON_RESULT,
                ("trivy", "fs"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "sca", "--path", str(repo), "--fail-on", "high"])

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
                ("trivy", "version", "--format", "json"): _VERSION_JSON_RESULT,
                ("trivy", "fs"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "sca", "--path", str(repo)])

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
                ("trivy", "version", "--format", "json"): _VERSION_JSON_RESULT,
                ("trivy", "fs"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )

    result = runner.invoke(
        app, ["scan", "sca", "--path", str(repo), "--format", "json", "--fail-on", "high"]
    )

    payload = json.loads(result.output)
    assert payload["findings"][0]["rule_id"] == "CVE-2023-37920"
    assert payload["verdict"]["passed"] is False
    # ADR §5: the vulnerability database's own build date always travels in the report.
    assert payload["executions"][0]["data_sources"][0]["name"] == "trivy-vulnerability-db"
    assert payload["executions"][0]["data_sources"][0]["built_at"] == "2026-09-14"


def test_dry_run_prints_the_command_without_running_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(app, ["scan", "sca", "--path", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "trivy fs --scanners vuln --format json --skip-db-update" in result.output
    assert str(tmp_path.resolve()) in result.output


def test_database_not_ready_prints_an_actionable_hint_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR R2/§5: offline by default surfaces one actionable failure, never a bare traceback."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        _stub_executor_factory(
            {
                ("trivy", "version", "--format", "json"): ProcessResult(
                    exit_code=0,
                    stdout='{"Version":"0.74.0"}',
                    stderr="",
                    started_at=_NOW,
                    finished_at=_NOW,
                ),
                ("trivy", "fs"): ProcessResult(
                    exit_code=1,
                    stdout="",
                    stderr=(
                        "FATAL\tFatal error\trun error: init error: DB error: database error: "
                        "--skip-db-update cannot be specified on the first run\n"
                    ),
                    started_at=_NOW,
                    finished_at=_NOW,
                ),
            }
        ),
    )

    result = runner.invoke(app, ["scan", "sca", "--path", str(repo)])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "vulnerability database" in result.output
    assert "--download-db-only" in result.output


def test_exclude_paths_is_wired_through_to_skip_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text('[tool_defaults]\nexclude_paths = ["vendor/"]\n')

    result = runner.invoke(
        app, ["scan", "sca", "--path", str(tmp_path), "--config", str(config_path), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "--skip-dirs vendor/" in result.output


def test_scan_history_on_trivy_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dependency-manifest scan has no notion of history to switch between (ADR §8.5)."""
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))
    config_path = tmp_path / "policy.toml"
    config_path.write_text("[tools.trivy]\nscan_history = false\n")

    result = runner.invoke(
        app, ["scan", "sca", "--path", str(tmp_path), "--config", str(config_path), "--dry-run"]
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
                ("trivy", "version", "--format", "json"): _VERSION_JSON_RESULT,
                ("trivy", "fs"): ProcessResult(
                    exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
                ),
            }
        ),
    )
    # `one_finding.json`'s single entry, reduced to the fingerprint
    # `TrivyIntegration` + `normalize_finding` compute for it: same package,
    # version, vulnerability id, and manifest path the fixture carries.
    fingerprint = sca_fingerprint(
        package_name="certifi",
        package_version="2015.4.28",
        vulnerability_id="CVE-2023-37920",
        manifest_path="requirements.txt",
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
        [
            "scan",
            "sca",
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
