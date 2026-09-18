"""Tests for `linceo baseline init` (ADR §8.2): the CLI wired end to end.

Mirrors `tests/unit/test_cli_scan.py`/`test_cli_scan_sca.py`: every scenario
runs through `typer.testing.CliRunner`, and none needs a real `gitleaks` or
`trivy` binary — `SubprocessToolExecutor` is replaced with
`linceo.testing.FakeToolExecutor` (ADR §11), fed the same recorded fixtures
those two files already use.
"""

from __future__ import annotations

import subprocess
import tomllib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from linceo.cli.main import app
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK, EXIT_TOOL_EXECUTION_FAILED
from linceo.core.policy import DEFAULT_BASELINE_EXPIRY_DAYS, parse_policy_document
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=UTC)
_GITLEAKS_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
_TRIVY_FIXTURES = Path(__file__).parent / "fixtures" / "trivy"

_GITLEAKS_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
)
_TRIVY_VERSION_RESULT = ProcessResult(
    exit_code=0,
    stdout='{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
    '"NextUpdate":"2026-09-20T00:00:00Z","UpdatedAt":"2026-09-14T01:15:36Z",'
    '"DownloadedAt":"2026-09-14T04:17:21Z"}}',
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
    (path / "config.py").write_text("AWS_KEY = 'not-really-checked-by-the-fake-executor'\n")
    (path / "requirements.txt").write_text("certifi==2015.4.28\n")
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", "initial commit", cwd=path)
    return path


def _stub_executor_factory(recordings: Mapping[tuple[str, ...], ProcessResult]) -> object:
    def factory() -> FakeToolExecutor:
        return FakeToolExecutor(recordings=dict(recordings))

    return factory


def _findings_recordings(
    *, gitleaks_fixture: str, trivy_fixture: str
) -> dict[tuple[str, ...], ProcessResult]:
    gitleaks_stdout = (_GITLEAKS_FIXTURES / gitleaks_fixture).read_text(encoding="utf-8")
    trivy_stdout = (_TRIVY_FIXTURES / trivy_fixture).read_text(encoding="utf-8")
    return {
        ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
        ("gitleaks", "detect"): ProcessResult(
            exit_code=1, stdout=gitleaks_stdout, stderr="", started_at=_NOW, finished_at=_NOW
        ),
        ("trivy", "version", "--format", "json"): _TRIVY_VERSION_RESULT,
        ("trivy", "fs"): ProcessResult(
            exit_code=0, stdout=trivy_stdout, stderr="", started_at=_NOW, finished_at=_NOW
        ),
    }


def _patch_executor(
    monkeypatch: pytest.MonkeyPatch, recordings: Mapping[tuple[str, ...], ProcessResult]
) -> None:
    monkeypatch.setattr(
        "linceo.cli.baseline.SubprocessToolExecutor", _stub_executor_factory(recordings)
    )


def test_owner_is_required(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "widgets")

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo)])

    assert result.exit_code != EXIT_OK
    assert "owner" in result.output.lower()


def test_writes_one_exclusion_per_active_finding_with_identity_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="one_finding.json"),
    )

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_OK, result.output
    output_path = repo / ".devsecops" / "config.toml"
    assert output_path.is_file()

    with output_path.open("rb") as f:
        document = tomllib.load(f)
    parsed = parse_policy_document(
        document, today=_NOW.date(), max_horizon_days=DEFAULT_BASELINE_EXPIRY_DAYS + 1
    )
    assert len(parsed.exclusions) == 2

    by_category = {
        exclusion.category.value: exclusion
        for exclusion in parsed.exclusions
        if exclusion.category is not None
    }
    secrets_entry = by_category["secrets"]
    assert secrets_entry.rule_id == "aws-access-token"
    assert secrets_entry.path == "config.py"
    assert secrets_entry.package is None
    assert secrets_entry.owner == "team-atlas"
    assert secrets_entry.reason == "Initial adoption baseline — pending real triage"
    assert secrets_entry.expires_at == _NOW.date() + timedelta(days=DEFAULT_BASELINE_EXPIRY_DAYS)

    sca_entry = by_category["sca"]
    assert sca_entry.rule_id == "CVE-2023-37920"
    assert sca_entry.path == "requirements.txt"
    assert sca_entry.package == "certifi"
    assert sca_entry.package_version == "2015.4.28"


def test_clean_repository_writes_an_empty_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_OK
    assert "Wrote 0 exclusion(s)" in result.output
    document = tomllib.loads((repo / ".devsecops" / "config.toml").read_text(encoding="utf-8"))
    assert document == {"version": 1}


def test_custom_reason_and_expiry_are_applied_to_every_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="one_finding.json"),
    )

    result = runner.invoke(
        app,
        [
            "baseline",
            "init",
            "--path",
            str(repo),
            "--owner",
            "team-atlas",
            "--reason",
            "Migrating from an older scanner",
            "--expires-in-days",
            "10",
        ],
    )

    assert result.exit_code == EXIT_OK
    document = tomllib.loads((repo / ".devsecops" / "config.toml").read_text(encoding="utf-8"))
    parsed = parse_policy_document(document, today=_NOW.date(), max_horizon_days=90)
    assert {e.reason for e in parsed.exclusions} == {"Migrating from an older scanner"}
    assert {e.expires_at for e in parsed.exclusions} == {_NOW.date() + timedelta(days=10)}


def test_custom_output_path_via_config_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    custom_path = tmp_path / "elsewhere" / "policy.toml"
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(
        app,
        [
            "baseline",
            "init",
            "--path",
            str(repo),
            "--owner",
            "team-atlas",
            "--config",
            str(custom_path),
        ],
    )

    assert result.exit_code == EXIT_OK
    assert custom_path.is_file()
    assert not (repo / ".devsecops").exists()


def test_declining_the_overwrite_prompt_aborts_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("version = 1\n", encoding="utf-8")
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"], input="n\n"
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Aborted" in result.output
    assert output_path.read_text(encoding="utf-8") == "version = 1\n"


def test_accepting_the_overwrite_prompt_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("version = 1\n", encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"], input="y\n"
    )

    assert result.exit_code == EXIT_OK
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    assert len(document["exclusions"]) == 1


def test_force_skips_the_confirmation_prompt_entirely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("version = 1\n", encoding="utf-8")
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )

    assert result.exit_code == EXIT_OK
    assert "?" not in result.output  # no prompt was ever printed


def test_missing_gitleaks_binary_refuses_to_write_a_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        {
            ("trivy", "version", "--format", "json"): _TRIVY_VERSION_RESULT,
            ("trivy", "fs"): ProcessResult(
                exit_code=0,
                stdout=(_TRIVY_FIXTURES / "empty.json").read_text(encoding="utf-8"),
                stderr="",
                started_at=_NOW,
                finished_at=_NOW,
            ),
        },
    )

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "incomplete evidence" in result.output
    assert "gitleaks" in result.output
    assert not (repo / ".devsecops").exists()


def test_a_path_that_is_not_a_git_repository_is_a_configuration_error(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(not_a_repo), "--owner", "team-atlas"]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Configuration error" in result.output


def test_baseline_init_is_listed_in_help() -> None:
    root_help = runner.invoke(app, ["--help"])
    baseline_help = runner.invoke(app, ["baseline", "--help"])

    assert "baseline" in root_help.output
    assert "init" in baseline_help.output
