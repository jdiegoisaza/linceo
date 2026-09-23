"""Tests for `linceo doctor` (ADR §8, R4): the CLI wired end to end.

`tests/unit/test_doctor.py` already covers `gather_report`/`render_report`
in detail without Typer at all — these scenarios only confirm the command
is wired correctly: it calls that same logic and maps its result to the
right exit code.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from linceo.cli.main import app
from linceo.core.exit_codes import EXIT_OK, EXIT_TOOL_EXECUTION_FAILED
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
_GITLEAKS_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
)
_TRIVY_VERSION_RESULT = ProcessResult(
    exit_code=0,
    stdout=(
        '{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
        '"NextUpdate":"2026-09-20T00:00:00Z","UpdatedAt":"2026-09-14T01:15:36Z",'
        '"DownloadedAt":"2026-09-14T04:17:21Z"}}'
    ),
    stderr="",
    started_at=_NOW,
    finished_at=_NOW,
)
_CHECKOV_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="3.3.19\n", stderr="", started_at=_NOW, finished_at=_NOW
)


def _stub_executor_factory(fake: FakeToolExecutor) -> object:
    def factory() -> FakeToolExecutor:
        return fake

    return factory


def test_doctor_exits_ok_when_every_tool_is_available_and_compatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
            ("trivy", "version", "--format", "json"): _TRIVY_VERSION_RESULT,
            ("checkov", "--version"): _CHECKOV_VERSION_RESULT,
        }
    )
    monkeypatch.setattr("linceo.cli.doctor.SubprocessToolExecutor", _stub_executor_factory(fake))

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == EXIT_OK
    assert "gitleaks (secrets):" in result.output
    assert "trivy (sca):" in result.output
    assert "checkov (iac):" in result.output


def test_doctor_exits_with_tool_execution_failed_when_a_binary_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeToolExecutor(recordings={})
    monkeypatch.setattr("linceo.cli.doctor.SubprocessToolExecutor", _stub_executor_factory(fake))

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "NOT FOUND on PATH" in result.output


def test_doctor_is_listed_in_the_root_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert "doctor" in result.output
