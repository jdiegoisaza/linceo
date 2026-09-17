"""Tests for `--platform` on `linceo scan secrets` (ADR §4 R1, §8, §10): the CLI wired end to end.

Mirrors `test_cli_scan.py`'s setup (`FakeToolExecutor` in place of a real
`gitleaks` binary) and adds the Azure-Pipelines-flavored environment
fixtures `--platform`/`auto` detection needs — a branch build, a pull
request build, and a plain directory with none of it, always scoped with
`monkeypatch` so nothing leaks from the host actually running this suite.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from linceo.cli.main import app
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
)

_ALL_KNOWN_AZURE_VARS = (
    "TF_BUILD",
    "BUILD_REPOSITORY_NAME",
    "BUILD_SOURCEVERSION",
    "BUILD_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_PULLREQUESTID",
    "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER",
    "BUILD_BUILDID",
    "BUILD_REPOSITORY_URI",
    "BUILD_SOURCESDIRECTORY",
)


@pytest.fixture(autouse=True)
def _clean_azure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_KNOWN_AZURE_VARS:
        monkeypatch.delenv(var, raising=False)


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


def _clean_recordings() -> dict[tuple[str, ...], ProcessResult]:
    stdout = (_FIXTURES / "empty.json").read_text(encoding="utf-8")
    return {
        ("gitleaks", "version"): _VERSION_RESULT,
        ("gitleaks", "detect"): ProcessResult(
            exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW
        ),
    }


def test_platform_local_resolves_via_git_even_with_azure_variables_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit --platform always wins over whatever `auto` would have detected."""
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/should-not-be-used")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory(_clean_recordings())
    )

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(repo), "--platform", "local", "--format", "json"]
    )

    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["context"]["platform"] == "local"


def test_platform_azure_devops_resolves_from_environment_without_a_git_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "a" * 40)
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/heads/main")
    monkeypatch.setenv("BUILD_BUILDID", "777")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory(_clean_recordings())
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "secrets",
            "--path",
            str(tmp_path),
            "--platform",
            "azure_devops",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["context"]["platform"] == "azure_devops"
    assert payload["context"]["repository"] == "acme/widgets"
    assert payload["context"]["branch"] == "main"
    assert payload["context"]["build_id"] == "777"


def test_platform_azure_devops_without_required_variables_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory({}))

    result = runner.invoke(
        app, ["scan", "secrets", "--path", str(tmp_path), "--platform", "azure_devops"]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "BUILD_REPOSITORY_NAME" in result.output


def test_platform_auto_detects_azure_devops_from_the_tf_build_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`auto` (the default) must pick Azure over local when TF_BUILD is set — no git repo needed."""
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "b" * 40)
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory(_clean_recordings())
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(tmp_path), "--format", "json"])

    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["context"]["platform"] == "azure_devops"


def test_platform_auto_falls_back_to_local_without_the_tf_build_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor", _stub_executor_factory(_clean_recordings())
    )

    result = runner.invoke(app, ["scan", "secrets", "--path", str(repo), "--format", "json"])

    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["context"]["platform"] == "local"
