"""Tests for `linceo scan image` (ADR §8, §10): the CLI wired end to end, no real trivy."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
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
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "trivy_image"
_VERSION = ProcessResult(
    exit_code=0,
    stdout='{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
    '"UpdatedAt":"2026-09-14T01:15:36.63677888Z"}}',
    stderr="",
    started_at=_NOW,
    finished_at=_NOW,
)


def _repo(path: Path) -> Path:
    path.mkdir(parents=True)
    for args in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "T"]):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)  # noqa: S603, S607
    (path / "f").write_text("x")
    for args in (["add", "-A"], ["commit", "-q", "-m", "i"]):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)  # noqa: S603, S607
    return path


def _stub(monkeypatch: pytest.MonkeyPatch, scan: ProcessResult | Exception | None = None) -> None:
    recordings: Mapping[tuple[str, ...], ProcessResult | Exception] = {
        ("trivy", "version"): _VERSION
    }
    if scan is not None:
        recordings = {**recordings, ("trivy", "image"): scan}
    monkeypatch.setattr(
        "linceo.cli.scan.SubprocessToolExecutor",
        lambda: FakeToolExecutor(recordings=dict(recordings)),
    )


def _out(name: str, exit_code: int = 0, stderr: str = "") -> ProcessResult:
    stdout = (_FIXTURES / f"{name}.json").read_text(encoding="utf-8") if name else ""
    return ProcessResult(
        exit_code=exit_code, stdout=stdout, stderr=stderr, started_at=_NOW, finished_at=_NOW
    )


def test_dry_run_prints_the_daemon_only_command(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "w")

    result = runner.invoke(app, ["scan", "image", "app:1", "--dry-run", "--path", str(repo)])

    assert result.exit_code == EXIT_OK
    assert "--image-src docker" in result.output
    assert result.output.strip().endswith("app:1")


def test_dry_run_reports_unsupported_tool_config(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "w")
    (repo / ".devsecops").mkdir()
    (repo / ".devsecops" / "config.toml").write_text("[tools.trivy]\nscan_history = true\n")

    result = runner.invoke(app, ["scan", "image", "app:1", "--dry-run", "--path", str(repo)])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR


def test_an_invalid_reference_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch)
    repo = _repo(tmp_path / "w")

    result = runner.invoke(app, ["scan", "image", "bad ref", "--path", str(repo)])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "invalid image reference" in result.output


def test_findings_render_origin_and_layer_and_fail_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub(monkeypatch, _out("os_and_gobinary"))
    repo = _repo(tmp_path / "w")

    result = runner.invoke(
        app, ["scan", "image", "app:1", "--path", str(repo), "--fail-on", "high"]
    )

    assert result.exit_code == EXIT_GATE_FAILED
    assert "ORIGIN" in result.output
    assert "usr/bin/gitleaks" in result.output
    assert "alpine" in result.output


def test_json_and_sarif_carry_the_layer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, _out("os_and_python"))
    repo = _repo(tmp_path / "w")

    as_json = runner.invoke(app, ["scan", "image", "i", "--path", str(repo), "--format", "json"])
    sarif = runner.invoke(app, ["scan", "image", "i", "--path", str(repo), "--format", "sarif"])

    document = json.loads(as_json.output)
    assert document["findings"][0]["category"] == "image"
    assert document["findings"][0]["location"]["layer"].startswith("sha256:")
    properties = json.loads(sarif.output)["runs"][0]["results"][0]["properties"]
    assert properties["layer"].startswith("sha256:")


def test_missing_image_surfaces_the_actionable_message_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stderr = "Error response from daemon: No such image: app:1"
    _stub(monkeypatch, _out("", exit_code=1, stderr=stderr))
    repo = _repo(tmp_path / "w")

    result = runner.invoke(app, ["scan", "image", "app:1", "--path", str(repo)])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "'app:1' is not in the local Docker daemon" in result.output


def test_unreachable_daemon_surfaces_the_actionable_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stderr = "failed to connect to the docker API at unix:///var/run/docker.sock"
    _stub(monkeypatch, _out("", exit_code=1, stderr=stderr))
    repo = _repo(tmp_path / "w")

    result = runner.invoke(app, ["scan", "image", "app:1", "--path", str(repo)])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "needs a reachable Docker daemon" in result.output
