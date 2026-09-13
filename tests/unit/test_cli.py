"""Tests for the linceo console entry point (src/linceo/cli/main.py)."""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from linceo import __version__
from linceo.cli.main import EXIT_USAGE_ERROR, app, main

runner = CliRunner()


def test_version_flag_prints_version_and_exits_zero() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_no_arguments_prints_help_to_stderr_and_exits_with_usage_error() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code == EXIT_USAGE_ERROR
    assert "Usage" in result.output


def test_console_script_entry_point_invokes_the_typer_app(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`main()`, registered as the `linceo` console script, must run `app()`."""
    monkeypatch.setattr(sys, "argv", ["linceo", "--version"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == __version__
