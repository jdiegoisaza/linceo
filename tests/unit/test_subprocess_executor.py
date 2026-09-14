"""Tests for `SubprocessToolExecutor` (ADR §9): real subprocesses, list argv, merged env."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from linceo.adapters.subprocess_executor import SubprocessToolExecutor


def test_runs_argv_as_a_list_and_captures_stdout_and_exit_code(tmp_path: Path) -> None:
    executor = SubprocessToolExecutor()

    result = executor.run(
        (sys.executable, "-c", "print('hello from child')"), env={}, cwd=str(tmp_path), timeout=None
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "hello from child"
    assert result.started_at <= result.finished_at


def test_captures_a_nonzero_exit_code_without_raising(tmp_path: Path) -> None:
    executor = SubprocessToolExecutor()

    result = executor.run(
        (sys.executable, "-c", "import sys; sys.exit(7)"), env={}, cwd=str(tmp_path), timeout=None
    )

    assert result.exit_code == 7


def test_captures_stderr_separately_from_stdout(tmp_path: Path) -> None:
    executor = SubprocessToolExecutor()

    result = executor.run(
        (
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ),
        env={},
        cwd=str(tmp_path),
        timeout=None,
    )

    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"


def test_runs_in_the_given_working_directory(tmp_path: Path) -> None:
    executor = SubprocessToolExecutor()
    marker = tmp_path / "marker.txt"
    marker.write_text("found me")

    result = executor.run(
        (sys.executable, "-c", "print(open('marker.txt').read())"),
        env={},
        cwd=str(tmp_path),
        timeout=None,
    )

    assert result.stdout.strip() == "found me"


def test_env_is_merged_over_the_inherited_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Passing one extra variable must not strip the rest of the environment (e.g. PATH)."""
    monkeypatch.setenv("LINCEO_INHERITED_VAR", "inherited")
    executor = SubprocessToolExecutor()
    script = (
        "import os; print(os.environ['LINCEO_INHERITED_VAR']); "
        "print(os.environ['LINCEO_EXTRA_VAR'])"
    )

    result = executor.run(
        (sys.executable, "-c", script),
        env={"LINCEO_EXTRA_VAR": "extra"},
        cwd=str(tmp_path),
        timeout=None,
    )

    lines = result.stdout.splitlines()
    assert lines == ["inherited", "extra"]


def test_missing_binary_raises_file_not_found_error(tmp_path: Path) -> None:
    executor = SubprocessToolExecutor()

    with pytest.raises(FileNotFoundError):
        executor.run(("definitely-not-a-real-binary-xyz",), env={}, cwd=str(tmp_path), timeout=None)


def test_timeout_raises_timeout_expired(tmp_path: Path) -> None:
    executor = SubprocessToolExecutor(timeout_seconds=0.05)

    with pytest.raises(subprocess.TimeoutExpired):
        executor.run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            env={},
            cwd=str(tmp_path),
            timeout=None,
        )


def test_per_call_timeout_overrides_the_executors_own_default(tmp_path: Path) -> None:
    """`ToolConfig.timeout` (ADR §8.5), threaded through as a per-call `timeout`, wins."""
    executor = SubprocessToolExecutor()  # no default timeout at all

    with pytest.raises(subprocess.TimeoutExpired):
        executor.run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            env={},
            cwd=str(tmp_path),
            timeout=0.05,
        )


def test_per_call_timeout_of_none_falls_back_to_the_executors_own_default(
    tmp_path: Path,
) -> None:
    executor = SubprocessToolExecutor(timeout_seconds=0.05)

    with pytest.raises(subprocess.TimeoutExpired):
        executor.run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            env={},
            cwd=str(tmp_path),
            timeout=None,
        )
