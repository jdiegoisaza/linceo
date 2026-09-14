"""Tests for `linceo.testing`'s permanent fakes: `FakeContextProvider`, `FakeToolExecutor`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from linceo.core.context import ExecutionContext, Platform
from linceo.core.ports import ProcessResult
from linceo.testing import FakeContextProvider, FakeToolExecutor

_CONTEXT = ExecutionContext(
    platform=Platform.LOCAL,
    repository="acme/widgets",
    workspace_path="/workspace",
    commit="abc123",
)


def test_fake_context_provider_resolves_to_its_fixed_context() -> None:
    provider = FakeContextProvider(context=_CONTEXT)

    assert provider.resolve() == _CONTEXT


def test_fake_tool_executor_replays_a_recorded_process_result() -> None:
    now = datetime(2026, 9, 13, tzinfo=UTC)
    recorded = ProcessResult(exit_code=0, stdout="[]", stderr="", started_at=now, finished_at=now)
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): recorded})

    result = executor.run(["gitleaks", "detect"], env={}, cwd="/workspace", timeout=None)

    assert result is recorded


def test_fake_tool_executor_raises_file_not_found_for_an_unrecorded_binary() -> None:
    executor = FakeToolExecutor()

    with pytest.raises(FileNotFoundError, match="trivy"):
        executor.run(["trivy", "fs"], env={}, cwd="/workspace", timeout=None)


def test_fake_tool_executor_raises_a_recorded_exception() -> None:
    executor = FakeToolExecutor(recordings={("gitleaks",): TimeoutError("scan timed out")})

    with pytest.raises(TimeoutError, match="timed out"):
        executor.run(["gitleaks", "detect"], env={}, cwd="/workspace", timeout=None)


def test_fake_tool_executor_records_every_call() -> None:
    now = datetime(2026, 9, 13, tzinfo=UTC)
    recorded = ProcessResult(exit_code=0, stdout="", stderr="", started_at=now, finished_at=now)
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): recorded})

    executor.run(
        ["gitleaks", "detect", "--source", "."], env={"FOO": "bar"}, cwd="/workspace", timeout=30.0
    )

    expected_call = (["gitleaks", "detect", "--source", "."], {"FOO": "bar"}, "/workspace", 30.0)
    assert executor.calls == [expected_call]


def test_fake_tool_executor_distinguishes_two_purposes_of_the_same_binary() -> None:
    """Keying by argv pattern, not just `argv[0]`, is the fix for the checkpoint finding

    (ADR §1): a fake indexed by binary name alone cannot tell `gitleaks version` apart
    from `gitleaks detect ...` against the same binary.
    """
    now = datetime(2026, 9, 13, tzinfo=UTC)
    version_result = ProcessResult(
        exit_code=0, stdout="8.30.1\n", stderr="", started_at=now, finished_at=now
    )
    detect_result = ProcessResult(
        exit_code=0, stdout="[]", stderr="", started_at=now, finished_at=now
    )
    executor = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): version_result,
            ("gitleaks", "detect"): detect_result,
        }
    )

    assert executor.run(["gitleaks", "version"], env={}, cwd=".", timeout=None) is version_result
    assert (
        executor.run(["gitleaks", "detect", "--source", "."], env={}, cwd=".", timeout=None)
        is detect_result
    )
