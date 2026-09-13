"""End-to-end tests for the orchestration engine and every exit code (ADR §1, §5, §8)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.core.baseline import Baseline
from linceo.core.config import Config, ConfigurationError, load_config
from linceo.core.context import ExecutionContext, Platform
from linceo.core.engine import run
from linceo.core.execution import DataSource, ExecutionStatus
from linceo.core.exit_codes import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_GATE_FAILED,
    EXIT_OK,
    EXIT_TOOL_EXECUTION_FAILED,
    compute_exit_code,
)
from linceo.core.findings import Category, Location, Package, RawFinding
from linceo.core.normalization import SeverityNormalizer
from linceo.core.ports import ProcessResult
from linceo.core.results import RunResult, RunStatus
from linceo.core.severity import Severity
from linceo.testing import FakeContextProvider, FakeToolExecutor

_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)

_CONTEXT = ExecutionContext(
    platform=Platform.LOCAL,
    repository="acme/widgets",
    workspace_path="/workspace",
    commit="abc123",
)
_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _process_result(*, exit_code: int = 0) -> ProcessResult:
    return ProcessResult(
        exit_code=exit_code, stdout="", stderr="", started_at=_NOW, finished_at=_NOW
    )


@dataclass
class StaticToolIntegration:
    """A minimal, structurally-valid `ToolIntegration` double for engine tests."""

    name: str
    version: str
    category: Category
    argv: Sequence[str]
    raw_findings: Sequence[RawFinding] = ()
    sources: Sequence[DataSource] = ()

    def build_command(self, *, workspace_path: str) -> Sequence[str]:  # noqa: ARG002
        return self.argv

    def parse_output(self, _result: ProcessResult) -> Sequence[RawFinding]:
        return self.raw_findings

    def data_sources(self) -> Sequence[DataSource]:
        return self.sources

    def native_severity_domain(self) -> frozenset[str]:
        return frozenset()


def _secret_raw_finding(severity_raw: str | None = None) -> RawFinding:
    return RawFinding(
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        raw_severity=severity_raw,
        secret_hash=_SECRET_HASH,
    )


def _sca_raw_finding() -> RawFinding:
    return RawFinding(
        tool="trivy",
        category=Category.SCA,
        rule_id="CVE-2023-32681",
        message="requests vulnerable to proxy auth leak",
        location=Location(path="requirements.txt"),
        raw_severity="HIGH",
        package=Package(name="requests", version="2.25.0"),
    )


def _run(
    *,
    integrations: dict[Category, StaticToolIntegration],
    executor: FakeToolExecutor,
    config: Config,
) -> RunResult:
    return run(
        run_id="run-1",
        context_provider=FakeContextProvider(context=_CONTEXT),
        integrations=integrations,
        executor=executor,
        normalizer=SeverityNormalizer(native_map={("trivy", "HIGH"): Severity.HIGH}),
        baseline=Baseline(),
        config=config,
        now=_NOW,
    )


def test_exit_code_0_when_the_run_completes_and_the_gate_passes() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={"gitleaks": _process_result()})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=Config(fail_on=Severity.HIGH),
    )

    assert result.status is RunStatus.COMPLETED
    assert result.verdict.passed is True
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_OK


def test_exit_code_1_when_the_run_completes_and_the_gate_fails() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks",
        version="8.18.0",
        category=Category.SECRETS,
        argv=("gitleaks", "detect"),
        raw_findings=(_secret_raw_finding(),),
    )
    executor = FakeToolExecutor(recordings={"gitleaks": _process_result()})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=Config(fail_on=Severity.HIGH),
    )

    assert result.status is RunStatus.COMPLETED
    assert result.verdict.passed is False
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_GATE_FAILED


def test_exit_code_2_when_configuration_is_invalid(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_config(
            cli_overrides={"fail_on": "not-a-severity"},
            explicit_config_path=None,
            workspace_path=str(tmp_path),
            package_root=str(tmp_path),
        )
    assert EXIT_CONFIGURATION_ERROR == 2


def test_exit_code_3_when_a_tool_binary_is_missing_and_evidence_is_incomplete() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={})  # no recording -> FileNotFoundError -> SKIPPED

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=Config(),
    )

    assert result.status is RunStatus.PARTIAL
    assert result.executions[0].status is ExecutionStatus.SKIPPED
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_TOOL_EXECUTION_FAILED


def test_executor_crash_marks_the_execution_failed_not_skipped() -> None:
    """A crash mid-run (e.g. a timeout) is distinct from a binary that was never found."""
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={"gitleaks": TimeoutError("scan timed out")})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=Config(),
    )

    assert result.executions[0].status is ExecutionStatus.FAILED
    assert result.status is RunStatus.PARTIAL
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_TOOL_EXECUTION_FAILED


def test_parse_output_failure_marks_the_execution_failed_with_no_findings() -> None:
    """Malformed tool output is absence of evidence, not zero findings (ADR §5)."""

    @dataclass
    class _BrokenParserIntegration(StaticToolIntegration):
        def parse_output(self, _result: ProcessResult) -> Sequence[RawFinding]:
            msg = "unexpected output format"
            raise ValueError(msg)

    gitleaks = _BrokenParserIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={"gitleaks": _process_result(exit_code=0)})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=Config(),
    )

    execution = result.executions[0]
    assert execution.status is ExecutionStatus.FAILED
    assert execution.findings == ()
    assert execution.exit_code == 0
    assert result.status is RunStatus.PARTIAL


def test_continue_on_tool_error_overrides_the_partial_run_exit_code() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=Config(),
    )

    assert result.status is RunStatus.PARTIAL
    assert compute_exit_code(result, continue_on_tool_error=True) == EXIT_OK


def test_two_tool_executions_in_one_run_produce_a_single_aggregated_verdict() -> None:
    """The ADR §1 invariant: N tool executions, one veredicto — never one per tool."""
    gitleaks = StaticToolIntegration(
        name="gitleaks",
        version="8.18.0",
        category=Category.SECRETS,
        argv=("gitleaks", "detect"),
        raw_findings=(_secret_raw_finding(),),
        sources=(DataSource(name="gitleaks-rules", version="1.0", built_at=_NOW.date()),),
    )
    trivy = StaticToolIntegration(
        name="trivy",
        version="0.50.0",
        category=Category.SCA,
        argv=("trivy", "fs", "."),
        raw_findings=(_sca_raw_finding(),),
        sources=(DataSource(name="trivy-db", version="2026-09-01", built_at=_NOW.date()),),
    )
    executor = FakeToolExecutor(
        recordings={"gitleaks": _process_result(), "trivy": _process_result()}
    )

    result = _run(
        integrations={Category.SECRETS: gitleaks, Category.SCA: trivy},
        executor=executor,
        config=Config(fail_on=Severity.HIGH),
    )

    assert len(result.executions) == 2
    assert {execution.tool for execution in result.executions} == {"gitleaks", "trivy"}
    assert all(execution.status is ExecutionStatus.COMPLETED for execution in result.executions)

    assert result.status is RunStatus.COMPLETED
    assert len(result.findings) == 2
    assert {finding.tool for finding in result.findings} == {"gitleaks", "trivy"}

    # One Verdict for the whole run, not one per tool execution.
    assert result.verdict.counts_by_severity[Severity.HIGH] == 2
    assert result.verdict.passed is False
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_GATE_FAILED
