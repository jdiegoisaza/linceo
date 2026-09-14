"""End-to-end tests for the orchestration engine and every exit code (ADR §1, §5, §8)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

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
from linceo.core.fingerprint import secret_fingerprint
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import ConfigLayer, Exclusion, Policy, ThresholdResolution, ToolSkip
from linceo.core.ports import ProcessResult, ToolExecutor
from linceo.core.report_schema import Column, ReportSchema
from linceo.core.results import RunResult, RunStatus
from linceo.core.severity import Severity
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError
from linceo.testing import FakeContextProvider, FakeToolExecutor

_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)

_CONTEXT = ExecutionContext(
    platform=Platform.LOCAL,
    repository="acme/widgets",
    workspace_path="/workspace",
    commit="abc123",
)
_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential
_SCHEMA = ReportSchema(location=Column(header="LOCATION", fields=("location.path",)))


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

    def build_command(
        self,
        *,
        workspace_path: str,  # noqa: ARG002
        config: ToolConfig,  # noqa: ARG002
    ) -> Sequence[str]:
        return self.argv

    def parse_output(self, _result: ProcessResult) -> Sequence[RawFinding]:
        return self.raw_findings

    def data_sources(self) -> Sequence[DataSource]:
        return self.sources

    def native_severity_domain(self) -> frozenset[str]:
        return frozenset()

    def report_schema(self) -> ReportSchema:
        return _SCHEMA

    @staticmethod
    def detect_version(_executor: ToolExecutor) -> str:
        return "0.0.0"

    def missing_binary_hint(self) -> str:
        return f"{self.name} binary not found on PATH"


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


def _config_with_fail_on(fail_on: Severity | None, **kwargs: object) -> Config:
    resolution = ThresholdResolution.for_fail_on(fail_on, source=ConfigLayer.CLI)
    return Config(threshold_resolution=resolution, **kwargs)  # type: ignore[arg-type]


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
        config=config,
        now=_NOW,
    )


def test_exit_code_0_when_the_run_completes_and_the_gate_passes() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=_config_with_fail_on(Severity.HIGH),
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
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})

    result = _run(
        integrations={Category.SECRETS: gitleaks},
        executor=executor,
        config=_config_with_fail_on(Severity.HIGH),
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
            today=date(2026, 9, 13),
        )
    assert EXIT_CONFIGURATION_ERROR == 2


def test_exit_code_3_when_a_tool_binary_is_missing_and_evidence_is_incomplete() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={})  # no recording -> FileNotFoundError -> SKIPPED

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=Config())

    assert result.status is RunStatus.PARTIAL
    assert result.executions[0].status is ExecutionStatus.SKIPPED
    assert result.executions[0].message == gitleaks.missing_binary_hint()
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_TOOL_EXECUTION_FAILED


def test_executor_crash_marks_the_execution_failed_not_skipped() -> None:
    """A crash mid-run (e.g. a timeout) is distinct from a binary that was never found."""
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): TimeoutError("scan timed out")})

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=Config())

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
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result(exit_code=0)})

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=Config())

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

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=Config())

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
        recordings={
            ("gitleaks", "detect"): _process_result(),
            ("trivy", "fs", "."): _process_result(),
        }
    )

    result = _run(
        integrations={Category.SECRETS: gitleaks, Category.SCA: trivy},
        executor=executor,
        config=_config_with_fail_on(Severity.HIGH),
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


# --- exclusions and tool skips, wired end to end (ADR §8.2) -------------------


def test_exclusion_suppresses_a_finding_and_it_does_not_count_for_the_gate() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks",
        version="8.18.0",
        category=Category.SECRETS,
        argv=("gitleaks", "detect"),
        raw_findings=(_secret_raw_finding(),),
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})
    fingerprint = secret_fingerprint(
        rule_id="aws-access-key", path="src/config.py", secret_hash=_SECRET_HASH
    )
    exclusion = Exclusion(
        fingerprint=fingerprint,
        reason="Synthetic credential in the parser test corpus",
        owner="team-atlas",
        expires_at=_NOW.date() + timedelta(days=1),
    )
    config = _config_with_fail_on(Severity.HIGH, policy=Policy(exclusions=(exclusion,)))

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=config)

    assert result.suppressed_findings != ()
    assert result.verdict.passed is True


def test_active_tool_skip_prevents_invocation_and_does_not_make_the_run_partial() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={})  # would raise FileNotFoundError if ever called
    skip = ToolSkip(
        tool="gitleaks",
        reason="Rollout paused while the team triages the initial backlog",
        owner="team-atlas",
        expires_at=_NOW.date() + timedelta(days=1),
    )
    config = Config(policy=Policy(tool_skips=(skip,)))

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=config)

    assert executor.calls == []
    assert result.executions[0].status is ExecutionStatus.SKIPPED_BY_POLICY
    assert result.status is RunStatus.COMPLETED
    assert result.applied_tool_skips == (skip,)
    assert compute_exit_code(result, continue_on_tool_error=False) == EXIT_OK


def test_expired_tool_skip_lets_the_tool_run_again() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})
    skip = ToolSkip(
        tool="gitleaks",
        reason="Rollout paused while the team triages the initial backlog",
        owner="team-atlas",
        expires_at=_NOW.date() - timedelta(days=1),
    )
    config = Config(policy=Policy(tool_skips=(skip,)))

    result = _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=config)

    assert result.executions[0].status is ExecutionStatus.COMPLETED
    assert result.applied_tool_skips == ()
    assert result.expired_tool_skips == (skip,)


# --- per-integration configuration (ADR §8.5) --------------------------------


def test_tool_config_timeout_is_threaded_through_to_the_executor() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})
    config = Config(tool_configs={"gitleaks": ToolConfig(timeout=42.0)})

    _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=config)

    [(_argv, _env, _cwd, timeout)] = executor.calls
    assert timeout == 42.0


def test_tool_defaults_apply_when_no_per_tool_override_sets_the_field() -> None:
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})
    config = Config(tool_defaults=ToolConfig(timeout=60.0))

    _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=config)

    [(_argv, _env, _cwd, timeout)] = executor.calls
    assert timeout == 60.0


def test_per_tool_override_wins_over_tool_defaults_for_the_same_field() -> None:
    """The motivating case, end to end: a shared default, overridden by one tool's own block."""
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})
    config = Config(
        tool_defaults=ToolConfig(timeout=60.0),
        tool_configs={"gitleaks": ToolConfig(timeout=10.0)},
    )

    _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=config)

    [(_argv, _env, _cwd, timeout)] = executor.calls
    assert timeout == 10.0


def test_an_unconfigured_tool_gets_the_all_default_tool_config() -> None:
    """No `[tools.<name>]` entry at all means `ToolConfig()`'s own defaults — `timeout=None`."""
    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})

    _run(integrations={Category.SECRETS: gitleaks}, executor=executor, config=Config())

    [(_argv, _env, _cwd, timeout)] = executor.calls
    assert timeout is None


def test_unsupported_tool_config_aborts_the_run_before_any_tool_executes() -> None:
    """`UnsupportedToolConfigError` (ADR §8.5) surfaces before a single tool actually runs —

    every integration's `build_command` is called up front, so a rejection from *any* one of
    them — even one that isn't first — must stop the run before the *other* one, which would
    have succeeded, ever reaches `executor.run` (ADR §8.4's validate-before-invoking principle,
    extended to per-tool configuration).
    """

    @dataclass
    class _PickyIntegration(StaticToolIntegration):
        def build_command(
            self,
            *,
            workspace_path: str,  # noqa: ARG002
            config: ToolConfig,  # noqa: ARG002
        ) -> Sequence[str]:
            msg = "this tool never honors any configuration at all"
            raise UnsupportedToolConfigError(msg)

    gitleaks = StaticToolIntegration(
        name="gitleaks", version="8.18.0", category=Category.SECRETS, argv=("gitleaks", "detect")
    )
    picky = _PickyIntegration(
        name="trivy", version="0.50.0", category=Category.SCA, argv=("trivy", "fs")
    )
    executor = FakeToolExecutor(recordings={("gitleaks", "detect"): _process_result()})

    with pytest.raises(UnsupportedToolConfigError):
        _run(
            integrations={Category.SECRETS: gitleaks, Category.SCA: picky},
            executor=executor,
            config=Config(),
        )

    assert executor.calls == []
