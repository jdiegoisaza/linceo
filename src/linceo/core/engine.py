"""The orchestration engine: context -> execution -> normalization -> dedup -> baseline -> gate.

`run()` is the single place these stages are wired together, over the
three ports from ADR §1 — `ContextProvider`, `ToolExecutor`,
`ToolIntegration` — so it runs identically whether those ports are
satisfied by `linceo.testing`'s fakes or by real adapters. Rendering a
report (`linceo.core.reporters`) and mapping the result to a process exit
code (`linceo.core.exit_codes`) are deliberately separate, composable
steps applied to the `RunResult` this function returns, not folded into it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime

from linceo.core.baseline import Baseline, apply_baseline
from linceo.core.config import Config
from linceo.core.dedup import deduplicate
from linceo.core.execution import DataSource, ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding
from linceo.core.gate import evaluate_gate
from linceo.core.normalization import SeverityNormalizer, normalize_finding
from linceo.core.ports import ContextProvider, ToolExecutor, ToolIntegration
from linceo.core.results import RunResult, RunStatus


def _execute_one(
    category: Category,
    integration: ToolIntegration,
    *,
    executor: ToolExecutor,
    workspace_path: str,
    normalizer: SeverityNormalizer,
) -> ToolExecution:
    """Run and normalize one `ToolIntegration`'s execution, absorbing its failures.

    A missing binary (`FileNotFoundError`) becomes `ExecutionStatus.SKIPPED`
    — the tool was never invoked at all (ADR R4: a missing tool is an
    actionable error, never silently retried). Any other failure to run,
    parse, or normalize becomes `ExecutionStatus.FAILED` — both are
    *absence of evidence*, not "zero findings" (ADR §5).
    """
    argv = tuple(integration.build_command(workspace_path=workspace_path))

    try:
        process_result = executor.run(argv, env={}, cwd=workspace_path)
    except FileNotFoundError:
        return ToolExecution(
            tool=integration.name,
            tool_version=integration.version,
            category=category,
            argv=argv,
            started_at=None,
            finished_at=None,
            exit_code=None,
            status=ExecutionStatus.SKIPPED,
            findings=(),
            data_sources=(),
        )
    except Exception:
        return ToolExecution(
            tool=integration.name,
            tool_version=integration.version,
            category=category,
            argv=argv,
            started_at=None,
            finished_at=None,
            exit_code=None,
            status=ExecutionStatus.FAILED,
            findings=(),
            data_sources=(),
        )

    try:
        raw_findings = integration.parse_output(process_result)
        findings = tuple(normalize_finding(raw, normalizer) for raw in raw_findings)
        data_sources: tuple[DataSource, ...] = tuple(integration.data_sources())
    except Exception:
        return ToolExecution(
            tool=integration.name,
            tool_version=integration.version,
            category=category,
            argv=argv,
            started_at=process_result.started_at,
            finished_at=process_result.finished_at,
            exit_code=process_result.exit_code,
            status=ExecutionStatus.FAILED,
            findings=(),
            data_sources=(),
        )

    return ToolExecution(
        tool=integration.name,
        tool_version=integration.version,
        category=category,
        argv=argv,
        started_at=process_result.started_at,
        finished_at=process_result.finished_at,
        exit_code=process_result.exit_code,
        status=ExecutionStatus.COMPLETED,
        findings=findings,
        data_sources=data_sources,
    )


def run(
    *,
    run_id: str,
    context_provider: ContextProvider,
    integrations: Mapping[Category, ToolIntegration],
    executor: ToolExecutor,
    normalizer: SeverityNormalizer,
    baseline: Baseline,
    config: Config,
    now: datetime,
) -> RunResult:
    """Run the full pipeline for one invocation and return its single `RunResult`.

    `now` is supplied by the caller rather than read from the system clock
    here (ADR R3's determinism corollary: no core module calls
    `datetime.now()` directly) — it is used only as the baseline's
    "today" for expiry comparisons.

    Every `ToolIntegration` in `integrations` runs, regardless of whether
    an earlier one failed — a run's evidence is only known to be
    incomplete once every execution has been attempted.
    """
    context = context_provider.resolve()
    effective_normalizer = replace(normalizer, strict=config.strict_normalization)

    executions = tuple(
        _execute_one(
            category,
            integration,
            executor=executor,
            workspace_path=context.workspace_path,
            normalizer=effective_normalizer,
        )
        for category, integration in integrations.items()
    )

    all_findings: tuple[Finding, ...] = tuple(
        finding for execution in executions for finding in execution.findings
    )
    deduplicated = deduplicate(all_findings)

    baseline_outcome = apply_baseline(
        deduplicated,
        baseline,
        today=now.date(),
        max_horizon_days=config.baseline_max_horizon_days,
    )
    verdict = evaluate_gate(baseline_outcome.active, fail_on=config.fail_on)

    status = (
        RunStatus.PARTIAL
        if any(execution.status is not ExecutionStatus.COMPLETED for execution in executions)
        else RunStatus.COMPLETED
    )

    return RunResult(
        run_id=run_id,
        context=context,
        executions=executions,
        findings=deduplicated,
        verdict=verdict,
        status=status,
        suppressed_findings=baseline_outcome.suppressed,
        expired_suppressions=baseline_outcome.expired,
    )
