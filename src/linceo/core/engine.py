"""The orchestration engine: context -> execution -> normalization -> dedup -> policy -> gate.

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
from datetime import date, datetime

from linceo.core.config import Config
from linceo.core.dedup import deduplicate
from linceo.core.execution import DataSource, ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding
from linceo.core.gate import evaluate_gate
from linceo.core.normalization import SeverityNormalizer, normalize_finding
from linceo.core.policy import ToolSkip, apply_exclusions, split_tool_skips
from linceo.core.ports import ContextProvider, ToolExecutor, ToolIntegration
from linceo.core.results import RunResult, RunStatus
from linceo.core.tool_config import ToolConfig, resolve_tool_config


def _execute_one(
    category: Category,
    integration: ToolIntegration,
    *,
    executor: ToolExecutor,
    workspace_path: str,
    argv: tuple[str, ...],
    normalizer: SeverityNormalizer,
    skip: ToolSkip | None,
    timeout: float | None,
) -> ToolExecution:
    """Run and normalize one `ToolIntegration`'s execution, absorbing its failures.

    `argv` arrives already built by `run()`, below — every integration's
    `build_command` has already been called, and any
    `UnsupportedToolConfigError` it could raise (ADR §8.5) has already had
    its chance to, before this function (or any real subprocess) runs at
    all. `timeout` is `ToolConfig.timeout` for this tool, enforced here by
    `executor.run` alone — never translated into a flag inside `argv`
    itself (see `ToolConfig.timeout`).

    When `skip` is not `None`, the tool is never invoked at all — the
    execution is `SKIPPED_BY_POLICY` (ADR §5, §8), a declared and caducable
    absence, distinct from `SKIPPED` (a missing binary) and `FAILED` (a
    crash), neither of which is sanctioned.

    A missing binary (`FileNotFoundError`) becomes `ExecutionStatus.SKIPPED`
    — the tool was never invoked at all (ADR R4: a missing tool is an
    actionable error, never silently retried) — with `message` set to
    `integration.missing_binary_hint()`, the single place this actionable
    message is produced (ADR §1 checkpoint; no separate preflight
    duplicates this detection elsewhere). Any other failure to run, parse,
    or normalize becomes `ExecutionStatus.FAILED` — both are *absence of
    evidence*, not "zero findings" (ADR §5). This is also where a
    `subprocess.TimeoutExpired` (or any other `TimeoutError`) from an
    elapsed `timeout` lands: a timed-out tool produced no usable evidence
    either, the same as a crash.
    """
    if skip is not None:
        return ToolExecution(
            tool=integration.name,
            tool_version=integration.version,
            category=category,
            argv=(),
            started_at=None,
            finished_at=None,
            exit_code=None,
            status=ExecutionStatus.SKIPPED_BY_POLICY,
            findings=(),
            data_sources=(),
        )

    try:
        process_result = executor.run(argv, env={}, cwd=workspace_path, timeout=timeout)
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
            message=integration.missing_binary_hint(),
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


def _incomplete(status: ExecutionStatus) -> bool:
    """Whether `status` means a `ToolExecution` did not produce usable evidence (ADR §5).

    `SKIPPED_BY_POLICY` is deliberately excluded: it is a declared,
    caducable absence, not the accidental one `RunStatus.PARTIAL` exists to
    flag.
    """
    return status not in (ExecutionStatus.COMPLETED, ExecutionStatus.SKIPPED_BY_POLICY)


def run(
    *,
    run_id: str,
    context_provider: ContextProvider,
    integrations: Mapping[Category, ToolIntegration],
    executor: ToolExecutor,
    normalizer: SeverityNormalizer,
    config: Config,
    now: datetime,
) -> RunResult:
    """Run the full pipeline for one invocation and return its single `RunResult`.

    `now` is supplied by the caller rather than read from the system clock
    here (ADR R3's determinism corollary: no core module calls
    `datetime.now()` directly) — its date is used both as the exclusion
    policy's "today" for expiry comparisons and to decide which of
    `config.policy.tool_skips` are still active.

    Every `ToolIntegration` in `integrations` is either skipped by an
    active `ToolSkip` or run, regardless of whether an earlier one failed —
    a run's evidence is only known to be incomplete once every execution
    has been attempted or sanctioned-skipped.

    Raises:
        UnsupportedToolConfigError: if any non-skipped integration's
            `build_command` rejects its resolved `ToolConfig` (ADR §8.5).
            Raised here, before any tool is actually invoked — every
            argv is built up front, in this one pass, precisely so a
            configuration error surfaces before N-1 other tools in this
            same run already executed for real (ADR §8.4's "se valida...
            antes de invocar ninguna herramienta", extended to per-tool
            configuration).
    """
    context = context_provider.resolve()
    effective_normalizer = replace(normalizer, strict=config.strict_normalization)
    today: date = now.date()

    active_skips, expired_skips = split_tool_skips(config.policy.tool_skips, today=today)
    skip_by_tool = {skip.tool: skip for skip in active_skips}

    tool_configs_by_tool = {
        integration.name: resolve_tool_config(
            defaults=config.tool_defaults,
            override=config.tool_configs.get(integration.name, ToolConfig()),
        )
        for integration in integrations.values()
    }
    argv_by_category: dict[Category, tuple[str, ...]] = {
        category: tuple(
            integration.build_command(
                workspace_path=context.workspace_path,
                config=tool_configs_by_tool[integration.name],
            )
        )
        for category, integration in integrations.items()
        if skip_by_tool.get(integration.name) is None
    }

    executions = tuple(
        _execute_one(
            category,
            integration,
            executor=executor,
            workspace_path=context.workspace_path,
            argv=argv_by_category.get(category, ()),
            normalizer=effective_normalizer,
            skip=skip_by_tool.get(integration.name),
            timeout=tool_configs_by_tool[integration.name].timeout,
        )
        for category, integration in integrations.items()
    )
    applied_tool_skips = tuple(
        skip_by_tool[execution.tool]
        for execution in executions
        if execution.status is ExecutionStatus.SKIPPED_BY_POLICY
    )

    all_findings: tuple[Finding, ...] = tuple(
        finding for execution in executions for finding in execution.findings
    )
    deduplicated = deduplicate(all_findings)

    exclusion_outcome = apply_exclusions(
        deduplicated, config.policy.exclusions, today=today, repository=context.repository
    )
    verdict = evaluate_gate(exclusion_outcome.active, resolution=config.threshold_resolution)

    status = (
        RunStatus.PARTIAL
        if any(_incomplete(execution.status) for execution in executions)
        else RunStatus.COMPLETED
    )

    return RunResult(
        run_id=run_id,
        context=context,
        executions=executions,
        findings=deduplicated,
        verdict=verdict,
        status=status,
        suppressed_findings=exclusion_outcome.suppressed,
        expired_exclusions=exclusion_outcome.expired,
        applied_tool_skips=applied_tool_skips,
        expired_tool_skips=expired_skips,
    )
