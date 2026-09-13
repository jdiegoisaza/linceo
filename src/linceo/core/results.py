"""`RunResult` and `Verdict`: N tool executions, one verdict (ADR §1, §5).

The invariant this module exists to satisfy: the model of a run's result
and the gate are built from day one to support N tool executions producing
a single aggregated verdict and a single exit code — never a report file
and an exit code per tool (ADR §1, "Invariante de aceptación").
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from linceo.core.baseline import BaselineEntry
from linceo.core.context import ExecutionContext
from linceo.core.execution import ToolExecution
from linceo.core.findings import Finding
from linceo.core.severity import Severity


class RunStatus(StrEnum):
    """Whether every tool execution in a run actually produced evidence (ADR §5).

    `PARTIAL` means at least one `ToolExecution` did not complete (failed or
    was skipped) — treated as *absence of evidence*, not "zero findings",
    and by default failing the whole run regardless of `Verdict.passed`
    (ADR §5, "Fallo parcial").
    """

    COMPLETED = "completed"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class Verdict:
    """The single aggregated outcome of a run, computed independently of `--fail-on` (ADR §8.1).

    A `Verdict` is always computed and always travels whole in the
    structured report, regardless of `fail_on` — that flag only decides
    whether `passed = False` is translated into a blocking exit code. This
    is why a non-blocking run's console output still ends with what
    threshold would have failed it, e.g. "with --fail-on HIGH this run
    would have failed: 3 CRITICAL, 12 HIGH" (ADR §8.1).

    `fail_on` is `None` when the run used the `none` default — reporting
    only, never blocking. `counts_by_severity` reflects the run's
    deduplicated findings, one count per `Severity`.
    """

    fail_on: Severity | None
    counts_by_severity: Mapping[Severity, int]
    passed: bool


@dataclass(frozen=True, slots=True)
class RunResult:
    """The result of one run: every tool execution, aggregated findings, one verdict (ADR §1, §5).

    The gate always receives a whole `RunResult`, never a bare list of
    `Finding` — there is deliberately no gate signature that accepts loose
    findings (ADR §5). `findings` holds every one of the run's findings
    after intra-run, fingerprint-based deduplication (ADR §5,
    "Deduplicación"), suppressed ones included, for a report that never
    silently drops evidence; each tool's own unmerged report survives in
    `executions`, which is how provenance for a deduplicated finding —
    which tool(s) reported it — stays recoverable without `Finding` itself
    needing to carry more than one tool name.

    `suppressed_findings` is the subset of `findings` a `Baseline` entry
    currently covers; `expired_suppressions` names the baseline entries
    whose `expires_at` has lapsed, so a report can call those out by name
    for someone to re-triage (ADR §8.2) — a finding covered by an expired
    entry is suppressed no longer, and so appears in the gate's evidence,
    not in `suppressed_findings`.
    """

    run_id: str
    context: ExecutionContext
    executions: tuple[ToolExecution, ...]
    findings: tuple[Finding, ...]
    verdict: Verdict
    status: RunStatus
    suppressed_findings: tuple[Finding, ...] = ()
    expired_suppressions: tuple[BaselineEntry, ...] = ()
