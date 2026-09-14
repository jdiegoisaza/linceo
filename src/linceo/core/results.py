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

from linceo.core.context import ExecutionContext
from linceo.core.execution import ToolExecution
from linceo.core.findings import Finding
from linceo.core.policy import Exclusion, ThresholdResolution, ToolSkip
from linceo.core.severity import Severity


class RunStatus(StrEnum):
    """Whether every tool execution in a run actually produced evidence (ADR §5).

    `PARTIAL` means at least one `ToolExecution` failed or was skipped
    outright (its binary missing) — treated as *absence of evidence*, not
    "zero findings", and by default failing the whole run regardless of
    `Verdict.passed` (ADR §5, "Fallo parcial"). A `ToolExecution` skipped by
    an active policy (`SKIPPED_BY_POLICY`, ADR §8) is a declared, caducable
    absence, not an accidental one, and does **not** make a run `PARTIAL` on
    its own.
    """

    COMPLETED = "completed"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class ThresholdBreach:
    """One severity whose active finding count exceeds its configured maximum (ADR §8.1)."""

    severity: Severity
    count: int
    maximum: int


@dataclass(frozen=True, slots=True)
class Verdict:
    """The single aggregated outcome of a run, computed independently of `RunStatus` (ADR §8.1).

    A `Verdict` is always computed and always travels whole in the
    structured report, regardless of whether any threshold is even
    configured — `resolution.thresholds` empty means "no gate", and
    `passed` is then always `True`. This is why a non-blocking run's
    console output still ends with what the recommended threshold would
    have decided (ADR §8.1). `counts_by_severity` reflects the run's active
    (non-suppressed) findings, one count per `Severity`. `breaches` lists,
    for each severity whose count exceeds its configured maximum, that
    count and that maximum — empty when `passed` is `True`.

    A `RunStatus.PARTIAL` run still gets a `Verdict` computed over whatever
    evidence exists, but a report must never render it as `PASSED`: the
    gate was not evaluated over complete evidence, only over what was
    available (ADR §5).
    """

    resolution: ThresholdResolution
    counts_by_severity: Mapping[Severity, int]
    breaches: tuple[ThresholdBreach, ...]
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

    `suppressed_findings` is the subset of `findings` an `Exclusion`
    currently covers; `expired_exclusions` names the exclusions whose
    `expires_at` has lapsed, so a report can call those out by name for
    someone to re-triage (ADR §8.2) — a finding covered by an expired entry
    is suppressed no longer, and so appears in the gate's evidence, not in
    `suppressed_findings`. `applied_tool_skips` names the `ToolSkip`
    entries that were active for this run (each corresponding to a
    `ToolExecution` with `status = SKIPPED_BY_POLICY`); `expired_tool_skips`
    names ones that had lapsed, whose tool ran normally instead.
    """

    run_id: str
    context: ExecutionContext
    executions: tuple[ToolExecution, ...]
    findings: tuple[Finding, ...]
    verdict: Verdict
    status: RunStatus
    suppressed_findings: tuple[Finding, ...] = ()
    expired_exclusions: tuple[Exclusion, ...] = ()
    applied_tool_skips: tuple[ToolSkip, ...] = ()
    expired_tool_skips: tuple[ToolSkip, ...] = ()
