"""`RunResult` and `Verdict`: N tool executions, one verdict (ADR §1, §5).

The invariant this module exists to satisfy: the model of a run's result
and the gate are built from day one to support N tool executions producing
a single aggregated verdict and a single exit code — never a report file
and an exit code per tool (ADR §1, "Invariante de aceptación").
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from linceo.core.context import ExecutionContext
from linceo.core.execution import ToolExecution
from linceo.core.findings import Category, Finding
from linceo.core.policy import Exclusion, SeverityOverride, ThresholdResolution, ToolSkip
from linceo.core.remote_policy import PolicySourceStatus
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
    """One category/severity pair whose active finding count exceeds its configured maximum.

    `category` is always the specific category this breach's counts and
    maximum came from — never a run-wide aggregate — since ADR §8.1's
    per-category thresholds mean two categories can breach independently,
    with different maximums, over the same run.
    """

    category: Category
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

    `counts_by_category` is what the gate actually evaluates against
    (ADR §8.1): each category's active findings, counted by severity,
    independently of every other category. `counts_by_severity` is the
    same findings pooled across categories into one flat summary — never
    used for gate evaluation itself, only for the run-wide count a report
    or a consumer that does not care about per-category thresholds wants.
    """

    resolution: ThresholdResolution
    counts_by_severity: Mapping[Severity, int]
    counts_by_category: Mapping[Category, Mapping[Severity, int]]
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
    `suppressed_findings`. `suppressed_by` maps each suppressed finding's
    own fingerprint to the exact `Exclusion` that suppressed it — the
    piece `suppressed_findings` alone never carried (*that* a finding is
    suppressed, but not *why*, by whom, or until when) and what
    `linceo.core.sarif` reads to fill a suppressed SARIF result's own
    `justification` field, instead of leaving it absent. `applied_tool_skips`
    names the `ToolSkip` entries that were active for this run (each
    corresponding to a `ToolExecution` with `status = SKIPPED_BY_POLICY`);
    `expired_tool_skips` names ones that had lapsed, whose tool ran
    normally instead.

    `applied_severity_overrides` names the `SeverityOverride` entries that
    were in scope and unexpired for this run's repository — each already
    folded into the `SeverityNormalizer` that produced `findings`, so this
    is a *declaration* of which reclassifications shaped the evidence
    above, not a second application of them; `expired_severity_overrides`
    names ones that had lapsed, whose findings resolved through the
    ordinary precedence chain instead (ADR §6, §8.4) — the same
    "never silent" transparency `expired_exclusions` already gives a
    lapsed suppression, extended to a lapsed severity reclassification.

    `policy_source` is `None` unless this run declared `[remote_policy]`
    (ADR R2, §8.4) — copied straight from
    `linceo.core.config.Config.policy_source` by `linceo.core.engine.run`,
    so a report can declare exactly where the thresholds and tool
    configuration that governed this run's gate actually came from:
    fetched fresh this run, a cached fallback (with its own age), or
    unavailable (local-only) — the same "no report is clean without
    declaring the age of its evidence" principle ADR §5 already applies to
    a tool's own data sources.

    `severity_map_version` is `severity_map.toml`'s own `map_version` at
    the time this run's `SeverityNormalizer` was built
    (`linceo.core.normalization.SeverityNormalizer.map_version`) — ADR §6:
    "un reporte declara con qué versión del mapa se produjeron sus
    severidades", so two runs of the same finding under different map
    versions are never mistaken for directly comparable.
    """

    run_id: str
    context: ExecutionContext
    executions: tuple[ToolExecution, ...]
    findings: tuple[Finding, ...]
    verdict: Verdict
    status: RunStatus
    severity_map_version: str
    suppressed_findings: tuple[Finding, ...] = ()
    suppressed_by: Mapping[str, Exclusion] = field(default_factory=dict)
    expired_exclusions: tuple[Exclusion, ...] = ()
    applied_tool_skips: tuple[ToolSkip, ...] = ()
    expired_tool_skips: tuple[ToolSkip, ...] = ()
    applied_severity_overrides: tuple[SeverityOverride, ...] = ()
    expired_severity_overrides: tuple[SeverityOverride, ...] = ()
    policy_source: PolicySourceStatus | None = None
