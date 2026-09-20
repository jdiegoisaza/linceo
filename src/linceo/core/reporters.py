"""Console and JSON reporters (ADR §7).

Both render the same `RunResult`. `render_json` is the project's canonical,
lossless format: it always serializes every finding, suppressed ones
included, with no row limit of any kind — `max_rows` is a console-only
presentation setting, and applying it to JSON (or, later, SARIF) would
turn a legibility option into a silent evidence loss, exactly what a
pipeline consuming that format must never be handed (ADR §7).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import date, datetime
from enum import Enum

from linceo.core.execution import ExecutionStatus
from linceo.core.findings import Category, Finding
from linceo.core.fingerprint import short_fingerprints
from linceo.core.gate import find_breaches
from linceo.core.policy import DEFAULT_REPORT_MAX_ROWS, ConfigLayer, ThresholdResolution
from linceo.core.remote_policy import PolicySourceState, PolicySourceStatus
from linceo.core.report_schema import ReportSchema
from linceo.core.results import RunResult, RunStatus, ThresholdBreach
from linceo.core.severity import SEVERITY_ORDER, Severity
from linceo.core.table import render_category_table, sort_key

#: The threshold the project's own quickstart recommends (ADR §8.1) — used
#: only to give a non-blocking run's console output a concrete "this is
#: what would have happened" hint, never to change `Verdict` itself.
_RECOMMENDED_FAIL_ON = Severity.HIGH

#: A `ToolExecution` in one of these states produced usable evidence; any
#: other status means the run's evidence is incomplete (ADR §5). Kept in
#: sync with `linceo.core.engine._incomplete`'s notion of "incomplete".
_EVIDENCE_STATUSES = (ExecutionStatus.COMPLETED, ExecutionStatus.SKIPPED_BY_POLICY)


def _format_thresholds(thresholds: Mapping[Severity, int]) -> str:
    """Render `{HIGH: 0, MEDIUM: 25}` as `"high=0, medium=25"`, most severe first."""
    return ", ".join(
        f"{severity.value.lower()}={thresholds[severity]}"
        for severity in SEVERITY_ORDER
        if severity in thresholds
    )


def _format_breach(breach: ThresholdBreach) -> str:
    return (
        f"{breach.category.value}: {breach.count} {breach.severity.value} exceeds "
        f"the maximum allowed of {breach.maximum}"
    )


def _describe_thresholds_table(label: str, thresholds: Mapping[Severity, int]) -> str:
    """Render one named table for the policy-override announcement: `"[thresholds] (high=5)"`."""
    return f"{label} ({_format_thresholds(thresholds) or 'no maximums'})"


def _superseded_tables_text(resolution: ThresholdResolution) -> str:
    """List every table a higher layer replaced — the default one and any per-category ones.

    Ordered `Category`'s own declaration order after the default table, so
    the listing is deterministic regardless of `dict` iteration order
    (ADR R3) — this is the only place in the reporter that iterates
    `Category`, and it does so generically, the same as `core.gate`.
    """
    parts = []
    if resolution.superseded is not None:
        parts.append(_describe_thresholds_table("[thresholds]", resolution.superseded))
    for category in Category:
        table = resolution.superseded_category_thresholds.get(category)
        if table is not None:
            parts.append(_describe_thresholds_table(f"[thresholds.{category.value}]", table))
    return "; ".join(parts) if parts else "no maximums"


def _policy_override_lines(resolution: ThresholdResolution) -> list[str]:
    """Announce when a higher layer replaced the policy file's threshold table(s) (ADR §8.1).

    A gate that silently diverges from the policy a repository declared
    would lose the trust of whoever wrote it — this is printed
    unconditionally whenever `resolution.superseded` or
    `resolution.superseded_category_thresholds` is set, never folded into
    a debug-only or `--verbose` path.
    """
    if resolution.superseded is None and not resolution.superseded_category_thresholds:
        return []

    if resolution.source is ConfigLayer.CLI and resolution.fail_on is not None:
        trigger = f"--fail-on {resolution.fail_on.value.lower()}"
    elif resolution.source is ConfigLayer.ENV and resolution.fail_on is not None:
        trigger = "the LINCEO_FAIL_ON environment variable"
    else:
        trigger = "the resolved configuration"

    source_name = resolution.superseded_from or "the policy file"
    return [
        f"Policy override: {trigger} replaced the thresholds declared in",
        f"  {source_name}: {_superseded_tables_text(resolution)}.",
        "",
    ]


def _threshold_source_lines(result: RunResult) -> list[str]:
    """Name, for each category that ran, which table its applied thresholds came from (ADR §8.1).

    Printed only when some gate is actually configured
    (`resolution.is_configured`) — an unconfigured gate already says so in
    `_gate_lines`' own "not enforced" line, and repeating that per category
    here would be noise. Uses `resolution.thresholds_for` — the same
    single lookup `core.gate` uses to evaluate breaches — so the label
    shown here can never disagree with what was actually enforced.
    """
    resolution = result.verdict.resolution
    if not resolution.is_configured:
        return []

    categories: list[Category] = []
    for execution in result.executions:
        if execution.category not in categories:
            categories.append(execution.category)
    if not categories:
        return []

    if resolution.source in (ConfigLayer.CLI, ConfigLayer.ENV) and resolution.fail_on is not None:
        trigger = f"--fail-on {resolution.fail_on.value.lower()}"
        rendered = _format_thresholds(resolution.thresholds) or "unconstrained"
        return [f"Thresholds: {trigger} ({rendered}), applies to every category.", ""]

    lines = ["Thresholds:"]
    for category in categories:
        table = resolution.thresholds_for(category)
        rendered = _format_thresholds(table) or "unconstrained"
        has_own_table = category in resolution.category_thresholds
        origin = f"[thresholds.{category.value}]" if has_own_table else "[thresholds]"
        lines.append(f"  - {category.value}: {origin} ({rendered})")
    lines.append("")
    return lines


def _active_findings(result: RunResult) -> tuple[Finding, ...]:
    """`result.findings` minus whatever `result.suppressed_findings` currently covers."""
    suppressed = {finding.fingerprint for finding in result.suppressed_findings}
    return tuple(finding for finding in result.findings if finding.fingerprint not in suppressed)


def _findings_by_category(findings: Sequence[Finding]) -> dict[Category, list[Finding]]:
    grouped: dict[Category, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)
    return grouped


def _findings_section(
    result: RunResult, *, schemas: Mapping[Category, ReportSchema], max_rows: int
) -> list[str]:
    """One table (or one "no findings" line) per category that ran, in execution order.

    ADR §7: a category with zero active findings collapses to a single
    line; one with more than `max_rows` shows the first `max_rows`, most
    severe first, and says how many more there are. This never touches
    `render_json`, which always carries every finding.
    """
    grouped = _findings_by_category(_active_findings(result))
    short_fps = short_fingerprints(finding.fingerprint for finding in result.findings)

    seen_categories: list[Category] = []
    for execution in result.executions:
        if execution.category not in seen_categories:
            seen_categories.append(execution.category)

    lines: list[str] = []
    for category in seen_categories:
        schema = schemas[category]
        findings = grouped.get(category, [])
        if not findings:
            lines.append(f"{category.value}: No findings.")
            lines.append("")
            continue

        ordered = sorted(findings, key=lambda finding: sort_key(finding, location=schema.location))
        shown = ordered[:max_rows]
        lines.append(f"{category.value}:")
        table_text = render_category_table(shown, schema=schema, short_fingerprints=short_fps)
        lines.extend(f"  {line}" for line in table_text.splitlines())
        remaining = len(ordered) - len(shown)
        if remaining:
            lines.append(
                f"  ... {remaining} more {category.value} findings "
                f"(showing {len(shown)} of {len(ordered)})"
            )
        lines.append("")
    return lines


def _policy_skip_lines(result: RunResult) -> list[str]:
    """Highlight every tool this run skipped by policy, and every skip that lapsed (ADR §8)."""
    lines: list[str] = []
    if result.applied_tool_skips:
        lines.append("Skipped by policy:")
        lines.extend(
            f"  - {skip.tool} owner={skip.owner} until={skip.expires_at} reason={skip.reason!r}"
            for skip in result.applied_tool_skips
        )
        lines.append("")
    if result.expired_tool_skips:
        lines.append(f"Expired tool skips, now running again ({len(result.expired_tool_skips)}):")
        lines.extend(
            f"  - {skip.tool} owner={skip.owner} was_until={skip.expires_at} reason={skip.reason!r}"
            for skip in result.expired_tool_skips
        )
        lines.append("")
    return lines


def _render_policy_source(status: PolicySourceStatus) -> str:
    """Render one `PolicySourceStatus` as its own console line (ADR R2, §8.4).

    Mirrors `linceo.cli.doctor._render_data_source`'s "declare the age,
    never just a flag" shape — ADR §5's `stale_data` principle applied to a
    remote policy document instead of a tool's vulnerability database.
    """
    origin = f"{status.repository}/{status.path}"
    if status.state is PolicySourceState.FRESH:
        return f"Remote policy: {origin} — fetched fresh this run"
    if status.state is PolicySourceState.CACHED:
        flag = "STALE" if status.stale else "OK"
        return (
            f"Remote policy: {origin} — WARN: fetch failed ({status.detail}), using a cached "
            f"copy from {status.fetched_at.isoformat() if status.fetched_at else '?'} "
            f"({status.age_days} days old) [{flag}]"
        )
    return (
        f"Remote policy: {origin} — WARN: unreachable and no cached copy ({status.detail}); "
        "this run's thresholds and tool configuration are the local document alone"
    )


def _policy_source_lines(result: RunResult) -> list[str]:
    """Declare this run's remote policy provenance, if `[remote_policy]` was configured at all."""
    if result.policy_source is None:
        return []
    return [_render_policy_source(result.policy_source), ""]


def _exclusion_summary_lines(result: RunResult) -> list[str]:
    """Suppressed and expired-exclusion counts — printed unconditionally, even when both are zero.

    A run this clean is exactly the case where an operator most needs to
    trust that nothing was silently swept aside (ADR §8.2).
    """
    lines = [
        f"Suppressed by policy: {len(result.suppressed_findings)}",
        f"Expired exclusions: {len(result.expired_exclusions)}",
    ]
    if result.expired_exclusions:
        lines.extend(
            f"  - {entry.fingerprint} owner={entry.owner} expired_at={entry.expires_at} "
            f"reason={entry.reason!r}"
            for entry in result.expired_exclusions
        )
    return lines


def _gate_lines(result: RunResult) -> list[str]:
    """The gate verdict, never rendered as `PASSED` when `result.status` is `PARTIAL` (ADR §5)."""
    verdict = result.verdict
    lines = _policy_override_lines(verdict.resolution)
    lines.extend(_threshold_source_lines(result))

    if result.status is RunStatus.PARTIAL:
        incomplete = sum(
            1 for execution in result.executions if execution.status not in _EVIDENCE_STATUSES
        )
        total = len(result.executions)
        lines.append(
            "Gate: NOT EVALUATED — evidence is incomplete "
            f"({incomplete} of {total} executions did not complete)."
        )
        if verdict.breaches:
            lines.append("  Evaluated anyway over the available evidence, it would also fail:")
            lines.extend(f"  - {_format_breach(breach)}" for breach in verdict.breaches)
        return lines

    if not verdict.resolution.is_configured:
        hint_resolution = ThresholdResolution.for_fail_on(
            _RECOMMENDED_FAIL_ON, source=ConfigLayer.DEFAULT
        )
        recommended_breaches = find_breaches(verdict.counts_by_category, hint_resolution)
        if recommended_breaches:
            summary = ", ".join(
                f"{breach.category.value}: {breach.count} {breach.severity.value}"
                for breach in recommended_breaches
            )
            lines.append(
                f"Gate: not enforced (no thresholds configured). With --fail-on "
                f"{_RECOMMENDED_FAIL_ON.value.lower()} this run would have failed: {summary}"
            )
        else:
            lines.append(
                f"Gate: not enforced (no thresholds configured). With --fail-on "
                f"{_RECOMMENDED_FAIL_ON.value.lower()} this run would have passed."
            )
        return lines

    if verdict.passed:
        lines.append("Gate: PASSED")
    else:
        lines.append("Gate: FAILED")
        lines.extend(f"  - {_format_breach(breach)}" for breach in verdict.breaches)
    return lines


def render_console(
    result: RunResult,
    *,
    schemas: Mapping[Category, ReportSchema],
    max_rows: int = DEFAULT_REPORT_MAX_ROWS,
) -> str:
    """Render `result` as a human-readable console report (ADR §7, §8.1).

    `schemas` must have an entry for every category `result.executions`
    ran — the CLI builds it from the same `ToolIntegration`s it constructed
    for the run (`ToolIntegration.report_schema`). `max_rows` bounds only
    the console tables (ADR §7); it never affects `render_json`.
    """
    lines = [
        f"Run {result.run_id} — platform={result.context.platform.value} "
        f"repository={result.context.repository} commit={result.context.commit}",
        f"Status: {result.status.value}",
        f"Severity map: {result.severity_map_version}",
        "",
        "Executions:",
    ]
    for execution in result.executions:
        lines.append(
            f"  - {execution.tool} {execution.tool_version} [{execution.category.value}]: "
            f"{execution.status.value} ({len(execution.findings)} findings)"
        )
    lines.append("")

    lines.extend(_policy_source_lines(result))
    lines.extend(_policy_skip_lines(result))
    lines.extend(_findings_section(result, schemas=schemas, max_rows=max_rows))
    lines.extend(_exclusion_summary_lines(result))
    lines.append("")
    lines.extend(_gate_lines(result))

    return "\n".join(lines)


def _to_jsonable(value: object) -> object:
    """Recursively convert dataclasses, enums, and dates into `json`-serializable values."""
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, date | datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {_jsonable_key(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_to_jsonable(item) for item in value]
    return value


def _jsonable_key(key: object) -> str:
    """Render a mapping key (possibly a `Severity`) as the string a JSON object key must be."""
    return key.value if isinstance(key, Enum) else str(key)


def render_json(result: RunResult) -> str:
    """Render `result` as canonical JSON: the project's lossless format (ADR §7).

    Always the full `RunResult` — every finding, suppressed ones included,
    with no row limit. `max_rows` (ADR §7) is a console-only concept and
    has no equivalent parameter here.
    """
    return json.dumps(_to_jsonable(result), indent=2)
