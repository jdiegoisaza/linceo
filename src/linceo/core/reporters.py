"""Console and JSON reporters (ADR §7).

Both render the same `RunResult` with no information loss — the JSON
reporter is the project's canonical, lossless format; SARIF (ADR §7),
an intentionally lossy interchange format for `sca` findings, is not
built here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import date, datetime
from enum import Enum

from linceo.core.results import RunResult
from linceo.core.severity import SEVERITY_ORDER, Severity

#: The threshold the project's own quickstart recommends (ADR §8.1) — used
#: only to give a non-blocking run's console output a concrete "this is
#: what would have happened" hint, never to change `Verdict` itself.
_RECOMMENDED_FAIL_ON = Severity.HIGH


def _at_or_above(counts: Mapping[Severity, int], threshold: Severity) -> dict[Severity, int]:
    """Return the subset of `counts` at or above `threshold` on the ADR §6 scale."""
    threshold_rank = SEVERITY_ORDER.index(threshold)
    return {
        severity: count
        for severity, count in counts.items()
        if count and SEVERITY_ORDER.index(severity) <= threshold_rank
    }


def _format_counts(counts: Mapping[Severity, int]) -> str:
    """Render `{HIGH: 12, CRITICAL: 3}` as `"3 CRITICAL, 12 HIGH"`, most severe first."""
    ordered = [(severity, counts[severity]) for severity in SEVERITY_ORDER if counts.get(severity)]
    return ", ".join(f"{count} {severity.value}" for severity, count in ordered)


def render_console(result: RunResult) -> str:
    """Render `result` as a human-readable console report (ADR §7, §8.1).

    Always ends with an explicit call to action, even for a non-blocking
    (`fail_on = None`) run: what `--fail-on HIGH` would have decided,
    exactly as ADR §8.1 requires so a permissive default is never silent
    about what it is permitting.
    """
    counts = result.verdict.counts_by_severity
    lines = [
        f"Run {result.run_id} — platform={result.context.platform.value} "
        f"repository={result.context.repository} commit={result.context.commit}",
        f"Status: {result.status.value}",
        "",
        "Executions:",
    ]
    for execution in result.executions:
        lines.append(
            f"  - {execution.tool} {execution.tool_version} [{execution.category.value}]: "
            f"{execution.status.value} ({len(execution.findings)} findings)"
        )

    lines.extend(["", "Findings by severity:"])
    lines.extend(f"  {severity.value:<8} {counts.get(severity, 0)}" for severity in SEVERITY_ORDER)

    if result.suppressed_findings:
        lines.append(f"\nSuppressed by baseline: {len(result.suppressed_findings)}")

    if result.expired_suppressions:
        lines.append(f"\nExpired baseline suppressions ({len(result.expired_suppressions)}):")
        lines.extend(
            f"  - {entry.fingerprint} owner={entry.owner} expired_at={entry.expires_at} "
            f"reason={entry.reason!r}"
            for entry in result.expired_suppressions
        )

    lines.append("")
    if result.verdict.fail_on is not None:
        outcome = "PASSED" if result.verdict.passed else "FAILED"
        lines.append(f"Gate (--fail-on {result.verdict.fail_on.value}): {outcome}")
    else:
        breaching = _at_or_above(counts, _RECOMMENDED_FAIL_ON)
        if breaching:
            summary = _format_counts(breaching)
            lines.append(
                f"Gate: not enforced (--fail-on none). With --fail-on "
                f"{_RECOMMENDED_FAIL_ON.value} this run would have failed: {summary}"
            )
        else:
            lines.append(
                f"Gate: not enforced (--fail-on none). With --fail-on "
                f"{_RECOMMENDED_FAIL_ON.value} this run would have passed."
            )

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
    """Render `result` as canonical JSON: the project's lossless format (ADR §7)."""
    return json.dumps(_to_jsonable(result), indent=2)
