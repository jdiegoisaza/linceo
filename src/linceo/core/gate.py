"""The gate: one `Verdict` from a run's active findings and a `--fail-on` threshold (ADR §8.1).

Computed unconditionally, for every run, regardless of `fail_on` — a
`none` threshold still produces a `Verdict` with `passed = True` and full
counts, so a non-blocking run's report can still say what threshold would
have failed it (ADR §8.1).
"""

from __future__ import annotations

from collections.abc import Iterable

from linceo.core.findings import Finding
from linceo.core.results import Verdict
from linceo.core.severity import SEVERITY_ORDER, Severity


def count_by_severity(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Count `findings` by normalized severity, one entry per `Severity` level, zeros included."""
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def evaluate_gate(findings: tuple[Finding, ...], *, fail_on: Severity | None) -> Verdict:
    """Compute the `Verdict` for `findings` against `fail_on` (ADR §8.1).

    `fail_on = None` is the `none` default: reporting only, `passed` is
    always `True`. Otherwise `passed` is `False` when at least one finding
    is at or above `fail_on` on the ADR §6 ordered scale.
    """
    counts = count_by_severity(findings)

    if fail_on is None:
        return Verdict(fail_on=None, counts_by_severity=counts, passed=True)

    threshold_rank = SEVERITY_ORDER.index(fail_on)
    breaching = sum(
        count
        for severity, count in counts.items()
        if SEVERITY_ORDER.index(severity) <= threshold_rank
    )
    return Verdict(fail_on=fail_on, counts_by_severity=counts, passed=breaching == 0)
