"""The gate: one `Verdict` from a run's active findings and a set of thresholds (ADR §8.1).

Computed unconditionally, for every run, regardless of whether any
threshold is configured — an empty `ThresholdResolution.thresholds` still
produces a `Verdict` with `passed = True` and full counts, so a
non-blocking run's report can still say what the recommended threshold
would have decided (ADR §8.1).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from linceo.core.findings import Finding
from linceo.core.policy import ThresholdResolution, Thresholds
from linceo.core.results import ThresholdBreach, Verdict
from linceo.core.severity import SEVERITY_ORDER, Severity


def count_by_severity(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Count `findings` by normalized severity, one entry per `Severity` level, zeros included."""
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def find_breaches(
    counts: Mapping[Severity, int], thresholds: Thresholds
) -> tuple[ThresholdBreach, ...]:
    """List every severity whose `counts` entry exceeds its `thresholds` maximum (ADR §8.1).

    Ordered most severe first, regardless of the iteration order
    `thresholds` happens to have (ADR R3: the order a mapping was built in
    must never leak into the report). A severity absent from `thresholds`
    is unconstrained and can never breach.
    """
    return tuple(
        ThresholdBreach(severity=severity, count=counts[severity], maximum=maximum)
        for severity in SEVERITY_ORDER
        if (maximum := thresholds.get(severity)) is not None and counts[severity] > maximum
    )


def evaluate_gate(findings: Iterable[Finding], *, resolution: ThresholdResolution) -> Verdict:
    """Compute the `Verdict` for `findings` against `resolution.thresholds` (ADR §8.1).

    `resolution.thresholds` empty means no gate is configured: reporting
    only, `passed` is always `True`.
    """
    counts = count_by_severity(findings)
    breaches = find_breaches(counts, resolution.thresholds)
    return Verdict(
        resolution=resolution,
        counts_by_severity=counts,
        breaches=breaches,
        passed=not breaches,
    )
