"""The gate: one `Verdict` from a run's active findings and a set of thresholds (ADR §8.1).

Computed unconditionally, for every run, regardless of whether any
threshold is configured — an empty `ThresholdResolution.thresholds` still
produces a `Verdict` with `passed = True` and full counts, so a
non-blocking run's report can still say what the recommended threshold
would have decided (ADR §8.1).

Findings are counted, and breaches found, **per category** — each
category's own active findings against whatever table
`ThresholdResolution.thresholds_for` resolves for it (its own
`[thresholds.<name>]`, or the default `[thresholds]`) — never pooled
across categories into one severity count. This module never branches on
which category it is looking at: `Category` is only ever a dictionary key
here, exactly as it already is in `linceo.core.reporters`'s per-category
tables (ADR §7) — a category the engine has never heard of by name still
gets a correct, independent gate the moment its findings and its
threshold table (if any) exist.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from linceo.core.findings import Category, Finding
from linceo.core.policy import ThresholdResolution
from linceo.core.results import ThresholdBreach, Verdict
from linceo.core.severity import SEVERITY_ORDER, Severity


def count_by_severity(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Count `findings` by normalized severity, one entry per `Severity` level, zeros included.

    Pooled across every category — used for the run-wide summary
    (`Verdict.counts_by_severity`), never for gate evaluation itself, which
    is per category (`count_by_category_and_severity`, `find_breaches`).
    """
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def count_by_category_and_severity(
    findings: Iterable[Finding],
) -> dict[Category, dict[Severity, int]]:
    """Count `findings` by category, then by normalized severity within each (ADR §8.1).

    Only categories with at least one finding appear; each one's inner
    mapping still has one entry per `Severity` level, zeros included
    (mirroring `count_by_severity`), so `find_breaches` never has to
    special-case a severity absent from a category's counts.
    """
    counts_by_category: dict[Category, dict[Severity, int]] = {}
    for finding in findings:
        counts = counts_by_category.setdefault(finding.category, dict.fromkeys(SEVERITY_ORDER, 0))
        counts[finding.severity] += 1
    return counts_by_category


def find_breaches(
    counts_by_category: Mapping[Category, Mapping[Severity, int]],
    resolution: ThresholdResolution,
) -> tuple[ThresholdBreach, ...]:
    """List every (category, severity) whose count exceeds its resolved maximum (ADR §8.1).

    For each category present in `counts_by_category`, the maximum comes
    from `resolution.thresholds_for(category)` — that one method is the
    only place that decides whether a category uses its own
    `[thresholds.<name>]` table or falls back to the default `[thresholds]`
    one; this function never inspects a category's name itself. Ordered by
    `Category`'s own declaration order, then most severe first within each
    category, regardless of the iteration order `counts_by_category` or a
    threshold table happens to have (ADR R3: mapping iteration order must
    never leak into the report). A severity absent from the resolved table
    is unconstrained and can never breach.
    """
    breaches: list[ThresholdBreach] = []
    for category in Category:
        counts = counts_by_category.get(category)
        if counts is None:
            continue
        thresholds = resolution.thresholds_for(category)
        breaches.extend(
            ThresholdBreach(
                category=category, severity=severity, count=counts[severity], maximum=maximum
            )
            for severity in SEVERITY_ORDER
            if (maximum := thresholds.get(severity)) is not None and counts[severity] > maximum
        )
    return tuple(breaches)


def evaluate_gate(findings: Iterable[Finding], *, resolution: ThresholdResolution) -> Verdict:
    """Compute the `Verdict` for `findings` against `resolution` (ADR §8.1).

    Each category present in `findings` is gated independently, against
    whichever table `resolution.thresholds_for` resolves for it — a
    category with no findings, and `resolution.is_configured` being
    `False` for every category present, both mean `passed` is `True`.
    """
    findings = tuple(findings)
    counts_by_category = count_by_category_and_severity(findings)
    breaches = find_breaches(counts_by_category, resolution)
    return Verdict(
        resolution=resolution,
        counts_by_severity=count_by_severity(findings),
        counts_by_category=counts_by_category,
        breaches=breaches,
        passed=not breaches,
    )
