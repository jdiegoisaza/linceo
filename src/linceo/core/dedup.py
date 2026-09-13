"""Intra-run deduplication by fingerprint (ADR §5, "Deduplicación").

Two tools reporting the same fact must collapse into one entry so the
run's counts are not inflated by finding it twice — but never by silently
discarding one report: a deduplicated finding's provenance stays
recoverable through each tool's own unmerged report in `RunResult.executions`
(ADR §5).
"""

from __future__ import annotations

from collections.abc import Iterable

from linceo.core.findings import Finding


def deduplicate(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Collapse `findings` to one entry per fingerprint, keeping the first occurrence.

    Order is preserved and, given the same input order, always produces
    the same output (ADR R3) — callers that combine findings from several
    `ToolExecution`s should do so in a fixed order (e.g. execution order)
    for that guarantee to hold end to end.
    """
    deduplicated: dict[str, Finding] = {}
    for finding in findings:
        deduplicated.setdefault(finding.fingerprint, finding)
    return tuple(deduplicated.values())
