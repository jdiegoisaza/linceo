"""Tests for intra-run deduplication by fingerprint (ADR §5, "Deduplicación")."""

from __future__ import annotations

from linceo.core.dedup import deduplicate
from linceo.core.findings import Category, Finding, Location
from linceo.core.severity import Severity, SeveritySource

_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _finding(*, fingerprint: str, tool: str) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool=tool,
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        severity=Severity.HIGH,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )


def test_deduplicate_collapses_two_tools_reporting_the_same_fingerprint() -> None:
    gitleaks_report = _finding(fingerprint="v1:abc", tool="gitleaks")
    other_scanner_report = _finding(fingerprint="v1:abc", tool="other-scanner")

    result = deduplicate([gitleaks_report, other_scanner_report])

    assert result == (gitleaks_report,)


def test_deduplicate_keeps_findings_with_distinct_fingerprints() -> None:
    first = _finding(fingerprint="v1:abc", tool="gitleaks")
    second = _finding(fingerprint="v1:def", tool="gitleaks")

    result = deduplicate([first, second])

    assert result == (first, second)


def test_deduplicate_preserves_input_order() -> None:
    findings = [_finding(fingerprint=f"v1:{i}", tool="gitleaks") for i in range(5)]

    assert deduplicate(findings) == tuple(findings)


def test_deduplicate_of_empty_input_is_empty() -> None:
    assert deduplicate([]) == ()
