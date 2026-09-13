"""Tests for the gate: one `Verdict` from findings and a `--fail-on` threshold (ADR §8.1)."""

from __future__ import annotations

from linceo.core.findings import Category, Finding, Location
from linceo.core.gate import count_by_severity, evaluate_gate
from linceo.core.severity import SEVERITY_ORDER, Severity, SeveritySource

_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _finding(severity: Severity) -> Finding:
    return Finding(
        fingerprint=f"v1:{severity.value}",
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        severity=severity,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )


def test_count_by_severity_includes_zero_counts_for_every_level() -> None:
    counts = count_by_severity([_finding(Severity.HIGH), _finding(Severity.HIGH)])

    assert counts == {
        Severity.CRITICAL: 0,
        Severity.HIGH: 2,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }


def test_fail_on_none_always_passes_regardless_of_findings() -> None:
    verdict = evaluate_gate((_finding(Severity.CRITICAL),), fail_on=None)

    assert verdict.fail_on is None
    assert verdict.passed is True
    assert verdict.counts_by_severity[Severity.CRITICAL] == 1


def test_finding_below_threshold_passes() -> None:
    verdict = evaluate_gate((_finding(Severity.LOW),), fail_on=Severity.HIGH)

    assert verdict.passed is True


def test_finding_at_threshold_fails() -> None:
    verdict = evaluate_gate((_finding(Severity.HIGH),), fail_on=Severity.HIGH)

    assert verdict.passed is False


def test_finding_above_threshold_fails() -> None:
    verdict = evaluate_gate((_finding(Severity.CRITICAL),), fail_on=Severity.HIGH)

    assert verdict.passed is False


def test_no_findings_passes_at_any_threshold() -> None:
    for threshold in SEVERITY_ORDER:
        verdict = evaluate_gate((), fail_on=threshold)
        assert verdict.passed is True
