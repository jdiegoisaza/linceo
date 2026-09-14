"""Tests for the gate: one `Verdict` from findings and a set of thresholds (ADR §8.1)."""

from __future__ import annotations

from linceo.core.findings import Category, Finding, Location
from linceo.core.gate import count_by_severity, evaluate_gate, find_breaches
from linceo.core.policy import ConfigLayer, ThresholdResolution
from linceo.core.results import ThresholdBreach
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


def test_no_thresholds_always_passes_regardless_of_findings() -> None:
    resolution = ThresholdResolution.for_fail_on(None, source=ConfigLayer.DEFAULT)

    verdict = evaluate_gate((_finding(Severity.CRITICAL),), resolution=resolution)

    assert verdict.resolution.thresholds == {}
    assert verdict.passed is True
    assert verdict.counts_by_severity[Severity.CRITICAL] == 1


def test_finding_below_threshold_passes() -> None:
    resolution = ThresholdResolution.for_fail_on(Severity.HIGH, source=ConfigLayer.CLI)

    verdict = evaluate_gate((_finding(Severity.LOW),), resolution=resolution)

    assert verdict.passed is True
    assert verdict.breaches == ()


def test_finding_at_threshold_fails() -> None:
    resolution = ThresholdResolution.for_fail_on(Severity.HIGH, source=ConfigLayer.CLI)

    verdict = evaluate_gate((_finding(Severity.HIGH),), resolution=resolution)

    assert verdict.passed is False
    assert verdict.breaches == (ThresholdBreach(severity=Severity.HIGH, count=1, maximum=0),)


def test_finding_above_threshold_fails() -> None:
    resolution = ThresholdResolution.for_fail_on(Severity.HIGH, source=ConfigLayer.CLI)

    verdict = evaluate_gate((_finding(Severity.CRITICAL),), resolution=resolution)

    assert verdict.passed is False


def test_no_findings_passes_at_any_threshold() -> None:
    for threshold in SEVERITY_ORDER:
        resolution = ThresholdResolution.for_fail_on(threshold, source=ConfigLayer.CLI)
        verdict = evaluate_gate((), resolution=resolution)
        assert verdict.passed is True


def test_a_severity_absent_from_thresholds_is_unconstrained() -> None:
    resolution = ThresholdResolution(thresholds={Severity.CRITICAL: 0}, source=ConfigLayer.FILE)

    verdict = evaluate_gate((_finding(Severity.HIGH),), resolution=resolution)

    assert verdict.passed is True


def test_a_maximum_greater_than_zero_allows_that_many_findings() -> None:
    resolution = ThresholdResolution(thresholds={Severity.MEDIUM: 2}, source=ConfigLayer.FILE)

    within_limit = evaluate_gate(
        (_finding(Severity.MEDIUM), _finding(Severity.MEDIUM)), resolution=resolution
    )
    over_limit = evaluate_gate(
        (_finding(Severity.MEDIUM), _finding(Severity.MEDIUM), _finding(Severity.MEDIUM)),
        resolution=resolution,
    )

    assert within_limit.passed is True
    assert over_limit.passed is False
    assert over_limit.breaches[0].count == 3
    assert over_limit.breaches[0].maximum == 2


def test_find_breaches_orders_most_severe_first_regardless_of_mapping_order() -> None:
    counts = {
        Severity.CRITICAL: 1,
        Severity.HIGH: 1,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }
    thresholds = {Severity.HIGH: 0, Severity.CRITICAL: 0}  # HIGH declared before CRITICAL

    breaches = find_breaches(counts, thresholds)

    assert [breach.severity for breach in breaches] == [Severity.CRITICAL, Severity.HIGH]
