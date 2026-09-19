"""Tests for the gate: one `Verdict` from findings and a set of thresholds (ADR §8.1)."""

from __future__ import annotations

from linceo.core.findings import Category, Finding, Location, Package
from linceo.core.gate import (
    count_by_category_and_severity,
    count_by_severity,
    evaluate_gate,
    find_breaches,
)
from linceo.core.policy import ConfigLayer, ThresholdResolution
from linceo.core.results import ThresholdBreach
from linceo.core.severity import SEVERITY_ORDER, Severity, SeveritySource

_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _finding(severity: Severity, *, category: Category = Category.SECRETS) -> Finding:
    if category is Category.SCA:
        return Finding(
            fingerprint=f"v1:{category.value}-{severity.value}",
            tool="trivy",
            category=Category.SCA,
            rule_id="CVE-2026-0001",
            message="Vulnerable dependency detected",
            location=Location(path="requirements.txt"),
            severity=severity,
            raw_severity=None,
            severity_source=SeveritySource.CATEGORY_DEFAULT,
            package=Package(name="acme-lib", version="1.0.0"),
        )
    return Finding(
        fingerprint=f"v1:{category.value}-{severity.value}",
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


def test_count_by_category_and_severity_keeps_categories_independent() -> None:
    counts = count_by_category_and_severity(
        [
            _finding(Severity.HIGH, category=Category.SECRETS),
            _finding(Severity.HIGH, category=Category.SCA),
            _finding(Severity.HIGH, category=Category.SCA),
        ]
    )

    assert counts[Category.SECRETS][Severity.HIGH] == 1
    assert counts[Category.SCA][Severity.HIGH] == 2
    assert counts[Category.SECRETS][Severity.CRITICAL] == 0


def test_no_thresholds_always_passes_regardless_of_findings() -> None:
    resolution = ThresholdResolution.for_fail_on(None, source=ConfigLayer.DEFAULT)

    verdict = evaluate_gate((_finding(Severity.CRITICAL),), resolution=resolution)

    assert verdict.resolution.thresholds == {}
    assert verdict.passed is True
    assert verdict.counts_by_severity[Severity.CRITICAL] == 1
    assert verdict.counts_by_category[Category.SECRETS][Severity.CRITICAL] == 1


def test_finding_below_threshold_passes() -> None:
    resolution = ThresholdResolution.for_fail_on(Severity.HIGH, source=ConfigLayer.CLI)

    verdict = evaluate_gate((_finding(Severity.LOW),), resolution=resolution)

    assert verdict.passed is True
    assert verdict.breaches == ()


def test_finding_at_threshold_fails() -> None:
    resolution = ThresholdResolution.for_fail_on(Severity.HIGH, source=ConfigLayer.CLI)

    verdict = evaluate_gate((_finding(Severity.HIGH),), resolution=resolution)

    assert verdict.passed is False
    assert verdict.breaches == (
        ThresholdBreach(category=Category.SECRETS, severity=Severity.HIGH, count=1, maximum=0),
    )


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
    counts_by_category = {
        Category.SECRETS: {
            Severity.CRITICAL: 1,
            Severity.HIGH: 1,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
    }
    # HIGH declared before CRITICAL in the table — order must not leak into the result.
    resolution = ThresholdResolution(
        thresholds={Severity.HIGH: 0, Severity.CRITICAL: 0}, source=ConfigLayer.FILE
    )

    breaches = find_breaches(counts_by_category, resolution)

    assert [breach.severity for breach in breaches] == [Severity.CRITICAL, Severity.HIGH]


# --- per-category thresholds (ADR §8.1) -----------------------------------------


def test_a_category_with_its_own_table_is_evaluated_against_it_alone() -> None:
    resolution = ThresholdResolution(
        thresholds={Severity.HIGH: 5},
        category_thresholds={Category.SECRETS: {Severity.HIGH: 0}},
        source=ConfigLayer.FILE,
    )

    finding = _finding(Severity.HIGH, category=Category.SECRETS)
    verdict = evaluate_gate((finding,), resolution=resolution)

    assert verdict.passed is False
    assert verdict.breaches == (
        ThresholdBreach(category=Category.SECRETS, severity=Severity.HIGH, count=1, maximum=0),
    )


def test_a_categorys_own_table_never_merges_with_the_default() -> None:
    """A category's own table replaces the default entirely — it never merges field by field."""
    resolution = ThresholdResolution(
        thresholds={Severity.MEDIUM: 0},
        category_thresholds={Category.SECRETS: {Severity.HIGH: 0}},
        source=ConfigLayer.FILE,
    )

    verdict = evaluate_gate(
        (_finding(Severity.MEDIUM, category=Category.SECRETS),), resolution=resolution
    )

    assert verdict.passed is True


def test_a_category_without_its_own_table_falls_back_to_the_default_table() -> None:
    resolution = ThresholdResolution(
        thresholds={Severity.HIGH: 0},
        category_thresholds={Category.SECRETS: {Severity.CRITICAL: 0}},
        source=ConfigLayer.FILE,
    )

    finding = _finding(Severity.HIGH, category=Category.SCA)
    verdict = evaluate_gate((finding,), resolution=resolution)

    assert verdict.passed is False
    assert verdict.breaches == (
        ThresholdBreach(category=Category.SCA, severity=Severity.HIGH, count=1, maximum=0),
    )


def test_two_categories_are_gated_independently_in_the_same_run() -> None:
    """Neither category's count or table leaks into the other's evaluation."""
    resolution = ThresholdResolution(
        thresholds={},
        category_thresholds={
            Category.SECRETS: {Severity.HIGH: 0},
            Category.SCA: {Severity.HIGH: 5},
        },
        source=ConfigLayer.FILE,
    )

    verdict = evaluate_gate(
        (
            _finding(Severity.HIGH, category=Category.SECRETS),
            _finding(Severity.HIGH, category=Category.SCA),
            _finding(Severity.HIGH, category=Category.SCA),
        ),
        resolution=resolution,
    )

    assert verdict.passed is False
    assert len(verdict.breaches) == 1
    assert verdict.breaches[0].category is Category.SECRETS


def test_thresholds_for_returns_the_categorys_own_table_when_present() -> None:
    resolution = ThresholdResolution(
        thresholds={Severity.HIGH: 5},
        category_thresholds={Category.SECRETS: {Severity.HIGH: 0}},
        source=ConfigLayer.FILE,
    )

    assert resolution.thresholds_for(Category.SECRETS) == {Severity.HIGH: 0}
    assert resolution.thresholds_for(Category.SCA) == {Severity.HIGH: 5}


def test_is_configured_is_true_when_only_a_category_table_is_declared() -> None:
    resolution = ThresholdResolution(
        thresholds={},
        category_thresholds={Category.SECRETS: {Severity.HIGH: 0}},
        source=ConfigLayer.FILE,
    )

    assert resolution.is_configured is True


def test_is_configured_is_false_with_no_thresholds_at_all() -> None:
    resolution = ThresholdResolution.for_fail_on(None, source=ConfigLayer.DEFAULT)

    assert resolution.is_configured is False
