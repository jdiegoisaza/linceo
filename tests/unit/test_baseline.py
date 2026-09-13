"""Tests for baseline suppressions (ADR §8.2)."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from linceo.core.baseline import (
    Baseline,
    BaselineConfigurationError,
    BaselineEntry,
    apply_baseline,
)
from linceo.core.findings import Category, Finding, Location
from linceo.core.severity import Severity, SeveritySource

TODAY = date(2026, 9, 13)
_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _finding(fingerprint: str) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        severity=Severity.HIGH,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )


def test_finding_with_no_matching_entry_is_active() -> None:
    outcome = apply_baseline((_finding("v1:abc"),), Baseline(), today=TODAY)

    assert outcome.active == (_finding("v1:abc"),)
    assert outcome.suppressed == ()
    assert outcome.expired == ()


def test_finding_covered_by_a_valid_entry_is_suppressed_not_active() -> None:
    entry = BaselineEntry(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=30),
    )
    baseline = Baseline(entries=(entry,))

    outcome = apply_baseline((_finding("v1:abc"),), baseline, today=TODAY)

    assert outcome.active == ()
    assert outcome.suppressed == (_finding("v1:abc"),)
    assert outcome.expired == ()


def test_finding_covered_by_an_entry_expiring_today_is_still_suppressed() -> None:
    entry = BaselineEntry(
        fingerprint="v1:abc", reason="accepted risk", owner="alice", expires_at=TODAY
    )
    baseline = Baseline(entries=(entry,))

    outcome = apply_baseline((_finding("v1:abc"),), baseline, today=TODAY)

    assert outcome.suppressed == (_finding("v1:abc"),)


def test_finding_covered_by_an_expired_entry_counts_back_as_active() -> None:
    entry = BaselineEntry(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY - timedelta(days=1),
    )
    baseline = Baseline(entries=(entry,))

    outcome = apply_baseline((_finding("v1:abc"),), baseline, today=TODAY)

    assert outcome.active == (_finding("v1:abc"),)
    assert outcome.suppressed == ()
    assert outcome.expired == (entry,)


def test_expired_entry_covering_two_findings_is_reported_only_once() -> None:
    entry = BaselineEntry(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY - timedelta(days=1),
    )
    baseline = Baseline(entries=(entry,))
    findings = (_finding("v1:abc"), _finding("v1:abc"))

    outcome = apply_baseline(findings, baseline, today=TODAY)

    assert outcome.expired == (entry,)


def test_entry_beyond_the_max_horizon_is_a_configuration_error() -> None:
    entry = BaselineEntry(
        fingerprint="v1:abc",
        reason="adoption",
        owner="alice",
        expires_at=TODAY + timedelta(days=91),
    )
    baseline = Baseline(entries=(entry,))

    with pytest.raises(BaselineConfigurationError, match="v1:abc"):
        apply_baseline((_finding("v1:abc"),), baseline, today=TODAY, max_horizon_days=90)


def test_entry_exactly_at_the_max_horizon_is_accepted() -> None:
    entry = BaselineEntry(
        fingerprint="v1:abc",
        reason="adoption",
        owner="alice",
        expires_at=TODAY + timedelta(days=90),
    )
    baseline = Baseline(entries=(entry,))

    outcome = apply_baseline((_finding("v1:abc"),), baseline, today=TODAY, max_horizon_days=90)

    assert outcome.suppressed == (_finding("v1:abc"),)


def test_missing_reason_or_owner_cannot_construct_an_entry_at_all() -> None:
    with pytest.raises(TypeError):
        BaselineEntry(fingerprint="v1:abc", expires_at=TODAY)  # type: ignore[call-arg]
