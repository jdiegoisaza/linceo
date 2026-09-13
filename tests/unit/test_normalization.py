"""Tests for `SeverityNormalizer` and `normalize_finding` (ADR §6 precedence chain)."""

from __future__ import annotations

import pytest

from linceo.core.findings import Category, Location, Package, RawFinding
from linceo.core.normalization import SeverityNormalizer, UnresolvedSeverityError, normalize_finding
from linceo.core.severity import Severity, SeveritySource

_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _raw_secret(
    *, tool: str = "gitleaks", rule_id: str = "aws-access-key", raw_severity: str | None = None
) -> RawFinding:
    return RawFinding(
        tool=tool,
        category=Category.SECRETS,
        rule_id=rule_id,
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        raw_severity=raw_severity,
        secret_hash=_SECRET_HASH,
    )


def _raw_sca(*, raw_severity: str | None = None, cvss_score: float | None = None) -> RawFinding:
    return RawFinding(
        tool="trivy",
        category=Category.SCA,
        rule_id="CVE-2023-32681",
        message="requests vulnerable to proxy auth leak",
        location=Location(path="requirements.txt"),
        raw_severity=raw_severity,
        cvss_score=cvss_score,
        package=Package(name="requests", version="2.25.0"),
    )


def test_override_wins_over_every_other_signal() -> None:
    normalizer = SeverityNormalizer(
        native_map={("trivy", "HIGH"): Severity.HIGH},
        overrides={("trivy", "CVE-2023-32681"): Severity.LOW},
    )
    raw = _raw_sca(raw_severity="HIGH", cvss_score=9.8)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.LOW, SeveritySource.OVERRIDE)


def test_native_severity_wins_over_cvss_when_no_override() -> None:
    normalizer = SeverityNormalizer(native_map={("trivy", "MEDIUM"): Severity.MEDIUM})
    raw = _raw_sca(raw_severity="MEDIUM", cvss_score=9.8)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.MEDIUM, SeveritySource.NATIVE)


def test_cvss_is_used_when_native_value_is_unmapped() -> None:
    normalizer = SeverityNormalizer(native_map={})
    raw = _raw_sca(raw_severity="UNKNOWN", cvss_score=9.8)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.CRITICAL, SeveritySource.CVSS)


def test_category_default_applies_when_gitleaks_emits_no_native_severity() -> None:
    normalizer = SeverityNormalizer()
    raw = _raw_secret(raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.HIGH, SeveritySource.CATEGORY_DEFAULT)


def test_fallback_applies_when_sca_has_no_native_cvss_or_category_default() -> None:
    normalizer = SeverityNormalizer()
    raw = _raw_sca(raw_severity=None, cvss_score=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.MEDIUM, SeveritySource.FALLBACK)


def test_strict_normalizer_raises_instead_of_falling_back() -> None:
    normalizer = SeverityNormalizer(strict=True)
    raw = _raw_sca(raw_severity=None, cvss_score=None)

    with pytest.raises(UnresolvedSeverityError, match="trivy"):
        normalizer.resolve(raw)


def test_strict_normalizer_does_not_raise_when_a_signal_resolves() -> None:
    normalizer = SeverityNormalizer(strict=True)
    raw = _raw_secret(raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.HIGH, SeveritySource.CATEGORY_DEFAULT)


def test_normalize_finding_computes_the_secret_fingerprint_and_resolved_severity() -> None:
    normalizer = SeverityNormalizer()
    raw = _raw_secret()

    finding = normalize_finding(raw, normalizer)

    assert finding.fingerprint.startswith("v1:")
    assert finding.severity is Severity.HIGH
    assert finding.severity_source is SeveritySource.CATEGORY_DEFAULT
    assert finding.raw_severity is None
    assert finding.tool == "gitleaks"
    assert finding.secret_hash == _SECRET_HASH


def test_normalize_finding_computes_the_sca_fingerprint_and_resolved_severity() -> None:
    normalizer = SeverityNormalizer(native_map={("trivy", "HIGH"): Severity.HIGH})
    raw = _raw_sca(raw_severity="HIGH")

    finding = normalize_finding(raw, normalizer)

    assert finding.fingerprint.startswith("v1:")
    assert finding.severity is Severity.HIGH
    assert finding.severity_source is SeveritySource.NATIVE
    assert finding.package == Package(name="requests", version="2.25.0")


def test_normalize_finding_rejects_a_secrets_raw_finding_without_a_secret_hash() -> None:
    raw = RawFinding(
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        raw_severity=None,
    )

    with pytest.raises(ValueError, match="secret_hash"):
        normalize_finding(raw, SeverityNormalizer())


def test_normalize_finding_rejects_an_sca_raw_finding_without_a_package() -> None:
    raw = RawFinding(
        tool="trivy",
        category=Category.SCA,
        rule_id="CVE-2023-32681",
        message="requests vulnerable to proxy auth leak",
        location=Location(path="requirements.txt"),
        raw_severity=None,
    )

    with pytest.raises(ValueError, match="package"):
        normalize_finding(raw, SeverityNormalizer())


def test_normalize_finding_is_deterministic_for_the_same_raw_finding() -> None:
    normalizer = SeverityNormalizer()
    raw = _raw_secret()

    first = normalize_finding(raw, normalizer)
    second = normalize_finding(raw, normalizer)

    assert first == second
