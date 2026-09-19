"""Tests for `SeverityNormalizer` and `normalize_finding` (ADR §6 precedence chain)."""

from __future__ import annotations

import pytest

from linceo.core.findings import Category, Location, Package, RawFinding
from linceo.core.normalization import (
    UNVERSIONED_SEVERITY_MAP,
    SeverityNormalizer,
    UnresolvedSeverityError,
    normalize_finding,
)
from linceo.core.severity import Severity, SeveritySource
from linceo.core.severity_map import CategorySeverityDefault, SeverityMap

_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential

#: A category-default table shaped like `severity_map.toml`'s own
#: `[defaults.secrets]` — used by tests exercising the *precedence chain*
#: in isolation, not `severity_map.toml` itself (that is
#: `tests/unit/test_severity_map.py` and `test_trivy.py`'s job): a bare
#: `SeverityNormalizer()` has no category default at all until one is
#: given, exactly as it has no `native_map` entry until one is given.
_SECRETS_DEFAULT_HIGH = {Category.SECRETS: CategorySeverityDefault(default=Severity.HIGH)}


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
    normalizer = SeverityNormalizer(category_defaults=_SECRETS_DEFAULT_HIGH)
    raw = _raw_secret(raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.HIGH, SeveritySource.CATEGORY_DEFAULT)


def test_category_default_rule_escalation_wins_over_the_flat_default() -> None:
    """ADR §6: "la severidad se asigna por regla, no globalmente"."""
    defaults = {
        Category.SECRETS: CategorySeverityDefault(
            default=Severity.HIGH, rules={"private-key-critical": Severity.CRITICAL}
        )
    }
    normalizer = SeverityNormalizer(category_defaults=defaults)
    raw = _raw_secret(rule_id="private-key-critical", raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.CRITICAL, SeveritySource.CATEGORY_DEFAULT)


def test_category_default_flat_default_applies_to_a_rule_without_its_own_escalation() -> None:
    defaults = {
        Category.SECRETS: CategorySeverityDefault(
            default=Severity.HIGH, rules={"private-key-critical": Severity.CRITICAL}
        )
    }
    normalizer = SeverityNormalizer(category_defaults=defaults)
    raw = _raw_secret(rule_id="some-other-rule", raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.HIGH, SeveritySource.CATEGORY_DEFAULT)


def test_a_bare_normalizer_has_no_category_default_at_all() -> None:
    """Unlike before ADR §6's severity_map.toml existed, nothing is implicit here."""
    normalizer = SeverityNormalizer()
    raw = _raw_secret(raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.MEDIUM, SeveritySource.FALLBACK)


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
    normalizer = SeverityNormalizer(strict=True, category_defaults=_SECRETS_DEFAULT_HIGH)
    raw = _raw_secret(raw_severity=None)

    severity, source = normalizer.resolve(raw)

    assert (severity, source) == (Severity.HIGH, SeveritySource.CATEGORY_DEFAULT)


def test_normalize_finding_computes_the_secret_fingerprint_and_resolved_severity() -> None:
    normalizer = SeverityNormalizer(category_defaults=_SECRETS_DEFAULT_HIGH)
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


def test_bare_normalizer_reports_the_unversioned_map_marker() -> None:
    """A `SeverityNormalizer` built by hand was never produced by any real `severity_map.toml`
    version — `map_version` must say so plainly, never a value that could pass for one."""
    assert SeverityNormalizer().map_version == UNVERSIONED_SEVERITY_MAP


def test_from_severity_map_carries_the_maps_own_version_and_data() -> None:
    severity_map = SeverityMap(
        map_version="test-v7",
        native_map={("some-tool", "HIGH"): Severity.HIGH},
        category_defaults=_SECRETS_DEFAULT_HIGH,
        cvss_source_preference=("nvd",),
    )

    normalizer = SeverityNormalizer.from_severity_map(severity_map)

    assert normalizer.map_version == "test-v7"
    assert normalizer.native_map == {("some-tool", "HIGH"): Severity.HIGH}
    assert normalizer.category_defaults == _SECRETS_DEFAULT_HIGH
    assert normalizer.overrides == {}


def test_from_severity_map_threads_overrides_strict_and_fallback_through() -> None:
    severity_map = SeverityMap(
        map_version="test-v7",
        native_map={},
        category_defaults={},
        cvss_source_preference=(),
    )
    overrides = {("trivy", "CVE-2023-32681"): Severity.LOW}

    normalizer = SeverityNormalizer.from_severity_map(
        severity_map, overrides=overrides, fallback=Severity.LOW, strict=True
    )

    assert normalizer.overrides == overrides
    assert normalizer.fallback is Severity.LOW
    assert normalizer.strict is True


def test_normalize_finding_is_deterministic_for_the_same_raw_finding() -> None:
    normalizer = SeverityNormalizer()
    raw = _raw_secret()

    first = normalize_finding(raw, normalizer)
    second = normalize_finding(raw, normalizer)

    assert first == second
