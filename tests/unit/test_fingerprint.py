"""Tests for the deterministic fingerprint algorithm (ADR §5).

Only `linceo.core.fingerprint` has real logic in the `Finding` model —
`Finding` itself, and its sibling value objects, are inert dataclasses with
no behavior of their own.
"""

from __future__ import annotations

from linceo.core.fingerprint import FINGERPRINT_VERSION, sca_fingerprint, secret_fingerprint


def test_secret_fingerprint_is_versioned() -> None:
    """The algorithm version travels embedded in the value, per ADR §5."""
    digest = "abc123"
    fingerprint = secret_fingerprint(
        rule_id="aws-access-key", path="src/config.py", secret_hash=digest
    )

    assert fingerprint.startswith(f"{FINGERPRINT_VERSION}:")


def test_secret_fingerprint_is_deterministic() -> None:
    """Same ingredients, in the same run or a different one, produce the same fingerprint."""
    rule_id, path, digest = "aws-access-key", "src/config.py", "abc123"

    first = secret_fingerprint(rule_id=rule_id, path=path, secret_hash=digest)
    second = secret_fingerprint(rule_id=rule_id, path=path, secret_hash=digest)

    assert first == second


def test_secret_fingerprint_changes_with_any_ingredient() -> None:
    """Changing rule_id, path, or the secret hash changes the fingerprint."""
    rule_id, path, digest = "aws-access-key", "src/config.py", "abc123"
    other_rule_id, other_path, other_digest = "gcp-api-key", "src/other.py", "def456"

    baseline = secret_fingerprint(rule_id=rule_id, path=path, secret_hash=digest)
    different_rule = secret_fingerprint(rule_id=other_rule_id, path=path, secret_hash=digest)
    different_path = secret_fingerprint(rule_id=rule_id, path=other_path, secret_hash=digest)
    different_hash = secret_fingerprint(rule_id=rule_id, path=path, secret_hash=other_digest)

    fingerprints = {baseline, different_rule, different_path, different_hash}
    assert len(fingerprints) == 4


def test_secret_fingerprint_does_not_concatenate_ambiguously() -> None:
    """Ingredients are separated so that shifting a boundary between them changes the hash.

    Without a separator, rule_id="ab", path="c" would hash identically to
    rule_id="a", path="bc" — silently colliding two unrelated findings.
    """
    digest = "x"
    first = secret_fingerprint(rule_id="ab", path="c", secret_hash=digest)
    second = secret_fingerprint(rule_id="a", path="bc", secret_hash=digest)

    assert first != second


def test_sca_fingerprint_is_versioned() -> None:
    """The algorithm version travels embedded in the value, per ADR §5."""
    fingerprint = sca_fingerprint(
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="CVE-2023-32681",
        manifest_path="requirements.txt",
    )

    assert fingerprint.startswith(f"{FINGERPRINT_VERSION}:")


def test_sca_fingerprint_is_deterministic() -> None:
    """Same ingredients produce the same fingerprint, run after run."""
    kwargs = {
        "package_name": "requests",
        "package_version": "2.25.0",
        "vulnerability_id": "CVE-2023-32681",
        "manifest_path": "requirements.txt",
    }

    assert sca_fingerprint(**kwargs) == sca_fingerprint(**kwargs)


def test_sca_fingerprint_changes_with_any_ingredient() -> None:
    """Changing the package, version, vulnerability id, or manifest path changes the fingerprint."""
    baseline = sca_fingerprint(
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="CVE-2023-32681",
        manifest_path="requirements.txt",
    )
    different_package = sca_fingerprint(
        package_name="urllib3",
        package_version="2.25.0",
        vulnerability_id="CVE-2023-32681",
        manifest_path="requirements.txt",
    )
    different_version = sca_fingerprint(
        package_name="requests",
        package_version="2.31.0",
        vulnerability_id="CVE-2023-32681",
        manifest_path="requirements.txt",
    )
    different_cve = sca_fingerprint(
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="CVE-2024-00000",
        manifest_path="requirements.txt",
    )
    different_manifest = sca_fingerprint(
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="CVE-2023-32681",
        manifest_path="services/api/requirements.txt",
    )

    fingerprints = {
        baseline,
        different_package,
        different_version,
        different_cve,
        different_manifest,
    }
    assert len(fingerprints) == 5
