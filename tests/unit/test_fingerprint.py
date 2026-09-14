"""Tests for the deterministic fingerprint algorithm (ADR §5).

Only `linceo.core.fingerprint` has real logic in the `Finding` model —
`Finding` itself, and its sibling value objects, are inert dataclasses with
no behavior of their own.
"""

from __future__ import annotations

import pytest

from linceo.core.fingerprint import (
    FINGERPRINT_VERSION,
    sca_fingerprint,
    secret_fingerprint,
    short_fingerprints,
)


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


# --- short_fingerprints (ADR §7, "FP") -----------------------------------------


def test_short_fingerprints_uses_the_minimum_length_by_default() -> None:
    digest = "abc123"
    full = secret_fingerprint(rule_id="aws-access-key", path="src/config.py", secret_hash=digest)

    short = short_fingerprints([full])

    assert short[full] == f"{FINGERPRINT_VERSION}:{full.split(':')[1][:8]}"


def test_short_fingerprints_keeps_the_version_prefix() -> None:
    digest = "abc123"
    full = secret_fingerprint(rule_id="aws-access-key", path="src/config.py", secret_hash=digest)

    short = short_fingerprints([full])

    assert short[full].startswith(f"{FINGERPRINT_VERSION}:")


def test_short_fingerprints_extends_length_only_far_enough_to_disambiguate() -> None:
    """Two fingerprints sharing an 8-char prefix get a longer, but still shared-safe, length."""
    colliding_a = (
        f"{FINGERPRINT_VERSION}:aaaaaaaa1111111111111111111111111111111111111111111111111111"
    )
    colliding_b = (
        f"{FINGERPRINT_VERSION}:aaaaaaaa2222222222222222222222222222222222222222222222222222"
    )
    distinct = f"{FINGERPRINT_VERSION}:bbbbbbbb3333333333333333333333333333333333333333333333333333"

    short = short_fingerprints([colliding_a, colliding_b, distinct])

    assert len({short[colliding_a], short[colliding_b], short[distinct]}) == 3
    assert short[colliding_a] != short[colliding_b]
    # every value still starts with the same 8-char shared prefix, just extended
    assert short[colliding_a].startswith(f"{FINGERPRINT_VERSION}:aaaaaaaa")


def test_short_fingerprints_is_stable_for_a_fixed_input_set() -> None:
    digest_a, digest_b = "abc123", "def456"
    fingerprints = [
        secret_fingerprint(rule_id="aws-access-key", path="src/config.py", secret_hash=digest_a),
        secret_fingerprint(rule_id="gcp-api-key", path="src/other.py", secret_hash=digest_b),
    ]

    assert short_fingerprints(fingerprints) == short_fingerprints(fingerprints)


def test_short_fingerprints_rejects_a_value_without_the_current_version_prefix() -> None:
    with pytest.raises(ValueError, match="v1"):
        short_fingerprints(["v2:abcdef0123456789"])


def test_short_fingerprints_of_an_empty_input_is_empty() -> None:
    assert short_fingerprints([]) == {}
