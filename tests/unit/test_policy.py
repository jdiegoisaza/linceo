"""Tests for gate policy: exclusions, tool skips, and thresholds (ADR §8, §8.1, §8.2)."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from linceo.core.findings import Category, Finding, Location
from linceo.core.policy import (
    Exclusion,
    PolicyConfigurationError,
    ToolSkip,
    apply_exclusions,
    parse_policy_document,
    split_tool_skips,
    thresholds_from_fail_on,
    validate_thresholds,
)
from linceo.core.severity import Severity, SeveritySource

TODAY = date(2026, 9, 13)
_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential
_REPOSITORY = "orion-web"


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


# --- apply_exclusions -------------------------------------------------------


def test_finding_with_no_matching_exclusion_is_active() -> None:
    outcome = apply_exclusions((_finding("v1:abc"),), (), today=TODAY, repository=_REPOSITORY)

    assert outcome.active == (_finding("v1:abc"),)
    assert outcome.suppressed == ()
    assert outcome.expired == ()


def test_finding_covered_by_a_valid_exclusion_is_suppressed_not_active() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=30),
    )

    outcome = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository=_REPOSITORY
    )

    assert outcome.active == ()
    assert outcome.suppressed == (_finding("v1:abc"),)
    assert outcome.expired == ()


def test_finding_covered_by_an_exclusion_expiring_today_is_still_suppressed() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc", reason="accepted risk", owner="alice", expires_at=TODAY
    )

    outcome = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository=_REPOSITORY
    )

    assert outcome.suppressed == (_finding("v1:abc"),)


def test_finding_covered_by_an_expired_exclusion_counts_back_as_active() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY - timedelta(days=1),
    )

    outcome = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository=_REPOSITORY
    )

    assert outcome.active == (_finding("v1:abc"),)
    assert outcome.suppressed == ()
    assert outcome.expired == (exclusion,)


def test_expired_exclusion_covering_two_findings_is_reported_only_once() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY - timedelta(days=1),
    )
    findings = (_finding("v1:abc"), _finding("v1:abc"))

    outcome = apply_exclusions(findings, (exclusion,), today=TODAY, repository=_REPOSITORY)

    assert outcome.expired == (exclusion,)
    assert outcome.active == findings


def test_missing_reason_or_owner_cannot_construct_an_exclusion_at_all() -> None:
    with pytest.raises(TypeError):
        Exclusion(fingerprint="v1:abc", expires_at=TODAY)  # type: ignore[call-arg]


# --- scope (ADR §8, "Alcance de las exclusiones") ---------------------------


def test_global_exclusion_applies_to_any_repository() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=1),
    )

    outcome = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository="any-repo"
    )

    assert outcome.suppressed == (_finding("v1:abc"),)


def test_scoped_exclusion_applies_only_to_its_listed_repositories() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=1),
        repositories=("orion-web", "orion-api"),
    )

    matching = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository="orion-web"
    )
    not_matching = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository="orion-mobile"
    )

    assert matching.suppressed == (_finding("v1:abc"),)
    assert not_matching.active == (_finding("v1:abc"),)
    assert not_matching.suppressed == ()
    assert not_matching.expired == ()


def test_scoped_exclusion_not_matching_the_repository_is_not_reported_as_expired_either() -> None:
    """An out-of-scope exclusion is silent, not surfaced as needing a decision (ADR §8)."""
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY - timedelta(days=1),
        repositories=("orion-web",),
    )

    outcome = apply_exclusions(
        (_finding("v1:abc"),), (exclusion,), today=TODAY, repository="orion-mobile"
    )

    assert outcome.expired == ()


# --- fingerprint prefix matching (ADR §7's "FP" column) ---------------------


def test_exclusion_fingerprint_prefix_matches_a_single_finding() -> None:
    exclusion = Exclusion(
        fingerprint="v1:ab",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=1),
    )

    outcome = apply_exclusions(
        (_finding("v1:abcdef"),), (exclusion,), today=TODAY, repository=_REPOSITORY
    )

    assert outcome.suppressed == (_finding("v1:abcdef"),)


def test_exclusion_fingerprint_prefix_matching_more_than_one_finding_is_a_configuration_error() -> (
    None
):
    exclusion = Exclusion(
        fingerprint="v1:ab",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=1),
    )
    findings = (_finding("v1:abcdef"), _finding("v1:abzzzz"))

    with pytest.raises(PolicyConfigurationError, match="ambiguous"):
        apply_exclusions(findings, (exclusion,), today=TODAY, repository=_REPOSITORY)


def test_exclusion_fingerprint_matching_no_finding_is_a_silent_no_op() -> None:
    exclusion = Exclusion(
        fingerprint="v1:zzz",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY + timedelta(days=1),
    )

    outcome = apply_exclusions(
        (_finding("v1:abcdef"),), (exclusion,), today=TODAY, repository=_REPOSITORY
    )

    assert outcome.active == (_finding("v1:abcdef"),)
    assert outcome.suppressed == ()
    assert outcome.expired == ()


# --- tool skips --------------------------------------------------------------


def test_split_tool_skips_separates_active_from_expired() -> None:
    active = ToolSkip(
        tool="gitleaks",
        reason="rollout paused",
        owner="alice",
        expires_at=TODAY + timedelta(days=1),
    )
    expired = ToolSkip(
        tool="trivy", reason="upgrading", owner="bob", expires_at=TODAY - timedelta(days=1)
    )

    still_active, lapsed = split_tool_skips((active, expired), today=TODAY)

    assert still_active == (active,)
    assert lapsed == (expired,)


def test_tool_skip_expiring_today_is_still_active() -> None:
    skip = ToolSkip(tool="gitleaks", reason="rollout paused", owner="alice", expires_at=TODAY)

    still_active, lapsed = split_tool_skips((skip,), today=TODAY)

    assert still_active == (skip,)
    assert lapsed == ()


# --- thresholds ----------------------------------------------------------------


def test_thresholds_from_fail_on_constrains_everything_at_or_above() -> None:
    thresholds = thresholds_from_fail_on(Severity.HIGH)

    assert thresholds == {Severity.CRITICAL: 0, Severity.HIGH: 0}


def test_validate_thresholds_rejects_info() -> None:
    with pytest.raises(PolicyConfigurationError, match="INFO"):
        validate_thresholds({Severity.INFO: 0})


# --- parse_policy_document: horizon and required fields -----------------------


def test_exclusion_beyond_the_max_horizon_is_a_configuration_error() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY + timedelta(days=91),
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="v1:abc"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_exclusion_exactly_at_the_max_horizon_is_accepted() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY + timedelta(days=90),
            }
        ]
    }

    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    assert parsed.exclusions[0].fingerprint == "v1:abc"


def test_exclusion_missing_a_required_field_is_a_configuration_error() -> None:
    document = {"exclusions": [{"fingerprint": "v1:abc", "reason": "adoption", "owner": "alice"}]}

    with pytest.raises(PolicyConfigurationError, match="missing required field"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_exclusion_with_an_unknown_field_is_a_configuration_error() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY,
                "bogus": "x",
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="unknown field"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_tool_skip_missing_a_required_field_is_a_configuration_error() -> None:
    document = {"skipped_tools": [{"tool": "gitleaks", "reason": "paused", "owner": "alice"}]}

    with pytest.raises(PolicyConfigurationError, match="missing required field"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_tool_skip_beyond_the_max_horizon_is_a_configuration_error() -> None:
    document = {
        "skipped_tools": [
            {
                "tool": "gitleaks",
                "reason": "paused",
                "owner": "alice",
                "expires_at": TODAY + timedelta(days=91),
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="gitleaks"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_thresholds_table_naming_info_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="INFO"):
        parse_policy_document({"thresholds": {"info": 0}}, today=TODAY, max_horizon_days=90)


def test_thresholds_table_with_an_unknown_severity_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="unknown severity"):
        parse_policy_document({"thresholds": {"bogus": 0}}, today=TODAY, max_horizon_days=90)


def test_thresholds_table_with_a_negative_count_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="negative"):
        parse_policy_document({"thresholds": {"high": -1}}, today=TODAY, max_horizon_days=90)


def test_thresholds_table_with_a_boolean_value_is_a_configuration_error() -> None:
    """`bool` is a subclass of `int` in Python — `true`/`false` must not pass as a count."""
    with pytest.raises(PolicyConfigurationError, match="must be an integer"):
        parse_policy_document({"thresholds": {"high": True}}, today=TODAY, max_horizon_days=90)


def test_exclusion_expires_at_of_the_wrong_type_is_a_configuration_error() -> None:
    document = {
        "exclusions": [
            {"fingerprint": "v1:abc", "reason": "adoption", "owner": "alice", "expires_at": 3.14}
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="must be a date"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_document_with_no_policy_sections_parses_to_empty() -> None:
    parsed = parse_policy_document({}, today=TODAY, max_horizon_days=90)

    assert parsed.thresholds is None
    assert parsed.exclusions == ()
    assert parsed.tool_skips == ()


def test_exclusions_not_a_list_of_tables_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="list of tables"):
        parse_policy_document({"exclusions": "not-a-list"}, today=TODAY, max_horizon_days=90)


def test_exclusions_list_containing_a_non_table_item_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="list of tables"):
        parse_policy_document({"exclusions": ["not-a-table"]}, today=TODAY, max_horizon_days=90)


def test_exclusion_expires_at_accepts_an_iso_string_too() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": "2026-11-30",
            }
        ]
    }

    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    assert parsed.exclusions[0].expires_at == date(2026, 11, 30)


def test_exclusion_expires_at_rejects_a_malformed_iso_string() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": "not-a-date",
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="not a valid ISO-8601 date"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_exclusion_repositories_not_a_list_of_strings_is_a_configuration_error() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY,
                "repositories": "orion-web",
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="repositories must be a list"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_tool_skip_with_an_unknown_field_is_a_configuration_error() -> None:
    document = {
        "skipped_tools": [
            {
                "tool": "gitleaks",
                "reason": "paused",
                "owner": "alice",
                "expires_at": TODAY,
                "bogus": "x",
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="unknown field"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_thresholds_table_not_a_mapping_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="must be a table"):
        parse_policy_document({"thresholds": "not-a-table"}, today=TODAY, max_horizon_days=90)
