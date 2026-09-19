"""Tests for gate policy: exclusions, tool skips, and thresholds (ADR §8, §8.1, §8.2)."""

from __future__ import annotations

import tomllib
from datetime import date, timedelta

import pytest

from linceo.core.findings import Category, Finding, Location
from linceo.core.policy import (
    Exclusion,
    PolicyConfigurationError,
    ToolSkip,
    apply_exclusions,
    baseline_wave_expiry,
    parse_policy_document,
    render_exclusion_fragment,
    render_exclusions_toml,
    split_tool_skips,
    thresholds_from_fail_on,
    validate_thresholds,
)
from linceo.core.severity import SEVERITY_ORDER, Severity, SeveritySource

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
    assert parsed.category_thresholds == {}
    assert parsed.exclusions == ()
    assert parsed.tool_skips == ()


# --- per-category thresholds (ADR §8.1) -----------------------------------------


def test_category_threshold_table_parses_separately_from_the_default_table() -> None:
    document = {
        "thresholds": {
            "high": 5,
            "secrets": {"critical": 0, "high": 0},
            "sca": {"high": 5, "medium": 25},
        }
    }

    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    assert parsed.thresholds == {Severity.HIGH: 5}
    assert parsed.category_thresholds == {
        Category.SECRETS: {Severity.CRITICAL: 0, Severity.HIGH: 0},
        Category.SCA: {Severity.HIGH: 5, Severity.MEDIUM: 25},
    }


def test_thresholds_present_only_as_category_tables_leaves_the_default_none() -> None:
    document = {"thresholds": {"secrets": {"high": 0}}}

    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    assert parsed.thresholds is None
    assert parsed.category_thresholds == {Category.SECRETS: {Severity.HIGH: 0}}


def test_unknown_category_under_thresholds_is_a_configuration_error() -> None:
    document = {"thresholds": {"bogus": {"high": 0}}}

    with pytest.raises(PolicyConfigurationError, match="unknown category"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_a_category_name_used_as_a_flat_key_is_still_an_unknown_severity() -> None:
    """`secrets = 5` (not a sub-table) is a severity-shaped entry, not a category one."""
    document = {"thresholds": {"secrets": 5}}

    with pytest.raises(PolicyConfigurationError, match="unknown severity"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_category_threshold_table_naming_info_is_a_configuration_error() -> None:
    document = {"thresholds": {"secrets": {"info": 0}}}

    with pytest.raises(PolicyConfigurationError, match="INFO"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_category_threshold_table_with_an_unknown_severity_is_a_configuration_error() -> None:
    document = {"thresholds": {"secrets": {"bogus": 0}}}

    with pytest.raises(PolicyConfigurationError, match="unknown severity"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


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


# --- exclusion "readable identity" fields (ADR §8.2, for `baseline migrate`) -----


def test_exclusion_identity_fields_default_to_none_when_absent() -> None:
    document = {
        "exclusions": [
            {"fingerprint": "v1:abc", "reason": "adoption", "owner": "alice", "expires_at": TODAY}
        ]
    }

    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    exclusion = parsed.exclusions[0]
    assert exclusion.category is None
    assert exclusion.rule_id is None
    assert exclusion.path is None
    assert exclusion.package is None
    assert exclusion.package_version is None


def test_exclusion_identity_fields_round_trip_through_parsing() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY,
                "category": "sca",
                "rule_id": "CVE-2023-37920",
                "path": "requirements.txt",
                "package": "certifi",
                "package_version": "2015.4.28",
            }
        ]
    }

    exclusion = parse_policy_document(document, today=TODAY, max_horizon_days=90).exclusions[0]

    assert exclusion.category is Category.SCA
    assert exclusion.rule_id == "CVE-2023-37920"
    assert exclusion.path == "requirements.txt"
    assert exclusion.package == "certifi"
    assert exclusion.package_version == "2015.4.28"


def test_exclusion_unknown_category_is_a_configuration_error() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY,
                "category": "not-a-real-category",
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="not a known category"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


def test_exclusion_identity_field_of_the_wrong_type_is_a_configuration_error() -> None:
    document = {
        "exclusions": [
            {
                "fingerprint": "v1:abc",
                "reason": "adoption",
                "owner": "alice",
                "expires_at": TODAY,
                "rule_id": 12345,
            }
        ]
    }

    with pytest.raises(PolicyConfigurationError, match="rule_id must be a string"):
        parse_policy_document(document, today=TODAY, max_horizon_days=90)


# --- render_exclusions_toml (ADR §8.2, `baseline init`'s own output) ------------


def test_render_exclusions_toml_round_trips_through_parse_policy_document() -> None:
    exclusions = (
        Exclusion(
            fingerprint="v1:abc",
            reason="Initial adoption baseline — pending real triage",
            owner="team-atlas",
            expires_at=TODAY + timedelta(days=30),
            category=Category.SECRETS,
            rule_id="aws-access-token",
            path="src/config.py",
        ),
        Exclusion(
            fingerprint="v1:def",
            reason="Initial adoption baseline — pending real triage",
            owner="team-atlas",
            expires_at=TODAY + timedelta(days=30),
            category=Category.SCA,
            rule_id="CVE-2023-37920",
            path="requirements.txt",
            package="certifi",
            package_version="2015.4.28",
        ),
    )

    rendered = render_exclusions_toml(exclusions)
    document = tomllib.loads(rendered)
    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    assert parsed.exclusions == exclusions


def test_render_exclusions_toml_omits_absent_optional_fields() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc", reason="accepted risk", owner="alice", expires_at=TODAY
    )

    rendered = render_exclusions_toml((exclusion,))

    assert "category" not in rendered
    assert "rule_id" not in rendered
    assert "package" not in rendered
    assert "repositories" not in rendered


def test_render_exclusions_toml_with_no_exclusions_is_still_a_valid_document() -> None:
    rendered = render_exclusions_toml(())

    document = tomllib.loads(rendered)

    assert document == {"version": 1}


def test_render_exclusions_toml_escapes_special_characters_in_strings() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason='Contains a "quote", a backslash \\, and a\nnewline',
        owner="alice",
        expires_at=TODAY,
    )

    rendered = render_exclusions_toml((exclusion,))
    document = tomllib.loads(rendered)

    assert document["exclusions"][0]["reason"] == exclusion.reason


def test_render_exclusions_toml_escapes_a_bare_control_character() -> None:
    """A control character with no named TOML escape (e.g. `\\x01`) still renders as a
    valid, parseable string, via the `\\uXXXX` form."""
    exclusion = Exclusion(
        fingerprint="v1:abc", reason="bell\x07here", owner="alice", expires_at=TODAY
    )

    rendered = render_exclusions_toml((exclusion,))
    document = tomllib.loads(rendered)

    assert document["exclusions"][0]["reason"] == "bell\x07here"


def test_render_exclusions_toml_renders_repositories_as_a_list() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc",
        reason="accepted risk",
        owner="alice",
        expires_at=TODAY,
        repositories=("orion-web", "orion-api"),
    )

    rendered = render_exclusions_toml((exclusion,))
    document = tomllib.loads(rendered)

    assert document["exclusions"][0]["repositories"] == ["orion-web", "orion-api"]


# --- render_exclusion_fragment (ADR §8.2, `baseline init`'s merge path) ---------


def test_render_exclusion_fragment_has_no_version_header() -> None:
    exclusion = Exclusion(
        fingerprint="v1:abc", reason="accepted risk", owner="alice", expires_at=TODAY
    )

    fragment = render_exclusion_fragment((exclusion,))

    assert "version" not in fragment
    assert fragment.startswith("[[exclusions]]")


def test_render_exclusion_fragment_of_nothing_is_empty() -> None:
    assert render_exclusion_fragment(()) == ""


def test_render_exclusion_fragment_appended_to_an_existing_document_parses_as_one() -> None:
    """The actual mechanism `linceo.cli.baseline` relies on: concatenating a fragment onto an
    existing document's raw text, with nothing more than a blank-line join, produces one valid
    document whose `exclusions` array holds both the old and the new entries."""
    existing = (
        "version = 1\n"
        "\n"
        "[thresholds]\n"
        "high = 0\n"
        "\n"
        "[[exclusions]]\n"
        'fingerprint = "v1:old"\n'
        'reason = "prior"\n'
        'owner = "alice"\n'
        "expires_at = 2026-12-01\n"
    )
    new_exclusion = Exclusion(
        fingerprint="v1:new", reason="fresh", owner="bob", expires_at=TODAY + timedelta(days=30)
    )

    merged_text = existing.rstrip("\n") + "\n\n" + render_exclusion_fragment((new_exclusion,))
    document = tomllib.loads(merged_text)
    parsed = parse_policy_document(document, today=TODAY, max_horizon_days=90)

    assert document["thresholds"] == {"high": 0}
    assert {e.fingerprint for e in parsed.exclusions} == {"v1:old", "v1:new"}


# --- baseline_wave_expiry (ADR §8.2, staggered by severity) ---------------------


def test_baseline_wave_expiry_is_deterministic_for_the_same_finding() -> None:
    """Same severity, same fingerprint, same today -> same date, every time (ADR R3)."""

    def _compute() -> date:
        return baseline_wave_expiry(
            severity=Severity.HIGH,
            fingerprint="v1:deadbeef",
            today=TODAY,
            min_expiry_days=30,
            max_expiry_days=90,
        )

    assert _compute() == _compute()


def test_baseline_wave_expiry_most_severe_expires_first() -> None:
    """Every CRITICAL date must be strictly earlier than every INFO date, regardless of
    which fingerprint lands where within its own band (no jitter-induced band overlap)."""
    fingerprints = [f"v1:{i:064x}" for i in range(100)]

    critical_dates = {
        baseline_wave_expiry(
            severity=Severity.CRITICAL,
            fingerprint=fp,
            today=TODAY,
            min_expiry_days=30,
            max_expiry_days=90,
        )
        for fp in fingerprints
    }
    info_dates = {
        baseline_wave_expiry(
            severity=Severity.INFO,
            fingerprint=fp,
            today=TODAY,
            min_expiry_days=30,
            max_expiry_days=90,
        )
        for fp in fingerprints
    }

    assert max(critical_dates) < min(info_dates)


def test_baseline_wave_expiry_never_exceeds_the_max_expiry_days() -> None:
    for severity in SEVERITY_ORDER:
        for i in range(50):
            expiry = baseline_wave_expiry(
                severity=severity,
                fingerprint=f"v1:{i:064x}",
                today=TODAY,
                min_expiry_days=30,
                max_expiry_days=90,
            )
            assert expiry <= TODAY + timedelta(days=90)


def test_baseline_wave_expiry_critical_never_precedes_min_expiry_days() -> None:
    for i in range(50):
        expiry = baseline_wave_expiry(
            severity=Severity.CRITICAL,
            fingerprint=f"v1:{i:064x}",
            today=TODAY,
            min_expiry_days=30,
            max_expiry_days=90,
        )
        assert expiry >= TODAY + timedelta(days=30)


def test_baseline_wave_expiry_with_a_tight_span_still_returns_a_valid_date() -> None:
    """`min_expiry_days`/`max_expiry_days` close enough together that there is no room left
    for jitter (`jitter_window` computes to 0) must not raise — just no sub-band spread."""
    for severity in SEVERITY_ORDER:
        expiry = baseline_wave_expiry(
            severity=severity,
            fingerprint="v1:abc",
            today=TODAY,
            min_expiry_days=30,
            max_expiry_days=32,
        )
        assert TODAY + timedelta(days=30) <= expiry <= TODAY + timedelta(days=32)
