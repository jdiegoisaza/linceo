"""Tests for `severity_map.toml`'s loader and validation (ADR §6)."""

from __future__ import annotations

import pytest

from linceo.adapters.checkov import CheckovIntegration
from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.trivy import TrivyIntegration
from linceo.core.findings import Category
from linceo.core.severity import Severity
from linceo.core.severity_map import (
    CategorySeverityDefault,
    SeverityMap,
    SeverityMapError,
    load_severity_map,
    parse_severity_map,
)

#: Every domain value a registered integration can produce that
#: `severity_map.toml`'s own `[native.<tool>]` table deliberately does not
#: map — the one, documented exception ADR §6 describes (trivy's own
#: `UNKNOWN`, so CVSS still gets a chance to run). Any *other* gap found by
#: `test_every_native_domain_value_is_mapped_or_a_documented_exception`
#: means either the map or this allowlist is out of date with the tool's
#: real behavior — never a silent pass.
_DOCUMENTED_NATIVE_GAPS = frozenset({("trivy", "UNKNOWN")})


# --- parse_severity_map: happy path -------------------------------------------


def test_parses_map_version_native_map_defaults_and_cvss_preference() -> None:
    document = {
        "map_version": "v7",
        "cvss_source_preference": ["nvd", "ghsa"],
        "native": {"trivy": {"HIGH": "high", "CRITICAL": "critical"}, "gitleaks": {}},
        "defaults": {
            "secrets": {"default": "high", "rules": {"some-rule": "critical"}},
        },
    }

    severity_map = parse_severity_map(document)

    assert severity_map == SeverityMap(
        map_version="v7",
        native_map={("trivy", "HIGH"): Severity.HIGH, ("trivy", "CRITICAL"): Severity.CRITICAL},
        category_defaults={
            Category.SECRETS: CategorySeverityDefault(
                default=Severity.HIGH, rules={"some-rule": Severity.CRITICAL}
            )
        },
        cvss_source_preference=("nvd", "ghsa"),
    )


def test_severity_names_are_parsed_case_insensitively() -> None:
    document = {"map_version": "v1", "native": {"trivy": {"HIGH": "HIGH"}}}

    severity_map = parse_severity_map(document)

    assert severity_map.native_map[("trivy", "HIGH")] is Severity.HIGH


def test_native_value_keys_are_kept_exactly_as_written() -> None:
    """The native value must match a tool's own raw output byte for byte — never re-cased."""
    document = {"map_version": "v1", "native": {"trivy": {"High": "high"}}}

    severity_map = parse_severity_map(document)

    assert ("trivy", "High") in severity_map.native_map
    assert ("trivy", "HIGH") not in severity_map.native_map


def test_absent_optional_sections_parse_to_empty_defaults() -> None:
    severity_map = parse_severity_map({"map_version": "v1"})

    assert severity_map.native_map == {}
    assert severity_map.category_defaults == {}
    assert severity_map.cvss_source_preference == ()


def test_a_category_default_with_no_rules_table_has_an_empty_one() -> None:
    document = {"map_version": "v1", "defaults": {"sca": {"default": "medium"}}}

    severity_map = parse_severity_map(document)

    assert severity_map.category_defaults[Category.SCA].rules == {}


# --- parse_severity_map: validation errors ------------------------------------


def test_unknown_top_level_field_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="unknown field"):
        parse_severity_map({"map_version": "v1", "bogus": True})


def test_missing_map_version_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="map_version"):
        parse_severity_map({})


def test_empty_map_version_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="map_version"):
        parse_severity_map({"map_version": ""})


def test_non_string_map_version_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="map_version"):
        parse_severity_map({"map_version": 1})


def test_native_not_a_table_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="native must be a table"):
        parse_severity_map({"map_version": "v1", "native": "not-a-table"})


def test_one_tools_native_table_not_a_table_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match=r"native\.trivy"):
        parse_severity_map({"map_version": "v1", "native": {"trivy": "not-a-table"}})


def test_unknown_severity_name_in_native_map_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="unknown severity"):
        parse_severity_map({"map_version": "v1", "native": {"trivy": {"HIGH": "extreme"}}})


def test_non_string_severity_value_in_native_map_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="must be a string"):
        parse_severity_map({"map_version": "v1", "native": {"trivy": {"HIGH": 1}}})


def test_defaults_not_a_table_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="defaults must be a table"):
        parse_severity_map({"map_version": "v1", "defaults": "not-a-table"})


def test_unknown_category_under_defaults_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="unknown category"):
        parse_severity_map({"map_version": "v1", "defaults": {"bogus": {"default": "high"}}})


def test_category_default_missing_the_default_field_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="missing required field 'default'"):
        parse_severity_map({"map_version": "v1", "defaults": {"secrets": {}}})


def test_category_default_declaring_an_unknown_field_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="unknown field"):
        parse_severity_map(
            {"map_version": "v1", "defaults": {"secrets": {"default": "high", "bogus": 1}}}
        )


def test_category_default_rules_not_a_table_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="rules must be a table"):
        parse_severity_map(
            {"map_version": "v1", "defaults": {"secrets": {"default": "high", "rules": "x"}}}
        )


def test_unknown_severity_in_category_default_rules_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="unknown severity"):
        parse_severity_map(
            {
                "map_version": "v1",
                "defaults": {"secrets": {"default": "high", "rules": {"r": "extreme"}}},
            }
        )


def test_cvss_source_preference_not_a_list_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="cvss_source_preference"):
        parse_severity_map({"map_version": "v1", "cvss_source_preference": "nvd"})


def test_cvss_source_preference_with_a_non_string_entry_is_a_configuration_error() -> None:
    with pytest.raises(SeverityMapError, match="cvss_source_preference"):
        parse_severity_map({"map_version": "v1", "cvss_source_preference": ["nvd", 1]})


# --- load_severity_map: the real packaged file --------------------------------


def test_load_severity_map_reads_the_real_packaged_file() -> None:
    severity_map = load_severity_map()

    assert severity_map.map_version == "v1"
    assert severity_map.cvss_source_preference == ("nvd",)
    assert severity_map.native_map == {
        ("trivy", "LOW"): Severity.LOW,
        ("trivy", "MEDIUM"): Severity.MEDIUM,
        ("trivy", "HIGH"): Severity.HIGH,
        ("trivy", "CRITICAL"): Severity.CRITICAL,
    }
    assert severity_map.category_defaults == {
        Category.SECRETS: CategorySeverityDefault(default=Severity.HIGH, rules={}),
        Category.IAC: CategorySeverityDefault(default=Severity.MEDIUM, rules={}),
    }


def test_load_severity_map_never_maps_trivys_unknown_native_value() -> None:
    """ADR §6: mapping UNKNOWN would short-circuit the CVSS tier before it ever runs."""
    severity_map = load_severity_map()

    assert ("trivy", "UNKNOWN") not in severity_map.native_map


# --- ADR §6 verification: table-driven domain coverage + completeness --------


def test_every_native_domain_value_is_mapped_or_a_documented_exception() -> None:
    """ADR §6's own two verification bullets in one test: every native value each registered
    integration's own declared domain can produce either resolves through the real map's
    NATIVE tier, or is exactly the one documented, deliberate gap — never a silent one a
    future tool version could introduce without anyone noticing."""
    severity_map = load_severity_map()
    integrations: dict[str, frozenset[str]] = {
        GitleaksIntegration(version="8.30.1").name: GitleaksIntegration(
            version="8.30.1"
        ).native_severity_domain(),
        TrivyIntegration(version="0.74.0").name: TrivyIntegration(
            version="0.74.0"
        ).native_severity_domain(),
        CheckovIntegration(version="3.3.19").name: CheckovIntegration(
            version="3.3.19"
        ).native_severity_domain(),
    }

    for tool, domain in integrations.items():
        for native_value in domain:
            key = (tool, native_value)
            if key in _DOCUMENTED_NATIVE_GAPS:
                assert key not in severity_map.native_map, (
                    f"{key} is listed as a documented gap but severity_map.toml maps it — "
                    "update _DOCUMENTED_NATIVE_GAPS, this is no longer a gap"
                )
                continue
            assert key in severity_map.native_map, (
                f"{key} is in {tool}'s native domain but severity_map.toml does not map it, "
                "and it is not in _DOCUMENTED_NATIVE_GAPS — either map it, or add it there "
                "with the same justification ADR §6 gives for trivy's own UNKNOWN"
            )
