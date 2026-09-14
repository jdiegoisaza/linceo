"""Tests for `GitleaksIntegration` (ADR §10) against golden fixtures (ADR §11).

Fixtures live in `tests/unit/fixtures/gitleaks/` — see that directory's
`README.md` for how `empty.json`, `one_finding.json`, and
`many_findings.json` were captured, and why `malformed_truncated.json` and
`missing_field.json` are hand-authored instead.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.adapters.gitleaks import (
    GITLEAKS_BINARY,
    GITLEAKS_MISSING_BINARY_HINT,
    GitleaksIntegration,
    GitleaksOutputError,
)
from linceo.core.findings import Category
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


def _process_result(stdout: str) -> ProcessResult:
    return ProcessResult(exit_code=0, stdout=stdout, stderr="", started_at=_NOW, finished_at=_NOW)


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def test_build_command_is_a_list_argv_scanning_workspace_path() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    argv = integration.build_command(workspace_path="/workspace/widgets")

    assert argv == (
        "gitleaks",
        "detect",
        "--source",
        "/workspace/widgets",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
    )
    assert all(isinstance(part, str) for part in argv)


def test_name_category_and_version_match_the_protocol_fields() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    assert integration.name == "gitleaks"
    assert integration.category is Category.SECRETS
    assert integration.version == "8.30.1"


def test_empty_report_yields_no_findings() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    findings = integration.parse_output(_process_result(_load("empty.json")))

    assert findings == ()


def test_one_finding_report_is_parsed_into_one_raw_finding() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    findings = integration.parse_output(_process_result(_load("one_finding.json")))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "gitleaks"
    assert finding.category is Category.SECRETS
    assert finding.rule_id == "aws-access-token"
    assert finding.location.path == "config.py"
    assert finding.location.line == 1
    assert finding.raw_severity is None
    assert finding.secret_hash == hashlib.sha256(b"AKIAQPFM3ZXVJ7HKQZ2A").hexdigest()


def test_many_findings_report_is_parsed_into_every_entry() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    findings = integration.parse_output(_process_result(_load("many_findings.json")))

    assert len(findings) == 3
    assert {finding.rule_id for finding in findings} == {
        "github-pat",
        "generic-api-key",
        "aws-access-token",
    }
    assert {finding.location.path for finding in findings} == {"secrets/tokens.env", "config.py"}


def test_secret_plaintext_never_appears_anywhere_in_the_parsed_findings() -> None:
    """Only the hash of a detected secret may ever leave `parse_output` (ADR §5, §9)."""
    integration = GitleaksIntegration(version="8.30.1")
    raw_report = _load("one_finding.json")
    plaintext_secret = "AKIAQPFM3ZXVJ7HKQZ2A"  # noqa: S105 -- test fixture value, not a credential
    assert plaintext_secret in raw_report  # sanity check: the fixture does contain it

    findings = integration.parse_output(_process_result(raw_report))

    for finding in findings:
        assert plaintext_secret not in repr(finding)
        assert plaintext_secret not in str(finding)
        assert plaintext_secret not in (finding.message or "")
        assert finding.secret_hash is not None
        assert finding.secret_hash != plaintext_secret


def test_malformed_json_raises_gitleaks_output_error() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    with pytest.raises(GitleaksOutputError, match="not valid JSON"):
        integration.parse_output(_process_result(_load("malformed_truncated.json")))


def test_entry_missing_a_required_field_raises_gitleaks_output_error() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    with pytest.raises(GitleaksOutputError, match="missing required field"):
        integration.parse_output(_process_result(_load("missing_field.json")))


def test_report_that_is_not_a_json_array_raises_gitleaks_output_error() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    with pytest.raises(GitleaksOutputError, match="JSON array"):
        integration.parse_output(_process_result('{"not": "a list"}'))


def test_report_entry_that_is_not_an_object_raises_gitleaks_output_error() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    with pytest.raises(GitleaksOutputError, match="JSON object"):
        integration.parse_output(_process_result('["just a string"]'))


def test_entry_with_a_non_string_rule_id_raises_gitleaks_output_error() -> None:
    integration = GitleaksIntegration(version="8.30.1")
    entry = json.dumps(
        [{"RuleID": 123, "Description": "x", "File": "a.py", "StartLine": 1, "Secret": "s"}]
    )

    with pytest.raises(GitleaksOutputError, match="RuleID and File must both be strings"):
        integration.parse_output(_process_result(entry))


def test_entry_with_a_non_string_secret_raises_gitleaks_output_error() -> None:
    integration = GitleaksIntegration(version="8.30.1")
    entry = json.dumps(
        [{"RuleID": "r", "Description": "x", "File": "a.py", "StartLine": 1, "Secret": 123}]
    )

    with pytest.raises(GitleaksOutputError, match="Secret must be a string"):
        integration.parse_output(_process_result(entry))


def test_blank_stdout_is_treated_as_an_empty_report() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    findings = integration.parse_output(_process_result(""))

    assert findings == ()


def test_data_sources_is_empty_gitleaks_has_no_separate_versioned_data_source() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    assert integration.data_sources() == ()


def test_native_severity_domain_is_empty_gitleaks_emits_no_native_severity() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    assert integration.native_severity_domain() == frozenset()


def test_report_schema_locates_findings_by_path_and_line() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    schema = integration.report_schema()

    assert schema.location.fields == ("location.path", "location.line")
    assert schema.location.separator == ":"
    assert schema.extra == ()


def test_detect_version_runs_gitleaks_version_and_returns_stripped_stdout() -> None:
    executor = FakeToolExecutor(
        recordings={
            (GITLEAKS_BINARY, "version"): ProcessResult(
                exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
            )
        }
    )

    version = GitleaksIntegration.detect_version(executor)

    assert version == "8.30.1"
    [(argv, env, cwd)] = executor.calls
    assert tuple(argv) == (GITLEAKS_BINARY, "version")
    assert env == {}
    assert cwd == "."


def test_detect_version_propagates_file_not_found_for_a_missing_binary() -> None:
    executor = FakeToolExecutor(recordings={})

    with pytest.raises(FileNotFoundError):
        GitleaksIntegration.detect_version(executor)


def test_missing_binary_hint_returns_gitleaks_actionable_install_text() -> None:
    integration = GitleaksIntegration(version="8.30.1")

    assert integration.missing_binary_hint() == GITLEAKS_MISSING_BINARY_HINT
