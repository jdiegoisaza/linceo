"""Tests for `TrivyIntegration` (ADR §10) against golden fixtures (ADR §11).

Fixtures live in `tests/unit/fixtures/trivy/` — see that directory's
`README.md` for how `empty.json`, `one_finding.json`, and
`many_findings.json` were captured against a real trivy 0.74.0 binary, and
why `malformed_truncated.json` and `missing_field.json` are hand-authored
instead. The `UNKNOWN`-severity/CVSS-fallback case and the
database-not-downloaded-yet case are constructed inline in this file for
the same reason documented there.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from linceo.adapters.trivy import (
    TRIVY_BINARY,
    TRIVY_MISSING_BINARY_HINT,
    TRIVY_VULNERABILITY_DB_NAME,
    TrivyDatabaseNotReadyError,
    TrivyIntegration,
    TrivyOutputError,
)
from linceo.core.execution import DataSource, ToolExecutionError
from linceo.core.findings import Category, Package
from linceo.core.normalization import SeverityNormalizer
from linceo.core.ports import ProcessResult
from linceo.core.severity import Severity, SeveritySource
from linceo.core.severity_map import load_severity_map
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError
from linceo.testing import FakeToolExecutor

_FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)

#: Captured verbatim by running `trivy fs --skip-db-update` by hand against
#: an empty `--cache-dir` (see `tests/unit/fixtures/trivy/README.md`) —
#: exit code 1, this exact stderr text.
_REAL_DB_NOT_READY_STDERR = (
    "2026-09-14T20:07:18-05:00\tERROR\t[vulndb] The first run cannot skip downloading DB\n"
    "2026-09-14T20:07:18-05:00\tFATAL\tFatal error\trun error: init error: DB error: "
    "database error: --skip-db-update cannot be specified on the first run\n"
)

#: A hand-built vulnerability entry — shaped exactly like a real one, just
#: with values chosen to exercise a case none of the small, disposable
#: scans behind the captured fixtures happened to produce naturally: a
#: native `Severity` of `UNKNOWN` (deliberately unmapped in
#: `severity_map.toml`'s own `[native.trivy]`, see that file) with two
#: disagreeing CVSS sources, to prove the `nvd`-first preference (ADR §6)
#: is honored even when `redhat` would produce a higher, more alarming
#: score.
_UNKNOWN_SEVERITY_REPORT = json.dumps(
    {
        "SchemaVersion": 2,
        "ArtifactName": ".",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-00001",
                        "PkgName": "example-pkg",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "UNKNOWN",
                        "CVSS": {"redhat": {"V3Score": 9.0}, "nvd": {"V3Score": 6.5}},
                    }
                ],
            }
        ],
    }
)


def _process_result(stdout: str = "", *, exit_code: int = 0, stderr: str = "") -> ProcessResult:
    return ProcessResult(
        exit_code=exit_code, stdout=stdout, stderr=stderr, started_at=_NOW, finished_at=_NOW
    )


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


# --- build_command -----------------------------------------------------------


def test_build_command_is_a_list_argv_scanning_workspace_path() -> None:
    integration = TrivyIntegration(version="0.74.0")

    argv = integration.build_command(workspace_path="/workspace/widgets", config=ToolConfig())

    assert argv == (
        "trivy",
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--skip-db-update",
        "/workspace/widgets",
    )
    assert all(isinstance(part, str) for part in argv)


# --- per-integration configuration (ADR §8.5) --------------------------------


def test_exclude_paths_are_translated_to_repeated_skip_dirs_flags() -> None:
    """Unlike gitleaks, trivy has a real flag for this (ADR §8.5's motivating contrast)."""
    integration = TrivyIntegration(version="0.74.0")

    argv = integration.build_command(
        workspace_path="/workspace/widgets",
        config=ToolConfig(exclude_paths=("node_modules/", ".venv/")),
    )

    assert "--skip-dirs" in argv
    skip_dirs = [argv[i + 1] for i, part in enumerate(argv) if part == "--skip-dirs"]
    assert skip_dirs == ["node_modules/", ".venv/"]
    assert argv[-1] == "/workspace/widgets"  # the positional path stays last


def test_scan_history_raises_unsupported_tool_config_error() -> None:
    """A dependency-manifest scan has no notion of history to switch between (ADR §8.5)."""
    integration = TrivyIntegration(version="0.74.0")

    with pytest.raises(UnsupportedToolConfigError, match="no notion of scan history"):
        integration.build_command(
            workspace_path="/workspace/widgets", config=ToolConfig(scan_history=False)
        )


def test_custom_rules_path_raises_unsupported_tool_config_error() -> None:
    """trivy's vulnerability scanner has no rule-file equivalent, unlike gitleaks (ADR §8.5)."""
    integration = TrivyIntegration(version="0.74.0")

    with pytest.raises(UnsupportedToolConfigError, match="no rule-file equivalent"):
        integration.build_command(
            workspace_path="/workspace/widgets",
            config=ToolConfig(custom_rules_path="/etc/linceo/trivy-custom.yaml"),
        )


def test_passthrough_flags_are_appended_after_the_positional_path() -> None:
    integration = TrivyIntegration(version="0.74.0")

    argv = integration.build_command(
        workspace_path="/workspace/widgets",
        config=ToolConfig(passthrough={"severity": ("HIGH", "CRITICAL"), "quiet": True}),
    )

    assert argv[-5:] == ("--severity", "HIGH", "--severity", "CRITICAL", "--quiet")


# --- protocol fields ----------------------------------------------------------


def test_name_category_and_version_match_the_protocol_fields() -> None:
    integration = TrivyIntegration(version="0.74.0")

    assert integration.name == "trivy"
    assert integration.category is Category.SCA
    assert integration.version == "0.74.0"


def test_missing_binary_hint_returns_trivy_actionable_install_text() -> None:
    integration = TrivyIntegration(version="0.74.0")

    assert integration.missing_binary_hint() == TRIVY_MISSING_BINARY_HINT


def test_native_severity_domain_matches_trivys_own_severity_flag_values() -> None:
    integration = TrivyIntegration(version="0.74.0")

    assert integration.native_severity_domain() == frozenset(
        {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    )


def test_report_schema_locates_findings_by_package_and_version() -> None:
    integration = TrivyIntegration(version="0.74.0")

    schema = integration.report_schema()

    assert schema.location.fields == ("package.name", "package.version")
    assert schema.location.separator == "@"
    assert [column.header for column in schema.extra] == ["MANIFEST", "FIXED"]


# --- data_sources() (ADR §5) --------------------------------------------------


def test_data_sources_is_empty_by_default() -> None:
    integration = TrivyIntegration(version="0.74.0")

    assert integration.data_sources() == ()


def test_data_sources_returns_whatever_was_resolved_at_construction() -> None:
    source = DataSource(name=TRIVY_VULNERABILITY_DB_NAME, version="2", built_at=date(2026, 9, 14))
    integration = TrivyIntegration(version="0.74.0", db_data_sources=(source,))

    assert integration.data_sources() == (source,)


# --- parse_output(): golden fixtures ------------------------------------------


def test_empty_report_yields_no_findings() -> None:
    integration = TrivyIntegration(version="0.74.0")

    findings = integration.parse_output(_process_result(_load("empty.json")))

    assert findings == ()


def test_one_finding_report_is_parsed_into_one_raw_finding() -> None:
    integration = TrivyIntegration(version="0.74.0")

    findings = integration.parse_output(_process_result(_load("one_finding.json")))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "trivy"
    assert finding.category is Category.SCA
    assert finding.rule_id == "CVE-2023-37920"
    assert finding.location.path == "requirements.txt"
    assert finding.raw_severity == "HIGH"
    assert finding.cvss_score == 9.8  # nvd's V3Score, preferred over ghsa's 7.5 and redhat's 9.1
    assert finding.package == Package(
        name="certifi", version="2015.4.28", fixed_version="2023.7.22"
    )


def test_many_findings_report_is_parsed_into_every_entry() -> None:
    integration = TrivyIntegration(version="0.74.0")

    findings = integration.parse_output(_process_result(_load("many_findings.json")))

    assert len(findings) == 3
    assert {finding.rule_id for finding in findings} == {
        "CVE-2020-14343",
        "CVE-2020-1747",
        "CVE-2023-37920",
    }
    assert {finding.package.name for finding in findings if finding.package} == {
        "PyYAML",
        "certifi",
    }
    assert all(finding.location.path == "requirements.txt" for finding in findings)


def test_blank_stdout_is_treated_as_an_empty_report() -> None:
    integration = TrivyIntegration(version="0.74.0")

    assert integration.parse_output(_process_result("")) == ()


# --- parse_output(): malformed and unexpected shapes --------------------------


def test_malformed_json_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")

    with pytest.raises(TrivyOutputError, match="not valid JSON"):
        integration.parse_output(_process_result(_load("malformed_truncated.json")))


def test_entry_missing_a_required_field_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")

    with pytest.raises(TrivyOutputError, match="missing required field"):
        integration.parse_output(_process_result(_load("missing_field.json")))


def test_report_that_is_not_a_json_object_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")

    with pytest.raises(TrivyOutputError, match="JSON object"):
        integration.parse_output(_process_result("[]"))


def test_results_that_is_not_a_list_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")

    with pytest.raises(TrivyOutputError, match="Results must be a JSON array"):
        integration.parse_output(_process_result(json.dumps({"Results": "nope"})))


def test_result_entry_that_is_not_an_object_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps({"Results": ["just a string"]})

    with pytest.raises(TrivyOutputError, match="Results entry must be a JSON object"):
        integration.parse_output(_process_result(document))


def test_result_entry_missing_target_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {"Results": [{"Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": []}]}
    )

    with pytest.raises(TrivyOutputError, match="Target"):
        integration.parse_output(_process_result(document))


def test_vulnerabilities_that_is_not_a_list_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": "nope"}]})

    with pytest.raises(TrivyOutputError, match="Vulnerabilities must be a JSON array"):
        integration.parse_output(_process_result(document))


def test_entry_with_a_non_string_package_name_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "PkgName": 123, "InstalledVersion": "1.0"}
                    ],
                }
            ]
        }
    )

    with pytest.raises(TrivyOutputError, match="VulnerabilityID and PkgName must both be strings"):
        integration.parse_output(_process_result(document))


def test_vulnerability_entry_that_is_not_an_object_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {"Results": [{"Target": "requirements.txt", "Vulnerabilities": ["just a string"]}]}
    )

    with pytest.raises(TrivyOutputError, match="vulnerability entry must be a JSON object"):
        integration.parse_output(_process_result(document))


def test_entry_with_a_non_string_installed_version_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "PkgName": "pkg", "InstalledVersion": 100}
                    ],
                }
            ]
        }
    )

    with pytest.raises(TrivyOutputError, match="InstalledVersion must be a string"):
        integration.parse_output(_process_result(document))


def test_entry_with_a_non_string_fixed_version_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "pkg",
                            "InstalledVersion": "1.0",
                            "FixedVersion": 100,
                        }
                    ],
                }
            ]
        }
    )

    with pytest.raises(TrivyOutputError, match="FixedVersion must be a string"):
        integration.parse_output(_process_result(document))


def test_entry_with_a_non_string_severity_raises_trivy_output_error() -> None:
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "pkg",
                            "InstalledVersion": "1.0",
                            "Severity": 5,
                        }
                    ],
                }
            ]
        }
    )

    with pytest.raises(TrivyOutputError, match="Severity must be a string"):
        integration.parse_output(_process_result(document))


def test_cvss_source_with_a_non_object_value_is_skipped() -> None:
    """A malformed single source is skipped, not fatal — the rest of the report is still usable."""
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "pkg",
                            "InstalledVersion": "1.0",
                            "Severity": "UNKNOWN",
                            "CVSS": {"nvd": "not an object", "redhat": {"V3Score": 4.2}},
                        }
                    ],
                }
            ]
        }
    )

    [finding] = integration.parse_output(_process_result(document))

    assert finding.cvss_score == 4.2  # falls through to the next source, alphabetically


def test_cvss_with_no_v3_score_anywhere_leaves_cvss_score_none() -> None:
    """Only a CVSS v2 (or v4) score, with no v3.1 base score, resolves to no usable CVSS."""
    integration = TrivyIntegration(version="0.74.0")
    document = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "pkg",
                            "InstalledVersion": "1.0",
                            "Severity": "UNKNOWN",
                            "CVSS": {"nvd": {"V2Score": 5.0}, "other": {"V40Score": 9.3}},
                        }
                    ],
                }
            ]
        }
    )

    [finding] = integration.parse_output(_process_result(document))

    assert finding.cvss_score is None


# --- parse_output(): non-zero exit codes (ADR §5, R2) -------------------------


def test_database_not_ready_raises_an_actionable_error_matching_the_real_trivy_message() -> None:
    integration = TrivyIntegration(version="0.74.0")
    result = _process_result(exit_code=1, stderr=_REAL_DB_NOT_READY_STDERR)

    with pytest.raises(TrivyDatabaseNotReadyError) as exc_info:
        integration.parse_output(result)

    assert isinstance(exc_info.value, ToolExecutionError)
    assert "download" in str(exc_info.value).lower()
    assert "--skip-db-update" in str(exc_info.value)


def test_some_other_nonzero_exit_raises_a_generic_trivy_output_error() -> None:
    """A generic crash is not the specific, actionable database-not-ready case."""
    integration = TrivyIntegration(version="0.74.0")
    result = _process_result(exit_code=1, stderr="panic: something unrelated crashed")

    with pytest.raises(TrivyOutputError, match="exited with status 1") as exc_info:
        integration.parse_output(result)

    assert not isinstance(exc_info.value, TrivyDatabaseNotReadyError)


# --- severity: native vs. CVSS precedence (ADR §6) ----------------------------


def test_native_severity_wins_over_a_present_cvss_score() -> None:
    integration = TrivyIntegration(version="0.74.0")
    [finding] = integration.parse_output(_process_result(_load("one_finding.json")))
    normalizer = SeverityNormalizer.from_severity_map(load_severity_map())

    severity, source = normalizer.resolve(finding)

    assert severity is Severity.HIGH  # trivy's own native Severity for this CVE
    assert source is SeveritySource.NATIVE


def test_unknown_severity_prefers_nvd_cvss_source_deterministically() -> None:
    """ADR §6's own worked example: NVD before a distro/vendor advisory — the default
    `cvss_source_preference` matches `severity_map.toml`'s own shipped value."""
    integration = TrivyIntegration(version="0.74.0")

    [finding] = integration.parse_output(_process_result(_UNKNOWN_SEVERITY_REPORT))

    assert finding.raw_severity == "UNKNOWN"
    assert finding.cvss_score == 6.5  # nvd, not redhat's higher 9.0


def test_unknown_native_severity_falls_back_to_the_cvss_bucket_via_the_normalizer() -> None:
    """severity_map.toml deliberately excludes UNKNOWN so CVSS still gets a chance."""
    integration = TrivyIntegration(version="0.74.0")
    [finding] = integration.parse_output(_process_result(_UNKNOWN_SEVERITY_REPORT))
    normalizer = SeverityNormalizer.from_severity_map(load_severity_map())

    severity, source = normalizer.resolve(finding)

    assert severity is Severity.MEDIUM  # 6.5 falls in CVSS v3.1's 4.0-6.9 bucket (ADR §6)
    assert source is SeveritySource.CVSS


# --- detect_version() ---------------------------------------------------------


def test_detect_version_runs_trivy_version_json_and_returns_the_version_field() -> None:
    executor = FakeToolExecutor(
        recordings={
            (TRIVY_BINARY, "version", "--format", "json"): ProcessResult(
                exit_code=0,
                stdout='{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
                '"NextUpdate":"2026-09-15T01:15:36.636778479Z",'
                '"UpdatedAt":"2026-09-14T01:15:36.63677888Z",'
                '"DownloadedAt":"2026-09-14T04:17:21.725730573Z"}}',
                stderr="",
                started_at=_NOW,
                finished_at=_NOW,
            )
        }
    )

    version = TrivyIntegration.detect_version(executor)

    assert version == "0.74.0"
    [(argv, env, cwd, timeout)] = executor.calls
    assert tuple(argv) == (TRIVY_BINARY, "version", "--format", "json")
    assert env == {}
    assert cwd == "."
    assert timeout is None


def test_detect_version_raises_trivy_output_error_when_version_field_is_not_a_string() -> None:
    executor = FakeToolExecutor(
        recordings={
            (TRIVY_BINARY, "version", "--format", "json"): ProcessResult(
                exit_code=0, stdout='{"Version": 74}', stderr="", started_at=_NOW, finished_at=_NOW
            )
        }
    )

    with pytest.raises(TrivyOutputError, match="'Version' field must be a string"):
        TrivyIntegration.detect_version(executor)


def test_detect_version_propagates_file_not_found_for_a_missing_binary() -> None:
    executor = FakeToolExecutor(recordings={})

    with pytest.raises(FileNotFoundError):
        TrivyIntegration.detect_version(executor)


def test_detect_version_raises_trivy_output_error_for_unparseable_output() -> None:
    executor = FakeToolExecutor(
        recordings={
            (TRIVY_BINARY, "version", "--format", "json"): ProcessResult(
                exit_code=0, stdout="not json at all", stderr="", started_at=_NOW, finished_at=_NOW
            )
        }
    )

    with pytest.raises(TrivyOutputError):
        TrivyIntegration.detect_version(executor)


# --- detect_data_sources() (ADR §5) -------------------------------------------


def test_detect_data_sources_returns_the_cached_database_metadata() -> None:
    executor = FakeToolExecutor(
        recordings={
            (TRIVY_BINARY, "version", "--format", "json"): ProcessResult(
                exit_code=0,
                stdout='{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
                '"NextUpdate":"2026-09-15T01:15:36.636778479Z",'
                '"UpdatedAt":"2026-09-14T01:15:36.63677888Z",'
                '"DownloadedAt":"2026-09-14T04:17:21.725730573Z"}}',
                stderr="",
                started_at=_NOW,
                finished_at=_NOW,
            )
        }
    )

    [source] = TrivyIntegration.detect_data_sources(executor)

    assert source.name == TRIVY_VULNERABILITY_DB_NAME
    assert source.version == "2"
    assert source.built_at == date(2026, 9, 14)


def test_detect_data_sources_is_empty_when_no_database_was_ever_downloaded() -> None:
    """Captured verbatim: `trivy version --format json` against an empty `--cache-dir`."""
    executor = FakeToolExecutor(
        recordings={
            (TRIVY_BINARY, "version", "--format", "json"): ProcessResult(
                exit_code=0,
                stdout='{"Version":"0.74.0"}',
                stderr="",
                started_at=_NOW,
                finished_at=_NOW,
            )
        }
    )

    assert TrivyIntegration.detect_data_sources(executor) == ()


def test_detect_data_sources_is_empty_for_unparseable_output() -> None:
    executor = FakeToolExecutor(
        recordings={
            (TRIVY_BINARY, "version", "--format", "json"): ProcessResult(
                exit_code=0, stdout="not json", stderr="", started_at=_NOW, finished_at=_NOW
            )
        }
    )

    assert TrivyIntegration.detect_data_sources(executor) == ()


def test_detect_data_sources_propagates_file_not_found_for_a_missing_binary() -> None:
    executor = FakeToolExecutor(recordings={})

    with pytest.raises(FileNotFoundError):
        TrivyIntegration.detect_data_sources(executor)
