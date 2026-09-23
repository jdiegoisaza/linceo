"""Tests for `CheckovIntegration` (ADR §10) against golden fixtures (ADR §11).

Fixtures live in `tests/unit/fixtures/checkov/` — see that directory's
`README.md` for how `empty.json`, `one_finding.json`, and
`many_findings.json` were captured against a real checkov 3.3.19 binary,
why the JSON report has three distinct top-level shapes, and why
`malformed_truncated.json` and `missing_field.json` are hand-authored
instead.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.adapters.checkov import (
    CHECKOV_BINARY,
    CHECKOV_MISSING_BINARY_HINT,
    CheckovIntegration,
    CheckovOutputError,
)
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.ports import ProcessResult
from linceo.core.severity import Severity, SeveritySource
from linceo.core.severity_map import load_severity_map
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError
from linceo.testing import FakeToolExecutor

_FIXTURES = Path(__file__).parent / "fixtures" / "checkov"
_NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=UTC)


def _process_result(stdout: str = "", *, exit_code: int = 0, stderr: str = "") -> ProcessResult:
    return ProcessResult(
        exit_code=exit_code, stdout=stdout, stderr=stderr, started_at=_NOW, finished_at=_NOW
    )


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


# --- build_command -------------------------------------------------------------


def test_build_command_is_a_list_argv_scanning_workspace_path_with_frameworks_excluded() -> None:
    integration = CheckovIntegration(version="3.3.19")

    argv = integration.build_command(workspace_path="/workspace/widgets", config=ToolConfig())

    assert argv[:5] == ("checkov", "-d", "/workspace/widgets", "-o", "json")
    assert argv[5] == "--skip-framework"
    excluded = set(argv[6].split(","))
    assert excluded == {
        "secrets",
        "sca_package",
        "sca_image",
        "sast",
        "sast_python",
        "sast_java",
        "sast_javascript",
        "sast_typescript",
        "sast_golang",
    }
    assert all(isinstance(part, str) for part in argv)


def test_skip_framework_excludes_secrets_and_sca_to_preserve_category_boundaries() -> None:
    """ADR §10's own reasoning for trivy's `--scanners vuln`, applied to checkov's frameworks."""
    integration = CheckovIntegration(version="3.3.19")

    argv = integration.build_command(workspace_path="/workspace/widgets", config=ToolConfig())

    excluded = set(argv[argv.index("--skip-framework") + 1].split(","))
    assert "secrets" in excluded  # this project's own Gitleaks integration owns that category
    assert "sca_package" in excluded  # this project's own Trivy integration owns that category
    assert "sca_image" in excluded


# --- per-integration configuration (ADR §8.5) -----------------------------------


def test_exclude_paths_are_translated_to_repeated_skip_path_flags() -> None:
    integration = CheckovIntegration(version="3.3.19")

    argv = integration.build_command(
        workspace_path="/workspace/widgets",
        config=ToolConfig(exclude_paths=(".terraform/", "modules/vendored/")),
    )

    skip_paths = [argv[i + 1] for i, part in enumerate(argv) if part == "--skip-path"]
    assert skip_paths == [".terraform/", "modules/vendored/"]


def test_scan_history_raises_unsupported_tool_config_error() -> None:
    """An IaC directory scan has no notion of history to switch between (ADR §8.5)."""
    integration = CheckovIntegration(version="3.3.19")

    with pytest.raises(UnsupportedToolConfigError, match="no notion of scan history"):
        integration.build_command(
            workspace_path="/workspace/widgets", config=ToolConfig(scan_history=True)
        )


def test_custom_rules_path_is_translated_to_external_checks_dir() -> None:
    integration = CheckovIntegration(version="3.3.19")

    argv = integration.build_command(
        workspace_path="/workspace/widgets",
        config=ToolConfig(custom_rules_path="/etc/linceo/checkov-checks"),
    )

    assert "--external-checks-dir" in argv
    index = argv.index("--external-checks-dir")
    assert argv[index + 1] == "/etc/linceo/checkov-checks"


def test_passthrough_flags_are_appended_last() -> None:
    integration = CheckovIntegration(version="3.3.19")

    argv = integration.build_command(
        workspace_path="/workspace/widgets",
        config=ToolConfig(passthrough={"soft-fail": True, "check": ("CKV_AWS_19",)}),
    )

    assert argv[-3:] == ("--soft-fail", "--check", "CKV_AWS_19")


# --- protocol fields -------------------------------------------------------------


def test_name_category_and_version_match_the_protocol_fields() -> None:
    integration = CheckovIntegration(version="3.3.19")

    assert integration.name == "checkov"
    assert integration.category is Category.IAC
    assert integration.version == "3.3.19"


def test_missing_binary_hint_returns_checkov_actionable_install_text() -> None:
    integration = CheckovIntegration(version="3.3.19")

    assert integration.missing_binary_hint() == CHECKOV_MISSING_BINARY_HINT


def test_native_severity_domain_is_empty() -> None:
    """checkov's open-source edition never emits a native severity value at all (ADR §6)."""
    integration = CheckovIntegration(version="3.3.19")

    assert integration.native_severity_domain() == frozenset()


def test_report_schema_locates_findings_by_path_and_line_with_a_resource_column() -> None:
    integration = CheckovIntegration(version="3.3.19")

    schema = integration.report_schema()

    assert schema.location.fields == ("location.path", "location.line")
    assert schema.location.separator == ":"
    assert [column.header for column in schema.extra] == ["RESOURCE"]
    assert schema.extra[0].fields == ("resource",)


def test_data_sources_is_always_empty() -> None:
    """checkov's rules ship baked into the installed package, like gitleaks' (ADR §5)."""
    integration = CheckovIntegration(version="3.3.19")

    assert integration.data_sources() == ()


# --- build_env (ADR R2, ADR §1 amendment) -----------------------------------------


def test_build_env_suppresses_checkovs_own_pypi_update_check() -> None:
    """Confirmed against the real 3.3.19 source: no CLI flag equivalent exists (module docstring)"""
    integration = CheckovIntegration(version="3.3.19")

    assert integration.build_env() == {"CKV_SKIP_PACKAGE_UPDATE_CHECK": "True"}


# --- parse_output(): golden fixtures ---------------------------------------------


def test_empty_report_yields_no_findings() -> None:
    """The bare-summary shape (no `results` key at all) — a clean scan, or no IaC files matched."""
    integration = CheckovIntegration(version="3.3.19")

    findings = integration.parse_output(_process_result(_load("empty.json")))

    assert findings == ()


def test_one_finding_report_is_parsed_into_one_raw_finding() -> None:
    """The single-framework-object shape."""
    integration = CheckovIntegration(version="3.3.19")

    findings = integration.parse_output(_process_result(_load("one_finding.json")))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "checkov"
    assert finding.category is Category.IAC
    assert finding.rule_id == "CKV2_AWS_61"
    assert finding.message == "Ensure that an S3 bucket has a lifecycle configuration"
    assert finding.location.path == "main.tf"  # the leading "/" is stripped
    assert finding.location.line == 1  # file_line_range[0]
    assert finding.resource == "aws_s3_bucket.logs"
    assert finding.raw_severity is None


def test_many_findings_report_is_parsed_into_every_entry_across_frameworks() -> None:
    """The array-of-per-framework-objects shape."""
    integration = CheckovIntegration(version="3.3.19")

    findings = integration.parse_output(_process_result(_load("many_findings.json")))

    assert len(findings) == 3
    assert {finding.rule_id for finding in findings} == {"CKV2_AWS_61", "CKV_DOCKER_8"}


def test_two_resources_sharing_a_rule_and_file_are_kept_as_distinct_findings() -> None:
    """The whole reason `resource` is a fingerprint ingredient (ADR §5 amendment, 2026-09-21):
    without it, these two would be indistinguishable by (rule_id, path) alone."""
    integration = CheckovIntegration(version="3.3.19")

    findings = integration.parse_output(_process_result(_load("many_findings.json")))

    same_rule_and_path = [
        f for f in findings if f.rule_id == "CKV2_AWS_61" and f.location.path == "subdir/main.tf"
    ]
    resources = {f.resource for f in same_rule_and_path}
    assert resources == {"aws_s3_bucket.logs", "aws_s3_bucket.assets"}


def test_blank_stdout_is_treated_as_an_empty_report() -> None:
    integration = CheckovIntegration(version="3.3.19")

    assert integration.parse_output(_process_result("")) == ()


def test_nonzero_exit_with_findings_is_not_treated_as_a_crash() -> None:
    """checkov, like gitleaks, exits non-zero by design whenever it finds anything (ADR §5)."""
    integration = CheckovIntegration(version="3.3.19")

    findings = integration.parse_output(_process_result(_load("one_finding.json"), exit_code=1))

    assert len(findings) == 1


# --- parse_output(): malformed and unexpected shapes ------------------------------


def test_malformed_json_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")

    with pytest.raises(CheckovOutputError, match="not valid JSON"):
        integration.parse_output(_process_result(_load("malformed_truncated.json")))


def test_entry_missing_a_required_field_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")

    with pytest.raises(CheckovOutputError, match="missing required field 'resource'"):
        integration.parse_output(_process_result(_load("missing_field.json")))


def test_report_that_is_neither_object_nor_array_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")

    with pytest.raises(CheckovOutputError, match="JSON object or array"):
        integration.parse_output(_process_result('"just a string"'))


def test_array_entry_that_is_not_an_object_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")

    with pytest.raises(CheckovOutputError, match="array must contain only JSON objects"):
        integration.parse_output(_process_result(json.dumps(["not an object"])))


def test_results_that_is_not_an_object_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps({"check_type": "terraform", "results": "nope"})

    with pytest.raises(CheckovOutputError, match="results must be a JSON object"):
        integration.parse_output(_process_result(document))


def test_failed_checks_that_is_not_a_list_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps({"check_type": "terraform", "results": {"failed_checks": "nope"}})

    with pytest.raises(CheckovOutputError, match="failed_checks must be a JSON array"):
        integration.parse_output(_process_result(document))


def test_framework_document_with_no_results_key_yields_no_findings() -> None:
    """A per-framework object inside an array can itself carry no `results` at all."""
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps([{"check_type": "terraform"}])

    assert integration.parse_output(_process_result(document)) == ()


def test_entry_with_a_non_string_resource_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps(
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_1",
                        "check_name": "example",
                        "file_path": "/main.tf",
                        "resource": 12345,
                    }
                ]
            },
        }
    )

    with pytest.raises(CheckovOutputError, match="must be strings"):
        integration.parse_output(_process_result(document))


def test_entry_that_is_not_an_object_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps(
        {"check_type": "terraform", "results": {"failed_checks": ["just a string"]}}
    )

    with pytest.raises(CheckovOutputError, match="entry must be a JSON object"):
        integration.parse_output(_process_result(document))


def test_entry_with_a_non_string_severity_raises_checkov_output_error() -> None:
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps(
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_1",
                        "check_name": "example",
                        "file_path": "/main.tf",
                        "resource": "aws_s3_bucket.logs",
                        "severity": 5,
                    }
                ]
            },
        }
    )

    with pytest.raises(CheckovOutputError, match="severity must be a string"):
        integration.parse_output(_process_result(document))


def test_entry_with_no_file_line_range_leaves_line_none() -> None:
    integration = CheckovIntegration(version="3.3.19")
    document = json.dumps(
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_1",
                        "check_name": "example",
                        "file_path": "/main.tf",
                        "resource": "aws_s3_bucket.logs",
                    }
                ]
            },
        }
    )

    [finding] = integration.parse_output(_process_result(document))

    assert finding.location.line is None


# --- severity: category default fallback (ADR §6) ---------------------------------


def test_iac_finding_with_no_native_severity_resolves_the_category_default() -> None:
    """[defaults.iac].default in severity_map.toml, not the shared fallback."""
    integration = CheckovIntegration(version="3.3.19")
    [finding] = integration.parse_output(_process_result(_load("one_finding.json")))
    normalizer = SeverityNormalizer.from_severity_map(load_severity_map())

    severity, source = normalizer.resolve(finding)

    assert severity is Severity.MEDIUM
    assert source is SeveritySource.CATEGORY_DEFAULT


# --- detect_version() --------------------------------------------------------------


def test_detect_version_runs_checkov_version_and_returns_stripped_stdout() -> None:
    executor = FakeToolExecutor(
        recordings={
            (CHECKOV_BINARY, "--version"): ProcessResult(
                exit_code=0, stdout="3.3.19\n", stderr="", started_at=_NOW, finished_at=_NOW
            )
        }
    )

    version = CheckovIntegration.detect_version(executor)

    assert version == "3.3.19"
    [(argv, env, cwd, timeout)] = executor.calls
    assert tuple(argv) == (CHECKOV_BINARY, "--version")
    assert env == {}
    assert cwd == "."
    assert timeout is None


def test_detect_version_propagates_file_not_found_for_a_missing_binary() -> None:
    executor = FakeToolExecutor(recordings={})

    with pytest.raises(FileNotFoundError):
        CheckovIntegration.detect_version(executor)
