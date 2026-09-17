"""Tests for `linceo.core.sarif.render_sarif` (ADR §7): the SARIF 2.1.0 exporter.

Every scenario validates its rendered output against the official SARIF
2.1.0 JSON Schema, vendored at `linceo/data/sarif-schema-2.1.0.json` — the
ADR §7 verification mechanism, run here rather than against any remote
copy of the schema, which would make this suite reach the network (ADR
R2).
"""

from __future__ import annotations

import importlib.resources
import json

import jsonschema
import pytest

from linceo.core.context import ExecutionContext, Platform
from linceo.core.execution import ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding, Location, Package
from linceo.core.gate import evaluate_gate
from linceo.core.policy import ConfigLayer, ThresholdResolution
from linceo.core.results import RunResult, RunStatus
from linceo.core.sarif import SARIF_VERSION, render_sarif
from linceo.core.severity import Severity, SeveritySource

_SCHEMA = json.loads(
    importlib.resources.files("linceo.data")
    .joinpath("sarif-schema-2.1.0.json")
    .read_text(encoding="utf-8")
)

_CONTEXT = ExecutionContext(
    platform=Platform.LOCAL,
    repository="acme/widgets",
    workspace_path="/workspace",
    commit="abc123",
)
_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _secret_finding(
    severity: Severity = Severity.HIGH,
    *,
    rule_id: str = "aws-access-key",
    path: str = "src/config.py",
    line: int | None = 12,
    fingerprint_suffix: str = "1",
) -> Finding:
    return Finding(
        fingerprint=f"v1:{fingerprint_suffix}{severity.value}{rule_id}{path}",
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id=rule_id,
        message="AWS access key detected",
        location=Location(path=path, line=line),
        severity=severity,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )


def _sca_finding(
    severity: Severity = Severity.CRITICAL,
    *,
    rule_id: str = "CVE-2024-0001",
    manifest_path: str = "requirements.txt",
    package_name: str = "requests",
    package_version: str = "2.25.0",
    fixed_version: str | None = "2.31.0",
    fingerprint_suffix: str = "1",
) -> Finding:
    return Finding(
        fingerprint=f"v1:{fingerprint_suffix}{severity.value}{rule_id}{manifest_path}",
        tool="trivy",
        category=Category.SCA,
        rule_id=rule_id,
        message=f"{rule_id} affects {package_name} {package_version}",
        location=Location(path=manifest_path),
        severity=severity,
        raw_severity=severity.value,
        severity_source=SeveritySource.NATIVE,
        package=Package(name=package_name, version=package_version, fixed_version=fixed_version),
    )


def _execution(
    *,
    tool: str,
    tool_version: str,
    category: Category,
    findings: tuple[Finding, ...],
    status: ExecutionStatus = ExecutionStatus.COMPLETED,
) -> ToolExecution:
    return ToolExecution(
        tool=tool,
        tool_version=tool_version,
        category=category,
        argv=(tool,),
        started_at=None,
        finished_at=None,
        exit_code=0 if status is ExecutionStatus.COMPLETED else None,
        status=status,
        findings=findings,
        data_sources=(),
    )


def _result(
    executions: tuple[ToolExecution, ...], *, suppressed_findings: tuple[Finding, ...] = ()
) -> RunResult:
    all_findings = tuple(f for execution in executions for f in execution.findings)
    resolution = ThresholdResolution.for_fail_on(None, source=ConfigLayer.DEFAULT)
    return RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=executions,
        findings=all_findings,
        verdict=evaluate_gate(all_findings, resolution=resolution),
        status=RunStatus.COMPLETED,
        suppressed_findings=suppressed_findings,
    )


def _validate(document: object) -> None:
    jsonschema.validate(instance=document, schema=_SCHEMA)


def test_sarif_validates_against_the_vendored_official_schema() -> None:
    secret = _secret_finding()
    vulnerability = _sca_finding()
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(secret,),
            ),
            _execution(
                tool="trivy",
                tool_version="0.50.0",
                category=Category.SCA,
                findings=(vulnerability,),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    _validate(document)


def test_top_level_version_and_schema_fields() -> None:
    result = _result(
        (
            _execution(
                tool="gitleaks", tool_version="8.18.0", category=Category.SECRETS, findings=()
            ),
        )
    )

    document = json.loads(render_sarif(result))

    assert document["version"] == SARIF_VERSION == "2.1.0"
    assert document["$schema"].startswith("https://docs.oasis-open.org/sarif/")


def test_one_sarif_run_per_tool_execution() -> None:
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(_secret_finding(),),
            ),
            _execution(
                tool="trivy",
                tool_version="0.50.0",
                category=Category.SCA,
                findings=(_sca_finding(),),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    assert len(document["runs"]) == 2
    assert document["runs"][0]["tool"]["driver"]["name"] == "gitleaks"
    assert document["runs"][0]["tool"]["driver"]["version"] == "8.18.0"
    assert document["runs"][1]["tool"]["driver"]["name"] == "trivy"
    assert document["runs"][1]["tool"]["driver"]["version"] == "0.50.0"


def test_a_tool_execution_with_no_findings_still_produces_a_valid_empty_run() -> None:
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(),
                status=ExecutionStatus.SKIPPED,
            ),
        )
    )

    document = json.loads(render_sarif(result))

    _validate(document)
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


def test_rules_have_stable_ids_and_results_reference_them_by_index() -> None:
    first = _secret_finding(rule_id="aws-access-key", fingerprint_suffix="1")
    second = _secret_finding(rule_id="generic-api-key", fingerprint_suffix="2")
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(first, second),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    driver = document["runs"][0]["tool"]["driver"]
    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert set(rule_ids) == {"aws-access-key", "generic-api-key"}
    assert len(rule_ids) == len(set(rule_ids))  # each rule declared exactly once

    for sarif_result in document["runs"][0]["results"]:
        rule_index = sarif_result["ruleIndex"]
        assert driver["rules"][rule_index]["id"] == sarif_result["ruleId"]


def test_sarif_carries_every_finding_with_no_row_limit_concept() -> None:
    findings = tuple(
        _secret_finding(rule_id=f"rule-{i}", fingerprint_suffix=str(i)) for i in range(25)
    )
    result = _result(
        (
            _execution(
                tool="gitleaks", tool_version="8.18.0", category=Category.SECRETS, findings=findings
            ),
        )
    )

    document = json.loads(render_sarif(result))

    assert len(document["runs"][0]["results"]) == 25


def test_secrets_finding_region_includes_column_when_the_location_carries_one() -> None:
    """No current parser sets `Location.column` — this locks down the mapping for when one does."""
    finding = Finding(
        fingerprint="v1:column-test",
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py", line=12, column=5),
        severity=Severity.HIGH,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(finding,),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    _validate(document)
    [sarif_result] = document["runs"][0]["results"]
    [location] = sarif_result["locations"]
    assert location["physicalLocation"]["region"] == {"startLine": 12, "startColumn": 5}


def test_sca_finding_location_points_at_the_manifest() -> None:
    finding = _sca_finding(manifest_path="services/api/requirements.txt")
    result = _result(
        (
            _execution(
                tool="trivy", tool_version="0.50.0", category=Category.SCA, findings=(finding,)
            ),
        )
    )

    document = json.loads(render_sarif(result))

    [sarif_result] = document["runs"][0]["results"]
    [location] = sarif_result["locations"]
    uri = location["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "services/api/requirements.txt"
    assert "region" not in location["physicalLocation"]


def test_sca_finding_carries_package_name_version_and_fixed_version_as_properties() -> None:
    finding = _sca_finding(
        package_name="requests", package_version="2.25.0", fixed_version="2.31.0"
    )
    result = _result(
        (
            _execution(
                tool="trivy", tool_version="0.50.0", category=Category.SCA, findings=(finding,)
            ),
        )
    )

    document = json.loads(render_sarif(result))

    [sarif_result] = document["runs"][0]["results"]
    assert sarif_result["properties"] == {
        "package_name": "requests",
        "package_version": "2.25.0",
        "fixed_version": "2.31.0",
    }


def test_sca_finding_with_no_fix_available_still_validates() -> None:
    """`fixed_version=None` documents the loss ADR §7 calls out, not a crash waiting to happen."""
    finding = _sca_finding(fixed_version=None)
    result = _result(
        (
            _execution(
                tool="trivy", tool_version="0.50.0", category=Category.SCA, findings=(finding,)
            ),
        )
    )

    document = json.loads(render_sarif(result))

    _validate(document)
    [sarif_result] = document["runs"][0]["results"]
    assert sarif_result["properties"]["fixed_version"] is None


def test_secrets_finding_has_no_properties_block_and_no_package_data() -> None:
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(_secret_finding(),),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    [sarif_result] = document["runs"][0]["results"]
    assert "properties" not in sarif_result


def test_the_secret_value_and_its_hash_never_appear_in_the_sarif_output() -> None:
    """`Finding` never carries the plaintext secret; this locks down its `secret_hash` too."""
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(_secret_finding(),),
            ),
        )
    )

    report = render_sarif(result)

    assert _SECRET_HASH not in report
    assert "aws-access-key" in report  # sanity: the result did render


def test_fingerprint_travels_in_partial_fingerprints() -> None:
    finding = _secret_finding()
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(finding,),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    [sarif_result] = document["runs"][0]["results"]
    assert sarif_result["partialFingerprints"]["linceo/fingerprint"] == finding.fingerprint


def test_suppressed_finding_carries_an_external_suppression() -> None:
    finding = _secret_finding()
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(finding,),
            ),
        ),
        suppressed_findings=(finding,),
    )

    document = json.loads(render_sarif(result))

    _validate(document)
    [sarif_result] = document["runs"][0]["results"]
    assert sarif_result["suppressions"] == [{"kind": "external"}]


def test_active_finding_carries_no_suppression() -> None:
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(_secret_finding(),),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    [sarif_result] = document["runs"][0]["results"]
    assert "suppressions" not in sarif_result


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_severity_maps_to_the_expected_sarif_level(severity: Severity, expected_level: str) -> None:
    finding = _secret_finding(severity)
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(finding,),
            ),
        )
    )

    document = json.loads(render_sarif(result))

    [sarif_result] = document["runs"][0]["results"]
    assert sarif_result["level"] == expected_level


def test_sarif_output_is_deterministic() -> None:
    result = _result(
        (
            _execution(
                tool="gitleaks",
                tool_version="8.18.0",
                category=Category.SECRETS,
                findings=(_secret_finding(),),
            ),
        )
    )

    assert render_sarif(result) == render_sarif(result)
