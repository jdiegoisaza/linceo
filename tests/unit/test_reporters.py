"""Tests for the console and JSON reporters (ADR §7)."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, date, datetime

from linceo.core.baseline import BaselineEntry
from linceo.core.context import ExecutionContext, Platform
from linceo.core.execution import ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding, Location
from linceo.core.gate import evaluate_gate
from linceo.core.reporters import render_console, render_json
from linceo.core.results import RunResult, RunStatus
from linceo.core.severity import Severity, SeveritySource

_CONTEXT = ExecutionContext(
    platform=Platform.LOCAL,
    repository="acme/widgets",
    workspace_path="/workspace",
    commit="abc123",
)
_SECRET_HASH = "deadbeef"  # noqa: S105 -- test fixture value, not a credential


def _finding(severity: Severity) -> Finding:
    return Finding(
        fingerprint=f"v1:{severity.value}",
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id="aws-access-key",
        message="AWS access key detected",
        location=Location(path="src/config.py"),
        severity=severity,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )


def _execution(findings: tuple[Finding, ...]) -> ToolExecution:
    now = datetime(2026, 9, 13, tzinfo=UTC)
    return ToolExecution(
        tool="gitleaks",
        tool_version="8.18.0",
        category=Category.SECRETS,
        argv=("gitleaks", "detect"),
        started_at=now,
        finished_at=now,
        exit_code=0,
        status=ExecutionStatus.COMPLETED,
        findings=findings,
        data_sources=(),
    )


def _result(*, fail_on: Severity | None, findings: tuple[Finding, ...]) -> RunResult:
    return RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(findings),),
        findings=findings,
        verdict=evaluate_gate(findings, fail_on=fail_on),
        status=RunStatus.COMPLETED,
    )


def test_console_report_shows_fixed_threshold_outcome() -> None:
    result = _result(fail_on=Severity.HIGH, findings=(_finding(Severity.HIGH),))

    report = render_console(result)

    assert "run-1" in report
    assert "acme/widgets" in report
    assert "Gate (--fail-on HIGH): FAILED" in report


def test_console_report_hints_at_recommended_threshold_when_not_enforced() -> None:
    result = _result(fail_on=None, findings=(_finding(Severity.CRITICAL),))

    report = render_console(result)

    assert "not enforced (--fail-on none)" in report
    assert "With --fail-on HIGH this run would have failed: 1 CRITICAL" in report


def test_console_report_says_would_have_passed_when_no_breaching_findings() -> None:
    result = _result(fail_on=None, findings=(_finding(Severity.LOW),))

    report = render_console(result)

    assert "would have passed" in report


def test_console_report_shows_the_suppressed_count() -> None:
    result = replace(
        _result(fail_on=None, findings=()), suppressed_findings=(_finding(Severity.HIGH),)
    )

    report = render_console(result)

    assert "Suppressed by baseline: 1" in report


def test_console_report_lists_expired_suppressions() -> None:
    entry = BaselineEntry(
        fingerprint="v1:HIGH", reason="accepted risk", owner="alice", expires_at=date(2026, 1, 1)
    )
    result = replace(_result(fail_on=None, findings=()), expired_suppressions=(entry,))

    report = render_console(result)

    assert "Expired baseline suppressions (1)" in report
    assert "owner=alice" in report


def test_json_report_round_trips_every_finding_losslessly() -> None:
    finding = _finding(Severity.HIGH)
    result = _result(fail_on=Severity.HIGH, findings=(finding,))

    document = json.loads(render_json(result))

    assert document["run_id"] == "run-1"
    assert document["context"]["platform"] == "local"
    assert document["verdict"]["fail_on"] == "HIGH"
    assert document["verdict"]["passed"] is False
    [reported] = document["findings"]
    assert reported["fingerprint"] == finding.fingerprint
    assert reported["severity"] == "HIGH"
    assert reported["location"] == {"path": "src/config.py", "line": None, "column": None}


def test_json_report_is_deterministic() -> None:
    result = _result(fail_on=Severity.HIGH, findings=(_finding(Severity.HIGH),))

    assert render_json(result) == render_json(result)
