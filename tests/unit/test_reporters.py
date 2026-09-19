"""Tests for the console and JSON reporters (ADR §7)."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, date, datetime

from linceo.core.context import ExecutionContext, Platform
from linceo.core.execution import ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding, Location
from linceo.core.gate import evaluate_gate
from linceo.core.policy import ConfigLayer, Exclusion, ThresholdResolution, ToolSkip
from linceo.core.report_schema import Column, ReportSchema, Truncate
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
_SCHEMAS = {
    Category.SECRETS: ReportSchema(
        location=Column(
            header="LOCATION",
            fields=("location.path", "location.line"),
            separator=":",
            max_width=20,
            truncate=Truncate.LEFT,
        )
    )
}


def _finding(
    severity: Severity, *, rule_id: str = "aws-access-key", path: str = "src/config.py"
) -> Finding:
    return Finding(
        fingerprint=f"v1:{severity.value}-{rule_id}-{path}",
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id=rule_id,
        message="AWS access key detected",
        location=Location(path=path, line=1),
        severity=severity,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash=_SECRET_HASH,
    )


def _execution(
    findings: tuple[Finding, ...], *, status: ExecutionStatus = ExecutionStatus.COMPLETED
) -> ToolExecution:
    now = datetime(2026, 9, 13, tzinfo=UTC)
    return ToolExecution(
        tool="gitleaks",
        tool_version="8.18.0",
        category=Category.SECRETS,
        argv=("gitleaks", "detect"),
        started_at=now if status is ExecutionStatus.COMPLETED else None,
        finished_at=now if status is ExecutionStatus.COMPLETED else None,
        exit_code=0 if status is ExecutionStatus.COMPLETED else None,
        status=status,
        findings=findings,
        data_sources=(),
    )


def _result(
    *,
    fail_on: Severity | None,
    findings: tuple[Finding, ...],
    status: RunStatus = RunStatus.COMPLETED,
    execution_status: ExecutionStatus = ExecutionStatus.COMPLETED,
) -> RunResult:
    resolution = ThresholdResolution.for_fail_on(fail_on, source=ConfigLayer.CLI)
    return RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(findings, status=execution_status),),
        findings=findings,
        verdict=evaluate_gate(findings, resolution=resolution),
        status=status,
    )


def _render(result: RunResult, **kwargs: object) -> str:
    return render_console(result, schemas=_SCHEMAS, **kwargs)  # type: ignore[arg-type]


# --- gate verdict lines --------------------------------------------------------


def test_console_report_shows_fixed_threshold_outcome() -> None:
    result = _result(fail_on=Severity.HIGH, findings=(_finding(Severity.HIGH),))

    report = _render(result)

    assert "run-1" in report
    assert "acme/widgets" in report
    assert "Gate: FAILED" in report
    assert "1 HIGH exceeds the maximum allowed of 0" in report


def test_console_report_says_passed_when_no_breaching_findings() -> None:
    result = _result(fail_on=Severity.HIGH, findings=())

    report = _render(result)

    assert "Gate: PASSED" in report


def test_console_report_hints_at_recommended_threshold_when_not_enforced() -> None:
    result = _result(fail_on=None, findings=(_finding(Severity.CRITICAL),))

    report = _render(result)

    assert "not enforced (no thresholds configured)" in report
    assert "With --fail-on high this run would have failed: secrets: 1 CRITICAL" in report


def test_console_report_says_would_have_passed_when_no_breaching_findings() -> None:
    result = _result(fail_on=None, findings=(_finding(Severity.LOW),))

    report = _render(result)

    assert "would have passed" in report


def test_partial_run_never_says_passed_even_if_the_verdict_would_have_passed() -> None:
    result = _result(
        fail_on=Severity.HIGH,
        findings=(),
        status=RunStatus.PARTIAL,
        execution_status=ExecutionStatus.FAILED,
    )

    report = _render(result)

    assert "PASSED" not in report
    assert "Gate: NOT EVALUATED" in report
    assert "evidence is incomplete (1 of 1 executions did not complete)" in report


def test_partial_run_also_reports_a_breach_found_over_the_available_evidence() -> None:
    result = _result(
        fail_on=Severity.HIGH,
        findings=(_finding(Severity.CRITICAL),),
        status=RunStatus.PARTIAL,
        execution_status=ExecutionStatus.FAILED,
    )

    report = _render(result)

    assert "NOT EVALUATED" in report
    assert "would also fail" in report
    assert "1 CRITICAL exceeds the maximum allowed of 0" in report


# --- policy override announcement (ADR §8.1) ----------------------------------


def test_policy_override_is_announced_when_a_flag_replaces_the_files_thresholds() -> None:
    resolution = ThresholdResolution(
        thresholds={Severity.CRITICAL: 0, Severity.HIGH: 0},
        source=ConfigLayer.CLI,
        fail_on=Severity.HIGH,
        superseded={Severity.CRITICAL: 0, Severity.HIGH: 5, Severity.MEDIUM: 25},
        superseded_from=".devsecops/config.toml",
    )
    result = RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(()),),
        findings=(),
        verdict=evaluate_gate((), resolution=resolution),
        status=RunStatus.COMPLETED,
    )

    report = _render(result)

    assert "Policy override: --fail-on high replaced the thresholds declared in" in report
    assert ".devsecops/config.toml" in report
    assert "high=5" in report


def test_policy_override_names_the_environment_variable_when_that_is_the_trigger() -> None:
    resolution = ThresholdResolution(
        thresholds={Severity.CRITICAL: 0},
        source=ConfigLayer.ENV,
        fail_on=Severity.CRITICAL,
        superseded={Severity.HIGH: 5},
        superseded_from=".devsecops/config.toml",
    )
    result = RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(()),),
        findings=(),
        verdict=evaluate_gate((), resolution=resolution),
        status=RunStatus.COMPLETED,
    )

    report = _render(result)

    assert "the LINCEO_FAIL_ON environment variable replaced" in report


def test_policy_override_falls_back_to_a_generic_trigger_when_fail_on_is_none() -> None:
    """`--fail-on none` still overrides the file's `[thresholds]` — it disables the gate."""
    resolution = ThresholdResolution(
        thresholds={},
        source=ConfigLayer.CLI,
        fail_on=None,
        superseded={Severity.HIGH: 5},
        superseded_from=".devsecops/config.toml",
    )
    result = RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(()),),
        findings=(),
        verdict=evaluate_gate((), resolution=resolution),
        status=RunStatus.COMPLETED,
    )

    report = _render(result)

    assert "the resolved configuration replaced" in report


def test_no_policy_override_line_when_nothing_was_superseded() -> None:
    result = _result(fail_on=Severity.HIGH, findings=())

    report = _render(result)

    assert "Policy override" not in report


def test_policy_override_names_a_replaced_category_table_too() -> None:
    resolution = ThresholdResolution(
        thresholds={Severity.CRITICAL: 0, Severity.HIGH: 0},
        source=ConfigLayer.CLI,
        fail_on=Severity.HIGH,
        superseded={Severity.MEDIUM: 25},
        superseded_category_thresholds={Category.SECRETS: {Severity.HIGH: 5}},
        superseded_from=".devsecops/config.toml",
    )
    result = RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(()),),
        findings=(),
        verdict=evaluate_gate((), resolution=resolution),
        status=RunStatus.COMPLETED,
    )

    report = _render(result)

    assert "[thresholds] (medium=25)" in report
    assert "[thresholds.secrets] (high=5)" in report


# --- per-category threshold source announcement (ADR §8.1) --------------------


def test_report_names_the_category_table_that_produced_its_thresholds() -> None:
    resolution = ThresholdResolution(
        thresholds={},
        category_thresholds={Category.SECRETS: {Severity.HIGH: 0}},
        source=ConfigLayer.FILE,
    )
    result = RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(()),),
        findings=(),
        verdict=evaluate_gate((), resolution=resolution),
        status=RunStatus.COMPLETED,
    )

    report = _render(result)

    assert "Thresholds:" in report
    assert "secrets: [thresholds.secrets] (high=0)" in report


def test_report_names_the_default_table_for_a_category_without_its_own() -> None:
    resolution = ThresholdResolution(thresholds={Severity.MEDIUM: 25}, source=ConfigLayer.FILE)
    result = RunResult(
        run_id="run-1",
        context=_CONTEXT,
        executions=(_execution(()),),
        findings=(),
        verdict=evaluate_gate((), resolution=resolution),
        status=RunStatus.COMPLETED,
    )

    report = _render(result)

    assert "secrets: [thresholds] (medium=25)" in report


def test_no_threshold_source_line_when_the_gate_is_not_configured() -> None:
    result = _result(fail_on=None, findings=())

    report = _render(result)

    assert "Thresholds:" not in report


def test_threshold_source_line_names_fail_on_when_it_is_the_active_gate() -> None:
    result = _result(fail_on=Severity.HIGH, findings=())

    report = _render(result)

    assert "Thresholds: --fail-on high (critical=0, high=0), applies to every category." in report


# --- findings tables (ADR §7) --------------------------------------------------


def test_no_findings_collapses_to_a_single_line() -> None:
    result = _result(fail_on=None, findings=())

    report = _render(result)

    assert "secrets: No findings." in report


def test_findings_table_has_the_five_base_columns_and_is_sorted_by_severity() -> None:
    findings = (
        _finding(Severity.LOW, rule_id="low-rule"),
        _finding(Severity.CRITICAL, rule_id="crit-rule"),
    )
    result = _result(fail_on=None, findings=findings)

    report = _render(result)

    header_line = next(line for line in report.splitlines() if line.strip().startswith("SEVERITY"))
    assert header_line.split()[:5] == ["SEVERITY", "ID", "LOCATION", "TOOL", "FP"]
    critical_index = report.index("crit-rule")
    low_index = report.index("low-rule")
    assert critical_index < low_index


def test_the_raw_secret_hash_field_is_never_printed_in_the_table() -> None:
    """`Finding` never carries the plaintext secret; this locks down its `secret_hash` too."""
    result = _result(fail_on=None, findings=(_finding(Severity.HIGH),))

    report = _render(result)

    assert _SECRET_HASH not in report
    assert "aws-access-key" in report  # sanity: the table did render


def test_more_findings_than_max_rows_are_summarized_with_a_count() -> None:
    findings = tuple(_finding(Severity.HIGH, rule_id=f"rule-{i}") for i in range(5))
    result = _result(fail_on=None, findings=findings)

    report = _render(result, max_rows=2)

    assert "... 3 more secrets findings (showing 2 of 5)" in report


def test_max_rows_never_truncates_the_json_report() -> None:
    findings = tuple(_finding(Severity.HIGH, rule_id=f"rule-{i}") for i in range(5))
    result = _result(fail_on=None, findings=findings)

    _render(result, max_rows=2)  # console truncates
    document = json.loads(render_json(result))

    assert len(document["findings"]) == 5


# --- suppressed / expired exclusions (ADR §8.2) -------------------------------


def test_suppressed_and_expired_counts_are_always_shown_even_when_zero() -> None:
    result = _result(fail_on=None, findings=())

    report = _render(result)

    assert "Suppressed by policy: 0" in report
    assert "Expired exclusions: 0" in report


def test_console_report_shows_the_suppressed_count() -> None:
    result = replace(
        _result(fail_on=None, findings=()), suppressed_findings=(_finding(Severity.HIGH),)
    )

    report = _render(result)

    assert "Suppressed by policy: 1" in report


def test_console_report_lists_expired_exclusions() -> None:
    entry = Exclusion(
        fingerprint="v1:HIGH", reason="accepted risk", owner="alice", expires_at=date(2026, 1, 1)
    )
    result = replace(_result(fail_on=None, findings=()), expired_exclusions=(entry,))

    report = _render(result)

    assert "Expired exclusions: 1" in report
    assert "owner=alice" in report


# --- tool skips (ADR §8) --------------------------------------------------------


def test_applied_tool_skip_is_highlighted() -> None:
    skip = ToolSkip(
        tool="gitleaks", reason="rollout paused", owner="team-atlas", expires_at=date(2026, 10, 1)
    )
    result = replace(_result(fail_on=None, findings=()), applied_tool_skips=(skip,))

    report = _render(result)

    assert "Skipped by policy:" in report
    assert "gitleaks owner=team-atlas until=2026-10-01" in report


def test_expired_tool_skip_is_surfaced_too() -> None:
    skip = ToolSkip(
        tool="gitleaks", reason="rollout paused", owner="team-atlas", expires_at=date(2026, 1, 1)
    )
    result = replace(_result(fail_on=None, findings=()), expired_tool_skips=(skip,))

    report = _render(result)

    assert "Expired tool skips, now running again (1)" in report


# --- JSON reporter --------------------------------------------------------------


def test_two_executions_of_the_same_category_only_render_one_table() -> None:
    """Defensive: `engine.run` never produces this (one execution per category), but a
    hand-built `RunResult` should not render the same category's table twice."""
    finding = _finding(Severity.HIGH)
    result = _result(fail_on=None, findings=(finding,))
    result = replace(result, executions=(*result.executions, *result.executions))

    report = _render(result)

    # The gate lines also say "secrets:" (a per-category hint/breach prefix, ADR §8.1) —
    # count only the findings-table section header, which always sits on its own line.
    assert report.count("secrets:\n") == 1


def test_json_report_round_trips_every_finding_losslessly() -> None:
    finding = _finding(Severity.HIGH)
    result = _result(fail_on=Severity.HIGH, findings=(finding,))

    document = json.loads(render_json(result))

    assert document["run_id"] == "run-1"
    assert document["context"]["platform"] == "local"
    assert document["verdict"]["passed"] is False
    assert document["verdict"]["resolution"]["thresholds"]["HIGH"] == 0
    [reported] = document["findings"]
    assert reported["fingerprint"] == finding.fingerprint
    assert reported["severity"] == "HIGH"
    assert reported["location"] == {"path": "src/config.py", "line": 1, "column": None}


def test_json_report_is_deterministic() -> None:
    result = _result(fail_on=Severity.HIGH, findings=(_finding(Severity.HIGH),))

    assert render_json(result) == render_json(result)
