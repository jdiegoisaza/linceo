"""Tests for the `only_fixable` gate counting mode (ADR §8.1 amendment, 2026-10-03)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from linceo.core.config import ConfigurationError, load_config
from linceo.core.context import ExecutionContext, Platform
from linceo.core.execution import ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding, Location, Package
from linceo.core.gate import evaluate_gate
from linceo.core.policy import (
    ConfigLayer,
    CountingCriterion,
    CriterionResolution,
    ThresholdResolution,
)
from linceo.core.remote_policy import merge_remote_into_local
from linceo.core.report_schema import Column, ReportSchema
from linceo.core.reporters import render_console, render_json
from linceo.core.results import RunResult, RunStatus
from linceo.core.severity import Severity, SeveritySource

_TODAY = date(2026, 10, 3)
_FIXABLE = CriterionResolution(CountingCriterion.FIXABLE_ONLY, ConfigLayer.CLI)


def _finding(
    severity: Severity,
    *,
    category: Category = Category.IMAGE,
    fixed: str | None = None,
    name: str = "pkg",
) -> Finding:
    has_package = category in (Category.SCA, Category.IMAGE)
    return Finding(
        fingerprint=f"v1:{category.value}-{name}-{severity.value}-{fixed}",
        tool="trivy" if has_package else "gitleaks",
        category=category,
        rule_id="CVE-2026-1" if has_package else "aws-key",
        message="m",
        location=Location(path="alpine" if has_package else "a.py"),
        severity=severity,
        raw_severity=None,
        severity_source=SeveritySource.NATIVE,
        package=Package(name=name, version="1", fixed_version=fixed) if has_package else None,
        secret_hash=None if has_package else "h",
    )


def _resolution() -> ThresholdResolution:
    return ThresholdResolution.for_fail_on(Severity.HIGH, source=ConfigLayer.CLI)


# --- gate ----------------------------------------------------------------------


def test_default_counts_every_finding_and_leaves_nothing_uncounted() -> None:
    findings = [_finding(Severity.HIGH), _finding(Severity.HIGH, fixed="2")]

    verdict = evaluate_gate(findings, resolution=_resolution())

    assert verdict.counting.criterion is CountingCriterion.ALL
    assert verdict.counts_by_category[Category.IMAGE][Severity.HIGH] == 2
    assert verdict.uncounted_by_category == {}
    assert verdict.criterion_not_applicable == ()
    assert not verdict.passed


def test_fixable_only_leaves_unfixed_findings_out_of_the_gate_but_tallies_them() -> None:
    findings = [
        _finding(Severity.CRITICAL, name="a"),
        _finding(Severity.HIGH, name="b"),
        _finding(Severity.HIGH, name="c", fixed="2"),
    ]

    verdict = evaluate_gate(findings, resolution=_resolution(), counting=_FIXABLE)

    assert verdict.counts_by_category[Category.IMAGE][Severity.CRITICAL] == 0
    assert verdict.counts_by_category[Category.IMAGE][Severity.HIGH] == 1
    assert verdict.uncounted_by_category[Category.IMAGE][Severity.CRITICAL] == 1
    assert verdict.uncounted_by_category[Category.IMAGE][Severity.HIGH] == 1
    assert verdict.counts_by_severity[Severity.CRITICAL] == 1, "the pooled summary lists all"
    assert [b.severity for b in verdict.breaches] == [Severity.HIGH]
    assert verdict.counting is _FIXABLE


def test_a_gate_that_fails_counting_everything_passes_when_only_unfixed_findings_breach() -> None:
    findings = [_finding(Severity.CRITICAL), _finding(Severity.HIGH, name="b")]

    assert not evaluate_gate(findings, resolution=_resolution()).passed
    assert evaluate_gate(findings, resolution=_resolution(), counting=_FIXABLE).passed


def test_an_empty_fixed_version_counts_as_unfixed() -> None:
    verdict = evaluate_gate(
        [_finding(Severity.HIGH, fixed="")], resolution=_resolution(), counting=_FIXABLE
    )

    assert verdict.passed
    assert verdict.uncounted_by_category[Category.IMAGE][Severity.HIGH] == 1


def test_findings_without_fix_data_are_always_counted_and_the_category_is_named() -> None:
    findings = [_finding(Severity.HIGH, category=Category.SECRETS)]

    verdict = evaluate_gate(findings, resolution=_resolution(), counting=_FIXABLE)

    assert not verdict.passed, "a secret must never be excluded for lacking a fix version"
    assert verdict.counts_by_category[Category.SECRETS][Severity.HIGH] == 1
    assert verdict.uncounted_by_category == {}
    assert verdict.criterion_not_applicable == (Category.SECRETS,)


def test_a_category_with_fix_data_is_not_reported_as_not_applicable() -> None:
    findings = [
        _finding(Severity.HIGH, category=Category.SCA, fixed="2"),
        _finding(Severity.HIGH, category=Category.SECRETS),
    ]

    verdict = evaluate_gate(findings, resolution=_resolution(), counting=_FIXABLE)

    assert verdict.criterion_not_applicable == (Category.SECRETS,)


# --- configuration -------------------------------------------------------------


def _load(tmp_path: Path, toml: str = "", **kwargs: object) -> CriterionResolution:
    if toml:
        (tmp_path / ".devsecops").mkdir(exist_ok=True)
        (tmp_path / ".devsecops" / "config.toml").write_text(toml)
    config = load_config(
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=_TODAY,
        **kwargs,  # type: ignore[arg-type]
    )
    return config.counting


def test_the_default_counts_everything(tmp_path: Path) -> None:
    assert _load(tmp_path) == CriterionResolution()


def test_the_policy_document_can_declare_it(tmp_path: Path) -> None:
    resolved = _load(tmp_path, "only_fixable = true\n")

    assert resolved == CriterionResolution(CountingCriterion.FIXABLE_ONLY, ConfigLayer.FILE)


def test_env_beats_the_file_and_records_what_it_replaced(tmp_path: Path) -> None:
    resolved = _load(tmp_path, "only_fixable = true\n", env={"LINCEO_ONLY_FIXABLE": "false"})

    assert resolved.criterion is CountingCriterion.ALL
    assert resolved.source is ConfigLayer.ENV
    assert resolved.superseded is CountingCriterion.FIXABLE_ONLY


def test_cli_beats_env_and_file(tmp_path: Path) -> None:
    resolved = _load(
        tmp_path,
        "only_fixable = false\n",
        cli_overrides={"only_fixable": "true"},
        env={"LINCEO_ONLY_FIXABLE": "false"},
    )

    assert resolved.criterion is CountingCriterion.FIXABLE_ONLY
    assert resolved.source is ConfigLayer.CLI
    assert resolved.superseded is CountingCriterion.ALL


def test_a_higher_layer_agreeing_with_the_policy_supersedes_nothing(tmp_path: Path) -> None:
    resolved = _load(tmp_path, "only_fixable = true\n", cli_overrides={"only_fixable": "true"})

    assert resolved.source is ConfigLayer.CLI
    assert resolved.superseded is None


def test_a_cli_flag_without_a_policy_declaration_supersedes_nothing(tmp_path: Path) -> None:
    resolved = _load(tmp_path, cli_overrides={"only_fixable": "true"})

    assert resolved.superseded is None


def test_env_without_a_policy_declaration(tmp_path: Path) -> None:
    resolved = _load(tmp_path, env={"LINCEO_ONLY_FIXABLE": "1"})

    assert resolved == CriterionResolution(CountingCriterion.FIXABLE_ONLY, ConfigLayer.ENV)


def test_a_non_boolean_value_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="only_fixable"):
        _load(tmp_path, env={"LINCEO_ONLY_FIXABLE": "sometimes"})


def test_a_remote_policy_can_govern_it_and_a_local_cli_flag_still_overrides(
    tmp_path: Path,
) -> None:
    remote = {"only_fixable": True}
    merged = merge_remote_into_local(local_document={}, remote_document=remote)
    assert merged["only_fixable"] is True

    (tmp_path / ".devsecops").mkdir()
    resolved = load_config(
        cli_overrides={"only_fixable": "false"},
        explicit_config_path=None,
        workspace_path=str(tmp_path),
        package_root=str(tmp_path / "package"),
        today=_TODAY,
        remote_document=remote,
    ).counting

    assert resolved.criterion is CountingCriterion.ALL
    assert resolved.superseded is CountingCriterion.FIXABLE_ONLY


# --- report --------------------------------------------------------------------

_CONTEXT = ExecutionContext(
    platform=Platform.LOCAL, repository="acme/w", workspace_path="/w", commit="abc"
)
_SCHEMAS = {
    category: ReportSchema(location=Column(header="LOCATION", fields=("location.path",)))
    for category in (Category.IMAGE, Category.SECRETS)
}


def _run(findings: list[Finding], counting: CriterionResolution) -> RunResult:
    now = datetime(2026, 10, 3, tzinfo=UTC)
    categories = {f.category for f in findings}
    executions = tuple(
        ToolExecution(
            tool="t",
            tool_version="1",
            category=category,
            argv=("t",),
            started_at=now,
            finished_at=now,
            exit_code=0,
            status=ExecutionStatus.COMPLETED,
            findings=tuple(f for f in findings if f.category is category),
            data_sources=(),
        )
        for category in sorted(categories)
    )
    return RunResult(
        run_id="r",
        context=_CONTEXT,
        executions=executions,
        findings=tuple(findings),
        verdict=evaluate_gate(findings, resolution=_resolution(), counting=counting),
        status=RunStatus.COMPLETED,
        severity_map_version="v1",
    )


def test_the_report_declares_what_the_gate_did_not_count() -> None:
    findings = [_finding(Severity.CRITICAL, name="a"), _finding(Severity.LOW, name="b")]

    report = render_console(_run(findings, _FIXABLE), schemas=_SCHEMAS)

    assert "Gate counting: only findings with a fixed version available" in report
    assert "image: 2 (1 CRITICAL, 1 LOW)" in report
    assert "Gate: PASSED (counting only findings with a fix available)" in report


def test_the_report_says_when_nothing_was_left_out() -> None:
    report = render_console(_run([_finding(Severity.LOW, fixed="2")], _FIXABLE), schemas=_SCHEMAS)

    assert "Not counted: none." in report


def test_the_report_warns_for_a_category_the_mode_cannot_apply_to() -> None:
    findings = [_finding(Severity.HIGH, category=Category.SECRETS)]

    report = render_console(_run(findings, _FIXABLE), schemas=_SCHEMAS)

    assert "only_fixable does not apply to secrets" in report
    assert "Gate: FAILED (counting only findings with a fix available)" in report


def test_the_default_report_has_no_counting_block() -> None:
    report = render_console(
        _run([_finding(Severity.HIGH)], CriterionResolution()), schemas=_SCHEMAS
    )

    assert "Gate counting" not in report
    assert "Gate: FAILED\n" in report


@pytest.mark.parametrize(
    ("source", "criterion", "superseded", "expected"),
    [
        (ConfigLayer.CLI, CountingCriterion.FIXABLE_ONLY, CountingCriterion.ALL, "--only-fixable"),
        (
            ConfigLayer.CLI,
            CountingCriterion.ALL,
            CountingCriterion.FIXABLE_ONLY,
            "--no-only-fixable",
        ),
        (
            ConfigLayer.ENV,
            CountingCriterion.ALL,
            CountingCriterion.FIXABLE_ONLY,
            "the LINCEO_ONLY_FIXABLE environment variable",
        ),
    ],
)
def test_the_report_announces_an_override_of_the_policys_criterion(
    source: ConfigLayer,
    criterion: CountingCriterion,
    superseded: CountingCriterion,
    expected: str,
) -> None:
    counting = CriterionResolution(criterion, source, superseded)

    report = render_console(_run([_finding(Severity.LOW)], counting), schemas=_SCHEMAS)

    assert f"Counting override: {expected} replaced" in report
    assert f"declared ({superseded.value}) with {criterion.value}" in report


def test_the_json_report_records_the_criterion_and_the_uncounted() -> None:
    import json

    document = json.loads(render_json(_run([_finding(Severity.HIGH)], _FIXABLE)))

    verdict = document["verdict"]
    assert verdict["counting"]["criterion"] == "fixable-only"
    assert verdict["counting"]["source"] == "cli"
    assert verdict["uncounted_by_category"]["image"]["HIGH"] == 1
