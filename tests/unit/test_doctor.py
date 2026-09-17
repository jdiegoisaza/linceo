"""Tests for `linceo.cli.doctor` (ADR §8, R4): the plain-Python half, no Typer involved.

Mirrors `tests/unit/test_cli_scan_sca.py`'s `FakeToolExecutor` setup for
trivy's `version --format json` shape; none of these scenarios need a real
`gitleaks` or `trivy` binary.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from linceo.adapters.gitleaks import GITLEAKS_BINARY
from linceo.adapters.gitleaks import SUPPORTED_VERSION_RANGE as GITLEAKS_SUPPORTED_VERSION_RANGE
from linceo.adapters.trivy import SUPPORTED_VERSION_RANGE as TRIVY_SUPPORTED_VERSION_RANGE
from linceo.adapters.trivy import TRIVY_BINARY
from linceo.cli.doctor import gather_report, render_report
from linceo.core.findings import Category
from linceo.core.ports import ProcessResult
from linceo.testing import FakeToolExecutor

_NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
_TODAY = date(2026, 9, 17)

_GITLEAKS_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
)


def _trivy_version_result(*, updated_at: str) -> ProcessResult:
    return ProcessResult(
        exit_code=0,
        stdout=(
            '{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
            f'"NextUpdate":"2026-09-20T00:00:00Z","UpdatedAt":"{updated_at}",'
            '"DownloadedAt":"2026-09-14T04:17:21Z"}}'
        ),
        stderr="",
        started_at=_NOW,
        finished_at=_NOW,
    )


def test_both_tools_available_and_compatible_are_healthy() -> None:
    executor = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
            ("trivy", "version", "--format", "json"): _trivy_version_result(
                updated_at="2026-09-14T01:15:36Z"
            ),
        }
    )

    gitleaks_status, trivy_status = gather_report(executor, today=_TODAY)

    assert gitleaks_status.name == "gitleaks"
    assert gitleaks_status.category is Category.SECRETS
    assert gitleaks_status.binary == GITLEAKS_BINARY
    assert gitleaks_status.available is True
    assert gitleaks_status.detected_version == "8.30.1"
    assert gitleaks_status.version_supported is True
    assert gitleaks_status.supported_range == GITLEAKS_SUPPORTED_VERSION_RANGE
    assert gitleaks_status.missing_binary_hint is None
    assert gitleaks_status.data_sources == ()
    assert gitleaks_status.healthy is True

    assert trivy_status.name == "trivy"
    assert trivy_status.category is Category.SCA
    assert trivy_status.binary == TRIVY_BINARY
    assert trivy_status.available is True
    assert trivy_status.detected_version == "0.74.0"
    assert trivy_status.version_supported is True
    assert trivy_status.supported_range == TRIVY_SUPPORTED_VERSION_RANGE
    assert trivy_status.healthy is True
    [db_status] = trivy_status.data_sources
    assert db_status.data_source.name == "trivy-vulnerability-db"
    assert db_status.age_days == 3
    assert db_status.stale is False


def test_a_stale_data_source_is_flagged_but_the_tool_is_still_healthy() -> None:
    """ADR §5: staleness is a WARN, not a hard failure — `healthy` only tracks availability."""
    executor = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
            ("trivy", "version", "--format", "json"): _trivy_version_result(
                updated_at="2026-09-01T00:00:00Z"
            ),
        }
    )

    _, trivy_status = gather_report(executor, today=_TODAY)

    [db_status] = trivy_status.data_sources
    assert db_status.age_days == 16
    assert db_status.stale is True
    assert trivy_status.healthy is True


def test_missing_gitleaks_binary_is_reported_with_its_install_hint() -> None:
    executor = FakeToolExecutor(
        recordings={
            ("trivy", "version", "--format", "json"): _trivy_version_result(
                updated_at="2026-09-14T01:15:36Z"
            ),
        }
    )

    gitleaks_status, _ = gather_report(executor, today=_TODAY)

    assert gitleaks_status.available is False
    assert gitleaks_status.detected_version is None
    assert gitleaks_status.version_supported is None
    assert gitleaks_status.healthy is False
    assert "install gitleaks" in (gitleaks_status.missing_binary_hint or "").lower()


def test_missing_trivy_binary_is_reported_with_its_install_hint() -> None:
    executor = FakeToolExecutor(recordings={("gitleaks", "version"): _GITLEAKS_VERSION_RESULT})

    _, trivy_status = gather_report(executor, today=_TODAY)

    assert trivy_status.available is False
    assert trivy_status.detected_version is None
    assert trivy_status.data_sources == ()
    assert trivy_status.healthy is False
    assert "install trivy" in (trivy_status.missing_binary_hint or "").lower()


def test_trivy_version_output_that_cannot_be_parsed_is_treated_as_unavailable() -> None:
    executor = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
            ("trivy", "version", "--format", "json"): ProcessResult(
                exit_code=0, stdout="not json", stderr="", started_at=_NOW, finished_at=_NOW
            ),
        }
    )

    _, trivy_status = gather_report(executor, today=_TODAY)

    assert trivy_status.available is False
    assert trivy_status.missing_binary_hint is not None


def test_incompatible_gitleaks_version_is_reported_but_still_available() -> None:
    executor = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): ProcessResult(
                exit_code=0, stdout="7.0.0\n", stderr="", started_at=_NOW, finished_at=_NOW
            ),
            ("trivy", "version", "--format", "json"): _trivy_version_result(
                updated_at="2026-09-14T01:15:36Z"
            ),
        }
    )

    gitleaks_status, _ = gather_report(executor, today=_TODAY)

    assert gitleaks_status.available is True
    assert gitleaks_status.detected_version == "7.0.0"
    assert gitleaks_status.version_supported is False
    assert gitleaks_status.healthy is False


def test_render_report_lists_both_tools_and_says_all_are_healthy() -> None:
    executor = FakeToolExecutor(
        recordings={
            ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
            ("trivy", "version", "--format", "json"): _trivy_version_result(
                updated_at="2026-09-14T01:15:36Z"
            ),
        }
    )

    report = render_report(gather_report(executor, today=_TODAY))

    assert "gitleaks (secrets):" in report
    assert "trivy (sca):" in report
    assert "8.30.1" in report
    assert "0.74.0" in report
    assert "trivy-vulnerability-db" in report
    assert "All configured tools are available and within their supported range." in report


def test_render_report_flags_an_unavailable_tool_and_says_so_overall() -> None:
    executor = FakeToolExecutor(recordings={("gitleaks", "version"): _GITLEAKS_VERSION_RESULT})

    report = render_report(gather_report(executor, today=_TODAY))

    assert "NOT FOUND on PATH" in report
    assert "One or more tools are unavailable" in report
