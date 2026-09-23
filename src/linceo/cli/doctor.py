"""``linceo doctor``: tool availability, version compatibility, data-source freshness (ADR §8, R4).

The verification mechanism ADR R4 names for the container image itself:
run as a smoke test in this project's own CI against the reference image,
so a broken or incompatible pinned binary fails the image build rather
than surfacing later as a confusing scan failure. `gather_report` is
reachable from plain Python, with no Typer involved — the `doctor` command
function below only translates its result into console output and an
exit code (AGENTS.md, "CLI framework").

This is also the "embedded, queryable version manifest" ADR R4 asks for,
deliberately realized as a *live* query over the actually-installed
binaries rather than a separate static manifest file baked into the image:
a hand-maintained file could drift from what is really on `PATH` the
moment either pinned version changes in the Dockerfile without someone
remembering to update it too — the same two-sources-of-truth risk this
project avoids everywhere else (`--dry-run` reusing `build_command`
verbatim, `engine.run` being the one place a missing binary's message is
decided, ...). The reference image's own OCI labels (`Dockerfile`, repo
root) are the *externally* queryable half of the same manifest, inspectable
without starting the container at all; `doctor` is the internal half, run
from inside it — both describe the same reality, so they cannot disagree.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime

import typer

from linceo.adapters.checkov import CHECKOV_BINARY, CheckovIntegration
from linceo.adapters.checkov import SUPPORTED_VERSION_RANGE as CHECKOV_SUPPORTED_VERSION_RANGE
from linceo.adapters.gitleaks import GITLEAKS_BINARY, GitleaksIntegration
from linceo.adapters.gitleaks import SUPPORTED_VERSION_RANGE as GITLEAKS_SUPPORTED_VERSION_RANGE
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import SUPPORTED_VERSION_RANGE as TRIVY_SUPPORTED_VERSION_RANGE
from linceo.adapters.trivy import TRIVY_BINARY, TrivyIntegration, TrivyOutputError
from linceo.core.execution import DataSource
from linceo.core.exit_codes import EXIT_OK, EXIT_TOOL_EXECUTION_FAILED
from linceo.core.findings import Category
from linceo.core.policy import DEFAULT_MAX_DATA_SOURCE_AGE_DAYS
from linceo.core.ports import ToolExecutor
from linceo.core.version_range import version_satisfies


@dataclass(frozen=True, slots=True)
class DataSourceStatus:
    """One declared `DataSource`'s age against `DEFAULT_MAX_DATA_SOURCE_AGE_DAYS` (ADR §5)."""

    data_source: DataSource
    age_days: int
    stale: bool


@dataclass(frozen=True, slots=True)
class ToolStatus:
    """One integration's full doctor report: availability, version compliance, data sources.

    `detected_version` and `version_supported` are both `None` exactly
    when `available` is `False` — there is nothing to have detected a
    version *of* — never a separate "unknown" sentinel string standing in
    for that absence (AGENTS.md, "No placeholder code").
    """

    name: str
    category: Category
    binary: str
    supported_range: str
    available: bool
    detected_version: str | None
    version_supported: bool | None
    missing_binary_hint: str | None
    data_sources: tuple[DataSourceStatus, ...]

    @property
    def healthy(self) -> bool:
        """Whether this tool needs no operator attention: present and within its supported range.

        A stale data source is deliberately *not* part of this — ADR §5
        treats staleness as a `WARN`, not a hard failure, by default (a
        stale database still scans, just with `stale_data` flagged); only
        `--max-db-age` (not yet built) would change that. `doctor`'s own
        exit code follows the same distinction (see `doctor` below).
        """
        return self.available and bool(self.version_supported)


def _data_source_status(data_source: DataSource, *, today: date) -> DataSourceStatus:
    age_days = (today - data_source.built_at).days
    return DataSourceStatus(
        data_source=data_source,
        age_days=age_days,
        stale=age_days > DEFAULT_MAX_DATA_SOURCE_AGE_DAYS,
    )


def _probe_gitleaks(executor: ToolExecutor) -> ToolStatus:
    """Probe gitleaks: availability, detected version, and range compliance.

    gitleaks declares no data sources at all (ADR §5; its rules ship baked
    into the binary), so `data_sources` is always empty here.
    """
    try:
        version = GitleaksIntegration.detect_version(executor)
    except FileNotFoundError:
        integration = GitleaksIntegration(version="unknown")
        return ToolStatus(
            name=integration.name,
            category=integration.category,
            binary=GITLEAKS_BINARY,
            supported_range=GITLEAKS_SUPPORTED_VERSION_RANGE,
            available=False,
            detected_version=None,
            version_supported=None,
            missing_binary_hint=integration.missing_binary_hint(),
            data_sources=(),
        )

    integration = GitleaksIntegration(version=version)
    return ToolStatus(
        name=integration.name,
        category=integration.category,
        binary=GITLEAKS_BINARY,
        supported_range=GITLEAKS_SUPPORTED_VERSION_RANGE,
        available=True,
        detected_version=version,
        version_supported=version_satisfies(version, GITLEAKS_SUPPORTED_VERSION_RANGE),
        missing_binary_hint=None,
        data_sources=(),
    )


def _probe_trivy(executor: ToolExecutor, *, today: date) -> ToolStatus:
    """Probe trivy: availability, detected version, range compliance, and its vulnerability DB.

    Raises nothing of its own: `TrivyOutputError` from a malformed
    `trivy version --format json` is treated exactly like a missing
    binary here — trivy is not usable either way, and the actionable hint
    is the same one a real scan would eventually surface. `detect_data_sources`
    is only ever attempted once `detect_version` has already succeeded —
    both call the exact same `trivy version --format json`, so there is no
    honest scenario where the first succeeds and the second then hits a
    missing binary that was not there a moment ago.
    """
    try:
        version = TrivyIntegration.detect_version(executor)
    except (FileNotFoundError, TrivyOutputError):
        integration = TrivyIntegration(version="unknown")
        return ToolStatus(
            name=integration.name,
            category=integration.category,
            binary=TRIVY_BINARY,
            supported_range=TRIVY_SUPPORTED_VERSION_RANGE,
            available=False,
            detected_version=None,
            version_supported=None,
            missing_binary_hint=integration.missing_binary_hint(),
            data_sources=(),
        )

    db_data_sources = TrivyIntegration.detect_data_sources(executor)
    integration = TrivyIntegration(version=version, db_data_sources=db_data_sources)
    return ToolStatus(
        name=integration.name,
        category=integration.category,
        binary=TRIVY_BINARY,
        supported_range=TRIVY_SUPPORTED_VERSION_RANGE,
        available=True,
        detected_version=version,
        version_supported=version_satisfies(version, TRIVY_SUPPORTED_VERSION_RANGE),
        missing_binary_hint=None,
        data_sources=tuple(
            _data_source_status(data_source, today=today)
            for data_source in integration.data_sources()
        ),
    )


def _probe_checkov(executor: ToolExecutor) -> ToolStatus:
    """Probe checkov: availability, detected version, and range compliance.

    checkov declares no data sources at all (ADR §5; like gitleaks, its
    detection rules ship baked into the installed package), so
    `data_sources` is always empty here.
    """
    try:
        version = CheckovIntegration.detect_version(executor)
    except FileNotFoundError:
        integration = CheckovIntegration(version="unknown")
        return ToolStatus(
            name=integration.name,
            category=integration.category,
            binary=CHECKOV_BINARY,
            supported_range=CHECKOV_SUPPORTED_VERSION_RANGE,
            available=False,
            detected_version=None,
            version_supported=None,
            missing_binary_hint=integration.missing_binary_hint(),
            data_sources=(),
        )

    integration = CheckovIntegration(version=version)
    return ToolStatus(
        name=integration.name,
        category=integration.category,
        binary=CHECKOV_BINARY,
        supported_range=CHECKOV_SUPPORTED_VERSION_RANGE,
        available=True,
        detected_version=version,
        version_supported=version_satisfies(version, CHECKOV_SUPPORTED_VERSION_RANGE),
        missing_binary_hint=None,
        data_sources=(),
    )


def gather_report(executor: ToolExecutor, *, today: date) -> tuple[ToolStatus, ...]:
    """Probe every reference integration (ADR §10) and return each one's `ToolStatus`.

    Reachable from plain Python (AGENTS.md, "CLI framework"): this is the
    entire `doctor` command's logic, with nothing here depending on Typer.
    """
    return (
        _probe_gitleaks(executor),
        _probe_trivy(executor, today=today),
        _probe_checkov(executor),
    )


def _render_data_source(status: DataSourceStatus) -> str:
    flag = "STALE" if status.stale else "OK"
    return (
        f"    - {status.data_source.name}: version {status.data_source.version}, "
        f"built {status.data_source.built_at.isoformat()} "
        f"({status.age_days} days old) — {flag}"
    )


def _render_tool(status: ToolStatus) -> list[str]:
    lines = [f"{status.name} ({status.category.value}):"]
    if not status.available:
        lines.append(f"  binary:  {status.binary} — NOT FOUND on PATH")
        lines.extend(f"  {line}" for line in (status.missing_binary_hint or "").splitlines())
        return lines

    lines.append(f"  binary:  {status.binary} — found on PATH")
    range_flag = "OK" if status.version_supported else "UNSUPPORTED"
    lines.append(
        f"  version: {status.detected_version} (supported: {status.supported_range}) — {range_flag}"
    )
    if not status.data_sources:
        lines.append("  data sources: none declared")
    else:
        lines.append("  data sources:")
        lines.extend(_render_data_source(entry) for entry in status.data_sources)
    return lines


def render_report(statuses: tuple[ToolStatus, ...]) -> str:
    """Render every `ToolStatus` as the human-readable text `doctor` prints."""
    lines: list[str] = []
    for status in statuses:
        lines.extend(_render_tool(status))
        lines.append("")

    if all(status.healthy for status in statuses):
        lines.append("All configured tools are available and within their supported range.")
    else:
        lines.append(
            "One or more tools are unavailable or outside their supported version range "
            "— see above for how to install or upgrade them."
        )
    return "\n".join(lines)


def doctor() -> None:
    """Report each configured tool's availability, version compatibility, and data-source age."""
    executor = SubprocessToolExecutor()
    today = datetime.now(UTC).date()

    statuses = gather_report(executor, today=today)

    typer.echo(render_report(statuses))

    all_healthy = all(status.healthy for status in statuses)
    raise typer.Exit(code=EXIT_OK if all_healthy else EXIT_TOOL_EXECUTION_FAILED)
