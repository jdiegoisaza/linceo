"""``linceo baseline init``: generate a fresh exclusions baseline from a real run (ADR §8.2).

Turns every active finding a real run over the current workspace produces
into a `[[exclusions]]` entry, with a shared adoption `reason`, the
operator-declared `owner`, and an `expires_at` deliberately shorter than
the general 90-day maximum (`DEFAULT_BASELINE_EXPIRY_DAYS`, 30 days) — the
whole point of a mass-generated baseline is that it "caduque por oleadas y
fuerce un triaje real", not freeze the repository's current state
permanently (ADR §8.2).

Runs with a bare `Config()` on purpose — no pre-existing exclusions,
thresholds, or tool skips applied, and no `--config`/`[tools.<name>]`
per-tool tuning picked up either: `baseline init` exists to answer "what
does this repository actually look like right now", not a view already
filtered by whatever policy happens to sit at the destination it is about
to (over)write.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import typer

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import TRIVY_NATIVE_SEVERITY_MAP, TrivyIntegration
from linceo.cli.scan import (
    PlatformOption,
    detect_gitleaks_version,
    detect_trivy,
    resolve_context_provider,
)
from linceo.core.config import Config, candidate_config_paths
from linceo.core.context import ContextResolutionError
from linceo.core.engine import run
from linceo.core.execution import ExecutionStatus
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK, EXIT_TOOL_EXECUTION_FAILED
from linceo.core.findings import Category, Finding
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import DEFAULT_BASELINE_EXPIRY_DAYS, Exclusion, render_exclusions_toml
from linceo.core.ports import ContextProvider, ToolExecutor
from linceo.core.results import RunResult, RunStatus
from linceo.providers.environment import process_environment

baseline_app = typer.Typer(help="Generate and maintain the exclusions baseline (ADR §8.2).")

#: Recorded on every entry a single `init` run generates — deliberately the
#: same text for all of them ("Un reason compartido de adopción inicial",
#: ADR §8.2), not a per-finding justification: individually justifying a
#: baseline that can run into the hundreds would make the mechanism
#: unusable in practice, a concession the ADR makes explicitly.
DEFAULT_REASON = "Initial adoption baseline — pending real triage"


@dataclass(frozen=True, slots=True)
class BaselineResult:
    """What one `gather_baseline` call produced: the run itself, and the entries built from it."""

    run_result: RunResult
    exclusions: tuple[Exclusion, ...]


def _build_exclusion(finding: Finding, *, reason: str, owner: str, expires_at: date) -> Exclusion:
    """Turn one active `Finding` into a baseline `Exclusion`.

    Carries its readable identity fields alongside the fingerprint (ADR
    §8.2) so a future `baseline migrate` can reindex it after a fingerprint
    algorithm bump or a tool renaming a rule.
    """
    return Exclusion(
        fingerprint=finding.fingerprint,
        reason=reason,
        owner=owner,
        expires_at=expires_at,
        category=finding.category,
        rule_id=finding.rule_id,
        path=finding.location.path,
        package=finding.package.name if finding.package is not None else None,
        package_version=finding.package.version if finding.package is not None else None,
    )


def gather_baseline(
    *,
    context_provider: ContextProvider,
    executor: ToolExecutor,
    now: datetime,
    reason: str,
    owner: str,
    expiry_days: int,
) -> BaselineResult:
    """Run both reference integrations fresh and build one `Exclusion` per active finding.

    Reachable from plain Python, with no Typer involved (AGENTS.md, "CLI
    framework"): `init()` below only translates flags into this call and
    renders/writes its result. Both categories run in a single `engine.run`
    call — `run` already accepts `integrations` as a category-keyed mapping
    of any size; `scan <category>`'s "one category per invocation" is a CLI
    surface constraint (ADR §8.3), not a limitation of `run` itself, and
    `baseline init` genuinely needs "el fichero completo" (ADR §8.2) in one
    real run, not two independently-triggered ones a caller would have to
    reconcile by hand. One combined `SeverityNormalizer` covers both tools
    correctly because `native_map` is keyed by `(tool, raw_severity)` —
    gitleaks contributes no native map at all (it reports no native
    severity, ADR §6), so merging in trivy's changes nothing for it.
    """
    gitleaks_version = detect_gitleaks_version(executor)
    trivy_version, db_data_sources = detect_trivy(executor)

    result = run(
        run_id=uuid.uuid4().hex,
        context_provider=context_provider,
        integrations={
            Category.SECRETS: GitleaksIntegration(version=gitleaks_version),
            Category.SCA: TrivyIntegration(version=trivy_version, db_data_sources=db_data_sources),
        },
        executor=executor,
        normalizer=SeverityNormalizer(native_map=TRIVY_NATIVE_SEVERITY_MAP),
        config=Config(),
        now=now,
    )

    expires_at = now.date() + timedelta(days=expiry_days)
    # No suppressed-findings filtering here: `Config()` carries no
    # exclusions, so `result.findings` (already deduplicated) already *is*
    # the complete active set — nothing in this run could have suppressed
    # anything.
    exclusions = tuple(
        _build_exclusion(finding, reason=reason, owner=owner, expires_at=expires_at)
        for finding in result.findings
    )
    return BaselineResult(run_result=result, exclusions=exclusions)


def _incomplete_executions_summary(result: RunResult) -> str:
    """One line per `ToolExecution` that did not produce usable evidence (ADR §5)."""
    lines = [
        f"  - {execution.tool} ({execution.category.value}): {execution.status.value}"
        + (f" — {execution.message}" if execution.message else "")
        for execution in result.executions
        if execution.status in (ExecutionStatus.FAILED, ExecutionStatus.SKIPPED)
    ]
    return "\n".join(lines)


def init(
    path: Path = typer.Option(Path(), "--path", help="Workspace directory to scan."),
    platform: PlatformOption = typer.Option(
        PlatformOption.AUTO,
        "--platform",
        help=(
            "CI platform to resolve ExecutionContext from. Same flag, same detection order, "
            "as `scan <category> --platform` (ADR §4 R1, §8)."
        ),
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        help=(
            "Where to write the baseline. Defaults to the conventional .devsecops/config.toml "
            "inside --path (ADR §5/R5) — the same file `scan <category> --config` would read."
        ),
    ),
    owner: str = typer.Option(
        ...,
        "--owner",
        help=(
            "Recorded as every generated entry's owner (ADR §8.2) — a team, not a person: "
            "never auto-detected, always explicit."
        ),
    ),
    reason: str = typer.Option(
        DEFAULT_REASON,
        "--reason",
        help=(
            "Shared reason recorded on every generated entry (ADR §8.2: one reason, "
            "not one per finding)."
        ),
    ),
    expires_in_days: int = typer.Option(
        DEFAULT_BASELINE_EXPIRY_DAYS,
        "--expires-in-days",
        help=(
            "Days until every generated entry expires (ADR §8.2: short, to force "
            "real triage in waves)."
        ),
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing file at the destination without asking."
    ),
) -> None:
    """Generate a fresh exclusions baseline from a real run over the current workspace."""
    workspace_path = str(path.resolve())
    now = datetime.now(UTC)
    env = process_environment()

    output_path = Path(
        candidate_config_paths(
            explicit_config_path=str(config) if config is not None else None,
            workspace_path=workspace_path,
        )[0]
    )

    if output_path.exists() and not force:
        overwrite = typer.confirm(f"{output_path} already exists. Overwrite it?", default=False)
        if not overwrite:
            typer.echo("Aborted: nothing written.", err=True)
            raise typer.Exit(code=EXIT_CONFIGURATION_ERROR)

    try:
        context_provider = resolve_context_provider(
            platform=platform, workspace_path=workspace_path, env=env
        )
        baseline = gather_baseline(
            context_provider=context_provider,
            executor=SubprocessToolExecutor(),
            now=now,
            reason=reason,
            owner=owner,
            expiry_days=expires_in_days,
        )
    except ContextResolutionError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

    if baseline.run_result.status is RunStatus.PARTIAL:
        typer.echo(
            "Refusing to write a baseline from incomplete evidence — at least one tool did "
            "not run cleanly, so this run cannot see the repository's real current state:\n"
            f"{_incomplete_executions_summary(baseline.run_result)}\n"
            "Run `linceo doctor` to see what needs fixing, then retry.",
            err=True,
        )
        raise typer.Exit(code=EXIT_TOOL_EXECUTION_FAILED)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_exclusions_toml(baseline.exclusions), encoding="utf-8")

    expires_at = now.date() + timedelta(days=expires_in_days)
    typer.echo(
        f"Wrote {len(baseline.exclusions)} exclusion(s) to {output_path}, "
        f"all expiring {expires_at.isoformat()}."
    )
    raise typer.Exit(code=EXIT_OK)


baseline_app.command("init")(init)
