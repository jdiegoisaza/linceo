"""``linceo baseline``: generate and maintain the exclusions baseline (ADR §8.2).

Two commands, both real-run-first, plain-Python-reachable (AGENTS.md, "CLI
framework"), and byte-preserving toward whatever else already lives in the
policy document:

- **`init`** turns every currently active finding *not already tracked by
  an existing exclusion* into a new `[[exclusions]]` entry, with a shared
  adoption `reason`, the operator-declared `owner`, and an `expires_at`
  staggered by severity (`linceo.core.policy.baseline_wave_expiry`) so a
  mass-generated baseline does not all come due on the same day. New
  entries are appended to the destination's own raw text — this command
  never replaces it (`render_exclusion_fragment`, `linceo.core.policy`).
- **`migrate`** reindexes every exclusion whose `fingerprint` is not on
  today's algorithm version (ADR §5) against a fresh run's findings, by
  the readable identity fields `init` already writes alongside each
  fingerprint (`linceo.core.policy.plan_baseline_migration`) — the
  recovery mechanism ADR §8.2 requires so a fingerprint-version bump does
  not orphan every baseline entry at once. Only the specific
  `fingerprint`/`rule_id` values that actually changed are rewritten, in
  place, in the file's own raw text — never a full re-render of the
  document (see `_apply_migrations_to_text`).

Both load whatever policy document already sits at the destination —
through the same `load_config` every other command uses — and scan *with*
it: `[tool_defaults]`/`[tools.<name>]` apply exactly as they would to a
real `scan <category>`.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

import typer

from linceo.adapters.checkov import CheckovIntegration
from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import TrivyIntegration
from linceo.cli.scan import (
    PlatformOption,
    detect_checkov_version,
    detect_gitleaks_version,
    detect_trivy,
    package_root,
    resolve_context_provider,
)
from linceo.core.config import Config, ConfigurationError, candidate_config_paths, load_config
from linceo.core.context import ContextResolutionError
from linceo.core.engine import run
from linceo.core.execution import ExecutionStatus
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK, EXIT_TOOL_EXECUTION_FAILED
from linceo.core.findings import Category, Finding
from linceo.core.fingerprint import FINGERPRINT_VERSION
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import (
    DEFAULT_BASELINE_EXPIRY_DAYS,
    Exclusion,
    ExclusionMigration,
    MigrationPlan,
    apply_exclusions,
    baseline_wave_expiry,
    is_current_fingerprint,
    plan_baseline_migration,
    render_exclusion_fragment,
    render_exclusions_toml,
    render_toml_string,
)
from linceo.core.ports import ContextProvider, ToolExecutor
from linceo.core.results import RunResult, RunStatus
from linceo.core.severity_map import load_severity_map
from linceo.providers.environment import process_environment

baseline_app = typer.Typer(help="Generate and maintain the exclusions baseline (ADR §8.2).")

#: Recorded on every entry a single `init` run generates — deliberately the
#: same text for all of them ("Un reason compartido de adopción inicial",
#: ADR §8.2), not a per-finding justification: individually justifying a
#: baseline that can run into the hundreds would make the mechanism
#: unusable in practice, a concession the ADR makes explicitly.
DEFAULT_REASON = "Initial adoption baseline — pending real triage"

#: Earlier than any real policy document's `expires_at` could legitimately
#: be — used only as `apply_exclusions`'s `today` in
#: `_already_tracked_fingerprints`, so that no exclusion can ever register
#: as expired relative to it (`apply_exclusions` treats `expires_at <
#: today` as expired; nothing is ever earlier than `date.min`). That is
#: the point: this asks "does *any* exclusion reference this finding",
#: deliberately blind to whether that exclusion has, for real, lapsed.
_ALWAYS_COVERED = date.min


@dataclass(frozen=True, slots=True)
class BaselineResult:
    """What one `gather_baseline` call produced."""

    run_result: RunResult
    new_exclusions: tuple[Exclusion, ...]
    already_tracked_count: int


def _already_tracked_fingerprints(
    findings: tuple[Finding, ...], exclusions: tuple[Exclusion, ...], *, repository: str
) -> set[str]:
    """Fingerprints of `findings` referenced by *any* existing exclusion, expired or not.

    Reuses `apply_exclusions`'s own fingerprint-prefix matching (ADR §7's
    `FP` column) rather than a second implementation of it here, by
    passing a `today` far enough in the future that no real exclusion
    could ever register as expired against it. That is deliberate, not a
    workaround: an exclusion that has genuinely expired is ADR §8.2's own
    signal that a real decision is overdue on that finding — `baseline
    init` must not quietly reset that clock by generating a fresh
    "new" entry for the same finding just because the old one lapsed.
    """
    outcome = apply_exclusions(findings, exclusions, today=_ALWAYS_COVERED, repository=repository)
    return {finding.fingerprint for finding in outcome.suppressed}


def _build_exclusion(
    finding: Finding,
    *,
    reason: str,
    owner: str,
    today: date,
    min_expiry_days: int,
    max_expiry_days: int,
) -> Exclusion:
    """Turn one newly-tracked `Finding` into a baseline `Exclusion`.

    Carries its readable identity fields alongside the fingerprint (ADR
    §8.2) so a future `baseline migrate` can reindex it after a fingerprint
    algorithm bump or a tool renaming a rule.
    """
    expires_at = baseline_wave_expiry(
        severity=finding.severity,
        fingerprint=finding.fingerprint,
        today=today,
        min_expiry_days=min_expiry_days,
        max_expiry_days=max_expiry_days,
    )
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
        resource=finding.resource,
    )


def _run_reference_scan(
    *,
    context_provider: ContextProvider,
    executor: ToolExecutor,
    resolved_config: Config,
    now: datetime,
) -> RunResult:
    """Run both reference integrations fresh, under `resolved_config` (ADR §8.2).

    Shared by `gather_baseline` (`baseline init`) and `gather_migration`
    (`baseline migrate`) — both need the same real run over the current
    workspace, under the same policy, before doing anything specific to
    what each command does with its findings. All three categories run in
    a single `engine.run` call — `run` already accepts `integrations` as a
    category-keyed mapping of any size; `scan <category>`'s "one category
    per invocation" is a CLI surface constraint (ADR §8.3), not a
    limitation of `run` itself, and both baseline commands genuinely need
    "el fichero completo" (ADR §8.2) from one real run, not three
    independently triggered ones a caller would have to reconcile by hand.
    One combined `SeverityNormalizer`, built once from the one loaded
    `severity_map.toml` (ADR §6), covers all three tools correctly: its
    `native_map` is keyed by `(tool, raw_severity)`, and that file's own
    `[native.gitleaks]`/`[native.checkov]` tables are both empty (neither
    tool reports native severity at all), so trivy's own entries are the
    only ones that ever match.

    Running `resolved_config` as-is (rather than a bare `Config()`) means
    `[tool_defaults]`/`[tools.<name>]` apply exactly as they would to a
    real `scan <category>` against the same workspace, and an active
    `ToolSkip` in it is honored the same way too — this is meant to answer
    "what does the repository look like *right now, under the policy
    already in force*", not a view of it with all tuning switched off.
    """
    gitleaks_version = detect_gitleaks_version(executor)
    trivy_version, db_data_sources = detect_trivy(executor)
    checkov_version = detect_checkov_version(executor)
    severity_map = load_severity_map()

    return run(
        run_id=uuid.uuid4().hex,
        context_provider=context_provider,
        integrations={
            Category.SECRETS: GitleaksIntegration(version=gitleaks_version),
            Category.SCA: TrivyIntegration(
                version=trivy_version,
                db_data_sources=db_data_sources,
                cvss_source_preference=severity_map.cvss_source_preference,
            ),
            Category.IAC: CheckovIntegration(version=checkov_version),
        },
        executor=executor,
        normalizer=SeverityNormalizer.from_severity_map(severity_map),
        config=resolved_config,
        now=now,
    )


def gather_baseline(
    *,
    context_provider: ContextProvider,
    executor: ToolExecutor,
    resolved_config: Config,
    now: datetime,
    reason: str,
    owner: str,
    min_expiry_days: int,
) -> BaselineResult:
    """Run a fresh reference scan and build a new `[[exclusions]]` entry per untracked finding.

    Reachable from plain Python, with no Typer involved (AGENTS.md, "CLI
    framework"): `init()` below only translates flags into this call and
    handles the merge/write/confirmation around it.
    """
    result = _run_reference_scan(
        context_provider=context_provider,
        executor=executor,
        resolved_config=resolved_config,
        now=now,
    )

    tracked = _already_tracked_fingerprints(
        result.findings, resolved_config.policy.exclusions, repository=result.context.repository
    )
    today = now.date()
    new_exclusions = tuple(
        _build_exclusion(
            finding,
            reason=reason,
            owner=owner,
            today=today,
            min_expiry_days=min_expiry_days,
            max_expiry_days=resolved_config.max_expiry_horizon_days,
        )
        for finding in result.findings
        if finding.fingerprint not in tracked
    )
    return BaselineResult(
        run_result=result, new_exclusions=new_exclusions, already_tracked_count=len(tracked)
    )


def _incomplete_executions_summary(result: RunResult) -> str:
    """One line per `ToolExecution` that did not produce usable evidence (ADR §5)."""
    lines = [
        f"  - {execution.tool} ({execution.category.value}): {execution.status.value}"
        + (f" — {execution.message}" if execution.message else "")
        for execution in result.executions
        if execution.status in (ExecutionStatus.FAILED, ExecutionStatus.SKIPPED)
    ]
    return "\n".join(lines)


def _render_merge_preview(
    output_path: Path, resolved_config: Config, *, new_count: int, already_tracked_count: int
) -> str:
    """Describe exactly what `init()` is about to do to an *existing* `output_path`.

    Named "merge", never "overwrite": this command only ever appends new
    `[[exclusions]]` entries to what is already there (ADR §8.2's own
    generation mechanism, not a replacement of the document it lives in).
    """
    lines = [f"{output_path} already exists:"]
    lines.append(f"  - {len(resolved_config.policy.exclusions)} existing exclusion(s)")
    lines.append(
        "  - gate: configured ([thresholds])"
        if resolved_config.threshold_resolution.thresholds
        else "  - gate: not configured"
    )
    if resolved_config.policy.tool_skips:
        lines.append(f"  - {len(resolved_config.policy.tool_skips)} tool skip(s)")
    lines.append("")
    lines.append(
        f"This will ADD {new_count} new exclusion(s) for active finding(s) not yet covered "
        f"({already_tracked_count} already are). Nothing existing is modified or removed."
    )
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
            "Where to read/write the baseline. Defaults to the conventional "
            ".devsecops/config.toml inside --path (ADR §5/R5) — the same file "
            "`scan <category> --config` would read. Existing content is never replaced, "
            "only added to."
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
            "Days until the most urgent wave (CRITICAL findings) expires; less severe "
            "findings get progressively longer windows up to the policy's own "
            "max_expiry_horizon_days, staggered so a mass baseline doesn't all come due "
            "on the same day (ADR §8.2)."
        ),
    ),
    force: bool = typer.Option(
        False, "--force", help="Skip the confirmation before adding entries to an existing file."
    ),
) -> None:
    """Generate a fresh exclusions baseline from a real run over the current workspace."""
    workspace_path = str(path.resolve())
    now = datetime.now(UTC)
    today = now.date()
    env = process_environment()

    output_path = Path(
        candidate_config_paths(
            explicit_config_path=str(config) if config is not None else None,
            workspace_path=workspace_path,
        )[0]
    )

    try:
        resolved_config = load_config(
            explicit_config_path=str(output_path),
            workspace_path=workspace_path,
            package_root=package_root(),
            today=today,
        )
    except ConfigurationError as exc:
        typer.echo(
            f"Configuration error: {output_path} already exists but is not a valid policy "
            f"document — refusing to touch it: {exc}",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

    if expires_in_days >= resolved_config.max_expiry_horizon_days:
        typer.echo(
            f"Configuration error: --expires-in-days {expires_in_days} leaves no room to "
            f"stagger within this policy's max_expiry_horizon_days "
            f"({resolved_config.max_expiry_horizon_days}) — lower --expires-in-days, or raise "
            "max_expiry_horizon_days in the policy file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR)

    try:
        context_provider = resolve_context_provider(
            platform=platform, workspace_path=workspace_path, env=env
        )
        baseline = gather_baseline(
            context_provider=context_provider,
            executor=SubprocessToolExecutor(),
            resolved_config=resolved_config,
            now=now,
            reason=reason,
            owner=owner,
            min_expiry_days=expires_in_days,
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

    file_exists = output_path.exists()

    if file_exists and not baseline.new_exclusions:
        # Nothing changes for an *existing* destination: every active
        # finding is already tracked, so there is nothing to append and no
        # reason to touch the file at all. A brand new destination still
        # gets written below even with zero findings (an empty, valid
        # `version = 1` document) — establishing the conventional file is
        # useful on its own, unlike a no-op rewrite of one that already
        # exists.
        typer.echo(
            f"Nothing to add: all {baseline.already_tracked_count} active finding(s) are "
            f"already covered by an existing exclusion in {output_path}."
        )
        raise typer.Exit(code=EXIT_OK)

    fragment = render_exclusion_fragment(baseline.new_exclusions)

    if file_exists:
        if not force:
            typer.echo(
                _render_merge_preview(
                    output_path,
                    resolved_config,
                    new_count=len(baseline.new_exclusions),
                    already_tracked_count=baseline.already_tracked_count,
                )
            )
            proceed = typer.confirm("Add these to the existing file?", default=False)
            if not proceed:
                typer.echo("Aborted: nothing written.", err=True)
                raise typer.Exit(code=EXIT_CONFIGURATION_ERROR)
        existing_text = output_path.read_text(encoding="utf-8")
        merged_text = existing_text.rstrip("\n") + "\n\n" + fragment
    else:
        merged_text = render_exclusions_toml(baseline.new_exclusions)

    # Verify the merged document is itself still valid — the exact same
    # `load_config` any other command would use to read it back, e.g. to
    # confirm these new entries' `expires_at` really do stay within this
    # policy's own `max_expiry_horizon_days` — rather than assuming the
    # arithmetic above got it right, or that concatenating text can't ever
    # produce something `[[exclusions]]`-shaped but otherwise broken.
    # Written to a temp file first and only ever moved into place with an
    # atomic rename: a failed validation, or a crash between the write and
    # the rename, never leaves `output_path` partially written.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(output_path.name + ".tmp")
    temp_path.write_text(merged_text, encoding="utf-8")
    try:
        load_config(
            explicit_config_path=str(temp_path),
            workspace_path=workspace_path,
            package_root=package_root(),
            today=today,
        )
    except ConfigurationError as exc:
        temp_path.unlink()
        typer.echo(f"Refusing to write: the merged document would be invalid: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc
    temp_path.replace(output_path)

    if not baseline.new_exclusions:
        typer.echo(f"No active findings — wrote an empty baseline to {output_path}.")
        raise typer.Exit(code=EXIT_OK)

    expiry_dates = sorted(exclusion.expires_at for exclusion in baseline.new_exclusions)
    typer.echo(
        f"Wrote {len(baseline.new_exclusions)} new exclusion(s) to {output_path} "
        f"({baseline.already_tracked_count} finding(s) already covered, left unchanged), "
        f"expiring between {expiry_dates[0].isoformat()} and {expiry_dates[-1].isoformat()}, "
        "staggered by severity."
    )
    if baseline.run_result.expired_exclusions:
        typer.echo(
            f"Note: {len(baseline.run_result.expired_exclusions)} existing exclusion(s) in "
            f"{output_path} have expired and their finding(s) are active again — left as-is; "
            "review them directly rather than relying on this command to renew them."
        )
    raise typer.Exit(code=EXIT_OK)


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """What one `gather_migration` call found, and what it could resolve (ADR §8.2)."""

    run_result: RunResult
    plan: MigrationPlan


def gather_migration(
    *,
    context_provider: ContextProvider,
    executor: ToolExecutor,
    resolved_config: Config,
) -> MigrationResult:
    """Run a fresh reference scan and compute this policy's `MigrationPlan` against it (ADR §8.2).

    Reachable from plain Python, with no Typer involved (AGENTS.md, "CLI
    framework"): `migrate()` below only translates flags into this call
    and handles the preview/write/confirmation around it. `now` does not
    need to be threaded through here the way `gather_baseline` needs it
    for `expires_at` staggering — migrating never computes a new
    `expires_at` at all (it preserves the original, ADR §8.2), so the only
    use `_run_reference_scan` has for it is the run's own bookkeeping.
    """
    result = _run_reference_scan(
        context_provider=context_provider,
        executor=executor,
        resolved_config=resolved_config,
        now=datetime.now(UTC),
    )
    plan = plan_baseline_migration(
        resolved_config.policy.exclusions, result.findings, repository=result.context.repository
    )
    return MigrationResult(run_result=result, plan=plan)


def _migration_detail_lines(plan: MigrationPlan, *, migrated_header: str) -> list[str]:
    """The per-entry listings shared by the plan preview and the write result (ADR §8.2).

    `migrated_header` is the only thing that differs between the two
    callers ("Would reindex" before writing, "Reindexed" after) — the
    `unresolved`/`out_of_scope` listings are plain facts about this run's
    evidence, true whether or not anything was actually written yet, so
    their wording never needs a tense of its own.
    """
    lines: list[str] = []
    if plan.migrated:
        lines.append("")
        lines.append(f"{migrated_header}:")
        for migration in plan.migrated:
            original, migrated = migration.original, migration.migrated
            renamed = (
                f" (rule_id renamed: {original.rule_id!r} -> {migrated.rule_id!r})"
                if original.rule_id != migrated.rule_id
                else ""
            )
            lines.append(
                f"  - {original.fingerprint} -> {migrated.fingerprint}{renamed} "
                f"owner={migrated.owner} expires_at={migrated.expires_at}"
            )
    if plan.unresolved:
        lines.append("")
        lines.append(
            "Unresolved — no current finding's identity matches theirs. The finding behind "
            "one may have been genuinely fixed, or its identity drifted in a way this cannot "
            "recover automatically either way — left untouched; review and remove, or "
            "re-baseline, by hand:"
        )
        for entry in plan.unresolved:
            lines.append(
                f"  - {entry.fingerprint} category={entry.category} rule_id={entry.rule_id!r} "
                f"path={entry.path!r} owner={entry.owner} reason={entry.reason!r} "
                f"expires_at={entry.expires_at}"
            )
    if plan.out_of_scope:
        lines.append("")
        lines.append(
            "Out of scope for this repository — left untouched; run `migrate` from within "
            "the repository each is scoped to instead:"
        )
        lines.extend(
            f"  - {entry.fingerprint} repositories={list(entry.repositories)}"
            for entry in plan.out_of_scope
        )
    return lines


def _render_migration_plan(plan: MigrationPlan, output_path: Path) -> str:
    """Preview of what `migrate` would do to `output_path`, shown before anything is written.

    Future tense throughout ("would be reindexed") — deliberately not the
    same string `_render_migration_result` prints after writing: printing
    the identical text twice, once before the confirmation prompt and once
    after, would read as an accidental repetition instead of two distinct
    moments (a plan, then what actually happened).
    """
    lines = [
        f"{output_path}: {len(plan.unchanged)} exclusion(s) already on {FINGERPRINT_VERSION}, "
        f"{len(plan.migrated)} would be reindexed, {len(plan.unresolved)} unresolved, "
        f"{len(plan.out_of_scope)} out of scope for this repository."
    ]
    lines.extend(_migration_detail_lines(plan, migrated_header="Would reindex"))
    return "\n".join(lines)


def _render_migration_result(plan: MigrationPlan, output_path: Path) -> str:
    """What `migrate` actually did to `output_path`, shown once, after writing (ADR §8.2).

    Past tense throughout, and names `output_path` as the file that was
    changed — see `_render_migration_plan` for why this is a distinct
    string rather than the same one printed again.
    """
    lines = [
        f"Reindexed {len(plan.migrated)} exclusion(s) in {output_path} "
        f"({len(plan.unchanged)} already on {FINGERPRINT_VERSION}, left unchanged), "
        f"{len(plan.unresolved)} unresolved, {len(plan.out_of_scope)} out of scope "
        "for this repository."
    ]
    lines.extend(_migration_detail_lines(plan, migrated_header="Reindexed"))
    return "\n".join(lines)


#: Matches the header line of one `[[exclusions]]` array-of-tables entry.
_EXCLUSION_HEADER = re.compile(r"^\[\[exclusions\]\][ \t]*$", re.MULTILINE)
#: Matches the start of *any* TOML table or array-of-tables header — where
#: the block a preceding `_EXCLUSION_HEADER` match opened necessarily ends.
_ANY_TABLE_HEADER = re.compile(r"^\[", re.MULTILINE)


def _exclusion_block_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of every `[[exclusions]]` block in `text`, in document order.

    A block runs from its own header to the next line beginning with `[`
    — any other table or array-of-tables header, TOML's own rule for
    where one block ends — or the end of the text. Deliberately not "the
    next `[[exclusions]]` header": that would silently swallow an
    unrelated section (say, `[[skipped_tools]]`) sitting between two
    exclusion entries into the first one's span.
    """
    starts = [match.start() for match in _EXCLUSION_HEADER.finditer(text)]
    spans = []
    for start in starts:
        next_header = _ANY_TABLE_HEADER.search(text, start + len("[[exclusions]]"))
        end = next_header.start() if next_header else len(text)
        spans.append((start, end))
    return spans


def _replace_scalar_field(block: str, *, field: str, new_value: str) -> str:
    """Replace the value of the one `field = "..."` (or `'...'`) line in `block`.

    Matches either TOML basic or literal string quoting, so a hand-edited
    entry that does not happen to use this project's own canonical
    double-quoting (`render_toml_string`) is not silently skipped. Only
    the value between the quotes changes — the line's own indentation and
    trailing whitespace, and everything else in `block`, is untouched.

    Raises:
        ValueError: if `field` is not a scalar-string assignment appearing
            exactly once in `block` — either not found at all (unexpected
            formatting) or found more than once (should be impossible for
            a valid TOML table, whose keys cannot repeat), both cases
            where guessing which line to touch would risk silently
            corrupting the wrong one.
    """
    pattern = re.compile(
        rf'^([ \t]*{re.escape(field)}[ \t]*=[ \t]*)(?:"[^"]*"|\'[^\']*\')([ \t]*)$', re.MULTILINE
    )
    matches = list(pattern.finditer(block))
    if len(matches) != 1:
        msg = f"expected exactly one {field!r} assignment, found {len(matches)}"
        raise ValueError(msg)
    match = matches[0]
    prefix, suffix = match.group(1), match.group(2)
    replacement = f"{prefix}{render_toml_string(new_value)}{suffix}"
    return block[: match.start()] + replacement + block[match.end() :]


def _apply_migrations_to_text(
    text: str, migrations: Sequence[ExclusionMigration], original_exclusions: Sequence[Exclusion]
) -> str:
    """Rewrite only what changed, in place — everything else stays byte-for-byte (ADR §8.2).

    Locates each migrated entry's `[[exclusions]]` block by its position
    in `original_exclusions` — matched to `migrations` by object identity
    (`id(...)`), never by equality, so two entries that happen to have
    identical fields are never confused — and replaces only its
    `fingerprint` line, plus its `rule_id` line when a rename is what
    recovered it. Every other `[[exclusions]]` block, and everything
    outside the `[[exclusions]]` array entirely (`[thresholds]`,
    `[tool_defaults]`/`[tools.<name>]`, comments, formatting), is never
    read, reformatted, or touched — this is what makes `migrate` safe to
    run against a hand-edited document.

    Edits are applied back-to-front (highest span first) so that
    replacing one block's text — which can change its length — never
    shifts the character offsets of a block not yet processed.

    Raises:
        ValueError: if the number of `[[exclusions]]` blocks found in
            `text` does not match `len(original_exclusions)` (the file
            changed under us, or was never what `load_config` parsed), or
            if a migrated entry's `fingerprint`/`rule_id` line cannot be
            replaced unambiguously (see `_replace_scalar_field`) — either
            way, nothing in `text` is modified at all; the caller must
            leave the real file untouched on this exception.
    """
    if not migrations:
        return text

    spans = _exclusion_block_spans(text)
    if len(spans) != len(original_exclusions):
        msg = (
            f"found {len(spans)} '[[exclusions]]' block(s) in the file but parsed "
            f"{len(original_exclusions)} — refusing to guess which is which"
        )
        raise ValueError(msg)

    index_by_id = {id(entry): index for index, entry in enumerate(original_exclusions)}
    ops = sorted(
        ((index_by_id[id(migration.original)], migration) for migration in migrations),
        key=lambda op: op[0],
        reverse=True,
    )

    for index, migration in ops:
        start, end = spans[index]
        block = text[start:end]
        block = _replace_scalar_field(
            block, field="fingerprint", new_value=migration.migrated.fingerprint
        )
        new_rule_id = migration.migrated.rule_id
        # `new_rule_id` is never `None` in practice — it always comes from a
        # matched `Finding.rule_id`, which is a required `str` — but
        # `Exclusion.rule_id`'s own type is `str | None`; the `is not None`
        # check narrows it for mypy as much as it guards against a rename
        # onto a blank original that never had a `rule_id` line to replace.
        if (
            migration.original.rule_id is not None
            and new_rule_id is not None
            and new_rule_id != migration.original.rule_id
        ):
            block = _replace_scalar_field(block, field="rule_id", new_value=new_rule_id)
        text = text[:start] + block + text[end:]
    return text


def migrate(
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
            "Where to read/write the baseline. Defaults to the conventional "
            ".devsecops/config.toml inside --path (ADR §5/R5) — the same file "
            "`scan <category> --config` and `baseline init` would read."
        ),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Skip the confirmation before rewriting entries in the existing file.",
    ),
) -> None:
    """Reindex exclusions whose fingerprint is not on the current algorithm version (ADR §8.2, §5).

    A fingerprint's algorithm version is embedded in its own value
    (`v1:...`); bumping it is a documented breaking change (ADR §5) that
    would otherwise orphan every entry of every baseline at once the
    moment it ships. This command re-runs both reference integrations
    against the current workspace and reindexes each orphaned entry by
    the readable identity fields `baseline init` already writes alongside
    its fingerprint — the same mechanism, without any special case, also
    recovers a tool renaming its `rule_id` between versions (ADR §5).
    """
    workspace_path = str(path.resolve())
    today = datetime.now(UTC).date()
    env = process_environment()

    output_path = Path(
        candidate_config_paths(
            explicit_config_path=str(config) if config is not None else None,
            workspace_path=workspace_path,
        )[0]
    )

    if not output_path.is_file():
        typer.echo(f"Nothing to migrate: {output_path} does not exist yet.")
        raise typer.Exit(code=EXIT_OK)

    try:
        resolved_config = load_config(
            explicit_config_path=str(output_path),
            workspace_path=workspace_path,
            package_root=package_root(),
            today=today,
        )
    except ConfigurationError as exc:
        typer.echo(
            f"Configuration error: {output_path} is not a valid policy document — refusing to "
            f"touch it: {exc}",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

    existing_exclusions = resolved_config.policy.exclusions
    if not existing_exclusions:
        typer.echo(f"Nothing to migrate: {output_path} declares no exclusions.")
        raise typer.Exit(code=EXIT_OK)

    if all(is_current_fingerprint(exclusion.fingerprint) for exclusion in existing_exclusions):
        typer.echo(
            f"Nothing to migrate: all {len(existing_exclusions)} exclusion(s) in {output_path} "
            f"are already on {FINGERPRINT_VERSION}."
        )
        raise typer.Exit(code=EXIT_OK)

    try:
        context_provider = resolve_context_provider(
            platform=platform, workspace_path=workspace_path, env=env
        )
        migration = gather_migration(
            context_provider=context_provider,
            executor=SubprocessToolExecutor(),
            resolved_config=resolved_config,
        )
    except ContextResolutionError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

    if migration.run_result.status is RunStatus.PARTIAL:
        typer.echo(
            "Refusing to migrate from incomplete evidence — at least one tool did not run "
            "cleanly, so this run cannot see the repository's real current state:\n"
            f"{_incomplete_executions_summary(migration.run_result)}\n"
            "Run `linceo doctor` to see what needs fixing, then retry.",
            err=True,
        )
        raise typer.Exit(code=EXIT_TOOL_EXECUTION_FAILED)

    plan = migration.plan

    if not plan.migrated:
        typer.echo(_render_migration_plan(plan, output_path))
        raise typer.Exit(code=EXIT_OK)

    if not force:
        typer.echo(_render_migration_plan(plan, output_path))
        proceed = typer.confirm("Rewrite these fingerprint(s) in place?", default=False)
        if not proceed:
            typer.echo("Aborted: nothing written.", err=True)
            raise typer.Exit(code=EXIT_CONFIGURATION_ERROR)

    original_text = output_path.read_text(encoding="utf-8")
    try:
        new_text = _apply_migrations_to_text(original_text, plan.migrated, existing_exclusions)
    except ValueError as exc:
        typer.echo(
            f"Refusing to migrate: could not locate the exact text to update in {output_path} "
            f"without risking a wrong edit: {exc}",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

    # Same atomic-write discipline as `init()`: written to a temp file,
    # verified by parsing it back with the same `load_config` any other
    # command would use, and only then moved into place — a failed
    # validation, or a crash in between, never leaves `output_path`
    # partially written.
    temp_path = output_path.with_name(output_path.name + ".tmp")
    temp_path.write_text(new_text, encoding="utf-8")
    try:
        load_config(
            explicit_config_path=str(temp_path),
            workspace_path=workspace_path,
            package_root=package_root(),
            today=today,
        )
    except ConfigurationError as exc:
        temp_path.unlink()
        typer.echo(f"Refusing to write: the migrated document would be invalid: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc
    temp_path.replace(output_path)

    typer.echo(_render_migration_result(plan, output_path))
    raise typer.Exit(code=EXIT_OK)


baseline_app.command("init")(init)
baseline_app.command("migrate")(migrate)
