"""``linceo scan secrets`` / ``linceo scan sca``: run one tool end to end (ADR §8, §10).

Translates CLI flags into the domain objects `linceo.core.engine.run`
already expects, and nothing more (AGENTS.md, "CLI framework") — the exact
same run is reachable from Python directly, by constructing the same
objects and calling `run`, without going through Typer at all.

`scan_secrets` (Gitleaks) and `scan_sca` (Trivy) share every step
downstream of constructing their own `ToolIntegration` instance — resolving
configuration, merging `ToolConfig`, `--dry-run`, calling `run`, error
handling, and reporting — through `_run_scan`, so that shared plumbing
exists exactly once instead of drifting between the two commands now that
there are two.
"""

import shlex
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import TRIVY_NATIVE_SEVERITY_MAP, TrivyIntegration, TrivyOutputError
from linceo.core.config import Config, ConfigurationError, load_config
from linceo.core.engine import run
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, compute_exit_code
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import PolicyConfigurationError
from linceo.core.ports import ToolExecutor, ToolIntegration
from linceo.core.reporters import render_console, render_json
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, resolve_tool_config
from linceo.providers.environment import process_environment
from linceo.providers.local import ContextResolutionError, LocalContextProvider

scan_app = typer.Typer(help="Run a scan category against a workspace and produce one verdict.")


class OutputFormat(StrEnum):
    """Report formats `scan <category>` can render today (ADR §7 minus SARIF, not yet built)."""

    CONSOLE = "console"
    JSON = "json"


class FailOnOption(StrEnum):
    """CLI-only mirror of the severity scale plus the `none` sentinel (ADR §8.1).

    Kept separate from `linceo.core.severity.Severity` because `none` — the
    default — is not itself a severity level, and because `INFO` is
    deliberately absent: ADR §6 guarantees INFO never blocks the gate under
    any threshold configuration, so it cannot be offered as a cutoff either.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _package_root() -> str:
    """The installed `linceo` package's own directory (ADR §5/R5's "never inside this package")."""
    return str(Path(__file__).resolve().parents[1])


def _cli_overrides(
    *,
    fail_on: FailOnOption | None,
    continue_on_tool_error: bool | None,
    strict_normalization: bool | None,
    max_rows: int | None,
) -> dict[str, str]:
    """Translate the scalar flags shared by every `scan <category>` command for `load_config`."""
    overrides: dict[str, str] = {}
    if fail_on is not None:
        overrides["fail_on"] = fail_on.value
    if continue_on_tool_error is not None:
        overrides["continue_on_tool_error"] = str(continue_on_tool_error)
    if strict_normalization is not None:
        overrides["strict_normalization"] = str(strict_normalization)
    if max_rows is not None:
        overrides["report_max_rows"] = str(max_rows)
    return overrides


def _load_resolved_config(
    *,
    cli_overrides: dict[str, str],
    config_path: Path | None,
    workspace_path: str,
    now: datetime,
) -> Config:
    """`load_config`, translating `ConfigurationError` into the CLI's exit-2 contract (ADR §8)."""
    try:
        return load_config(
            cli_overrides=cli_overrides,
            env=process_environment(),
            explicit_config_path=str(config_path) if config_path is not None else None,
            workspace_path=workspace_path,
            package_root=_package_root(),
            today=now.date(),
        )
    except ConfigurationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc


def _run_scan(
    *,
    category: Category,
    integration: ToolIntegration,
    workspace_path: str,
    executor: ToolExecutor,
    normalizer: SeverityNormalizer,
    resolved_config: Config,
    output_format: OutputFormat,
    dry_run: bool,
    now: datetime,
) -> None:
    """Resolve `integration`'s `ToolConfig`, run it, and report — shared by every `scan` command.

    Everything from here on is identical for `secrets` and `sca`: only the
    already-constructed `integration`, its `category`, the `executor` it
    was detected through, and the `SeverityNormalizer` it needs differ by
    caller.
    """
    tool_config = resolve_tool_config(
        defaults=resolved_config.tool_defaults,
        override=resolved_config.tool_configs.get(integration.name, ToolConfig()),
    )

    if dry_run:
        try:
            argv = integration.build_command(workspace_path=workspace_path, config=tool_config)
        except UnsupportedToolConfigError as exc:
            typer.echo(f"Configuration error: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc
        typer.echo(shlex.join(argv))
        raise typer.Exit(code=0)

    try:
        result = run(
            run_id=uuid.uuid4().hex,
            context_provider=LocalContextProvider(workspace_path=workspace_path),
            integrations={category: integration},
            executor=executor,
            normalizer=normalizer,
            config=resolved_config,
            now=now,
        )
    except ContextResolutionError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc
    except PolicyConfigurationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc
    except UnsupportedToolConfigError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

    for execution in result.executions:
        if execution.message is not None:
            typer.echo(execution.message, err=True)

    schemas = {category: integration.report_schema()}
    report = (
        render_json(result)
        if output_format is OutputFormat.JSON
        else render_console(result, schemas=schemas, max_rows=resolved_config.report_max_rows)
    )
    typer.echo(report)

    exit_code = compute_exit_code(
        result, continue_on_tool_error=resolved_config.continue_on_tool_error
    )
    raise typer.Exit(code=exit_code)


@scan_app.command("secrets")
def scan_secrets(
    path: Path = typer.Option(Path(), "--path", help="Workspace directory to scan."),
    fail_on: FailOnOption | None = typer.Option(
        None,
        "--fail-on",
        help=(
            "Severity threshold that fails the exit code. Given at all, this replaces any "
            "[thresholds] table declared in the policy file entirely (ADR §8.1)."
        ),
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.CONSOLE, "--format", help="Report format."
    ),
    config: Path | None = typer.Option(
        None, "--config", help="Explicit configuration file path (ADR R5)."
    ),
    continue_on_tool_error: bool | None = typer.Option(
        None,
        "--continue-on-tool-error/--no-continue-on-tool-error",
        help="Do not fail the run over a tool execution failure or incomplete evidence.",
    ),
    strict_normalization: bool | None = typer.Option(
        None,
        "--strict-normalization/--no-strict-normalization",
        help="Fail if any finding has no severity signal but the fallback.",
    ),
    max_rows: int | None = typer.Option(
        None,
        "--max-rows",
        help="Console table rows shown per category before summarizing the rest (ADR §7).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the command that would run and exit, without scanning anything.",
    ),
) -> None:
    """Scan a workspace for secrets with Gitleaks and report a single verdict."""
    workspace_path = str(path.resolve())
    now = datetime.now(UTC)

    resolved_config = _load_resolved_config(
        cli_overrides=_cli_overrides(
            fail_on=fail_on,
            continue_on_tool_error=continue_on_tool_error,
            strict_normalization=strict_normalization,
            max_rows=max_rows,
        ),
        config_path=config,
        workspace_path=workspace_path,
        now=now,
    )

    executor = SubprocessToolExecutor()
    try:
        gitleaks_version = GitleaksIntegration.detect_version(executor)
    except FileNotFoundError:
        # No hint printed here: `engine.run` below attempts the exact same
        # invocation regardless, and its own missing-binary handling (ADR
        # §5) is the single place that decides the actionable message a
        # missing binary produces (ADR §1 checkpoint) — carried on the
        # resulting `ToolExecution.message` and displayed once `result`
        # exists, below. This fallback only lets a `GitleaksIntegration` be
        # constructed at all when its version cannot be detected.
        gitleaks_version = "unknown"

    _run_scan(
        category=Category.SECRETS,
        integration=GitleaksIntegration(version=gitleaks_version),
        workspace_path=workspace_path,
        executor=executor,
        normalizer=SeverityNormalizer(),
        resolved_config=resolved_config,
        output_format=output_format,
        dry_run=dry_run,
        now=now,
    )


@scan_app.command("sca")
def scan_sca(
    path: Path = typer.Option(Path(), "--path", help="Workspace directory to scan."),
    fail_on: FailOnOption | None = typer.Option(
        None,
        "--fail-on",
        help=(
            "Severity threshold that fails the exit code. Given at all, this replaces any "
            "[thresholds] table declared in the policy file entirely (ADR §8.1)."
        ),
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.CONSOLE, "--format", help="Report format."
    ),
    config: Path | None = typer.Option(
        None, "--config", help="Explicit configuration file path (ADR R5)."
    ),
    continue_on_tool_error: bool | None = typer.Option(
        None,
        "--continue-on-tool-error/--no-continue-on-tool-error",
        help="Do not fail the run over a tool execution failure or incomplete evidence.",
    ),
    strict_normalization: bool | None = typer.Option(
        None,
        "--strict-normalization/--no-strict-normalization",
        help="Fail if any finding has no severity signal but the fallback.",
    ),
    max_rows: int | None = typer.Option(
        None,
        "--max-rows",
        help="Console table rows shown per category before summarizing the rest (ADR §7).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the command that would run and exit, without scanning anything.",
    ),
) -> None:
    """Scan a workspace for vulnerable dependencies with Trivy and report a single verdict."""
    workspace_path = str(path.resolve())
    now = datetime.now(UTC)

    resolved_config = _load_resolved_config(
        cli_overrides=_cli_overrides(
            fail_on=fail_on,
            continue_on_tool_error=continue_on_tool_error,
            strict_normalization=strict_normalization,
            max_rows=max_rows,
        ),
        config_path=config,
        workspace_path=workspace_path,
        now=now,
    )

    executor = SubprocessToolExecutor()
    try:
        trivy_version = TrivyIntegration.detect_version(executor)
    except (FileNotFoundError, TrivyOutputError):
        # Same fallback as `scan_secrets` above, and for the same reason:
        # `engine.run` below attempts the exact same invocation regardless,
        # and is the single place that turns a missing (or, for trivy,
        # otherwise unusable) binary into an actionable
        # `ToolExecution.message` (ADR §1 checkpoint).
        trivy_version = "unknown"

    try:
        db_data_sources = TrivyIntegration.detect_data_sources(executor)
    except FileNotFoundError:
        db_data_sources = ()

    _run_scan(
        category=Category.SCA,
        integration=TrivyIntegration(version=trivy_version, db_data_sources=db_data_sources),
        workspace_path=workspace_path,
        executor=executor,
        normalizer=SeverityNormalizer(native_map=TRIVY_NATIVE_SEVERITY_MAP),
        resolved_config=resolved_config,
        output_format=output_format,
        dry_run=dry_run,
        now=now,
    )
