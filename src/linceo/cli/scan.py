"""``linceo scan secrets``: run Gitleaks against a workspace end to end (ADR §8, §10).

Translates CLI flags into the domain objects `linceo.core.engine.run`
already expects, and nothing more (AGENTS.md, "CLI framework") — the exact
same run is reachable from Python directly, by constructing the same
objects and calling `run`, without going through Typer at all.
"""

import shlex
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.core.config import ConfigurationError, load_config
from linceo.core.engine import run
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, compute_exit_code
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import PolicyConfigurationError
from linceo.core.reporters import render_console, render_json
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, resolve_tool_config
from linceo.providers.environment import process_environment
from linceo.providers.local import ContextResolutionError, LocalContextProvider

scan_app = typer.Typer(help="Run a scan category against a workspace and produce one verdict.")


class OutputFormat(StrEnum):
    """Report formats `scan secrets` can render today (ADR §7 minus SARIF, not yet built)."""

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

    cli_overrides: dict[str, str] = {}
    if fail_on is not None:
        cli_overrides["fail_on"] = fail_on.value
    if continue_on_tool_error is not None:
        cli_overrides["continue_on_tool_error"] = str(continue_on_tool_error)
    if strict_normalization is not None:
        cli_overrides["strict_normalization"] = str(strict_normalization)
    if max_rows is not None:
        cli_overrides["report_max_rows"] = str(max_rows)

    try:
        resolved_config = load_config(
            cli_overrides=cli_overrides,
            env=process_environment(),
            explicit_config_path=str(config) if config is not None else None,
            workspace_path=workspace_path,
            package_root=_package_root(),
            today=now.date(),
        )
    except ConfigurationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIGURATION_ERROR) from exc

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

    integration = GitleaksIntegration(version=gitleaks_version)
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
            integrations={Category.SECRETS: integration},
            executor=executor,
            normalizer=SeverityNormalizer(),
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

    schemas = {Category.SECRETS: integration.report_schema()}
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
