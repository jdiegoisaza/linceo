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
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import TRIVY_NATIVE_SEVERITY_MAP, TrivyIntegration, TrivyOutputError
from linceo.core.config import Config, ConfigurationError, load_config
from linceo.core.context import ContextResolutionError, Platform
from linceo.core.engine import run
from linceo.core.execution import DataSource
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, compute_exit_code
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import PolicyConfigurationError
from linceo.core.ports import ContextProvider, ToolExecutor, ToolIntegration
from linceo.core.reporters import render_console, render_json
from linceo.core.sarif import render_sarif
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, resolve_tool_config
from linceo.providers.azure_devops import AzureDevOpsContextProvider
from linceo.providers.detection import detect_platform
from linceo.providers.environment import process_environment
from linceo.providers.local import LocalContextProvider

scan_app = typer.Typer(help="Run a scan category against a workspace and produce one verdict.")


class OutputFormat(StrEnum):
    """Report formats `scan <category>` can render (ADR §7): console, JSON, and SARIF 2.1.0."""

    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


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


class PlatformOption(StrEnum):
    """CI platform to resolve `ExecutionContext` from, plus the `auto` sentinel (ADR §4 R1, §8).

    Kept separate from `linceo.core.context.Platform` for the same reason
    `FailOnOption` is kept separate from `Severity`: `auto` is not itself a
    platform an `ExecutionContext` can be resolved for, only an instruction
    to run `linceo.providers.detection.detect_platform` and use whatever it
    returns.
    """

    AUTO = "auto"
    LOCAL = "local"
    AZURE_DEVOPS = "azure_devops"


def resolve_context_provider(
    *, platform: PlatformOption, workspace_path: str, env: Mapping[str, str]
) -> ContextProvider:
    """Construct the `ContextProvider` `--platform` (or its `auto` detection) selects.

    `auto`'s check order is declared exactly once, in
    `linceo.providers.detection.detect_platform` (ADR §4 R1, §8) — this
    function never re-implements or second-guesses it, only translates the
    resulting `Platform` (or an explicit `--platform` override, which skips
    detection entirely) into a constructed provider. Every provider gets
    the same `workspace_path` regardless of which one is chosen — see
    `linceo.providers.azure_devops`'s module docstring for why
    `azure_devops` needs it passed in exactly like `local` does, rather
    than reading the runner's own checkout root from its environment.

    Public (not underscore-prefixed) because `linceo.cli.context` shares
    it too — platform resolution has exactly one implementation, not one
    per CLI command that happens to need it.
    """
    resolved = detect_platform(env) if platform is PlatformOption.AUTO else Platform(platform.value)
    if resolved is Platform.AZURE_DEVOPS:
        return AzureDevOpsContextProvider(workspace_path=workspace_path)
    return LocalContextProvider(workspace_path=workspace_path)


def detect_gitleaks_version(executor: ToolExecutor) -> str:
    """Detect the installed gitleaks version, or `"unknown"` if its binary is missing.

    Shared by `scan_secrets` and `linceo.cli.baseline` (both construct a
    `GitleaksIntegration`): `"unknown"` is a safe placeholder to construct
    one with either way — `engine.run` below attempts the exact same
    invocation regardless, and its own missing-binary handling (ADR §5) is
    the single place the actionable message for that case is produced
    (ADR §1 checkpoint).
    """
    try:
        return GitleaksIntegration.detect_version(executor)
    except FileNotFoundError:
        return "unknown"


def detect_trivy(executor: ToolExecutor) -> tuple[str, tuple[DataSource, ...]]:
    """Detect the installed trivy version and its vulnerability DB data sources.

    `"unknown"`/no data sources on failure, for the same reason as
    `detect_gitleaks_version` — shared by `scan_sca` and
    `linceo.cli.baseline`. Data sources are only probed once a version was
    actually detected, unguarded (matching `linceo.cli.doctor._probe_trivy`):
    both calls hit the exact same `trivy version --format json`, so there
    is no honest scenario where the first succeeds and the second then
    hits a binary that was not there a moment ago.
    """
    try:
        version = TrivyIntegration.detect_version(executor)
    except (FileNotFoundError, TrivyOutputError):
        return "unknown", ()

    return version, TrivyIntegration.detect_data_sources(executor)


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
    env: Mapping[str, str],
    config_path: Path | None,
    workspace_path: str,
    now: datetime,
) -> Config:
    """`load_config`, translating `ConfigurationError` into the CLI's exit-2 contract (ADR §8)."""
    try:
        return load_config(
            cli_overrides=cli_overrides,
            env=env,
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
    context_provider: ContextProvider,
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
    already-constructed `integration`, its `category`, the `context_provider`
    `--platform` (or its `auto` detection) selected, the `executor` it was
    detected through, and the `SeverityNormalizer` it needs differ by
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
            context_provider=context_provider,
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

    if output_format is OutputFormat.JSON:
        report = render_json(result)
    elif output_format is OutputFormat.SARIF:
        report = render_sarif(result)
    else:
        schemas = {category: integration.report_schema()}
        report = render_console(result, schemas=schemas, max_rows=resolved_config.report_max_rows)
    typer.echo(report)

    exit_code = compute_exit_code(
        result, continue_on_tool_error=resolved_config.continue_on_tool_error
    )
    raise typer.Exit(code=exit_code)


@scan_app.command("secrets")
def scan_secrets(
    path: Path = typer.Option(Path(), "--path", help="Workspace directory to scan."),
    platform: PlatformOption = typer.Option(
        PlatformOption.AUTO,
        "--platform",
        help=(
            "CI platform to resolve ExecutionContext from. `auto` detects Azure Pipelines via "
            "its TF_BUILD sentinel and falls back to `local` otherwise (ADR §4 R1, §8) — always "
            "overridable explicitly."
        ),
    ),
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
    env = process_environment()

    resolved_config = _load_resolved_config(
        cli_overrides=_cli_overrides(
            fail_on=fail_on,
            continue_on_tool_error=continue_on_tool_error,
            strict_normalization=strict_normalization,
            max_rows=max_rows,
        ),
        env=env,
        config_path=config,
        workspace_path=workspace_path,
        now=now,
    )
    context_provider = resolve_context_provider(
        platform=platform, workspace_path=workspace_path, env=env
    )

    executor = SubprocessToolExecutor()
    gitleaks_version = detect_gitleaks_version(executor)

    _run_scan(
        category=Category.SECRETS,
        integration=GitleaksIntegration(version=gitleaks_version),
        context_provider=context_provider,
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
    platform: PlatformOption = typer.Option(
        PlatformOption.AUTO,
        "--platform",
        help=(
            "CI platform to resolve ExecutionContext from. `auto` detects Azure Pipelines via "
            "its TF_BUILD sentinel and falls back to `local` otherwise (ADR §4 R1, §8) — always "
            "overridable explicitly."
        ),
    ),
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
    env = process_environment()

    resolved_config = _load_resolved_config(
        cli_overrides=_cli_overrides(
            fail_on=fail_on,
            continue_on_tool_error=continue_on_tool_error,
            strict_normalization=strict_normalization,
            max_rows=max_rows,
        ),
        env=env,
        config_path=config,
        workspace_path=workspace_path,
        now=now,
    )
    context_provider = resolve_context_provider(
        platform=platform, workspace_path=workspace_path, env=env
    )

    executor = SubprocessToolExecutor()
    trivy_version, db_data_sources = detect_trivy(executor)

    _run_scan(
        category=Category.SCA,
        integration=TrivyIntegration(version=trivy_version, db_data_sources=db_data_sources),
        context_provider=context_provider,
        workspace_path=workspace_path,
        executor=executor,
        normalizer=SeverityNormalizer(native_map=TRIVY_NATIVE_SEVERITY_MAP),
        resolved_config=resolved_config,
        output_format=output_format,
        dry_run=dry_run,
        now=now,
    )
