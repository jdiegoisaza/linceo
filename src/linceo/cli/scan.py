"""``linceo scan <secrets|sca|iac>``: run one tool end to end (ADR §8, §10).

Translates CLI flags into the domain objects `linceo.core.engine.run`
already expects, and nothing more (AGENTS.md, "CLI framework") — the exact
same run is reachable from Python directly, by constructing the same
objects and calling `run`, without going through Typer at all.

`scan_secrets` (Gitleaks), `scan_sca` (Trivy), and `scan_iac` (Checkov)
share every step downstream of constructing their own `ToolIntegration`
instance — resolving configuration, merging `ToolConfig`, `--dry-run`,
calling `run`, error handling, and reporting — through `_run_scan`, so that
shared plumbing exists exactly once instead of drifting between the
commands now that there are three. `_load_resolved_config` also resolves
this run's `[remote_policy]` declaration, if any, before calling `load_config` (ADR
R2, §8.4) — no CLI flag of its own: the declaration lives entirely in the
local `.devsecops/config.toml` this same call already resolves.
"""

import shlex
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer

from linceo.adapters.checkov import CheckovIntegration
from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import TrivyIntegration, TrivyOutputError
from linceo.core.config import Config, ConfigurationError, load_config, resolve_local_document
from linceo.core.context import ContextResolutionError, Platform
from linceo.core.engine import run
from linceo.core.execution import DataSource
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, compute_exit_code
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.policy import PolicyConfigurationError
from linceo.core.ports import ContextProvider, PolicySource, ToolExecutor, ToolIntegration
from linceo.core.remote_policy import (
    PolicySourceStatus,
    RemotePolicyDeclaration,
    default_cache_dir,
    parse_remote_policy_declaration,
    resolve_remote_policy_document,
)
from linceo.core.reporters import render_console, render_json
from linceo.core.sarif import render_sarif
from linceo.core.severity_map import load_severity_map
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, resolve_tool_config
from linceo.providers.azure_devops import AzureDevOpsContextProvider, AzureDevOpsPolicySource
from linceo.providers.detection import detect_platform
from linceo.providers.environment import process_environment
from linceo.providers.github_actions import GitHubActionsContextProvider
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
    GITHUB_ACTIONS = "github_actions"


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
    `azure_devops` (and, for the same reason, `github_actions`) needs it
    passed in exactly like `local` does, rather than reading the runner's
    own checkout root from its environment.

    Public (not underscore-prefixed) because `linceo.cli.context` shares
    it too — platform resolution has exactly one implementation, not one
    per CLI command that happens to need it.
    """
    resolved = detect_platform(env) if platform is PlatformOption.AUTO else Platform(platform.value)
    if resolved is Platform.AZURE_DEVOPS:
        return AzureDevOpsContextProvider(workspace_path=workspace_path)
    if resolved is Platform.GITHUB_ACTIONS:
        return GitHubActionsContextProvider(workspace_path=workspace_path)
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


def detect_checkov_version(executor: ToolExecutor) -> str:
    """Detect the installed checkov version, or `"unknown"` if its binary is missing.

    Shared by `scan_iac` and `linceo.cli.baseline` (both construct a
    `CheckovIntegration`) — the same pattern `detect_gitleaks_version`
    already establishes, for the same reason.
    """
    try:
        return CheckovIntegration.detect_version(executor)
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


def package_root() -> str:
    """The installed `linceo` package's own directory (ADR §5/R5's "never inside this package").

    Public because `linceo.cli.baseline` needs the exact same value to
    resolve its own destination policy file through `load_config` — same
    reasoning as `resolve_context_provider` being public.
    """
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


def _build_policy_source(declaration: RemotePolicyDeclaration) -> PolicySource:
    """Construct the concrete `PolicySource` for `declaration` (today: Azure DevOps only, ADR §10).

    The only reference implementation, the same way `local`+`azure_devops`
    are today's only two `ContextProvider`s — hardcoded here rather than
    resolved through `linceo.core.registry`'s plugin mechanism, exactly the
    same way `resolve_context_provider` above hardcodes its own two
    choices: that registry exists for *third-party* plugins, not for this
    project's own reference adapters.
    """
    return AzureDevOpsPolicySource(
        repository=declaration.repository,
        path=declaration.path,
        project=declaration.project,
        token_env=declaration.token_env,
    )


def _resolve_remote_policy(
    *, config_path: Path | None, workspace_path: str, env: Mapping[str, str], now: datetime
) -> tuple[Mapping[str, object] | None, PolicySourceStatus | None]:
    """Resolve this run's `[remote_policy]` declaration, if any, into a mapping to merge in.

    `(None, None)` when the local document declares no `remote_policy`
    table at all — the common case, and the only one every `scan <category>`
    invocation hit before this existed. A *fetch* failure never raises from
    here: `resolve_remote_policy_document` already turns it into a
    degraded `PolicySourceStatus` on its own (ADR §5, §8.4) — only a
    malformed local `[remote_policy]` table itself propagates, the same as
    any other invalid part of the local document.

    Raises:
        PolicyConfigurationError: see
            `linceo.core.remote_policy.parse_remote_policy_declaration`.
        ConfigurationError: see `linceo.core.config.resolve_local_document`.
    """
    _, local_document = resolve_local_document(
        explicit_config_path=str(config_path) if config_path is not None else None,
        workspace_path=workspace_path,
        package_root=package_root(),
    )
    declaration = parse_remote_policy_declaration(local_document)
    if declaration is None:
        return None, None

    return resolve_remote_policy_document(
        source=_build_policy_source(declaration),
        declaration=declaration,
        cache_dir=default_cache_dir(env),
        now=now,
    )


def _load_resolved_config(
    *,
    cli_overrides: dict[str, str],
    env: Mapping[str, str],
    config_path: Path | None,
    workspace_path: str,
    now: datetime,
) -> Config:
    """`load_config`, translating `ConfigurationError` into the CLI's exit-2 contract (ADR §8).

    Resolves this run's `[remote_policy]` declaration first (ADR R2, §8.4,
    `_resolve_remote_policy`) and feeds its outcome into `load_config`,
    which merges it into the local document per its own governance rules
    (`linceo.core.remote_policy.merge_remote_into_local`).
    """
    try:
        remote_document, policy_source = _resolve_remote_policy(
            config_path=config_path, workspace_path=workspace_path, env=env, now=now
        )
        return load_config(
            cli_overrides=cli_overrides,
            env=env,
            explicit_config_path=str(config_path) if config_path is not None else None,
            workspace_path=workspace_path,
            package_root=package_root(),
            today=now.date(),
            remote_document=remote_document,
            policy_source=policy_source,
        )
    except (ConfigurationError, PolicyConfigurationError) as exc:
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
        report = render_console(
            result,
            schemas=schemas,
            max_rows=resolved_config.report_max_rows,
            banner=resolved_config.banner,
        )
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
            "its TF_BUILD sentinel, GitHub Actions via its GITHUB_ACTIONS sentinel, and falls "
            "back to `local` otherwise (ADR §4 R1, §8) — always overridable explicitly."
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
    severity_map = load_severity_map()

    _run_scan(
        category=Category.SECRETS,
        integration=GitleaksIntegration(version=gitleaks_version),
        context_provider=context_provider,
        workspace_path=workspace_path,
        executor=executor,
        normalizer=SeverityNormalizer.from_severity_map(severity_map),
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
            "its TF_BUILD sentinel, GitHub Actions via its GITHUB_ACTIONS sentinel, and falls "
            "back to `local` otherwise (ADR §4 R1, §8) — always overridable explicitly."
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
    severity_map = load_severity_map()

    _run_scan(
        category=Category.SCA,
        integration=TrivyIntegration(
            version=trivy_version,
            db_data_sources=db_data_sources,
            cvss_source_preference=severity_map.cvss_source_preference,
        ),
        context_provider=context_provider,
        workspace_path=workspace_path,
        executor=executor,
        normalizer=SeverityNormalizer.from_severity_map(severity_map),
        resolved_config=resolved_config,
        output_format=output_format,
        dry_run=dry_run,
        now=now,
    )


@scan_app.command("iac")
def scan_iac(
    path: Path = typer.Option(Path(), "--path", help="Workspace directory to scan."),
    platform: PlatformOption = typer.Option(
        PlatformOption.AUTO,
        "--platform",
        help=(
            "CI platform to resolve ExecutionContext from. `auto` detects Azure Pipelines via "
            "its TF_BUILD sentinel, GitHub Actions via its GITHUB_ACTIONS sentinel, and falls "
            "back to `local` otherwise (ADR §4 R1, §8) — always overridable explicitly."
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
    """Scan a workspace for IaC misconfigurations with Checkov and report a single verdict."""
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
    checkov_version = detect_checkov_version(executor)
    severity_map = load_severity_map()

    _run_scan(
        category=Category.IAC,
        integration=CheckovIntegration(version=checkov_version),
        context_provider=context_provider,
        workspace_path=workspace_path,
        executor=executor,
        normalizer=SeverityNormalizer.from_severity_map(severity_map),
        resolved_config=resolved_config,
        output_format=output_format,
        dry_run=dry_run,
        now=now,
    )
