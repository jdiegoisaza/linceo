"""``linceo context``: how a run resolves its `ExecutionContext`, and why (ADR §4 R1, §10).

Exists because platform detection failing open, silently, is worse than
failing loud. `--platform auto` falling back to `local` inside a container
whose Azure Pipelines variables never crossed the `docker run` boundary is
not a crash: `local` still resolves successfully, against whatever git
checkout happens to be mounted, so the run "succeeds" while looking at the
wrong platform's context entirely — `build_id` and `pull_request_id`
silently absent, `repository` derived from a git remote instead of the
runner's own `BUILD_REPOSITORY_NAME`. Before this command existed, the
only way to notice was reading the `platform=...` header
`linceo.core.reporters.render_console` prints after a full scan already
ran. `linceo context` surfaces the same reasoning up front, without
running any tool.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import typer

from linceo.cli.scan import PlatformOption, resolve_context_provider
from linceo.core.context import ContextResolutionError, ExecutionContext, Platform
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK
from linceo.core.remote_policy import DEFAULT_TOKEN_ENV_VAR
from linceo.providers.azure_devops import ENV_VARS as AZURE_DEVOPS_ENV_VARS
from linceo.providers.azure_devops import (
    REMOTE_POLICY_ENV_VARS as AZURE_DEVOPS_REMOTE_POLICY_ENV_VARS,
)
from linceo.providers.azure_devops import AzureDevOpsContextProvider
from linceo.providers.detection import (
    AZURE_DEVOPS_SENTINEL_ENV_VAR,
    GITHUB_ACTIONS_SENTINEL_ENV_VAR,
)
from linceo.providers.environment import process_environment
from linceo.providers.github_actions import ENV_VARS as GITHUB_ACTIONS_ENV_VARS
from linceo.providers.github_actions import GitHubActionsContextProvider

#: `AzureDevOpsPolicySource`'s own env vars (`REMOTE_POLICY_ENV_VARS`) minus
#: the bearer token — a secret this diagnostic command must never print a
#: value for (ADR §9), unlike everything else in either table below, none
#: of which is sensitive. `SYSTEM_COLLECTIONURI`/`SYSTEM_TEAMPROJECT` are
#: shown here even though `AzureDevOpsContextProvider.resolve()` never
#: reads them itself — only `AzureDevOpsPolicySource` does — because a
#: `[remote_policy]` failure is exactly the kind of thing `linceo context`
#: exists to make diagnosable without running a full scan.
_AZURE_DEVOPS_POLICY_ENV_VARS = tuple(
    var for var in AZURE_DEVOPS_REMOTE_POLICY_ENV_VARS if var != DEFAULT_TOKEN_ENV_VAR
)

#: One short, human-facing description per variable in the table below —
#: display only, the actual behavior is `linceo.providers.detection`
#: (the sentinel) and `linceo.providers.azure_devops` (everything else).
#: `tests/unit/test_cli_context.py` asserts this stays exactly in sync
#: with `AZURE_DEVOPS_SENTINEL_ENV_VAR`, `AZURE_DEVOPS_ENV_VARS`, and
#: `_AZURE_DEVOPS_POLICY_ENV_VARS`, so a variable added to any of them
#: can't silently go undescribed here.
_AZURE_DEVOPS_VAR_DESCRIPTIONS: dict[str, str] = {
    AZURE_DEVOPS_SENTINEL_ENV_VAR: "auto-detection sentinel",
    "BUILD_REPOSITORY_NAME": "repository (required)",
    "BUILD_SOURCEVERSION": "commit (required)",
    "BUILD_SOURCEBRANCH": "branch, non-PR trigger",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH": "branch, PR trigger",
    "SYSTEM_PULLREQUEST_PULLREQUESTID": "pull request id, Azure DevOps internal",
    "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER": "pull request id, GitHub-backed repository",
    "BUILD_BUILDID": "build id",
    "BUILD_REPOSITORY_URI": "source URL",
    "SYSTEM_COLLECTIONURI": "organization URL (used by the azure_devops policy source)",
    "SYSTEM_TEAMPROJECT": "project name (used by the azure_devops policy source)",
}

#: Mirrors `_AZURE_DEVOPS_VAR_DESCRIPTIONS`, for `github_actions`.
#: `tests/unit/test_cli_context.py` asserts this stays exactly in sync
#: with `GITHUB_ACTIONS_SENTINEL_ENV_VAR` and `GITHUB_ACTIONS_ENV_VARS`.
_GITHUB_ACTIONS_VAR_DESCRIPTIONS: dict[str, str] = {
    GITHUB_ACTIONS_SENTINEL_ENV_VAR: "auto-detection sentinel",
    "GITHUB_REPOSITORY": "repository (required)",
    "GITHUB_SHA": "commit (required)",
    "GITHUB_REF": "branch/tag ref, non-PR trigger",
    "GITHUB_HEAD_REF": "branch, PR trigger",
    "GITHUB_RUN_ID": "build id",
    "GITHUB_SERVER_URL": "source URL (combined with GITHUB_REPOSITORY)",
}


@dataclass(frozen=True, slots=True)
class EnvVarStatus:
    """One environment variable this project reads for a CI platform, and its current value."""

    name: str
    description: str
    value: str | None


@dataclass(frozen=True, slots=True)
class ContextReport:
    """Everything `linceo context` shows: what was requested, what was selected, and why."""

    requested: PlatformOption
    selected: Platform
    azure_devops_vars: tuple[EnvVarStatus, ...]
    github_actions_vars: tuple[EnvVarStatus, ...]
    resolved: ExecutionContext | None
    error: str | None


def _azure_devops_var_statuses(env: Mapping[str, str]) -> tuple[EnvVarStatus, ...]:
    all_names = (
        AZURE_DEVOPS_SENTINEL_ENV_VAR,
        *AZURE_DEVOPS_ENV_VARS,
        *_AZURE_DEVOPS_POLICY_ENV_VARS,
    )
    return tuple(
        EnvVarStatus(
            name=name, description=_AZURE_DEVOPS_VAR_DESCRIPTIONS[name], value=env.get(name)
        )
        for name in all_names
    )


def _github_actions_var_statuses(env: Mapping[str, str]) -> tuple[EnvVarStatus, ...]:
    all_names = (GITHUB_ACTIONS_SENTINEL_ENV_VAR, *GITHUB_ACTIONS_ENV_VARS)
    return tuple(
        EnvVarStatus(
            name=name, description=_GITHUB_ACTIONS_VAR_DESCRIPTIONS[name], value=env.get(name)
        )
        for name in all_names
    )


def gather_report(
    *, platform: PlatformOption, workspace_path: str, env: Mapping[str, str]
) -> ContextReport:
    """Resolve `ExecutionContext` exactly as `scan <category>` would, and record how.

    Reachable from plain Python, with no Typer involved (AGENTS.md, "CLI
    framework"): the entire diagnostic lives here, and `context()` below
    only renders it and picks an exit code. Never raises
    `ContextResolutionError` itself — a failed resolution is data this
    report carries (`error`), the same way a missing tool binary is data
    `doctor`'s `ToolStatus` carries rather than an exception `gather_report`
    lets escape.
    """
    provider = resolve_context_provider(platform=platform, workspace_path=workspace_path, env=env)
    if isinstance(provider, AzureDevOpsContextProvider):
        selected = Platform.AZURE_DEVOPS
    elif isinstance(provider, GitHubActionsContextProvider):
        selected = Platform.GITHUB_ACTIONS
    else:
        selected = Platform.LOCAL

    try:
        resolved: ExecutionContext | None = provider.resolve()
        error: str | None = None
    except ContextResolutionError as exc:
        resolved = None
        error = str(exc)

    return ContextReport(
        requested=platform,
        selected=selected,
        azure_devops_vars=_azure_devops_var_statuses(env),
        github_actions_vars=_github_actions_var_statuses(env),
        resolved=resolved,
        error=error,
    )


def _render_execution_context(context: ExecutionContext) -> list[str]:
    return [
        "Resolved ExecutionContext:",
        f"  platform: {context.platform.value}",
        f"  repository: {context.repository}",
        f"  workspace_path: {context.workspace_path}",
        f"  commit: {context.commit}",
        f"  branch: {context.branch or '(none)'}",
        f"  pull_request_id: {context.pull_request_id or '(none)'}",
        f"  build_id: {context.build_id or '(none)'}",
        f"  source_url: {context.source_url or '(none)'}",
    ]


def render_report(report: ContextReport) -> str:
    """Render `report` as the human-readable text `linceo context` prints."""
    how = (
        "forced via --platform" if report.requested is not PlatformOption.AUTO else "auto-detected"
    )
    lines = [f"Platform: {report.selected.value} ({how})", ""]

    lines.append("Azure Pipelines environment (checked regardless of the platform selected):")
    azure_name_width = max(len(status.name) for status in report.azure_devops_vars)
    for status in report.azure_devops_vars:
        shown = status.value if status.value is not None else "not set"
        lines.append(f"  {status.name:<{azure_name_width}}  {shown:<20} — {status.description}")
    lines.append("")

    lines.append("GitHub Actions environment (checked regardless of the platform selected):")
    github_name_width = max(len(status.name) for status in report.github_actions_vars)
    for status in report.github_actions_vars:
        shown = status.value if status.value is not None else "not set"
        lines.append(f"  {status.name:<{github_name_width}}  {shown:<20} — {status.description}")
    lines.append("")

    surprising_fallback = (
        report.requested is PlatformOption.AUTO
        and report.selected is Platform.LOCAL
        and all(status.value is None for status in report.azure_devops_vars)
        and all(status.value is None for status in report.github_actions_vars)
    )
    if surprising_fallback:
        lines.append(
            "Every variable above is unset, so `auto` selected `local`. If this process is "
            "meant to be running inside a CI platform's own runner or agent, its environment "
            "was not passed into this one — a `docker run` invocation must forward each "
            'variable explicitly with `-e VAR` (see README.md, "Container image"). If this '
            "really is a local run, this is expected and there is nothing to fix."
        )
        lines.append("")

    if report.resolved is not None:
        lines.extend(_render_execution_context(report.resolved))
    else:
        lines.append("Resolved ExecutionContext: FAILED")
        lines.append(f"  {report.error}")

    return "\n".join(lines)


def context(
    path: Path = typer.Option(Path(), "--path", help="Workspace directory to resolve context for."),
    platform: PlatformOption = typer.Option(
        PlatformOption.AUTO,
        "--platform",
        help=(
            "CI platform to resolve ExecutionContext from. Same flag, same detection order, "
            "as `scan <category> --platform` (ADR §4 R1, §8)."
        ),
    ),
) -> None:
    """Show which platform a run would resolve, why, and its full ExecutionContext."""
    workspace_path = str(path.resolve())
    env = process_environment()

    report = gather_report(platform=platform, workspace_path=workspace_path, env=env)
    typer.echo(render_report(report))

    raise typer.Exit(code=EXIT_OK if report.resolved is not None else EXIT_CONFIGURATION_ERROR)
