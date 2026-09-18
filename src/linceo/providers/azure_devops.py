"""``azure_devops``: the reference `ContextProvider` proving the port against a second source.

Fills the same `ExecutionContext` as `linceo.providers.local`, but from a
source with nothing in common: variables the Azure Pipelines agent injects
into the process environment, rather than interrogating a git checkout on
disk (ADR §10). Everything below is `os.environ` knowledge, confined to
this module inside `providers/` (AGENTS.md, "Layer boundaries") via
`linceo.providers.environment.process_environment`, the one function
allowed to read it.

Two decisions worth stating up front, because they are exactly the kind of
thing a design that only ever looked at `local` would get wrong:

- **Required vs. optional `ExecutionContext` fields are handled
  differently, deliberately.** `repository`, `commit`, and
  `workspace_path` have no default in `ExecutionContext` — a provider
  cannot honestly construct one without them, so their absence is
  `ContextResolutionError` (ADR §10: "no inventes valores"). `branch`,
  `pull_request_id`, `build_id`, and `source_url` are optional there for
  exactly this reason: Azure Pipelines does not set all of them on every
  trigger (a branch build has no pull request; a pipeline that skips a
  pull-request trigger's extra variables still has to resolve *something*)
  — their absence resolves to `None`, never a fabricated placeholder.
- **`workspace_path` is still a constructor argument, like `local`'s,
  never read from the environment.** Azure Pipelines does expose the
  agent's checkout root as `BUILD_SOURCESDIRECTORY`, but
  `linceo.core.engine.run` uses `ExecutionContext.workspace_path` as the
  literal directory it scans — the same property `local` relies on to
  scan only a requested sub-directory of a larger repository (ADR §10)
  rather than always the checkout root. Reading `BUILD_SOURCESDIRECTORY`
  here instead would silently ignore `--path` the moment `--platform
  azure_devops` is active, and would do so specifically for the one
  platform where a monorepo pipeline is most likely to invoke this tool
  from a sub-directory. `linceo.cli.scan` passes the same `--path` (or its
  default: the current directory) to whichever provider `--platform`
  selects, exactly as it already does for `local`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from linceo.core.context import ContextResolutionError, ExecutionContext, Platform
from linceo.providers.environment import process_environment

#: Set by the agent for any repository-backed pipeline; required (ADR §10).
_ENV_REPOSITORY = "BUILD_REPOSITORY_NAME"
#: The commit SHA the run checked out; required (ADR §10).
_ENV_SOURCE_VERSION = "BUILD_SOURCEVERSION"
#: Full ref for the triggering branch/tag — `refs/heads/<branch>` for a branch
#: build, `refs/tags/<tag>` for a tag, or `refs/pull/<id>/merge` for a pull
#: request (see `_resolve_branch` for why that last shape is never used as-is).
_ENV_SOURCE_BRANCH = "BUILD_SOURCEBRANCH"
#: Only set on a pull-request-triggered build: the *actual* source branch of
#: the PR, as `refs/heads/<branch>` — unlike `_ENV_SOURCE_BRANCH`, which on a
#: PR trigger holds the synthetic merge ref instead (see `_resolve_branch`).
_ENV_PR_SOURCE_BRANCH = "SYSTEM_PULLREQUEST_SOURCEBRANCH"
#: Only set on a pull-request-triggered build: Azure DevOps's own internal PR
#: id. Always present on a PR trigger, for any repository type.
_ENV_PR_ID = "SYSTEM_PULLREQUEST_PULLREQUESTID"
#: Only set on a pull-request-triggered build against a GitHub-backed
#: repository: the human-facing PR number (what shows up in the GitHub UI
#: and URL) — see `_resolve_pull_request_id` for why it is preferred over
#: `_ENV_PR_ID` when both are present.
_ENV_PR_NUMBER = "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER"
#: The numeric build id; optional per `ExecutionContext` (ADR §10) even
#: though a real Azure Pipelines agent always sets it.
_ENV_BUILD_ID = "BUILD_BUILDID"
#: The repository's own URL; optional per `ExecutionContext` for the same
#: reason as `_ENV_BUILD_ID`.
_ENV_REPOSITORY_URI = "BUILD_REPOSITORY_URI"

#: Every environment variable `resolve()` reads, gathered in one place —
#: the exact allowlist a container invocation must forward
#: (`docker run -e VAR ...`) for this provider to resolve anything at all
#: once `--platform azure_devops` is selected, explicitly or via `auto`.
#: `auto` detection itself needs one variable more, not read here since
#: `resolve()` never runs detection:
#: `linceo.providers.detection.AZURE_DEVOPS_SENTINEL_ENV_VAR`.
#:
#: This is deliberately an allowlist, not "forward the whole environment":
#: a container invocation's process environment routinely carries far more
#: than these — pipeline secrets mapped to variables, feed credentials,
#: other steps' exports — none of which this provider has any business
#: seeing. `linceo.cli.context` imports this tuple directly; the reference
#: azure-pipelines template (a YAML/bash file, unable to import Python)
#: hand-maintains its own copy of the same `-e VAR` list instead, kept
#: honest by `tests/unit/test_cli_context.py`'s cross-check against it.
ENV_VARS = (
    _ENV_REPOSITORY,
    _ENV_SOURCE_VERSION,
    _ENV_SOURCE_BRANCH,
    _ENV_PR_SOURCE_BRANCH,
    _ENV_PR_ID,
    _ENV_PR_NUMBER,
    _ENV_BUILD_ID,
    _ENV_REPOSITORY_URI,
)

#: Ref prefixes this module knows how to strip, longest/most specific first
#: only matters in that none of these overlap — order is otherwise
#: irrelevant. A ref that matches neither (e.g. `refs/pull/17/merge`, or
#: some future ref kind) is returned unstripped rather than guessed at.
_KNOWN_REF_PREFIXES = ("refs/heads/", "refs/tags/")


def _strip_ref_prefix(ref: str) -> str:
    """Strip a known `refs/...` prefix from `ref`, leaving anything else untouched."""
    for prefix in _KNOWN_REF_PREFIXES:
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


def _resolve_branch(env: Mapping[str, str]) -> str | None:
    """Resolve the branch a run is scanning, favoring a pull request's real source branch.

    On a pull-request trigger, `_ENV_SOURCE_BRANCH` holds the synthetic
    merge ref (`refs/pull/<id>/merge`) rather than anything resembling a
    branch name — `_ENV_PR_SOURCE_BRANCH`, set only in that case, is the
    actual branch under review, so it is checked first and wins whenever
    present. A plain branch (or tag) build has no PR variables at all, so
    `_ENV_SOURCE_BRANCH` is exactly right there, stripped of its
    `refs/heads/`/`refs/tags/` prefix — deliberately *not*
    `BUILD_SOURCEBRANCHNAME`, which Azure Pipelines derives by keeping only
    the last `/`-separated segment of the ref: for a branch actually named
    `feature/foo` that variable holds only `foo`, silently discarding the
    rest of the name. Stripping the known prefix off the full ref instead
    keeps `feature/foo` intact, matching the full branch name
    `local`'s `git rev-parse --abbrev-ref HEAD` already produces.
    """
    pr_source_branch = env.get(_ENV_PR_SOURCE_BRANCH)
    if pr_source_branch:
        return _strip_ref_prefix(pr_source_branch)
    source_branch = env.get(_ENV_SOURCE_BRANCH)
    if source_branch:
        return _strip_ref_prefix(source_branch)
    return None


def _resolve_pull_request_id(env: Mapping[str, str]) -> str | None:
    """Resolve this run's pull request id, preferring the human-facing number when it exists.

    `_ENV_PR_NUMBER` only exists for a GitHub-backed repository, and is the
    number a person actually sees (in the GitHub UI, in the PR's URL);
    `_ENV_PR_ID` is Azure DevOps's own internal id, set for every PR
    trigger regardless of repository type but not something a human
    recognizes for a GitHub-backed one. Preferring the number when both are
    present loses nothing for Azure Repos Git, which never sets it in the
    first place and so always falls through to the internal id.
    """
    return env.get(_ENV_PR_NUMBER) or env.get(_ENV_PR_ID) or None


@dataclass(frozen=True, slots=True)
class AzureDevOpsContextProvider:
    """Resolves `ExecutionContext` from Azure Pipelines' runner-injected environment (ADR §10).

    Reads `os.environ` itself, via `process_environment`, exactly once per
    `resolve()` call — the caller supplies only `workspace_path` (see the
    module docstring for why that one field is not read from the
    environment like everything else here is).
    """

    workspace_path: str

    def resolve(self) -> ExecutionContext:
        """Resolve this run's `ExecutionContext` from the current process environment.

        Raises:
            ContextResolutionError: if `_ENV_REPOSITORY` or
                `_ENV_SOURCE_VERSION` is absent — the two `ExecutionContext`
                fields this provider cannot leave `None`, so their absence
                means this process is not actually running under an Azure
                Pipelines agent for a repository-backed pipeline.
        """
        env = process_environment()

        repository = env.get(_ENV_REPOSITORY)
        if not repository:
            msg = (
                f"{_ENV_REPOSITORY} is not set — the `azure_devops` context provider needs it "
                "to resolve which repository this run belongs to. Azure Pipelines sets this for "
                "every repository-backed pipeline; its absence means this process is not "
                "actually running under an Azure Pipelines agent (or --platform azure_devops "
                "was forced somewhere it should not have been)."
            )
            raise ContextResolutionError(msg)

        commit = env.get(_ENV_SOURCE_VERSION)
        if not commit:
            msg = (
                f"{_ENV_SOURCE_VERSION} is not set — the `azure_devops` context provider needs "
                "it to resolve this run's commit."
            )
            raise ContextResolutionError(msg)

        return ExecutionContext(
            platform=Platform.AZURE_DEVOPS,
            repository=repository,
            workspace_path=str(Path(self.workspace_path).resolve()),
            commit=commit,
            branch=_resolve_branch(env),
            pull_request_id=_resolve_pull_request_id(env),
            build_id=env.get(_ENV_BUILD_ID) or None,
            source_url=env.get(_ENV_REPOSITORY_URI) or None,
        )
