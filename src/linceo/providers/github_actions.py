"""``github_actions``: the third `ContextProvider` (ADR §1, §10).

Added once the `ContextProvider` port had already been proven against two
implementations of maximum mutual distance (`local` interrogates a git
checkout on disk; `azure_devops` reads runner-injected environment
variables) — exactly the trigger ADR §1's deferred-work table names for
this platform: "el contrato ya está validado con dos proveedores de máxima
distancia, así que el trabajo restante es de adaptador, no de diseño." What
follows is therefore adapter work only: mapping GitHub Actions' own
runner-injected variables onto the same `ExecutionContext` `local` and
`azure_devops` already fill, confined to `providers/` exactly like
`azure_devops` (AGENTS.md, "Layer boundaries") via
`linceo.providers.environment.process_environment`.

Two decisions worth stating up front, both direct analogues of choices
`linceo.providers.azure_devops` already made for the same reasons:

- **Required vs. optional `ExecutionContext` fields are handled
  differently, deliberately** (ADR §10, "no inventes valores"):
  `repository` and `commit` have no default in `ExecutionContext`, so a
  provider that cannot honestly determine them raises
  `ContextResolutionError`. `branch`, `pull_request_id`, `build_id`, and
  `source_url` resolve to `None` when GitHub Actions does not expose them
  for the current trigger — never a fabricated placeholder.
- **`workspace_path` is still a constructor argument, never read from the
  environment.** GitHub Actions does expose the runner's checkout root as
  `GITHUB_WORKSPACE`, but `linceo.core.engine.run` uses
  `ExecutionContext.workspace_path` as the literal directory it scans —
  reading `GITHUB_WORKSPACE` here instead would silently ignore `--path`
  the moment `--platform github_actions` is active, exactly the failure
  mode `azure_devops`'s own module docstring already documents for
  `BUILD_SOURCESDIRECTORY`.

One decision this module makes that `azure_devops` did not have to: **on a
`pull_request` trigger, `GITHUB_SHA` is deliberately used as-is for
`commit`, even though it is the ephemeral merge commit GitHub Actions
creates to test mergeability — not the pull request branch's own head
commit.** This mirrors the precedent `azure_devops.py` already sets:
`BUILD_SOURCEVERSION` is used unconditionally there too, with no
special-cased "real PR head commit" variable, because it already
describes what the agent actually checked out onto disk, regardless of
trigger type — and `actions/checkout`'s own default behavior on a
`pull_request` trigger checks out that same merge commit, so `GITHUB_SHA`
stays accurate to what `workspace_path` actually contains. The pull
request's true head commit exists nowhere in the runner-injected
environment at all — only inside the event payload JSON that
`GITHUB_EVENT_PATH` points at (`pull_request.head.sha`), which this
provider deliberately does not read: doing so would make this the only
`ContextProvider` that parses anything beyond `os.environ` plus, for
`local`, `git` itself — a materially different (and heavier) contract than
either reference provider before it. `branch`, unlike `commit`, *is* fixed
below (via `GITHUB_HEAD_REF`) because a caller comparing branches by name
has no use for the synthetic `refs/pull/<n>/merge` ref at all, whereas a
caller comparing commits by hash is already comparing against whatever the
workspace actually contains — the merge commit is simply the true answer
to "what commit is this evidence for" in that case, not a wrong one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from linceo.core.context import ContextResolutionError, ExecutionContext, Platform
from linceo.providers.environment import process_environment

#: Set on every GitHub Actions run, for any event type: `"<owner>/<repo>"`.
#: Required (ADR §10).
_ENV_REPOSITORY = "GITHUB_REPOSITORY"
#: The commit SHA this run is evaluating. Required (ADR §10). On a
#: `pull_request` trigger this is the ephemeral merge commit GitHub creates
#: to test mergeability, not the pull request branch's own head commit —
#: see the module docstring for why that is used as-is rather than
#: resolved away.
_ENV_SHA = "GITHUB_SHA"
#: The full ref that triggered the run — `refs/heads/<branch>` for a push
#: to a branch, `refs/tags/<tag>` for a tag, or `refs/pull/<n>/merge` for a
#: `pull_request`/`pull_request_target` trigger (the latter shape is never
#: used as a branch name as-is; see `_resolve_branch`).
_ENV_REF = "GITHUB_REF"
#: Only set on a `pull_request`/`pull_request_target` trigger: the actual
#: source branch's short name (e.g. `feature/foo`, already without any
#: `refs/heads/` prefix) — unlike `_ENV_REF`, which on those triggers holds
#: a synthetic ref instead (see `_resolve_branch`).
_ENV_HEAD_REF = "GITHUB_HEAD_REF"
#: A unique, stable id for this workflow run within its repository. Set on
#: every trigger; optional per `ExecutionContext` (ADR §10) for the same
#: reason `BUILD_BUILDID` is optional for `azure_devops` — a defensive
#: default, not an expectation that a real GitHub Actions run ever omits it.
_ENV_RUN_ID = "GITHUB_RUN_ID"
#: The base URL of the GitHub instance running this workflow —
#: `https://github.com` on github.com, the enterprise server's own base URL
#: on GHES. Combined with `_ENV_REPOSITORY` to derive `source_url`, since
#: GitHub Actions exposes no single variable carrying the repository's own
#: URL directly (unlike Azure Pipelines' `BUILD_REPOSITORY_URI`).
_ENV_SERVER_URL = "GITHUB_SERVER_URL"

#: Every environment variable `resolve()` reads, gathered in one place —
#: mirrors `linceo.providers.azure_devops.ENV_VARS`. `auto` detection
#: itself needs one variable more, not read here since `resolve()` never
#: runs detection: `linceo.providers.detection.GITHUB_ACTIONS_SENTINEL_ENV_VAR`.
ENV_VARS = (
    _ENV_REPOSITORY,
    _ENV_SHA,
    _ENV_REF,
    _ENV_HEAD_REF,
    _ENV_RUN_ID,
    _ENV_SERVER_URL,
)

#: Ref prefixes this module knows how to strip — identical set to
#: `linceo.providers.azure_devops._KNOWN_REF_PREFIXES`, since both
#: platforms use the same `refs/heads/<name>` / `refs/tags/<name>` shape
#: for a plain branch or tag build. A ref that matches neither (e.g. the PR
#: merge ref, seen with `_ENV_HEAD_REF` absent) is returned unstripped
#: rather than guessed at.
_KNOWN_REF_PREFIXES = ("refs/heads/", "refs/tags/")

#: The synthetic ref GitHub Actions sets `_ENV_REF` to on a `pull_request`
#: trigger: `refs/pull/<number>/merge`. There is no plain runner-injected
#: variable carrying the pull request number directly — this reserved ref
#: shape is the only place it appears in the process environment at all,
#: so `_resolve_pull_request_id` extracts it from here rather than reading
#: the event payload JSON (see the module docstring for why that is out of
#: scope). `pull_request_target` sets `_ENV_REF` to the *base* branch's
#: ref instead (that trigger deliberately runs against the base branch's
#: code, not the fork's) — this pattern does not match there, so
#: `pull_request_id` resolves to `None` for that trigger, documented here
#: rather than silently guessed at.
_PULL_REQUEST_REF = re.compile(r"^refs/pull/(?P<number>\d+)/merge$")


def _strip_ref_prefix(ref: str) -> str:
    """Strip a known `refs/...` prefix from `ref`, leaving anything else untouched."""
    for prefix in _KNOWN_REF_PREFIXES:
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


def _resolve_branch(env: Mapping[str, str]) -> str | None:
    """Resolve the branch a run is scanning, favoring a pull request's real source branch.

    On a `pull_request`/`pull_request_target` trigger, `_ENV_REF` holds a
    synthetic ref rather than anything resembling a branch name —
    `_ENV_HEAD_REF`, set only in that case, is the actual branch under
    review, already a short name with no prefix to strip, so it is checked
    first and wins whenever present. A plain branch (or tag) build has no
    `_ENV_HEAD_REF` at all, so `_ENV_REF` is exactly right there, stripped
    of its `refs/heads/`/`refs/tags/` prefix.
    """
    head_ref = env.get(_ENV_HEAD_REF)
    if head_ref:
        return head_ref
    ref = env.get(_ENV_REF)
    if ref:
        return _strip_ref_prefix(ref)
    return None


def _resolve_pull_request_id(env: Mapping[str, str]) -> str | None:
    """Resolve this run's pull request number from `_ENV_REF`'s reserved merge-ref shape.

    See `_PULL_REQUEST_REF` for why this is read from the ref rather than
    from a dedicated variable (there is none), and why `pull_request_target`
    is not covered.
    """
    ref = env.get(_ENV_REF)
    if not ref:
        return None
    match = _PULL_REQUEST_REF.match(ref)
    return match.group("number") if match else None


def _resolve_source_url(env: Mapping[str, str]) -> str | None:
    """Derive the repository's own URL from the server base URL and repository name.

    `None` if either half is absent — never a URL built from a fabricated
    default server (ADR §10, "no inventes valores").
    """
    server_url = env.get(_ENV_SERVER_URL)
    repository = env.get(_ENV_REPOSITORY)
    if not server_url or not repository:
        return None
    return f"{server_url.rstrip('/')}/{repository}"


@dataclass(frozen=True, slots=True)
class GitHubActionsContextProvider:
    """Resolves `ExecutionContext` from GitHub Actions' runner-injected environment (ADR §1, §10).

    Reads `os.environ` itself, via `process_environment`, exactly once per
    `resolve()` call — the caller supplies only `workspace_path` (see the
    module docstring for why that one field is not read from the
    environment like everything else here is).
    """

    workspace_path: str

    def resolve(self) -> ExecutionContext:
        """Resolve this run's `ExecutionContext` from the current process environment.

        Raises:
            ContextResolutionError: if `_ENV_REPOSITORY` or `_ENV_SHA` is
                absent — the two `ExecutionContext` fields this provider
                cannot leave `None`, so their absence means this process is
                not actually running under a GitHub Actions runner (or
                `--platform github_actions` was forced somewhere it should
                not have been).
        """
        env = process_environment()

        repository = env.get(_ENV_REPOSITORY)
        if not repository:
            msg = (
                f"{_ENV_REPOSITORY} is not set — the `github_actions` context provider needs it "
                "to resolve which repository this run belongs to. GitHub Actions sets this for "
                "every workflow run; its absence means this process is not actually running "
                "under a GitHub Actions runner (or --platform github_actions was forced "
                "somewhere it should not have been)."
            )
            raise ContextResolutionError(msg)

        commit = env.get(_ENV_SHA)
        if not commit:
            msg = (
                f"{_ENV_SHA} is not set — the `github_actions` context provider needs it to "
                "resolve this run's commit."
            )
            raise ContextResolutionError(msg)

        return ExecutionContext(
            platform=Platform.GITHUB_ACTIONS,
            repository=repository,
            workspace_path=str(Path(self.workspace_path).resolve()),
            commit=commit,
            branch=_resolve_branch(env),
            pull_request_id=_resolve_pull_request_id(env),
            build_id=env.get(_ENV_RUN_ID) or None,
            source_url=_resolve_source_url(env),
        )
