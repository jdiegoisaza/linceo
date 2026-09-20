"""``azure_devops``: the reference `ContextProvider`, and the reference `PolicySource` (ADR §10).

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

`AzureDevOpsPolicySource`, at the bottom of this module, is a second,
unrelated port's reference implementation (`linceo.core.ports.PolicySource`,
ADR R2, §8.4) that happens to live here because it resolves its own
location — organization and project — from exactly the same runner-injected
environment variables `AzureDevOpsContextProvider` already reads, via the
same `process_environment` gateway.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from linceo.core.context import ContextResolutionError, ExecutionContext, Platform
from linceo.core.ports import FetchedPolicy
from linceo.core.remote_policy import DEFAULT_TOKEN_ENV_VAR, RemotePolicyFetchError
from linceo.core.secret import Secret, SecretRedactingFilter
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


#: Every Azure Pipelines job sets both of these, on every trigger type —
#: unlike `_ENV_REPOSITORY`/`_ENV_SOURCE_VERSION` above, neither requires a
#: repository-backed pipeline. `System.CollectionUri` is the organization's
#: own base URL (e.g. `https://dev.azure.com/myorg/`); `System.TeamProject`
#: is the current project's name.
_ENV_COLLECTION_URI = "SYSTEM_COLLECTIONURI"
_ENV_TEAM_PROJECT = "SYSTEM_TEAMPROJECT"

#: Every environment variable `AzureDevOpsPolicySource` reads, gathered in
#: one place — mirrors `ENV_VARS` above, but for the *policy source* port
#: rather than the *context* one: the exact allowlist a container
#: invocation must forward (`docker run -e VAR ...`) for a `[remote_policy]`
#: declaration to resolve at all, distinct from `ENV_VARS` because a run
#: with no remote policy configured needs none of these. Unlike
#: `_ENV_COLLECTION_URI`/`_ENV_TEAM_PROJECT`, `DEFAULT_TOKEN_ENV_VAR`
#: (`SYSTEM_ACCESSTOKEN`) is *not* forwarded into a process environment
#: automatically by Azure Pipelines the way the other two are — a step must
#: explicitly map it via its own `env:` block (`$(System.AccessToken)`)
#: before it exists to be forwarded into the container at all; the
#: reference `azure-pipelines/templates/linceo-scan.yml` does this by
#: default (docs/ADOPTION.md, "Fuente remota de la política") — nothing to
#: configure if you use it. `tests/unit/test_azure_devops_policy_source.py`
#: cross-checks the template forwards every one of these, the same anti-drift
#: pattern `tests/unit/test_cli_context.py` already applies to `ENV_VARS`.
REMOTE_POLICY_ENV_VARS = (_ENV_COLLECTION_URI, _ENV_TEAM_PROJECT, DEFAULT_TOKEN_ENV_VAR)

#: Azure DevOps REST API version this reference implementation targets
#: (ADR R2, §8.4) — pinned the same way a tool binary version is (ADR R4):
#: an explicit, reviewed choice, never "whatever the server defaults to".
_REST_API_VERSION = "7.1"


@dataclass(frozen=True, slots=True)
class AzureDevOpsPolicySource:
    """Fetches one remote policy document's raw content from an Azure DevOps Git repository.

    The one reference `PolicySource` (ADR R2, §8.4, "no implementes un
    cliente git"): a single authenticated HTTP GET against Azure DevOps'
    own "Get Item" REST endpoint, not a git clone — a repository this
    provider only ever reads one small file from has no business paying for
    authentication, history, or submodule handling a full clone would
    require, and the REST endpoint already returns exactly the raw bytes
    this needs. Requires the `linceo[remote-config]` extra (`httpx`,
    imported lazily inside `fetch` itself — never at module import time, so
    importing this module, or constructing this class, never requires the
    extra to be installed; only calling `fetch` without it does, and that
    failure degrades exactly like any other, ADR §5).

    `repository` and `path` are `RemotePolicyDeclaration.repository`/`.path`
    verbatim — a name, never a URL (ADR §8.4). The organization is resolved
    from the current build's own environment (`_ENV_COLLECTION_URI`), the
    same way `AzureDevOpsContextProvider` resolves everything else about
    this build — "el ContextProvider resuelve la ubicación... dentro de la
    organización del build". `project` defaults to the same build's own
    project (`_ENV_TEAM_PROJECT`) when `None`, but is overridable — a
    security team's baseline repository realistically lives in its own
    dedicated Azure DevOps project, not necessarily the one being scanned.
    `token_env` names the environment variable carrying the bearer token
    (ADR §9: the flag/field names the origin, never the value), defaulting
    to `DEFAULT_TOKEN_ENV_VAR` (`SYSTEM_ACCESSTOKEN`) — the running build's
    own OAuth identity, scoped to the job, requiring no PAT anyone has to
    create or rotate; the correct credential whenever the policy repository
    lives in the *same organization* as the build (ADR §8.4,
    docs/ADOPTION.md). Overridden with a different variable name for a
    repository outside that scope, in a different organization entirely,
    which `System.AccessToken` cannot reach regardless of permissions —
    there, a Personal Access Token named by its own variable is the correct
    credential instead. Resolving to no value at all in the environment
    (the variable genuinely absent — this default is harmless even when
    unset) sends no `Authorization` header, the case of a public or
    anonymously readable repository.

    The resolved token value is held as a `linceo.core.secret.Secret` from
    the moment it is read out of the environment until the single point
    (`fetch`'s own `Authorization` header assignment) where the literal
    string is actually needed (ADR §9) — closing the window between "read"
    and "used" during which an unrelated debug statement added later could
    otherwise print it by accident. `fetch` additionally attaches a
    `linceo.core.secret.SecretRedactingFilter` to the `httpx`/`httpcore`
    loggers before every authenticated request, as defense in depth against
    those libraries' own internal logging (verified, by reading their
    source, not to include request headers in the version this project
    pins — but a third-party library's internal logging is not a contract
    this project controls, so the second layer stays regardless).
    """

    repository: str
    path: str
    project: str | None = None
    token_env: str = DEFAULT_TOKEN_ENV_VAR

    def _resolve_organization_and_project(self, env: Mapping[str, str]) -> tuple[str, str]:
        """Resolve `(organization_url, project)` from `env`.

        The one place both `fetch` and `cache_key` do so, so the two can
        never disagree about this source's real location.

        Raises:
            RemotePolicyFetchError: if `_ENV_COLLECTION_URI` is unset, or
                `project` is neither set on this declaration nor resolvable
                from `_ENV_TEAM_PROJECT`.
        """
        organization_url = env.get(_ENV_COLLECTION_URI)
        if not organization_url:
            msg = (
                f"{_ENV_COLLECTION_URI} is not set — the azure_devops policy source needs it to "
                "resolve which organization this build's remote policy repository lives in. "
                "Azure Pipelines sets this for every job; its absence means this process is not "
                "actually running under an Azure Pipelines agent."
            )
            raise RemotePolicyFetchError(msg)

        project = self.project or env.get(_ENV_TEAM_PROJECT)
        if not project:
            msg = (
                f"remote_policy.project was not set and {_ENV_TEAM_PROJECT} is not set either — "
                "the azure_devops policy source needs one of the two to know which project "
                f"{self.repository!r} lives in."
            )
            raise RemotePolicyFetchError(msg)

        return organization_url, project

    def cache_key(self) -> str:
        """A hash of organization, project, repository, and path (ADR §8.4, R2, §9).

        Every one of the four is part of this real-world location's own
        identity — omitting organization (or leaving project only
        implicit) would let two different tenants of a shared self-hosted
        agent pool, each naming the same `repository`/`path` in their own
        `.devsecops/config.toml`, collide on the same cache entry and be
        served each other's policy document the moment either one's fetch
        failed. Resolves organization/project via
        `_resolve_organization_and_project` — the exact same call `fetch`
        itself makes — so this can never point at a different location than
        the one `fetch` actually reads from.

        Raises:
            RemotePolicyFetchError: see `_resolve_organization_and_project`.
        """
        organization_url, project = self._resolve_organization_and_project(process_environment())
        canonical = f"{organization_url.rstrip('/')}/{project}/{self.repository}/{self.path}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def fetch(self) -> FetchedPolicy:
        """Fetch this document's current raw content over HTTPS.

        Raises:
            RemotePolicyFetchError: if the `linceo[remote-config]` extra is
                not installed; the build's own organization or project
                cannot be resolved (see `_resolve_organization_and_project`);
                or the HTTP request itself fails for any reason (network
                error, authentication failure, the item not existing at
                `path`, any non-2xx response).
        """
        try:
            import httpx
        except ImportError as exc:
            msg = (
                "fetching a remote policy document from Azure DevOps requires the 'httpx' "
                "package (the 'linceo[remote-config]' extra): if you installed linceo with "
                "pip, run `pip install 'linceo[remote-config]'`; the reference container image "
                "(ADR §4/R4) already bundles it, so seeing this from inside that image means "
                "an out-of-date image — pull or rebuild the current one"
            )
            raise RemotePolicyFetchError(msg) from exc

        env = process_environment()
        organization_url, project = self._resolve_organization_and_project(env)

        base = organization_url.rstrip("/")
        url = f"{base}/{project}/_apis/git/repositories/{self.repository}/items"
        params = {"path": self.path, "download": "true", "api-version": _REST_API_VERSION}
        headers: dict[str, str] = {}
        raw_token = env.get(self.token_env)
        token = Secret(raw_token) if raw_token else None
        if token is not None:
            _redact_from_http_client_logs(token)
            headers["Authorization"] = f"Bearer {token.reveal()}"

        try:
            response = httpx.get(url, params=params, headers=headers, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            hint = _error_hint(
                exc.response.status_code,
                token_env=self.token_env,
                repository=self.repository,
                path=self.path,
            )
            msg = (
                f"failed to fetch {self.repository}/{self.path} from Azure DevOps: "
                f"{exc.response.status_code} {exc.response.reason_phrase} for {exc.response.url}"
                f"{hint}"
            )
            raise RemotePolicyFetchError(msg) from exc
        except httpx.HTTPError as exc:
            # No response at all (a network error, a timeout, ...) — `str(exc)`
            # is the best information available; there is no status code to
            # build a more specific message from, and no `_error_hint` for it.
            msg = f"failed to fetch {self.repository}/{self.path} from Azure DevOps: {exc}"
            raise RemotePolicyFetchError(msg) from exc

        return FetchedPolicy(content=response.text)


def _error_hint(status_code: int, *, token_env: str, repository: str, path: str) -> str:
    """The likely-cause hint appended to an HTTP status this project can actually explain.

    Deliberately narrow — `""` (no hint at all) for any status but the two
    specific cases below. The caller builds the rest of the message from
    the status code, reason phrase, and requested URL directly rather than
    `str()`-ing the `httpx.HTTPStatusError` itself, which would otherwise
    also carry that exception's own generic "for more information" link to
    MDN's HTTP status documentation — redundant, and actively less useful
    than the specific causes this project can already name, once one of
    them applies.
    """
    if status_code == 404:
        return _not_found_hint(token_env=token_env, repository=repository, path=path)
    if status_code in (401, 403):
        return _permission_hint(token_env=token_env, repository=repository)
    return ""


def _not_found_hint(*, token_env: str, repository: str, path: str) -> str:
    """Azure DevOps' own 404 collapses at least four distinct causes into one status code.

    Unlike the 401/403 hint below, this one is never narrowed to the
    default `token_env`: every one of the four causes can happen
    regardless of which credential (or none) made the request — including
    the fourth, since Azure DevOps applies the same permission-hides-as-404
    behavior to a Personal Access Token exactly as it does to the build's
    own identity. Reported unconditionally rather than guessed at, so
    nobody has to rediscover this by elimination the way the report that
    prompted this message did.
    """
    return (
        f" — Azure DevOps returns 404 for at least four different causes, indistinguishable "
        f"from this response alone: (1) {repository!r} does not exist, or not in the "
        "organization/project this fetch resolved; "
        f"(2) {path!r} does not exist in that repository; "
        f"(3) {path!r} exists, but not on the repository's default branch — this fetch always "
        "reads the default branch, never a specific one; "
        f"(4) the identity behind {token_env} lacks Read permission on the repository — Azure "
        "DevOps deliberately returns 404, not 403, when permission is denied, to avoid revealing "
        "a private repository's existence to an unauthorized caller."
    )


def _permission_hint(*, token_env: str, repository: str) -> str:
    """The likely-cause hint appended to a 401/403 raised through the build's own identity.

    Deliberately narrow: only when `token_env` is still
    `DEFAULT_TOKEN_ENV_VAR` — a custom `token_env` means the operator
    already chose a specific credential (a Personal Access Token,
    typically), whose own permissions are that operator's to reason about;
    naming a "build identity" cause there would be actively misleading.
    For the default case, though, a 401 or 403 (as opposed to a 404 —
    `_not_found_hint` — Azure DevOps returns either depending on the
    endpoint and circumstances) has one overwhelmingly likely cause:
    nobody has yet granted the running build's own identity permission to
    read the policy repository.
    """
    if token_env != DEFAULT_TOKEN_ENV_VAR:
        return ""
    return (
        f" — the most likely cause: the build identity behind {DEFAULT_TOKEN_ENV_VAR} has no "
        f"Read permission on {repository!r}. Grant it under Project Settings > Repositories > "
        f"{repository} > Security, to the '<Project> Build Service (<Organization>)' identity. "
        "If the policy repository lives in a different project than this build's own, also "
        "check Organization Settings > Pipelines > Settings > 'Limit job authorization scope', "
        "which can block cross-project access even once the repository's own permissions are "
        "correct."
    )


def _redact_from_http_client_logs(token: Secret) -> None:
    """Attach a `SecretRedactingFilter` for `token` to the `httpx` and `httpcore` loggers (ADR §9).

    Defense in depth: neither library currently includes request headers in
    their own DEBUG-level tracing (verified by reading their source), but
    that is their implementation detail, not a contract this project can
    rely on across every version `linceo[remote-config]`'s range allows —
    this filter still redacts `token`'s value from any log record either
    logger produces, regardless.
    """
    filter_ = SecretRedactingFilter(token)
    logging.getLogger("httpx").addFilter(filter_)
    logging.getLogger("httpcore").addFilter(filter_)
