"""`ExecutionContext`: the platform-agnostic answer to "where am I running?" (ADR §4, R1).

No module in `core` resolves this for itself — that is the `ContextProvider`
port's job (see `linceo.core.ports`), implemented per-platform in
`linceo.providers`, the only package allowed to read `os.environ`
(AGENTS.md, "Layer boundaries").
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Platform(StrEnum):
    """A CI platform (or the absence of one) an `ExecutionContext` was resolved for.

    `LOCAL` and `AZURE_DEVOPS` are the v0.1 reference platforms (ADR §10);
    `LOCAL` is mandatory in any scope of the project, since the tool must
    run on a developer's laptop with no pipeline involved at all.
    `GITHUB_ACTIONS` was added afterward, once the `ContextProvider`
    contract had already been proven against two implementations of
    maximum mutual distance — exactly the trigger ADR §1's deferred-work
    table names for adding a further platform (adapter work, not design
    work) — see `linceo.providers.github_actions`.
    """

    LOCAL = "local"
    AZURE_DEVOPS = "azure_devops"
    GITHUB_ACTIONS = "github_actions"


class ContextResolutionError(Exception):
    """A `ContextProvider` could not resolve a required `ExecutionContext` field (ADR §10).

    Shared by every `ContextProvider` implementation — originally specific
    to `local` (a missing `git` binary, or `workspace_path` not being a git
    checkout), generalized here once `azure_devops` became a second
    consumer that fails the same way for a different reason (a required
    runner-injected variable absent from the process environment). A
    single shared type is what lets `linceo.cli.scan` catch one exception
    regardless of which platform's provider produced it.
    """


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Everything a run needs to know about where it is executing (ADR §4, R1).

    Resolved once per run by a `ContextProvider` and never re-derived
    piecemeal elsewhere — this is the object that makes "what platform am I
    on" a single, explicit, testable question instead of scattered
    environment-variable checks (ADR §4, R1).

    `branch`, `pull_request_id`, `build_id`, and `source_url` are optional
    because not every context can supply them: a local run with a detached
    `HEAD` has no branch, and a local run outside any CI has no build id,
    PR/MR id, or origin URL.
    """

    platform: Platform
    repository: str
    workspace_path: str
    commit: str
    branch: str | None = None
    pull_request_id: str | None = None
    build_id: str | None = None
    source_url: str | None = None
