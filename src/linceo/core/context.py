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
    """

    LOCAL = "local"
    AZURE_DEVOPS = "azure_devops"


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
