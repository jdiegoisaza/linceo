"""The port contracts the orchestrator depends on (ADR §1, R2, §8.4).

`ContextProvider`, `ToolExecutor`, `ToolIntegration`, and `PolicySource` are
`typing.Protocol` definitions, not base classes — a concrete
adapter satisfies a port by structure, without importing `core` at runtime
or subclassing anything here. Concrete implementations live in
`linceo.adapters` (`ToolIntegration`) and `linceo.providers`
(`ContextProvider`, `PolicySource`); `linceo.testing` carries the permanent
fakes (`FakeContextProvider`, `FakeToolExecutor`, `FakePolicySource`) that
exercise these same contracts (ADR §11).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from linceo.core.context import ExecutionContext
from linceo.core.execution import DataSource
from linceo.core.findings import Category, RawFinding
from linceo.core.report_schema import ReportSchema
from linceo.core.tool_config import ToolConfig


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """The outcome of running a tool's binary once, independent of how it was run.

    `FakeToolExecutor` (ADR §11) produces this same shape from previously
    recorded real-tool output, so a `ToolIntegration`'s parser cannot tell
    whether it is looking at a real or a replayed execution.
    """

    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime


@runtime_checkable
class ContextProvider(Protocol):
    """Resolves the `ExecutionContext` for a run (ADR §4, R1).

    A concrete provider is constructed with whatever it needs to do that —
    the port itself takes no arguments, so that no assumption about a
    specific platform's inputs leaks into the contract every provider must
    satisfy. In the two reference providers (ADR §10), that turns out to be
    the same `workspace_path` for both: `local` needs it to know which git
    checkout to interrogate, and `azure_devops` needs it for the same
    reason `local` does — `ExecutionContext.workspace_path` is the
    directory `linceo.core.engine.run` actually scans, so every provider
    must honor a caller's requested path (e.g. a monorepo sub-directory)
    rather than substitute a platform-specific default of its own.
    `azure_devops` additionally reads the runner-injected process
    environment for everything else the context needs (repository, commit,
    branch, pull request, build id, origin URL).
    """

    def resolve(self) -> ExecutionContext:
        """Resolve and return this run's `ExecutionContext`."""
        ...


@runtime_checkable
class ToolExecutor(Protocol):
    """Runs a tool's binary as a subprocess (ADR §9).

    Secrets are passed via `env`, never appended to `argv` — this is what
    makes `--dry-run` safe to print `argv` verbatim and lets
    `ToolExecution.argv` (ADR §9) be persisted in a report with no
    redaction step, because the value simply is never there.

    `timeout` (seconds, `None` for no limit) is the one place
    `ToolConfig.timeout` (ADR §8.5) is actually enforced — at this process
    boundary, identically for every tool, regardless of whether that tool
    has a timeout flag of its own. An implementation kills the child
    process outright once `timeout` elapses; it never delegates that to
    the tool being run.
    """

    def run(
        self, argv: Sequence[str], *, env: Mapping[str, str], cwd: str, timeout: float | None
    ) -> ProcessResult:
        """Execute `argv` with `env` merged into the child process's environment, run from `cwd`.

        Raises:
            FileNotFoundError: if `argv[0]` cannot be found.
            TimeoutError: (or a subclass, e.g. `subprocess.TimeoutExpired`)
                if `timeout` is not `None` and elapses before the process
                exits.
        """
        ...


@runtime_checkable
class ToolIntegration(Protocol):
    """A thin adapter around one external tool's CLI and output format (ADR §13.1).

    Deliberately thin: invoke the binary and parse its output, nothing
    more — not even severity normalization, which lives in a single shared
    component applying the versioned severity map (ADR §6), never in a
    per-tool parser. `parse_output` returns `RawFinding`, not `Finding`:
    each finding's native severity travels as-is in `RawFinding.raw_severity`,
    and turning that into a normalized `Finding` is the
    `SeverityNormalizer`'s job, never the parser's.

    `name`, `version`, and `category` are read-only properties, not plain
    attributes: a `Protocol` attribute declared as a plain field requires
    every implementation to expose a *settable* member, which rules out a
    frozen dataclass — the pattern the rest of the domain uses
    (`ProcessResult`, `DataSource`, `ToolExecution`, `ExecutionContext`).
    Declaring them as properties instead lifts that restriction: a frozen
    dataclass field, a plain mutable attribute, or an actual computed
    property all satisfy a read-only property member equally (checkpoint
    finding, ADR §1).
    """

    @property
    def name(self) -> str:
        """This tool's stable identifier, e.g. `"gitleaks"` — independent of `version`."""
        ...

    @property
    def version(self) -> str:
        """The installed tool version this integration instance was constructed for (ADR R4)."""
        ...

    @property
    def category(self) -> Category:
        """The `Category` this integration's findings belong to."""
        ...

    @staticmethod
    def detect_version(executor: ToolExecutor) -> str:
        """Detect the installed tool binary's version via `executor`, before any instance exists.

        The detected version is itself the constructor argument that
        produces a `ToolIntegration` instance (ADR R4), so this is a
        contract on the *type*, not on an instance — callers invoke it
        directly on the concrete class, e.g.
        `GitleaksIntegration.detect_version(executor)`, before that class
        is ever constructed. Declaring it here, instead of leaving each
        integration to invent its own out-of-contract helper (checkpoint
        finding, ADR §1), is what lets `linceo.core.engine` and the CLI
        rely on every integration exposing it the same way.

        Raises:
            FileNotFoundError: if the tool binary is not on `PATH`. A
                caller that cannot detect a version this way still
                constructs the integration with a placeholder version and
                lets the run itself hit the same absence again — that
                second occurrence is what `missing_binary_hint` below and
                `ToolExecution.message` (ADR §5) exist to make actionable.
        """
        ...

    def missing_binary_hint(self) -> str:
        """The actionable hint to show when this tool's binary is absent from `PATH` (ADR R4).

        Names what is missing, which version range is supported, and how
        to install it. `linceo.core.engine` is the only caller: it copies
        this into `ToolExecution.message` the moment a `ToolExecution` for
        this integration is marked `SKIPPED` over a `FileNotFoundError` —
        the single place that decides a missing binary's actionable
        message, replacing the separate CLI-side preflight that used to
        duplicate the same detection (checkpoint finding, ADR §1).
        """
        ...

    def build_env(self) -> Mapping[str, str]:
        """Environment variables this tool's subprocess needs set, merged over the inherited one.

        Added post-v0.1 (ADR §1 amendment, 2026-09-21) — the first two
        reference integrations never needed this: gitleaks makes no network
        call at all, and trivy's one offline-by-default requirement
        (`--skip-db-update`) has a real CLI flag, so both were satisfiable
        entirely through `build_command`'s own argv. Checkov's own
        offline-by-default requirement (ADR R2) is not: suppressing its
        per-invocation PyPI version check has no CLI flag, only an
        environment variable read at import time
        (`CKV_SKIP_PACKAGE_UPDATE_CHECK`) — the third integration is what
        proved `build_command` alone was not a general enough mechanism for
        "guarantee this tool's offline default, unconditionally, regardless
        of what the operator's own shell happens to have set" (the same
        standard `--skip-db-update` already meets for trivy). Returning
        `{}` (every existing integration's neutral, unchanged behavior) is
        exactly as valid an implementation as returning a real mapping —
        this is additive to the port, not a behavior change for anything
        that does not need it.

        `linceo.core.engine.run` merges this over the inherited process
        environment (`ToolExecutor.run`'s own `env` parameter), the same
        way `build_command`'s argv is built once per run, before any tool
        actually executes.
        """
        ...

    def build_command(self, *, workspace_path: str, config: ToolConfig) -> Sequence[str]:
        """Build the argv to invoke this tool against `workspace_path`, applying `config`.

        Translates whichever of `config`'s level 1 fields
        (`exclude_paths`, `scan_history`, `custom_rules_path`) this tool
        has a real flag for; `config.timeout` is never among them (see
        `ToolConfig.timeout`). `config.passthrough` (ADR §8.5's level 2)
        is appended last, exactly as given — an implementation should
        build it through `linceo.core.tool_config.render_passthrough_flags`
        rather than its own string handling, so the anti-injection
        guarantee that function documents actually holds.

        Raises:
            UnsupportedToolConfigError: if a level 1 field this tool has
                no equivalent for is set away from its neutral default —
                never silently ignored (ADR §8.5).
        """
        ...

    def parse_output(self, result: ProcessResult) -> Sequence[RawFinding]:
        """Parse a completed `ProcessResult` into this tool's raw findings.

        Raises:
            linceo.core.execution.ToolExecutionError: for a known,
                anticipated failure mode this integration can name
                specifically (e.g. a vulnerability database that was never
                downloaded) — `linceo.core.engine` copies its message onto
                the resulting `FAILED` execution, the same actionable
                treatment `missing_binary_hint()` gets for `SKIPPED`. Any
                other exception is also caught (into a `FAILED` execution
                with no message), so a parser is free to raise its own
                plain exception type for a generic parse failure instead.
        """
        ...

    def data_sources(self) -> Sequence[DataSource]:
        """Declare every versioned data source this integration relied on (ADR §5)."""
        ...

    def native_severity_domain(self) -> frozenset[str]:
        """Declare this tool's complete native severity value domain (ADR §6)."""
        ...

    def report_schema(self) -> ReportSchema:
        """Declare this category's console table columns (ADR §7).

        The reporter renders whatever `ReportSchema` a category declares
        with no conditional of its own on category or tool name — this is
        where a category's `LOCATION` shape and extra columns (e.g. `sca`'s
        `MANIFEST`/`FIXED`) enter the pipeline as data, not as rendering
        code.
        """
        ...


@dataclass(frozen=True, slots=True)
class FetchedPolicy:
    """The raw content a `PolicySource` fetched, before it is even parsed as TOML (ADR R2, §8.4).

    Deliberately just `content: str` — no metadata about *how* it was
    fetched (an HTTP status, a response header, an SDK-specific object):
    `linceo.core.remote_policy` decides `fetched_at` itself (the resolving
    caller's own `now`, ADR R3), never a timestamp a concrete `PolicySource`
    reports about itself, so every source behaves identically from `core`'s
    point of view regardless of which platform or HTTP client produced this.
    """

    content: str


@runtime_checkable
class PolicySource(Protocol):
    """Fetches one remote policy document's current raw content by name (ADR R2, §8.4).

    Optional, in every sense R2 already establishes for remote configuration:
    a run with no `[remote_policy]` declared never constructs one at all, and
    even a configured one requires the `linceo[remote-config]` extra to
    actually succeed — the base package depends on no HTTP client, and this
    Protocol itself imports nothing beyond the standard library, so it is
    satisfiable (as a type) whether or not that extra is installed.

    A concrete implementation resolves *where* the named document lives
    itself — "reference by name, not by URL" (ADR §8.4): the caller supplies
    only a repository name and a path within it, mirroring how
    `ContextProvider` resolves an `ExecutionContext` from platform-specific
    inputs the port itself never sees. `linceo.providers.azure_devops`'s
    `AzureDevOpsPolicySource` is the one reference implementation, reading
    the build's own organization from the process environment exactly as
    `AzureDevOpsContextProvider` reads everything else about that build.
    """

    def fetch(self) -> FetchedPolicy:
        """Fetch the named document's current content.

        Raises:
            linceo.core.remote_policy.RemotePolicyFetchError: on *any*
                failure to reach or read the source — a network error, a
                missing auth token, a 404, an unparseable response, the
                `linceo[remote-config]` extra not being installed — never a
                lower-level exception type (an HTTP client's own exception
                class, e.g.), so `linceo.core.remote_policy` can catch one
                exception type regardless of which concrete source or HTTP
                client produced it, and treat every one of these causes the
                same way: a failed fetch to degrade from (ADR §5, §8.4).
        """
        ...

    def cache_key(self) -> str:
        """A filesystem-safe string uniquely identifying the real-world location `fetch` reads.

        Deliberately distinct from a repository *name* (ADR §8.4's
        "referencia por nombre, no por URL"): a name alone is not unique
        across the platforms and organizations a single self-hosted agent
        pool can serve. Two `RemotePolicyDeclaration`s naming the same
        repository in two different organizations, or two different
        projects of the same organization, must never resolve to the same
        `cache_key` — an agent shared across those tenants would otherwise
        silently serve one team's cached policy document to another's
        pipeline the moment its own fetch failed (ADR §8.4).
        `AzureDevOpsPolicySource.cache_key` hashes organization, project,
        repository, and path together, resolving organization and project
        through the exact same helper `fetch` itself uses, so the two can
        never disagree about where this source actually points.

        Raises:
            linceo.core.remote_policy.RemotePolicyFetchError: under the
                same conditions `fetch` itself raises for being unable to
                resolve this source's location (e.g. a required environment
                variable is absent) — never a lower-level exception type,
                matching `fetch`'s own contract. A caller unable to compute
                this treats the source as having no cache to read from or
                write to at all, rather than guessing at one.
        """
        ...
