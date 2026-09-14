"""The three port contracts the orchestrator depends on (ADR §1).

`ContextProvider`, `ToolExecutor`, and `ToolIntegration` are
`typing.Protocol` definitions, not base classes — a concrete
adapter satisfies a port by structure, without importing `core` at runtime
or subclassing anything here. Concrete implementations live in
`linceo.adapters` (`ToolIntegration`) and `linceo.providers`
(`ContextProvider`); `linceo.testing` carries the permanent fakes
(`FakeContextProvider`, `FakeToolExecutor`) that exercise these same
contracts (ADR §11).
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

    A concrete provider is constructed with whatever it needs to do that
    (a workspace path for `local`, nothing for `azure_devops`, which reads
    the runner's environment) — the port itself takes no arguments, so
    that no assumption about a specific platform's inputs leaks into the
    contract every provider must satisfy.
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
    """

    def run(self, argv: Sequence[str], *, env: Mapping[str, str], cwd: str) -> ProcessResult:
        """Execute `argv` with `env` merged into the child process's environment, run from `cwd`."""
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

    def build_command(self, *, workspace_path: str) -> Sequence[str]:
        """Build the argv to invoke this tool against `workspace_path`."""
        ...

    def parse_output(self, result: ProcessResult) -> Sequence[RawFinding]:
        """Parse a completed `ProcessResult` into this tool's raw findings."""
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
