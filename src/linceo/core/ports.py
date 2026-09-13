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
    """

    name: str
    version: str
    category: Category

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
