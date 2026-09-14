"""A single tool execution within a run, and the data sources it relied on (ADR §5).

`RunResult` (see `linceo.core.results`) holds a list of these — `executions`
— from day one, even when it has length 1, because a per-tool report file
is exactly the "wrapper, not orchestrator" pattern ADR §1 rejects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum

from linceo.core.findings import Category, Finding


class ExecutionStatus(StrEnum):
    """The outcome of one tool execution within a run (ADR §5).

    `FAILED` and `SKIPPED` are both *absence of evidence*, not "zero
    findings" — a run containing either defaults to failing the whole run
    (`RunResult.status = partial`) rather than reporting a clean verdict
    over incomplete evidence (ADR §5, "Fallo parcial"). `SKIPPED_BY_POLICY`
    is different in kind, not just in name: it is a declared, caducable
    absence with an owner and a deadline (a `ToolSkip`, ADR §8), not an
    accidental one — a run containing it still completes normally and its
    gate is still evaluated (ADR §5, §8).
    """

    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    SKIPPED_BY_POLICY = "skipped_by_policy"


@dataclass(frozen=True, slots=True)
class DataSource:
    """A versioned data source a `ToolIntegration` consulted (ADR §5, "Frescura").

    Every `ToolIntegration` declares its data sources — a vulnerability
    database, a rule set — uniformly, so the core can apply the staleness
    policy (default: warn past 7 days) without knowing any tool-specific
    detail about what that data source is.
    """

    name: str
    version: str
    built_at: date


@dataclass(frozen=True, slots=True)
class ToolExecution:
    """One tool's execution within a run — never the whole story on its own (ADR §5).

    `argv` is the exact command line invoked, safe to persist and to print
    verbatim (e.g. under `--dry-run`) because secrets are passed to the
    child process through its environment and never appear in `argv` at all
    (ADR §9) — there is no redaction to perform at this boundary, the value
    simply was never there.

    `exit_code` and `finished_at` are `None` when the tool never ran at all
    — `status = SKIPPED` (e.g. its binary was absent from `PATH`) or
    `status = SKIPPED_BY_POLICY` (an active `ToolSkip`, ADR §8), in which
    case `argv` is also empty: the tool was never even invoked.

    `message` carries the one actionable message a `ToolExecution` needs
    to surface beyond its structured fields — today, only
    `ToolIntegration.missing_binary_hint()` when `status = SKIPPED` over a
    missing binary. `linceo.core.engine` is the single place that sets it;
    a caller (the CLI) only ever displays it, never re-derives it — the
    checkpoint fix (ADR §1) that replaced a CLI-side preflight duplicating
    the same missing-binary detection `engine.run` already performs.
    `None` for every other status.
    """

    tool: str
    tool_version: str
    category: Category
    argv: tuple[str, ...]
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    status: ExecutionStatus
    findings: tuple[Finding, ...]
    data_sources: tuple[DataSource, ...]
    message: str | None = None
