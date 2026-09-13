"""`FakeContextProvider` and `FakeToolExecutor`: permanent doubles for the ADR §1 ports.

Distributed as part of the installed package (ADR §11) — not scaffolding
discarded once real adapters exist. `FakeToolExecutor` replays previously
recorded output rather than simulating a tool's behavior from scratch, to
minimize drift between what the fake allows and what a real tool produces.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from linceo.core.context import ExecutionContext
from linceo.core.ports import ProcessResult


@dataclass(frozen=True, slots=True)
class FakeContextProvider:
    """A `ContextProvider` that always resolves to a fixed, caller-supplied `ExecutionContext`."""

    context: ExecutionContext

    def resolve(self) -> ExecutionContext:
        """Return the fixed `ExecutionContext` this fake was constructed with."""
        return self.context


@dataclass(slots=True)
class FakeToolExecutor:
    """A `ToolExecutor` that replays a previously recorded outcome instead of running anything.

    Each recording is keyed by the tool binary's name — `argv[0]` — since
    that is what identifies which real tool run was captured. A recording
    may be a `ProcessResult` to return, or an `Exception` instance to
    raise, so a test can simulate a missing binary (`FileNotFoundError`)
    or a crash without needing a real one.

    Every call is appended to `calls`, so a test can assert what argv,
    env, and cwd a caller invoked this fake with.
    """

    recordings: Mapping[str, ProcessResult | Exception] = field(default_factory=dict)
    calls: list[tuple[Sequence[str], Mapping[str, str], str]] = field(default_factory=list)

    def run(self, argv: Sequence[str], *, env: Mapping[str, str], cwd: str) -> ProcessResult:
        """Return (or raise) the outcome recorded for `argv[0]`.

        Raises:
            FileNotFoundError: if no recording exists for `argv[0]` at
                all — mirroring a real `ToolExecutor` faced with a binary
                absent from `PATH`.
        """
        self.calls.append((argv, env, cwd))
        binary = argv[0] if argv else ""
        recorded = self.recordings.get(binary)
        if recorded is None:
            msg = f"FakeToolExecutor has no recording for {binary!r}"
            raise FileNotFoundError(msg)
        if isinstance(recorded, Exception):
            raise recorded
        return recorded
