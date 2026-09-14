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

    Each recording is keyed by an argv *pattern* — a tuple of leading
    tokens, e.g. `("gitleaks", "version")` or `("gitleaks", "detect")` —
    matched against the start of the actual `argv` a caller invokes this
    fake with; the longest recorded pattern that is a prefix of `argv`
    wins. Keying by binary name alone (`argv[0]`) could not tell two
    invocations of the same binary for different purposes apart —
    `gitleaks version` and `gitleaks detect ...` collided on one shared
    recording — which is exactly what pattern matching fixes (ADR §1
    checkpoint). A recording may be a `ProcessResult` to return, or an
    `Exception` instance to raise, so a test can simulate a missing binary
    (`FileNotFoundError`) or a crash without needing a real one.

    Every call is appended to `calls`, so a test can assert what argv,
    env, and cwd a caller invoked this fake with.
    """

    recordings: Mapping[tuple[str, ...], ProcessResult | Exception] = field(default_factory=dict)
    calls: list[tuple[Sequence[str], Mapping[str, str], str]] = field(default_factory=list)

    def run(self, argv: Sequence[str], *, env: Mapping[str, str], cwd: str) -> ProcessResult:
        """Return (or raise) the outcome recorded for the longest pattern matching `argv`.

        Raises:
            FileNotFoundError: if no recorded pattern is a prefix of
                `argv` at all — mirroring a real `ToolExecutor` faced with
                a binary absent from `PATH`.
        """
        self.calls.append((argv, env, cwd))
        argv_tuple = tuple(argv)
        matching = [pattern for pattern in self.recordings if argv_tuple[: len(pattern)] == pattern]
        if not matching:
            binary = argv[0] if argv else ""
            msg = f"FakeToolExecutor has no recording matching {argv_tuple!r} (binary {binary!r})"
            raise FileNotFoundError(msg)
        recorded = self.recordings[max(matching, key=len)]
        if isinstance(recorded, Exception):
            raise recorded
        return recorded
