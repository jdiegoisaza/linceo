"""`FakeContextProvider`, `FakeToolExecutor`, `FakePolicySource`: permanent doubles for the ports.

Distributed as part of the installed package (ADR §11) — not scaffolding
discarded once real adapters exist. `FakeToolExecutor` replays previously
recorded output rather than simulating a tool's behavior from scratch, to
minimize drift between what the fake allows and what a real tool produces.
`FakePolicySource` exercises `linceo.core.ports.PolicySource` (ADR R2, §8.4)
the same way `FakeContextProvider` exercises `ContextProvider`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from linceo.core.context import ExecutionContext
from linceo.core.ports import FetchedPolicy, ProcessResult


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
    env, cwd, and timeout a caller invoked this fake with — `timeout` is
    recorded, never enforced: this fake never actually runs anything, so
    there is nothing for a timeout to bound.
    """

    recordings: Mapping[tuple[str, ...], ProcessResult | Exception] = field(default_factory=dict)
    calls: list[tuple[Sequence[str], Mapping[str, str], str, float | None]] = field(
        default_factory=list
    )

    def run(
        self, argv: Sequence[str], *, env: Mapping[str, str], cwd: str, timeout: float | None
    ) -> ProcessResult:
        """Return (or raise) the outcome recorded for the longest pattern matching `argv`.

        Raises:
            FileNotFoundError: if no recorded pattern is a prefix of
                `argv` at all — mirroring a real `ToolExecutor` faced with
                a binary absent from `PATH`.
        """
        self.calls.append((argv, env, cwd, timeout))
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


@dataclass(slots=True)
class FakePolicySource:
    """A `PolicySource` that returns (or raises) fixed, caller-supplied outcomes (ADR R2, §8.4).

    `outcome` is either the `FetchedPolicy` every `fetch()` call returns, or
    the `Exception` instance every call raises — a test constructs it with
    `linceo.core.remote_policy.RemotePolicyFetchError` to simulate a failed
    fetch without needing a real network or HTTP client. `calls` counts how
    many times `fetch` was invoked, so a test can assert whether
    `linceo.core.remote_policy.resolve_remote_policy_document` actually
    attempted one. `cache_key_outcome` is the fixed string `cache_key()`
    returns (default: an arbitrary but stable value, distinct instances
    given different values so a test can assert two fakes never collide —
    ADR §9's cache-collision fix, exercised without a real `PolicySource`),
    or an `Exception` it raises instead, for a test that simulates a source
    unable to resolve its own location.
    """

    outcome: FetchedPolicy | Exception
    cache_key_outcome: str | Exception = "fake-cache-key"
    calls: int = field(default=0, init=False)

    def fetch(self) -> FetchedPolicy:
        """Return (or raise) the fixed outcome this fake was constructed with."""
        self.calls += 1
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    def cache_key(self) -> str:
        """Return (or raise) the fixed `cache_key_outcome` this fake was constructed with."""
        if isinstance(self.cache_key_outcome, Exception):
            raise self.cache_key_outcome
        return self.cache_key_outcome
