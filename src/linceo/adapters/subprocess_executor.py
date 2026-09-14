"""`SubprocessToolExecutor`: the default `ToolExecutor`, running a real OS subprocess (ADR §9).

`argv` is always passed to `subprocess.run` as a list, never assembled into
a shell string (ADR §9, "argumentos en lista, nunca shell=True") — a tool
name or argument can never be reinterpreted by a shell.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from linceo.core.ports import ProcessResult
from linceo.providers.environment import process_environment


@dataclass(frozen=True, slots=True)
class SubprocessToolExecutor:
    """Runs a tool's binary as a real subprocess, with no shell involved (ADR §9).

    `env` is merged on top of the inherited process environment rather
    than replacing it outright: replacing it would drop `PATH` (and with
    it, the ability to even locate the binary this executor was asked to
    run) the moment a `ToolIntegration` needs to pass through a single
    extra variable. `timeout_seconds` is `None` by default (no timeout);
    a `subprocess.TimeoutExpired` and every other execution failure look
    identical to `linceo.core.engine`, which treats both as absence of
    evidence (ADR §5), the same way it treats a missing binary.
    """

    timeout_seconds: float | None = None

    def run(self, argv: Sequence[str], *, env: Mapping[str, str], cwd: str) -> ProcessResult:
        """Run `argv` as a subprocess, `env` merged over the inherited process environment.

        Raises:
            FileNotFoundError: if `argv[0]` cannot be found on `PATH`.
            subprocess.TimeoutExpired: if `timeout_seconds` is set and exceeded.
        """
        child_env = {**process_environment(), **env}
        started_at = datetime.now(UTC)
        completed = subprocess.run(  # noqa: S603 -- argv is always a list, never shell=True
            list(argv),
            env=child_env,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        finished_at = datetime.now(UTC)
        return ProcessResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started_at,
            finished_at=finished_at,
        )
