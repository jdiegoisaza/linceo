"""The one primitive every case in `run.py` is built from: run a subprocess, time it, capture it.

`CaseResult.status` is about whether *this script* could capture the case
at all (`ok`, `failed_to_invoke`, `omitted`, `not_available`) — entirely
separate from `exit_code`, which is whatever the invoked process itself
returned, recorded verbatim as data. A `linceo scan iac` that cleanly
reports "checkov binary not found on PATH" and exits 3 is `status="ok"`
with `exit_code=3` — the script successfully captured a real, honest
result; it is not a script failure.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class CaseResult:
    """Everything one case produced — raw, unnormalized (`run.py` normalizes on the way out)."""

    id: str
    description: str
    mode: str  # "installed" | "container" | "meta"
    argv: tuple[str, ...]
    status: str  # "ok" | "failed_to_invoke" | "omitted" | "not_available"
    reason: str | None = None
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout: str = ""
    stderr: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    captured_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


def docker_available() -> bool:
    """Whether `docker` is on `PATH` *and* its daemon actually answers, not just present on disk."""
    if shutil.which("docker") is None:
        return False
    argv = ["docker", "info"]  # `docker` resolved via PATH on purpose
    try:
        subprocess.run(argv, capture_output=True, timeout=10, check=True)  # noqa: S603
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return True


def run_capture(
    case_id: str,
    description: str,
    argv: Sequence[str],
    *,
    mode: str,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
    timeout: float = 600.0,
) -> CaseResult:
    """Run `argv` for real, timing it, into a `CaseResult` — never raises on the child's failure.

    A non-zero exit, a crash, or the child producing no output at all are
    all legitimate, capturable outcomes (`status="ok"`, whatever
    `exit_code` the process actually returned) — only this function's own
    inability to even start the process (missing binary, timeout) becomes
    `status="failed_to_invoke"`.
    """
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603
            list(argv),
            env=dict(env) if env is not None else None,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CaseResult(
            id=case_id,
            description=description,
            mode=mode,
            argv=tuple(argv),
            status="failed_to_invoke",
            reason=f"timed out after {timeout:.0f}s",
            duration_seconds=time.monotonic() - started,
            stdout=(exc.stdout or b"").decode()
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode()
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
        )
    except OSError as exc:
        return CaseResult(
            id=case_id,
            description=description,
            mode=mode,
            argv=tuple(argv),
            status="failed_to_invoke",
            reason=str(exc),
            duration_seconds=time.monotonic() - started,
        )

    return CaseResult(
        id=case_id,
        description=description,
        mode=mode,
        argv=tuple(argv),
        status="ok",
        exit_code=completed.returncode,
        duration_seconds=time.monotonic() - started,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def omitted(
    case_id: str, description: str, *, mode: str, argv: Sequence[str], reason: str
) -> CaseResult:
    """A case deliberately never attempted — a missing credential, absent Docker, an older release.

    Distinct from a failure: nothing was tried, and the reason is always
    named (ADR §5's own "never silent" principle, applied to this script's
    own report rather than to a run's evidence).
    """
    return CaseResult(
        id=case_id,
        description=description,
        mode=mode,
        argv=tuple(argv),
        status="omitted",
        reason=reason,
    )
