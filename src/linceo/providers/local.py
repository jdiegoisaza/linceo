"""``local``: the mandatory `ContextProvider` for a plain git checkout (ADR §4, §10).

Resolves `ExecutionContext` by asking `git` about the workspace directly —
current commit, branch, and (when configured) the `origin` remote — rather
than any CI-specific environment variable. That is exactly what makes this
the one provider guaranteed to work on a developer's laptop with no
pipeline involved at all (ADR §10): it depends on nothing but `git` itself
being on `PATH`.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from linceo.core.context import ExecutionContext, Platform

#: Binary name looked up on `PATH` — never a path baked in at install time.
GIT_BINARY = "git"

#: `git@host:owner/repo.git` and `ssh://git@host/owner/repo.git` style remotes.
_SCP_LIKE_REMOTE = re.compile(r"^[^/@\s]+@[^:/\s]+:(?P<path>.+?)(?:\.git)?/?$")
#: `https://host/owner/repo.git`, `ssh://host/owner/repo.git`, and similar.
_URL_LIKE_REMOTE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+/(?P<path>.+?)(?:\.git)?/?$")


class ContextResolutionError(Exception):
    """`workspace_path` is not a usable local git checkout, or `git` is unavailable (ADR §10)."""


def _run_git(args: Sequence[str], *, cwd: str) -> str:
    """Run ``git <args>`` in `cwd` and return its stripped stdout.

    Raises:
        ContextResolutionError: if `git` is not on `PATH`, or the command
            exits non-zero (e.g. `cwd` is not inside a git working tree).
    """
    try:
        completed = subprocess.run(  # noqa: S603 -- argv is a fixed list, never shell=True
            [GIT_BINARY, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        msg = (
            "git binary not found on PATH — the `local` context provider needs it to resolve "
            "the current repository, commit, and branch. Install git and ensure it is on PATH."
        )
        raise ContextResolutionError(msg) from exc

    if completed.returncode != 0:
        msg = (
            f"`git {' '.join(args)}` failed in {cwd!r} (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
        raise ContextResolutionError(msg)
    return completed.stdout.strip()


def _repository_name(*, remote_url: str | None, workspace_root: str) -> str:
    """Derive a human-readable repository identifier.

    Prefers `owner/repo` parsed out of a configured `origin` remote; falls
    back to the git checkout's top-level directory name when there is no
    remote at all (a common state for a brand-new local repository).
    """
    if remote_url:
        for pattern in (_SCP_LIKE_REMOTE, _URL_LIKE_REMOTE):
            match = pattern.match(remote_url)
            if match:
                return match.group("path")
    return Path(workspace_root).name


@dataclass(frozen=True, slots=True)
class LocalContextProvider:
    """Resolves `ExecutionContext` from the git checkout at `workspace_path` (ADR §10).

    `pull_request_id`, `build_id`, and `source_url` are always `None` — a
    local run outside any CI pipeline has none of the three by definition
    (see `linceo.core.context.ExecutionContext`). `workspace_path` in the
    resolved context is `workspace_path` itself (resolved to an absolute
    path), never the git checkout's top-level directory: scanning a
    sub-directory of a larger repository must scan only that
    sub-directory, even though `repository` and `commit` are still
    resolved against the checkout as a whole.
    """

    workspace_path: str

    def resolve(self) -> ExecutionContext:
        """Resolve this run's `ExecutionContext` by asking `git` about `workspace_path`.

        Raises:
            ContextResolutionError: if `git` is missing, or `workspace_path`
                is not inside a git working tree.
        """
        resolved_path = str(Path(self.workspace_path).resolve())
        commit = _run_git(("rev-parse", "HEAD"), cwd=resolved_path)
        branch_name = _run_git(("rev-parse", "--abbrev-ref", "HEAD"), cwd=resolved_path)
        workspace_root = _run_git(("rev-parse", "--show-toplevel"), cwd=resolved_path)

        try:
            remote_url: str | None = _run_git(("remote", "get-url", "origin"), cwd=resolved_path)
        except ContextResolutionError:
            remote_url = None

        return ExecutionContext(
            platform=Platform.LOCAL,
            repository=_repository_name(remote_url=remote_url, workspace_root=workspace_root),
            workspace_path=resolved_path,
            commit=commit,
            branch=None if branch_name == "HEAD" else branch_name,
        )
