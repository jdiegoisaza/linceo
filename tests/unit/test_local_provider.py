"""Tests for `LocalContextProvider` (ADR §10) against real, disposable git repositories.

`git` itself (unlike Gitleaks/Trivy) is treated as always available in any
environment capable of running this project's own test suite — it is not
one of the optional security-tool binaries `tests/integration/` exists for.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from linceo.core.context import Platform
from linceo.providers.local import ContextResolutionError, LocalContextProvider


def _git(*args: str, cwd: Path) -> None:
    _git_output(*args, cwd=cwd)


def _git_output(*args: str, cwd: Path) -> str:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    completed = subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603
    return completed.stdout.strip()


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)


def _commit_all(path: Path, message: str) -> None:
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", message, cwd=path)


def test_resolves_platform_workspace_path_and_commit(tmp_path: Path) -> None:
    repo = tmp_path / "widgets"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    assert context.platform is Platform.LOCAL
    assert context.workspace_path == str(repo.resolve())
    expected_commit = _git_output("rev-parse", "HEAD", cwd=repo)
    assert context.commit == expected_commit
    assert len(context.commit) == 40


def test_branch_is_the_current_branch_name(tmp_path: Path) -> None:
    repo = tmp_path / "widgets"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    current_branch = _git_output("rev-parse", "--abbrev-ref", "HEAD", cwd=repo)
    assert context.branch == current_branch


def test_detached_head_resolves_branch_to_none(tmp_path: Path) -> None:
    repo = tmp_path / "widgets"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")
    _git("checkout", "-q", "--detach", "HEAD", cwd=repo)

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    assert context.branch is None


def test_pull_request_id_build_id_and_source_url_are_always_none(tmp_path: Path) -> None:
    repo = tmp_path / "widgets"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    assert context.pull_request_id is None
    assert context.build_id is None
    assert context.source_url is None


@pytest.mark.parametrize(
    ("remote_url", "expected_repository"),
    [
        ("https://github.com/acme/widgets.git", "acme/widgets"),
        ("https://github.com/acme/widgets", "acme/widgets"),
        ("git@github.com:acme/widgets.git", "acme/widgets"),
        ("ssh://git@github.com/acme/widgets.git", "acme/widgets"),
        ("https://dev.azure.com/acme/project/_git/widgets", "acme/project/_git/widgets"),
    ],
)
def test_repository_is_parsed_from_the_origin_remote_url(
    tmp_path: Path, remote_url: str, expected_repository: str
) -> None:
    repo = tmp_path / "widgets"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")
    _git("remote", "add", "origin", remote_url, cwd=repo)

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    assert context.repository == expected_repository


def test_repository_falls_back_to_the_checkout_directory_name_without_a_remote(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "widgets-without-a-remote"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    assert context.repository == "widgets-without-a-remote"


def test_repository_falls_back_to_the_directory_name_for_an_unrecognized_remote_shape(
    tmp_path: Path,
) -> None:
    """A remote URL that is neither scp-like nor scheme-like (e.g. a bare local path)
    matches neither pattern — the fallback must still apply rather than raising."""
    repo = tmp_path / "widgets-with-a-local-remote"
    _init_repo(repo)
    (repo / "app.py").write_text("print('hi')\n")
    _commit_all(repo, "initial commit")
    _git("remote", "add", "origin", "/srv/git/widgets.git", cwd=repo)

    context = LocalContextProvider(workspace_path=str(repo)).resolve()

    assert context.repository == "widgets-with-a-local-remote"


def test_scanning_a_subdirectory_keeps_that_subdirectory_as_workspace_path(tmp_path: Path) -> None:
    """Scanning a monorepo subdirectory must scan only that subdirectory, not the whole repo."""
    repo = tmp_path / "monorepo"
    _init_repo(repo)
    (repo / "services").mkdir()
    (repo / "services" / "api.py").write_text("print('api')\n")
    _commit_all(repo, "initial commit")

    context = LocalContextProvider(workspace_path=str(repo / "services")).resolve()

    assert context.workspace_path == str((repo / "services").resolve())
    # repository/commit are still resolved against the checkout as a whole.
    assert context.repository == "monorepo"


def test_a_directory_that_is_not_a_git_repository_raises_context_resolution_error(
    tmp_path: Path,
) -> None:
    plain_dir = tmp_path / "not-a-repo"
    plain_dir.mkdir()

    with pytest.raises(ContextResolutionError, match="git rev-parse HEAD"):
        LocalContextProvider(workspace_path=str(plain_dir)).resolve()


def test_missing_git_binary_raises_an_actionable_context_resolution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("linceo.providers.local.GIT_BINARY", "definitely-not-a-real-binary-xyz")

    with pytest.raises(ContextResolutionError, match="git binary not found on PATH"):
        LocalContextProvider(workspace_path=str(tmp_path)).resolve()
