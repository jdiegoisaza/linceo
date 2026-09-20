"""Tests for `GitHubActionsContextProvider` (ADR §1, §10): environment fixtures for real triggers.

Mirrors `tests/unit/test_azure_devops_provider.py`'s structure and
intent: every scenario clears the full set of variables this provider
reads before setting only the ones the scenario needs, so a test never
passes by accident because the *host* running this suite happens to carry
one of these variables (e.g. this suite itself running inside a real
GitHub Actions runner one day).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from linceo.core.context import ContextResolutionError, Platform
from linceo.providers.github_actions import ENV_VARS, GitHubActionsContextProvider

#: Every variable `resolve()` actually reads (`ENV_VARS`), plus one it
#: deliberately does not: `GITHUB_WORKSPACE` — see
#: `test_workspace_path_is_the_constructor_argument_not_github_workspace`.
_ALL_KNOWN_VARS = (*ENV_VARS, "GITHUB_WORKSPACE")


@pytest.fixture(autouse=True)
def _clean_github_actions_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_KNOWN_VARS:
        monkeypatch.delenv(var, raising=False)


def test_push_to_branch_resolves_repository_commit_and_full_branch_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A branch named `feature/foo` must survive whole, not truncated to its last segment."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/feature/foo")
    monkeypatch.setenv("GITHUB_RUN_ID", "4242")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")

    context = GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.platform is Platform.GITHUB_ACTIONS
    assert context.repository == "acme/widgets"
    assert context.commit == "a" * 40
    assert context.branch == "feature/foo"
    assert context.build_id == "4242"
    assert context.source_url == "https://github.com/acme/widgets"
    assert context.pull_request_id is None


def test_push_of_a_tag_strips_the_tags_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v1.2.3")

    context = GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch == "v1.2.3"


def test_pull_request_prefers_the_head_ref_and_extracts_the_number_from_the_merge_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a `pull_request` trigger, GITHUB_REF holds the synthetic merge ref, not a real branch.

    `commit` is left as `GITHUB_SHA` even though that is the ephemeral merge
    commit, not the PR branch's own head — see `linceo.providers.github_actions`'s
    module docstring for why that is a deliberate, documented decision.
    """
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/17/merge")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/foo")

    context = GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch == "feature/foo"
    assert context.pull_request_id == "17"
    assert context.commit == "b" * 40


def test_branch_with_an_unrecognized_ref_shape_is_returned_unstripped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ref matching neither known prefix (e.g. the PR merge ref, seen with no head ref set)
    is returned as-is rather than guessed at."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/17/merge")

    context = GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch == "refs/pull/17/merge"
    assert context.pull_request_id == "17"


def test_missing_required_variables_raise_an_actionable_context_resolution_error(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContextResolutionError, match="GITHUB_REPOSITORY"):
        GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()


def test_missing_commit_alone_raises_an_actionable_context_resolution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")

    with pytest.raises(ContextResolutionError, match="GITHUB_SHA"):
        GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()


def test_optional_fields_resolve_to_none_when_their_variables_are_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A push build with nothing else set still resolves — nothing invented."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)

    context = GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch is None
    assert context.pull_request_id is None
    assert context.build_id is None
    assert context.source_url is None


def test_source_url_is_none_when_the_server_url_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)

    context = GitHubActionsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.source_url is None


def test_workspace_path_is_the_constructor_argument_not_github_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--path` must still control what gets scanned, exactly as it does for `local`."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("GITHUB_SHA", "e" * 40)
    monkeypatch.setenv("GITHUB_WORKSPACE", "/home/runner/work/widgets/widgets")
    requested = tmp_path / "services" / "api"
    requested.mkdir(parents=True)

    context = GitHubActionsContextProvider(workspace_path=str(requested)).resolve()

    assert context.workspace_path == str(requested.resolve())
