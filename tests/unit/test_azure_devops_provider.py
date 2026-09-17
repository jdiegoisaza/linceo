"""Tests for `AzureDevOpsContextProvider` (ADR §10): environment fixtures for real triggers.

Every scenario clears the full set of variables this provider reads before
setting only the ones the scenario needs — deliberately, so a test never
passes by accident because the *host* running this suite happens to carry
one of these variables (e.g. this suite itself running inside a real Azure
Pipelines agent one day).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from linceo.core.context import ContextResolutionError, Platform
from linceo.providers.azure_devops import AzureDevOpsContextProvider

_ALL_KNOWN_VARS = (
    "BUILD_REPOSITORY_NAME",
    "BUILD_SOURCEVERSION",
    "BUILD_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_PULLREQUESTID",
    "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER",
    "BUILD_BUILDID",
    "BUILD_REPOSITORY_URI",
    "BUILD_SOURCESDIRECTORY",
)


@pytest.fixture(autouse=True)
def _clean_azure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_KNOWN_VARS:
        monkeypatch.delenv(var, raising=False)


def test_branch_build_resolves_repository_commit_and_full_branch_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A branch named `feature/foo` must survive whole, not truncated to its last segment."""
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "a" * 40)
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/heads/feature/foo")
    monkeypatch.setenv("BUILD_BUILDID", "4242")
    monkeypatch.setenv("BUILD_REPOSITORY_URI", "https://dev.azure.com/acme/widgets/_git/widgets")

    context = AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.platform is Platform.AZURE_DEVOPS
    assert context.repository == "acme/widgets"
    assert context.commit == "a" * 40
    assert context.branch == "feature/foo"
    assert context.build_id == "4242"
    assert context.source_url == "https://dev.azure.com/acme/widgets/_git/widgets"
    assert context.pull_request_id is None


def test_tag_build_strips_the_tags_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "a" * 40)
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/tags/v1.2.3")

    context = AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch == "v1.2.3"


def test_pull_request_build_prefers_the_pr_source_branch_over_the_merge_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a PR trigger, BUILD_SOURCEBRANCH holds the synthetic merge ref, not a real branch."""
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "b" * 40)
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/pull/17/merge")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature/foo")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "17")

    context = AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch == "feature/foo"
    assert context.pull_request_id == "17"


def test_github_backed_pull_request_prefers_the_human_facing_pr_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A GitHub-backed repository sets both PR variables; the human-facing number wins."""
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "c" * 40)
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature/foo")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "9001")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", "42")

    context = AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.pull_request_id == "42"


def test_branch_with_an_unrecognized_ref_shape_is_returned_unstripped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ref matching neither known prefix (e.g. the PR merge ref, seen with no PR source set)
    is returned as-is rather than guessed at."""
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "f" * 40)
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/pull/17/merge")

    context = AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch == "refs/pull/17/merge"


def test_missing_required_variables_raise_an_actionable_context_resolution_error(
    tmp_path: Path,
) -> None:
    with pytest.raises(ContextResolutionError, match="BUILD_REPOSITORY_NAME"):
        AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()


def test_missing_commit_alone_raises_an_actionable_context_resolution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")

    with pytest.raises(ContextResolutionError, match="BUILD_SOURCEVERSION"):
        AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()


def test_optional_fields_resolve_to_none_when_their_variables_are_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A branch build with no PR context and no build metadata still resolves — nothing invented."""
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "d" * 40)

    context = AzureDevOpsContextProvider(workspace_path=str(tmp_path)).resolve()

    assert context.branch is None
    assert context.pull_request_id is None
    assert context.build_id is None
    assert context.source_url is None


def test_workspace_path_is_the_constructor_argument_not_build_sourcesdirectory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--path` must still control what gets scanned under Azure, exactly as it does for `local`."""
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "e" * 40)
    monkeypatch.setenv("BUILD_SOURCESDIRECTORY", "/some/agent/checkout/root")
    requested = tmp_path / "services" / "api"
    requested.mkdir(parents=True)

    context = AzureDevOpsContextProvider(workspace_path=str(requested)).resolve()

    assert context.workspace_path == str(requested.resolve())
