"""Tests for `linceo context` (ADR §4 R1, §10): the CLI wired end to end, plus the
anti-drift checks that keep this command, `linceo.providers.azure_devops.ENV_VARS`, and
the reference azure-pipelines template from silently disagreeing with each other.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from linceo.cli.context import _AZURE_DEVOPS_VAR_DESCRIPTIONS
from linceo.cli.main import app
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK
from linceo.providers.azure_devops import ENV_VARS as AZURE_DEVOPS_ENV_VARS
from linceo.providers.detection import AZURE_DEVOPS_SENTINEL_ENV_VAR

runner = CliRunner()

#: Mirrors `tests/unit/test_azure_devops_provider.py`'s `_ALL_KNOWN_VARS`: every
#: variable any scenario below might set, cleared up front so this suite never passes
#: (or fails) by accident because the host actually running it happens to carry one.
_ALL_KNOWN_VARS = (AZURE_DEVOPS_SENTINEL_ENV_VAR, *AZURE_DEVOPS_ENV_VARS)


@pytest.fixture(autouse=True)
def _clean_azure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_KNOWN_VARS:
        monkeypatch.delenv(var, raising=False)


def test_var_descriptions_stay_in_sync_with_the_canonical_provider_lists() -> None:
    """A variable added to `detection`/`azure_devops` can't silently go undescribed here."""
    assert set(_AZURE_DEVOPS_VAR_DESCRIPTIONS) == set(_ALL_KNOWN_VARS)


def test_azure_pipelines_template_forwards_every_variable_this_project_reads() -> None:
    """The exact regression this whole feature exists to prevent (task 2): the reference
    template's `docker run` must pass `-e VARNAME` for every variable `linceo` reads for
    `azure_devops`, not a partial or stale copy of the list hand-maintained separately.

    Plain text search, not a YAML/bash parse: all that matters is the literal `-e VARNAME`
    token reaching the `docker run` invocation somewhere in the step script, and this way
    the test needs no extra dependency to express that.
    """
    template_path = (
        Path(__file__).resolve().parents[2] / "azure-pipelines" / "templates" / "linceo-scan.yml"
    )
    script = template_path.read_text(encoding="utf-8")

    missing = [var for var in _ALL_KNOWN_VARS if f"-e {var}" not in script]
    assert not missing, (
        f"{missing} not forwarded with `-e` in azure-pipelines/templates/linceo-scan.yml — "
        "a container invocation using this template would silently lose them, exactly the "
        "bug this test exists to catch."
    )


def test_clean_container_environment_falls_back_to_local_and_explains_why() -> None:
    """Reproduces the reported bug end to end: no Azure variable reaches this process
    (exactly what `docker run` with no `-e` flags produces), `auto` picks `local`, and the
    output says so explicitly instead of leaving it to be inferred from a scan's own
    `platform=...` header after the fact.
    """
    result = runner.invoke(app, ["context"])

    assert result.exit_code == EXIT_OK
    assert "Platform: local (auto-detected)" in result.output
    assert "TF_BUILD" in result.output
    assert "not set" in result.output
    assert "its environment was not passed into this one" in result.output


def test_azure_devops_variables_present_are_detected_and_resolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "acme/widgets")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "a" * 40)
    monkeypatch.setenv("BUILD_BUILDID", "4242")

    result = runner.invoke(app, ["context", "--path", str(tmp_path)])

    assert result.exit_code == EXIT_OK
    assert "Platform: azure_devops (auto-detected)" in result.output
    assert "repository: acme/widgets" in result.output
    assert "build_id: 4242" in result.output
    assert "was not passed into this one" not in result.output


def test_forced_azure_devops_with_nothing_set_fails_with_an_actionable_message(
    tmp_path: Path,
) -> None:
    result = runner.invoke(app, ["context", "--platform", "azure_devops", "--path", str(tmp_path)])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Resolved ExecutionContext: FAILED" in result.output
    assert "BUILD_REPOSITORY_NAME is not set" in result.output


def test_context_is_listed_in_the_root_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert "context" in result.output
