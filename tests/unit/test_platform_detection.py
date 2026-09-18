"""Tests for `linceo.providers.detection.detect_platform` (ADR §4 R1, §8).

`detect_platform` takes `env` as a plain `Mapping`, so every scenario here
is a pure function call — no `monkeypatch.setenv`, no risk of leaking real
process environment into the assertion. The one exception is
`test_host_variables_absent_from_the_passed_env_still_fall_back_to_local`,
which needs a real, separate "host" environment to reproduce the bug it
guards against — see its own docstring.
"""

from __future__ import annotations

import pytest

from linceo.core.context import Platform
from linceo.providers.detection import detect_platform


def test_tf_build_true_detects_azure_devops() -> None:
    assert detect_platform({"TF_BUILD": "True"}) is Platform.AZURE_DEVOPS


def test_empty_environment_falls_back_to_local() -> None:
    assert detect_platform({}) is Platform.LOCAL


def test_tf_build_absent_falls_back_to_local_even_with_other_azure_variables_present() -> None:
    """A partial/forged environment without the sentinel itself must not be mistaken for Azure."""
    env = {"BUILD_REPOSITORY_NAME": "acme/widgets", "BUILD_SOURCEVERSION": "a" * 40}

    assert detect_platform(env) is Platform.LOCAL


def test_tf_build_with_an_unexpected_value_falls_back_to_local() -> None:
    """Azure Pipelines only ever sets this to the literal string "True" — nothing else counts."""
    assert detect_platform({"TF_BUILD": "true"}) is Platform.LOCAL
    assert detect_platform({"TF_BUILD": "1"}) is Platform.LOCAL
    assert detect_platform({"TF_BUILD": ""}) is Platform.LOCAL


def test_host_variables_absent_from_the_passed_env_still_fall_back_to_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reproduces the real bug found running the reference container on an actual Azure
    Pipelines agent: `docker run` does not inherit its own process's environment, so an
    agent that genuinely has `TF_BUILD` (and every other Azure variable) set is invisible
    to `linceo` running inside a container the invocation never forwarded them into —
    `auto` then falls back to `local`, silently, for a run that really is on Azure DevOps.

    `monkeypatch.setenv` here stands in for "the host agent's own shell environment" —
    a real, separate `os.environ`, deliberately not what gets passed as `env` below (that
    plain `{}` stands in for the container's own process, exactly what a `docker run` with
    no `-e TF_BUILD` produces regardless of what the host has). `detect_platform` must
    answer only from the `env` mapping it is explicitly handed; if it — or anything
    upstream of it — ever started reading the real process environment instead, this is
    the test that would catch it, since the two disagree here on purpose.
    """
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REPOSITORY_NAME", "juandiego-13/fast_Api/_git/dummy-vulnerable-repo")

    assert detect_platform({}) is Platform.LOCAL
