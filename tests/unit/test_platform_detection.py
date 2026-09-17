"""Tests for `linceo.providers.detection.detect_platform` (ADR §4 R1, §8).

`detect_platform` takes `env` as a plain `Mapping`, so every scenario here
is a pure function call — no `monkeypatch.setenv`, no risk of leaking real
process environment into the assertion.
"""

from __future__ import annotations

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
