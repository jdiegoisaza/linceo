"""Tests for `linceo.providers.environment.process_environment`."""

from __future__ import annotations

import pytest

from linceo.providers.environment import process_environment


def test_returns_a_plain_mapping_reflecting_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LINCEO_TEST_VAR", "some-value")

    env = process_environment()

    assert env["LINCEO_TEST_VAR"] == "some-value"


def test_returns_a_snapshot_not_a_live_view(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutating the returned mapping must never mutate `os.environ` itself."""
    monkeypatch.setenv("LINCEO_TEST_VAR", "before")

    env = dict(process_environment())
    env["LINCEO_TEST_VAR"] = "after"

    assert process_environment()["LINCEO_TEST_VAR"] == "before"
