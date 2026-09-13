"""Tests for `PluginRegistry` (explicit registration and entry-point discovery)."""

from __future__ import annotations

import pytest

from linceo.core.registry import PluginRegistry, UnknownPluginError


class _DummyPlugin:
    """A stand-in for whatever an entry point loads — a class or factory."""


def test_register_and_get_round_trip() -> None:
    registry: PluginRegistry[str] = PluginRegistry()

    registry.register("gitleaks", "gitleaks-plugin")

    assert registry.get("gitleaks") == "gitleaks-plugin"


def test_register_overwrites_a_prior_registration_under_the_same_name() -> None:
    registry: PluginRegistry[str] = PluginRegistry()

    registry.register("gitleaks", "first")
    registry.register("gitleaks", "second")

    assert registry.get("gitleaks") == "second"


def test_get_raises_and_lists_available_names_when_missing() -> None:
    registry: PluginRegistry[str] = PluginRegistry()
    registry.register("gitleaks", "gitleaks-plugin")

    with pytest.raises(UnknownPluginError, match="gitleaks"):
        registry.get("trivy")


def test_names_and_len_and_iter_reflect_registrations() -> None:
    registry: PluginRegistry[str] = PluginRegistry()
    registry.register("gitleaks", "a")
    registry.register("trivy", "b")

    assert registry.names() == frozenset({"gitleaks", "trivy"})
    assert len(registry) == 2
    assert set(registry) == {"gitleaks", "trivy"}


class _FakeEntryPoint:
    """A stand-in for `importlib.metadata.EntryPoint` that skips real import machinery."""

    def __init__(self, name: str, plugin: object) -> None:
        self.name = name
        self._plugin = plugin

    def load(self) -> object:
        return self._plugin


def test_discover_registers_every_entry_point_in_the_group(monkeypatch: pytest.MonkeyPatch) -> None:
    entry_points = [
        _FakeEntryPoint("gitleaks", _DummyPlugin),
        _FakeEntryPoint("trivy", _DummyPlugin),
    ]

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == "linceo.tool_integrations"
        return entry_points

    monkeypatch.setattr("linceo.core.registry.metadata.entry_points", fake_entry_points)

    group = "linceo.tool_integrations"
    registry = PluginRegistry[type[_DummyPlugin]].discover(entry_point_group=group)

    assert registry.names() == frozenset({"gitleaks", "trivy"})
    assert registry.get("gitleaks") is _DummyPlugin


def test_discover_returns_an_empty_registry_for_an_empty_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_entry_points(*, group: str) -> list[_FakeEntryPoint]:  # noqa: ARG001
        return []

    monkeypatch.setattr("linceo.core.registry.metadata.entry_points", no_entry_points)

    group = "linceo.context_providers"
    registry: PluginRegistry[object] = PluginRegistry.discover(entry_point_group=group)

    assert len(registry) == 0
