"""A name -> plugin lookup for `ToolIntegration` and `ContextProvider` selection.

Backs both the `--tool` and `--platform` flags described in ADR §8: a
registry is populated either by explicit registration or by discovering
the `linceo.tool_integrations` / `linceo.context_providers` entry point
groups declared in `pyproject.toml` (AGENTS.md, "Plugin entry points").
Those groups exist from the first commit specifically so third-party
integrations are a first-class extension mechanism, not something bolted
on after the fact (ADR §13.1).
"""

from __future__ import annotations

from collections.abc import Iterator
from importlib import metadata
from typing import Generic, TypeVar

#: Entry point group for third-party `ToolIntegration` plugins.
TOOL_INTEGRATION_ENTRY_POINT_GROUP = "linceo.tool_integrations"

#: Entry point group for third-party `ContextProvider` plugins.
CONTEXT_PROVIDER_ENTRY_POINT_GROUP = "linceo.context_providers"

T = TypeVar("T")


class UnknownPluginError(KeyError):
    """No plugin is registered under the requested name."""


class PluginRegistry(Generic[T]):
    """A name -> plugin lookup, populated by registration or entry-point discovery.

    Stores whatever an entry point loads — typically a class or a factory
    callable — rather than an already-constructed instance: a provider
    like `local` needs constructor arguments (a workspace path) that only
    the caller knows, so eager instantiation here would not generalize.
    """

    def __init__(self) -> None:
        """Create an empty registry."""
        self._plugins: dict[str, T] = {}

    def register(self, name: str, plugin: T) -> None:
        """Register `plugin` under `name`, overwriting any prior registration for it."""
        self._plugins[name] = plugin

    def get(self, name: str) -> T:
        """Return the plugin registered under `name`.

        Raises:
            UnknownPluginError: if `name` was never registered; the
                message lists every name that was, for an actionable CLI
                error (ADR §4/R4).
        """
        try:
            return self._plugins[name]
        except KeyError:
            available = ", ".join(sorted(self._plugins)) or "(none)"
            msg = f"no plugin registered under {name!r}; available: {available}"
            raise UnknownPluginError(msg) from None

    def names(self) -> frozenset[str]:
        """Return every currently registered plugin name."""
        return frozenset(self._plugins)

    def __iter__(self) -> Iterator[str]:
        """Iterate over every currently registered plugin name."""
        return iter(self._plugins)

    def __len__(self) -> int:
        """Return how many plugins are currently registered."""
        return len(self._plugins)

    @classmethod
    def discover(cls, *, entry_point_group: str) -> PluginRegistry[T]:
        """Build a registry from every entry point in `entry_point_group`.

        Each entry point's loaded object is registered under the entry
        point's own declared name — the convention AGENTS.md, "Plugin
        entry points", documents for third-party integrations.
        """
        registry: PluginRegistry[T] = cls()
        for entry_point in metadata.entry_points(group=entry_point_group):
            registry.register(entry_point.name, entry_point.load())
        return registry
