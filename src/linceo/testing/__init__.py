"""Permanent test doubles and fixtures.

Distributed as part of the installed package and versioned with the same
backward-compatibility guarantees as any other public module — not
scaffolding discarded once real adapters exist. Holds ``FakeContextProvider``,
``FakeToolExecutor``, and ``FakePolicySource``, an injectable clock and
identifier generator, and golden fixtures captured from real tool output.
See ``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md``, §11.
"""

from linceo.testing.fakes import FakeContextProvider, FakePolicySource, FakeToolExecutor

__all__ = ["FakeContextProvider", "FakePolicySource", "FakeToolExecutor"]
