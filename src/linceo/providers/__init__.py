"""Concrete context providers.

Implementations of the core ``ContextProvider`` port for specific CI
platforms — ``local`` and ``azure_devops`` in the reference build (see
``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md``, §10). This is the
only package in the project allowed to read ``os.environ`` directly — see
``AGENTS.md``, "Layer boundaries" — confined here to
``environment.process_environment``, used by callers (such as CLI
configuration loading, ADR §5/R5) that need the raw process environment
for reasons unrelated to any specific ``ContextProvider``.
"""

from linceo.providers.environment import process_environment
from linceo.providers.local import ContextResolutionError, LocalContextProvider

__all__ = ["ContextResolutionError", "LocalContextProvider", "process_environment"]
