"""Concrete context providers.

Implementations of the core ``ContextProvider`` port for specific CI
platforms — ``local`` and ``azure_devops`` in the reference build (see
``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md``, §10). This is the
only package in the project allowed to read ``os.environ`` directly — see
``AGENTS.md``, "Layer boundaries" — confined here to
``environment.process_environment`` and, through it, ``azure_devops``'s own
resolution; also used directly by callers (such as CLI configuration
loading, ADR §5/R5, and ``--platform auto`` detection) that need the raw
process environment for reasons unrelated to any specific
``ContextProvider``.
"""

from linceo.core.context import ContextResolutionError
from linceo.providers.azure_devops import AzureDevOpsContextProvider
from linceo.providers.detection import detect_platform
from linceo.providers.environment import process_environment
from linceo.providers.local import LocalContextProvider

__all__ = [
    "AzureDevOpsContextProvider",
    "ContextResolutionError",
    "LocalContextProvider",
    "detect_platform",
    "process_environment",
]
