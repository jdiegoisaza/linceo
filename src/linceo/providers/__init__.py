"""Concrete context and policy-source providers.

Implementations of the core ``ContextProvider`` port for specific CI
platforms — ``local``, ``azure_devops``, and ``github_actions`` (see
``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md``, §1, §10) — plus
the one reference ``PolicySource`` implementation, ``AzureDevOpsPolicySource``
(ADR R2, §8.4). This is the only package in the project allowed to read
``os.environ`` directly — see ``AGENTS.md``, "Layer boundaries" — confined
here to ``environment.process_environment`` and, through it, each
platform provider's own resolution; also used directly by callers (such as
CLI configuration loading, ADR §5/R5, and ``--platform auto`` detection)
that need the raw process environment for reasons unrelated to any specific
``ContextProvider``.
"""

from linceo.core.context import ContextResolutionError
from linceo.providers.azure_devops import AzureDevOpsContextProvider, AzureDevOpsPolicySource
from linceo.providers.detection import detect_platform
from linceo.providers.environment import process_environment
from linceo.providers.github_actions import GitHubActionsContextProvider
from linceo.providers.local import LocalContextProvider

__all__ = [
    "AzureDevOpsContextProvider",
    "AzureDevOpsPolicySource",
    "ContextResolutionError",
    "GitHubActionsContextProvider",
    "LocalContextProvider",
    "detect_platform",
    "process_environment",
]
