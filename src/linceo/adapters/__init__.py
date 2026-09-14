"""Concrete tool integrations.

Implementations of the core ``ToolIntegration`` port for specific security
tools — Gitleaks and Trivy in the reference build (see
``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md``, §10). Also holds
``SubprocessToolExecutor``, the default real ``ToolExecutor`` every
integration here runs under.
"""

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor

__all__ = ["GitleaksIntegration", "SubprocessToolExecutor"]
