"""linceo: a DevSecOps tool orchestrator.

Runs one or more security tools against a workspace and produces a single
verdict over their combined evidence — see
``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`` for the full
architectural contract.
"""

from importlib.metadata import version

__version__ = version("linceo")

__all__ = ["__version__"]
