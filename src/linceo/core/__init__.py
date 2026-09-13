"""Domain and ports.

This package holds the orchestrator's domain model and the port contracts
it depends on (``ContextProvider``, ``ToolExecutor``, ``ToolIntegration``).

It imports nothing beyond the standard library and other ``linceo.core``
modules — no ``adapters``, ``providers``, ``cli``, or third-party package —
and never reads ``os.environ`` directly. See ``AGENTS.md``, "Layer
boundaries", for the full rule and
``tests/unit/test_import_boundaries.py`` for how it is enforced.
"""

from linceo.core.context import ExecutionContext, Platform
from linceo.core.execution import DataSource, ExecutionStatus, ToolExecution
from linceo.core.findings import Category, Finding, Location, Package
from linceo.core.ports import ContextProvider, ProcessResult, ToolExecutor, ToolIntegration
from linceo.core.results import RunResult, RunStatus, Verdict
from linceo.core.severity import Severity, SeveritySource

__all__ = [
    "Category",
    "ContextProvider",
    "DataSource",
    "ExecutionContext",
    "ExecutionStatus",
    "Finding",
    "Location",
    "Package",
    "Platform",
    "ProcessResult",
    "RunResult",
    "RunStatus",
    "Severity",
    "SeveritySource",
    "ToolExecution",
    "ToolExecutor",
    "ToolIntegration",
    "Verdict",
]
