"""Domain, ports, and the orchestration engine.

This package holds the orchestrator's domain model, the port contracts it
depends on (``ContextProvider``, ``ToolExecutor``, ``ToolIntegration``),
and the engine that wires them into a run (``linceo.core.engine``).

It imports nothing beyond the standard library and other ``linceo.core``
modules — no ``adapters``, ``providers``, ``cli``, or third-party package —
and never reads ``os.environ`` directly. See ``AGENTS.md``, "Layer
boundaries", for the full rule and
``tests/unit/test_import_boundaries.py`` for how it is enforced.
"""

from linceo.core.baseline import (
    Baseline,
    BaselineConfigurationError,
    BaselineEntry,
    BaselineOutcome,
    apply_baseline,
)
from linceo.core.config import Config, ConfigurationError, load_config
from linceo.core.context import ExecutionContext, Platform
from linceo.core.dedup import deduplicate
from linceo.core.engine import run
from linceo.core.execution import DataSource, ExecutionStatus, ToolExecution
from linceo.core.exit_codes import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_GATE_FAILED,
    EXIT_OK,
    EXIT_TOOL_EXECUTION_FAILED,
    compute_exit_code,
)
from linceo.core.findings import Category, Finding, Location, Package, RawFinding
from linceo.core.gate import count_by_severity, evaluate_gate
from linceo.core.normalization import (
    SeverityNormalizer,
    UnresolvedSeverityError,
    normalize_finding,
)
from linceo.core.ports import ContextProvider, ProcessResult, ToolExecutor, ToolIntegration
from linceo.core.registry import (
    CONTEXT_PROVIDER_ENTRY_POINT_GROUP,
    TOOL_INTEGRATION_ENTRY_POINT_GROUP,
    PluginRegistry,
    UnknownPluginError,
)
from linceo.core.reporters import render_console, render_json
from linceo.core.results import RunResult, RunStatus, Verdict
from linceo.core.severity import SEVERITY_ORDER, Severity, SeveritySource

__all__ = [
    "CONTEXT_PROVIDER_ENTRY_POINT_GROUP",
    "EXIT_CONFIGURATION_ERROR",
    "EXIT_GATE_FAILED",
    "EXIT_OK",
    "EXIT_TOOL_EXECUTION_FAILED",
    "SEVERITY_ORDER",
    "TOOL_INTEGRATION_ENTRY_POINT_GROUP",
    "Baseline",
    "BaselineConfigurationError",
    "BaselineEntry",
    "BaselineOutcome",
    "Category",
    "Config",
    "ConfigurationError",
    "ContextProvider",
    "DataSource",
    "ExecutionContext",
    "ExecutionStatus",
    "Finding",
    "Location",
    "Package",
    "Platform",
    "PluginRegistry",
    "ProcessResult",
    "RawFinding",
    "RunResult",
    "RunStatus",
    "Severity",
    "SeverityNormalizer",
    "SeveritySource",
    "ToolExecution",
    "ToolExecutor",
    "ToolIntegration",
    "UnknownPluginError",
    "UnresolvedSeverityError",
    "Verdict",
    "apply_baseline",
    "compute_exit_code",
    "count_by_severity",
    "deduplicate",
    "evaluate_gate",
    "load_config",
    "normalize_finding",
    "render_console",
    "render_json",
    "run",
]
