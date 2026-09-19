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

from linceo.core.config import Config, ConfigurationError, load_config
from linceo.core.context import ContextResolutionError, ExecutionContext, Platform
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
from linceo.core.gate import count_by_category_and_severity, count_by_severity, evaluate_gate
from linceo.core.normalization import (
    SeverityNormalizer,
    UnresolvedSeverityError,
    normalize_finding,
)
from linceo.core.policy import (
    DEFAULT_MAX_DATA_SOURCE_AGE_DAYS,
    CategoryThresholds,
    ConfigLayer,
    Exclusion,
    ExclusionOutcome,
    Policy,
    PolicyConfigurationError,
    ThresholdResolution,
    Thresholds,
    ToolSkip,
    apply_exclusions,
    thresholds_from_fail_on,
)
from linceo.core.ports import ContextProvider, ProcessResult, ToolExecutor, ToolIntegration
from linceo.core.registry import (
    CONTEXT_PROVIDER_ENTRY_POINT_GROUP,
    TOOL_INTEGRATION_ENTRY_POINT_GROUP,
    PluginRegistry,
    UnknownPluginError,
)
from linceo.core.report_schema import Column, ReportSchema, Truncate
from linceo.core.reporters import render_console, render_json
from linceo.core.results import RunResult, RunStatus, ThresholdBreach, Verdict
from linceo.core.sarif import render_sarif
from linceo.core.severity import SEVERITY_ORDER, Severity, SeveritySource
from linceo.core.tool_config import (
    LEVEL_1_FIELD_NAMES,
    PassthroughValue,
    ToolConfig,
    UnsupportedToolConfigError,
    parse_tool_configs,
    parse_tool_defaults,
    render_passthrough_flags,
    resolve_tool_config,
)
from linceo.core.version_range import (
    InvalidVersionRangeError,
    parse_version,
    version_satisfies,
)

__all__ = [
    "CONTEXT_PROVIDER_ENTRY_POINT_GROUP",
    "DEFAULT_MAX_DATA_SOURCE_AGE_DAYS",
    "EXIT_CONFIGURATION_ERROR",
    "EXIT_GATE_FAILED",
    "EXIT_OK",
    "EXIT_TOOL_EXECUTION_FAILED",
    "LEVEL_1_FIELD_NAMES",
    "SEVERITY_ORDER",
    "TOOL_INTEGRATION_ENTRY_POINT_GROUP",
    "Category",
    "CategoryThresholds",
    "Column",
    "Config",
    "ConfigLayer",
    "ConfigurationError",
    "ContextProvider",
    "ContextResolutionError",
    "DataSource",
    "Exclusion",
    "ExclusionOutcome",
    "ExecutionContext",
    "ExecutionStatus",
    "Finding",
    "InvalidVersionRangeError",
    "Location",
    "Package",
    "PassthroughValue",
    "Platform",
    "PluginRegistry",
    "Policy",
    "PolicyConfigurationError",
    "ProcessResult",
    "RawFinding",
    "ReportSchema",
    "RunResult",
    "RunStatus",
    "Severity",
    "SeverityNormalizer",
    "SeveritySource",
    "ThresholdBreach",
    "ThresholdResolution",
    "Thresholds",
    "ToolConfig",
    "ToolExecution",
    "ToolExecutor",
    "ToolIntegration",
    "ToolSkip",
    "Truncate",
    "UnknownPluginError",
    "UnresolvedSeverityError",
    "UnsupportedToolConfigError",
    "Verdict",
    "apply_exclusions",
    "compute_exit_code",
    "count_by_category_and_severity",
    "count_by_severity",
    "deduplicate",
    "evaluate_gate",
    "load_config",
    "normalize_finding",
    "parse_tool_configs",
    "parse_tool_defaults",
    "parse_version",
    "render_console",
    "render_json",
    "render_passthrough_flags",
    "render_sarif",
    "resolve_tool_config",
    "run",
    "thresholds_from_fail_on",
    "version_satisfies",
]
