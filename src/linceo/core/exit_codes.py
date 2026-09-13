"""Exit codes as a public contract covered by semver (ADR §8).

| Code | Meaning |
|---|---|
| 0 | The run completed and the gate passed (or `fail_on` is `none`). |
| 1 | The run completed and the gate failed. |
| 2 | Usage error or configuration error. |
| 3 | A tool execution failed, or evidence is incomplete, without `continue_on_tool_error`. |
| 4+ | Reserved for future use. |

Code `3` outranks `1`: if a tool execution failed and
`continue_on_tool_error` is not set, that wins even when the gate would
also have failed — "the orchestrator is broken" must dominate "the
orchestrator found findings", because a pipeline needs to react to each
differently (ADR §8).
"""

from __future__ import annotations

from linceo.core.results import RunResult, RunStatus

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_CONFIGURATION_ERROR = 2
EXIT_TOOL_EXECUTION_FAILED = 3


def compute_exit_code(result: RunResult, *, continue_on_tool_error: bool) -> int:
    """Map a completed `RunResult` to its process exit code (ADR §8).

    Never returns `EXIT_CONFIGURATION_ERROR`: that code belongs to usage
    and configuration failures raised before a `RunResult` exists at all
    (e.g. `linceo.core.config.ConfigurationError`), not to anything this
    function inspects.
    """
    if result.status is RunStatus.PARTIAL and not continue_on_tool_error:
        return EXIT_TOOL_EXECUTION_FAILED
    if not result.verdict.passed:
        return EXIT_GATE_FAILED
    return EXIT_OK
