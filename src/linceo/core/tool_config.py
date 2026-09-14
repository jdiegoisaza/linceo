"""Per-integration configuration: level 1 (normalized) plus level 2 (raw passthrough) (ADR §8.5).

Both levels are resolved exclusively from the policy document's `[tools.<name>]`
table — the same file, and the same R5-governed resolution, that already carries
`[[exclusions]]` and `[[skipped_tools]]` (ADR §8.4) — because none of level 1's
shapes (a list of patterns, a local file path, a raw per-tool table) fit a scalar
CLI flag or environment variable any better than those two mechanisms already did
(ADR §8.5 explains why in full).

`ToolConfig` and `PassthroughValue` are what `linceo.core.ports.ToolIntegration
.build_command` receives and reads; `parse_tool_configs` is what `linceo.core.config
.load_config` calls to produce them from an already-decoded document. Kept in a
module of its own, separate from `linceo.core.policy`, because none of this affects
gate evaluation — it is a different, unrelated concern that happens to be resolved
from the same file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from linceo.core.policy import PolicyConfigurationError

#: One passthrough value from a `[tools.<name>]` table: a TOML scalar, or a
#: homogeneous tuple of strings for a repeatable flag — never a nested table
#: (ADR §8.5). Every value here maps to *exactly one* argv token (or, for a
#: tuple, exactly one token per item) — that fixed shape is what makes a
#: passthrough entry unable to expand into more command-line arguments than
#: it visibly declares, which is the concrete guarantee
#: `render_passthrough_flags` below exists to keep.
PassthroughValue = str | bool | int | float | tuple[str, ...]

#: A passthrough key must already look like a bare flag name — no spaces, no
#: leading dashes of its own, nothing that could read as more than one
#: token once `render_passthrough_flags` prefixes it. TOML table keys can
#: otherwise be almost any string (a quoted key may contain spaces), so this
#: is validated, never assumed.
_FLAG_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

#: Level 1's field names — reserved inside a `[tools.<name>]` table; every
#: other key in that table is level 2 passthrough (ADR §8.5).
_LEVEL_1_KEYS = frozenset({"exclude_paths", "scan_history", "custom_rules_path", "timeout"})


class UnsupportedToolConfigError(Exception):
    """A `ToolConfig` field this integration cannot honor was set to a non-default value.

    Raised by a `ToolIntegration.build_command` implementation itself (ADR
    §8.5), never silently ignored: a level 1 field is "the same shape for
    every integration", not "guaranteed to mean something for every
    integration" — a tool with no native equivalent for, say,
    `exclude_paths` must say so explicitly the moment a document actually
    asks for it, rather than building a command that quietly scans
    everything anyway. Raised only when the field differs from its neutral
    default (`ToolConfig`'s own field default) — a document that never
    mentions the field at all never triggers this.

    Maps to the configuration-error exit code (2), the same as any other
    invalid policy document (ADR §8.4): this is a request the operator
    made that cannot be honored, not a tool execution failure.
    """


@dataclass(frozen=True, slots=True)
class ToolConfig:
    """One integration's effective configuration: level 1 (normalized) + level 2 (passthrough).

    Level 1 has the same four fields, with the same meaning, for every
    integration (ADR §8.5):

    - `exclude_paths` — paths or patterns the tool must not scan.
    - `scan_history` — `True` to cover a repository's full version
      history, `False` to scan only the current working tree, `None`
      (the default) to leave it to whatever the integration already does
      by default. Applies straightforwardly to `secrets` (ADR §10:
      gitleaks defaults to full history). A category with no notion of
      history at all — a dependency-manifest scan, which only ever
      reflects the tree as checked out — has nothing to switch between;
      such an integration leaves `None` alone (nothing was asked of it)
      but raises `UnsupportedToolConfigError` the moment a document sets
      this to `True` or `False` explicitly, since neither value can
      honestly be honored.
    - `custom_rules_path` — a local path to the tool's own rule/config
      file.
    - `timeout` — seconds before the run is killed. Deliberately **not**
      one of the fields `ToolIntegration.build_command` ever translates
      into a flag, even for a tool that happens to have its own native
      timeout flag (gitleaks does: `--timeout`) — see the note below.

    Every integration must translate whichever of the first three fields
    its underlying tool has a real equivalent for, and raise
    `UnsupportedToolConfigError` for any other one left at a non-default
    value — never drop it silently (ADR §8.5).

    `timeout` bypasses `build_command` entirely and is enforced once, by
    `ToolExecutor.run`, at the process boundary — the one mechanism every
    `ToolExecutor` implementation provides identically regardless of the
    tool being run. A tool-specific `--timeout` flag is a *soft* signal:
    it depends on that tool's own internal implementation noticing the
    deadline on every code path, and not every tool has one at all — using
    it would make "timeout" mean something different, with different
    reliability, per integration, defeating the point of normalizing it.
    `ToolExecutor.run`'s timeout is a *hard* one: the OS process is killed
    outright, the same way, for any tool. `build_command` implementations
    ignore `config.timeout` on purpose; that is not the silent-ignore
    ADR §8.5 forbids, since it is documented here as the one field routed
    around them entirely, not dropped.

    Level 2 — `passthrough` — is opaque to every integration except the
    one it names: parsed into typed values by `parse_tool_configs` (so a
    document cannot smuggle something stranger than a TOML scalar or a
    flat list of strings into it), then handed to `build_command` exactly
    as written, with no interpretation by `core` at all. Using it breaks
    portability between scanners of the same category (ADR §8.5, ADR §8)
    — a document that only ever uses level 1 fields scans identically
    however `--tool` is set for a category; one that uses `passthrough`
    does not, by construction, since the keys only mean something to the
    one tool named in that `[tools.<name>]` block.
    """

    exclude_paths: tuple[str, ...] = ()
    scan_history: bool | None = None
    custom_rules_path: str | None = None
    timeout: float | None = None
    passthrough: Mapping[str, PassthroughValue] = field(default_factory=dict)


def render_passthrough_flags(
    passthrough: Mapping[str, PassthroughValue], *, prefix: str = "--"
) -> tuple[str, ...]:
    """Render a `[tools.<name>]` passthrough table into argv tokens, safely (ADR §8.5).

    Each `(key, value)` pair becomes exactly one flag token and, for a
    non-boolean value, exactly one additional value token per item — never
    more, by construction, regardless of what `value` contains: a string
    is never split, a value is never concatenated into an existing token.
    That fixed, mechanical expansion is what makes a policy document
    unable to inject extra, unrelated flags into a tool's invocation no
    matter what a passthrough value contains (ADR §8.5's anti-injection
    rule) — there is no argv shell involved either (ADR §9), so this is
    the whole of the control that stands between a policy document and the
    tool's own argv.

    A `bool` value renders as a presence flag: `True` emits the flag
    alone, `False` omits it entirely. A `tuple[str, ...]` value repeats
    `<flag> <item>` once per item, in order — a repeatable flag. Any other
    value renders as `<flag> <str(value)>`. Iteration order follows
    `passthrough`'s own order, which `parse_tool_configs` preserves from
    the document's own declaration order (ADR R3: same input, same argv,
    every time).

    Raises:
        ValueError: if a key does not look like a bare flag name (no
            spaces, no leading dashes of its own) — `parse_tool_configs`
            never rejects an odd TOML key on its own, so this is where
            that gets caught, before it reaches an integration's argv.
    """
    tokens: list[str] = []
    for key, value in passthrough.items():
        if not _FLAG_NAME_PATTERN.match(key):
            msg = f"passthrough key {key!r} is not a valid flag name"
            raise ValueError(msg)
        flag = f"{prefix}{key}"
        if isinstance(value, bool):
            if value:
                tokens.append(flag)
            continue
        if isinstance(value, tuple):
            for item in value:
                tokens.extend((flag, item))
            continue
        tokens.extend((flag, str(value)))
    return tuple(tokens)


def _parse_exclude_paths(value: object, *, tool: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        msg = f"tools.{tool}.exclude_paths must be a list of strings"
        raise PolicyConfigurationError(msg)
    return tuple(value)


def _parse_scan_history(value: object, *, tool: str) -> bool:
    if not isinstance(value, bool):
        msg = f"tools.{tool}.scan_history must be a boolean"
        raise PolicyConfigurationError(msg)
    return value


def _parse_custom_rules_path(value: object, *, tool: str) -> str:
    if not isinstance(value, str):
        msg = f"tools.{tool}.custom_rules_path must be a string"
        raise PolicyConfigurationError(msg)
    return value


def _parse_timeout(value: object, *, tool: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"tools.{tool}.timeout must be a number of seconds"
        raise PolicyConfigurationError(msg)
    if value <= 0:
        msg = f"tools.{tool}.timeout must be positive, got {value}"
        raise PolicyConfigurationError(msg)
    return float(value)


def _parse_passthrough_value(value: object, *, tool: str, key: str) -> PassthroughValue:
    """Coerce one raw passthrough value into `PassthroughValue`'s narrow shape.

    Raises:
        PolicyConfigurationError: if `value` is a nested table, a list
            containing anything but strings, or any other type TOML can
            produce that isn't a bare scalar.
    """
    if isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    msg = f"tools.{tool}.{key} must be a string, number, boolean, or list of strings"
    raise PolicyConfigurationError(msg)


def _parse_tool_config(entry: object, *, tool: str) -> ToolConfig:
    """Parse and validate one `[tools.<name>]` table.

    Raises:
        PolicyConfigurationError: see `_parse_exclude_paths`,
            `_parse_scan_history`, `_parse_custom_rules_path`,
            `_parse_timeout`, and `_parse_passthrough_value`; or if
            `entry` is not a table at all.
    """
    if not isinstance(entry, Mapping):
        msg = f"tools.{tool} must be a table"
        raise PolicyConfigurationError(msg)

    exclude_paths = (
        _parse_exclude_paths(entry["exclude_paths"], tool=tool) if "exclude_paths" in entry else ()
    )
    scan_history = (
        _parse_scan_history(entry["scan_history"], tool=tool) if "scan_history" in entry else None
    )
    custom_rules_path = (
        _parse_custom_rules_path(entry["custom_rules_path"], tool=tool)
        if "custom_rules_path" in entry
        else None
    )
    timeout = _parse_timeout(entry["timeout"], tool=tool) if "timeout" in entry else None
    passthrough = {
        key: _parse_passthrough_value(value, tool=tool, key=key)
        for key, value in entry.items()
        if key not in _LEVEL_1_KEYS
    }

    return ToolConfig(
        exclude_paths=exclude_paths,
        scan_history=scan_history,
        custom_rules_path=custom_rules_path,
        timeout=timeout,
        passthrough=passthrough,
    )


def parse_tool_configs(document: Mapping[str, object]) -> Mapping[str, ToolConfig]:
    """Parse every `[tools.<name>]` table of an already-decoded policy document (ADR §8.5).

    `document` is decoded TOML data today, the same already-decoded
    mapping `linceo.core.policy.parse_policy_document` reads (ADR §8.4) —
    only the `tools` key is read here; an unknown top-level key elsewhere
    in the document is `linceo.core.config`'s concern. A tool name absent
    from the returned mapping has no configured `ToolConfig` at all — the
    caller substitutes `ToolConfig()`, level 1's own all-`None`/empty
    defaults, meaning "nothing was asked of this tool."

    Raises:
        PolicyConfigurationError: if `tools` is present but is not a
            table, or any of its entries fails to parse (see
            `_parse_tool_config`).
    """
    raw = document.get("tools")
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        msg = "tools must be a table of per-tool tables"
        raise PolicyConfigurationError(msg)
    return {tool: _parse_tool_config(entry, tool=tool) for tool, entry in raw.items()}


__all__ = [
    "PassthroughValue",
    "ToolConfig",
    "UnsupportedToolConfigError",
    "parse_tool_configs",
    "render_passthrough_flags",
]
