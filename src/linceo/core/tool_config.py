"""Per-integration configuration: level 1 (normalized) plus level 2 (raw passthrough) (ADR §8.5).

Level 1 has two places to declare it, both resolved exclusively from the policy
document — the same file, and the same R5-governed resolution, that already carries
`[[exclusions]]` and `[[skipped_tools]]` (ADR §8.4) — because none of level 1's
shapes (a list of patterns, a local file path, a number of seconds) fit a scalar CLI
flag or environment variable any better than those two mechanisms already did:

- `[tool_defaults]` — applies to every integration in the run that doesn't override
  a given field itself. Parsed by `parse_tool_defaults`.
- `[tools.<name>]` — applies to one named tool only, and also carries level 2's raw
  passthrough (any key that isn't one of level 1's four). Parsed by
  `parse_tool_configs`.

`resolve_tool_config` merges the two, field by field, `[tools.<name>]` winning over
`[tool_defaults]` for any field it actually sets — see its own docstring for the
precedence this mirrors. `ToolConfig` and `PassthroughValue` are what
`linceo.core.ports.ToolIntegration.build_command` receives and reads, always already
merged: no integration ever sees `[tool_defaults]` and `[tools.<name>]` as separate
objects. Kept in a module of its own, separate from `linceo.core.policy`, because
none of this affects gate evaluation — it is a different, unrelated concern that
happens to be resolved from the same file.
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

#: Level 1's field names. Reserved inside a `[tools.<name>]` table — every other
#: key in that table is level 2 passthrough — and the *only* fields
#: `[tool_defaults]` accepts at all, since passthrough has no meaning shared
#: across tools (ADR §8.5). Public (not `_`-prefixed) so `linceo.core.config`
#: can point to it by name when a document declares one of these at the
#: document root, where neither section exists.
LEVEL_1_FIELD_NAMES = frozenset({"exclude_paths", "scan_history", "custom_rules_path", "timeout"})


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
    mentions the field at all, in `[tool_defaults]` or in `[tools.<name>]`,
    never triggers this.

    Maps to the configuration-error exit code (2), the same as any other
    invalid policy document (ADR §8.4): this is a request the operator
    made that cannot be honored, not a tool execution failure.
    """


@dataclass(frozen=True, slots=True)
class ToolConfig:
    """One integration's effective configuration: level 1 (normalized) + level 2 (passthrough).

    Level 1 has the same four fields, with the same meaning, for every
    integration (ADR §8.5), each `None` (or, for `exclude_paths`, also `None`)
    when nothing set it:

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

    Every field's "nothing was asked" value is `None`, `exclude_paths`
    included — not `()` — precisely so a document can tell "not mentioned
    here, fall back to `[tool_defaults]`" apart from "explicitly set to
    empty" once `resolve_tool_config` merges the two (see its docstring).
    `build_command` reads `if config.exclude_paths:` either way, since
    `None` and `()` are both falsy — the distinction only matters to the
    merge, never to an integration.

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
    as written, with no interpretation by `core` at all. `[tool_defaults]`
    never carries a `passthrough` of its own (`parse_tool_defaults`
    rejects any key that isn't one of the four level 1 fields) — a raw
    flag name only ever means something to the one tool it was written
    for, so there is nothing sensible for it to default across tools.
    Using it breaks portability between scanners of the same category
    (ADR §8.5, ADR §8) — a document that only ever uses level 1 fields
    scans identically however `--tool` is set for a category; one that
    uses `passthrough` does not, by construction, since the keys only
    mean something to the one tool named in that `[tools.<name>]` block.
    """

    exclude_paths: tuple[str, ...] | None = None
    scan_history: bool | None = None
    custom_rules_path: str | None = None
    timeout: float | None = None
    passthrough: Mapping[str, PassthroughValue] = field(default_factory=dict)


def resolve_tool_config(*, defaults: ToolConfig, override: ToolConfig) -> ToolConfig:
    """Merge `[tool_defaults]` with one tool's own `[tools.<name>]` block (ADR §8.5).

    Field by field: `override`'s value wins for any level 1 field it
    actually sets (is not `None`); a field `override` leaves at `None`
    falls back to `defaults`' value for that same field. This is the same
    "a layer that doesn't mention a field never hides a lower layer's
    value" precedence ADR §5/R5 already uses for the CLI/env/file scalar
    settings (`linceo.core.config._resolve_scalar`) — just two layers
    instead of four, since both `[tool_defaults]` and `[tools.<name>]` are
    file-only (ADR §8.4's exclusions/tool-skips reasoning, extended to
    per-tool configuration). The common case this exists for — "exclude
    `node_modules/` from every scanner" in `[tool_defaults]` — and the
    specific one — "this one tool needs a longer timeout" in
    `[tools.<name>]` — combine without either document author needing to
    repeat the other's declaration.

    `override.passthrough` always wins outright, with no merge at all:
    `defaults` (parsed by `parse_tool_defaults`) never carries a
    passthrough of its own to merge against in the first place.

    Every caller that constructs a `ToolConfig` to hand to a
    `ToolIntegration.build_command` — `linceo.core.engine.run` for a real
    run, `linceo.cli.scan`'s `--dry-run` path for the printed argv — calls
    this first; no integration ever sees `defaults` and `override` as
    separate objects.
    """
    return ToolConfig(
        exclude_paths=(
            override.exclude_paths if override.exclude_paths is not None else defaults.exclude_paths
        ),
        scan_history=(
            override.scan_history if override.scan_history is not None else defaults.scan_history
        ),
        custom_rules_path=(
            override.custom_rules_path
            if override.custom_rules_path is not None
            else defaults.custom_rules_path
        ),
        timeout=override.timeout if override.timeout is not None else defaults.timeout,
        passthrough=override.passthrough,
    )


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


def _parse_exclude_paths(value: object, *, field_prefix: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        msg = f"{field_prefix}.exclude_paths must be a list of strings"
        raise PolicyConfigurationError(msg)
    return tuple(value)


def _parse_scan_history(value: object, *, field_prefix: str) -> bool:
    if not isinstance(value, bool):
        msg = f"{field_prefix}.scan_history must be a boolean"
        raise PolicyConfigurationError(msg)
    return value


def _parse_custom_rules_path(value: object, *, field_prefix: str) -> str:
    if not isinstance(value, str):
        msg = f"{field_prefix}.custom_rules_path must be a string"
        raise PolicyConfigurationError(msg)
    return value


def _parse_timeout(value: object, *, field_prefix: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"{field_prefix}.timeout must be a number of seconds"
        raise PolicyConfigurationError(msg)
    if value <= 0:
        msg = f"{field_prefix}.timeout must be positive, got {value}"
        raise PolicyConfigurationError(msg)
    return float(value)


def _parse_level1_fields(
    entry: Mapping[str, object], *, field_prefix: str
) -> tuple[tuple[str, ...] | None, bool | None, str | None, float | None]:
    """Extract and validate whichever of the four level 1 fields `entry` declares.

    Shared by `_parse_tool_config` (`[tools.<name>]`, which also carries
    passthrough) and `parse_tool_defaults` (`[tool_defaults]`, which does
    not) — the same four fields, the same validation, differing only in
    `field_prefix` for the error messages this produces. Returns them in
    `ToolConfig`'s own field order (`exclude_paths`, `scan_history`,
    `custom_rules_path`, `timeout`), `None` for any field `entry` does not
    mention at all.

    Raises:
        PolicyConfigurationError: see `_parse_exclude_paths`,
            `_parse_scan_history`, `_parse_custom_rules_path`, and
            `_parse_timeout`.
    """
    exclude_paths = (
        _parse_exclude_paths(entry["exclude_paths"], field_prefix=field_prefix)
        if "exclude_paths" in entry
        else None
    )
    scan_history = (
        _parse_scan_history(entry["scan_history"], field_prefix=field_prefix)
        if "scan_history" in entry
        else None
    )
    custom_rules_path = (
        _parse_custom_rules_path(entry["custom_rules_path"], field_prefix=field_prefix)
        if "custom_rules_path" in entry
        else None
    )
    timeout = (
        _parse_timeout(entry["timeout"], field_prefix=field_prefix) if "timeout" in entry else None
    )
    return exclude_paths, scan_history, custom_rules_path, timeout


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
    """Parse and validate one `[tools.<name>]` table: level 1 fields plus passthrough.

    Raises:
        PolicyConfigurationError: see `_parse_level1_fields` and
            `_parse_passthrough_value`; or if `entry` is not a table at
            all.
    """
    if not isinstance(entry, Mapping):
        msg = f"tools.{tool} must be a table"
        raise PolicyConfigurationError(msg)

    exclude_paths, scan_history, custom_rules_path, timeout = _parse_level1_fields(
        entry, field_prefix=f"tools.{tool}"
    )
    passthrough = {
        key: _parse_passthrough_value(value, tool=tool, key=key)
        for key, value in entry.items()
        if key not in LEVEL_1_FIELD_NAMES
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
    from the returned mapping has no `[tools.<name>]` block of its own —
    it may still get `[tool_defaults]`' values, via `resolve_tool_config`;
    the caller substitutes `ToolConfig()` here only as the "nothing
    tool-specific was asked" override to merge `[tool_defaults]` against.

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


def parse_tool_defaults(document: Mapping[str, object]) -> ToolConfig:
    """Parse the `[tool_defaults]` table of an already-decoded policy document (ADR §8.5).

    Level 1 fields only — no passthrough, since a raw flag name has no
    meaning shared across tools. The result applies to every integration
    in a run via `resolve_tool_config`, whether or not that tool also has
    its own `[tools.<name>]` block: `[tool_defaults]` is not indexed by
    tool name, and a run's set of active integrations isn't known yet at
    config-load time (it depends on `--tool`, resolved later), so this
    returns one `ToolConfig`, not a mapping.

    Raises:
        PolicyConfigurationError: if `tool_defaults` is present but is
            not a table, declares a field that isn't one of the four
            level 1 fields (including anything shaped like passthrough —
            that belongs under `[tools.<name>]` instead), or any level 1
            field fails to parse (see `_parse_level1_fields`).
    """
    raw = document.get("tool_defaults")
    if raw is None:
        return ToolConfig()
    if not isinstance(raw, Mapping):
        msg = "tool_defaults must be a table"
        raise PolicyConfigurationError(msg)

    unknown = set(raw) - LEVEL_1_FIELD_NAMES
    if unknown:
        msg = (
            f"tool_defaults declares unknown field(s): {sorted(unknown)} — tool_defaults "
            f"only accepts {sorted(LEVEL_1_FIELD_NAMES)} (ADR §8.5); tool-specific "
            "passthrough has no meaning shared across tools and belongs under "
            "[tools.<name>] instead"
        )
        raise PolicyConfigurationError(msg)

    exclude_paths, scan_history, custom_rules_path, timeout = _parse_level1_fields(
        raw, field_prefix="tool_defaults"
    )
    return ToolConfig(
        exclude_paths=exclude_paths,
        scan_history=scan_history,
        custom_rules_path=custom_rules_path,
        timeout=timeout,
    )


__all__ = [
    "LEVEL_1_FIELD_NAMES",
    "PassthroughValue",
    "ToolConfig",
    "UnsupportedToolConfigError",
    "parse_tool_configs",
    "parse_tool_defaults",
    "render_passthrough_flags",
    "resolve_tool_config",
]
