"""Configuration resolution with the ADR §5/R5 precedence chain.

```
CLI flags > environment variables > --config (explicit path) >
conventional paths inside the scanned workspace > compiled-in defaults
```

No step of this chain ever points inside this package: `load_config`
never reads `os.environ` itself (that stays confined to `providers/`,
AGENTS.md, "Layer boundaries") and takes `env` as an already-resolved
mapping the caller supplies, and every file-path candidate it considers is
checked against the installed package directory before use (ADR §5/R5).

Two things are resolved from the same file here, at the same precedence
chain, but interact differently:

- The **scalar** settings (`continue_on_tool_error`, `strict_normalization`,
  `max_expiry_horizon_days`, `report_max_rows`, and the `fail_on` cutoff)
  follow the chain field by field — the highest layer that mentions a
  field wins, independently of the others.
- The **gate's thresholds** are richer than a single `fail_on` cutoff can
  express (ADR §8.1): a policy file's `[thresholds]` table is read too, and
  a `fail_on` value from a *higher* layer (CLI or an environment variable)
  replaces that table entirely rather than merging with it field by field
  — one flag should not partially edit a policy file's declared intent.
  When that happens, `ThresholdResolution.superseded` records what was
  replaced, so a report can say so explicitly (ADR §8.1).
- **Exclusions, tool skips, and per-tool configuration** are file-only for
  now (ADR §8, §8.2, §8.5): there is no CLI or environment-variable
  equivalent, only the policy document's `[[exclusions]]`,
  `[[skipped_tools]]`, and `[tools.<name>]` sections.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from types import MappingProxyType
from typing import cast

from linceo.core.policy import (
    DEFAULT_MAX_HORIZON_DAYS,
    DEFAULT_REPORT_MAX_ROWS,
    ConfigLayer,
    Policy,
    PolicyConfigurationError,
    ThresholdResolution,
    Thresholds,
    parse_policy_document,
)
from linceo.core.severity import Severity
from linceo.core.tool_config import (
    LEVEL_1_FIELD_NAMES,
    ToolConfig,
    parse_tool_configs,
    parse_tool_defaults,
)

#: Conventional config file location inside the scanned workspace,
#: resolved only when no explicit `--config` path is given (ADR §5/R5).
CONVENTIONAL_CONFIG_RELATIVE_PATH = ".devsecops/config.toml"

#: The only policy document schema version this loader understands.
SUPPORTED_CONFIG_VERSION = 1

#: `LINCEO_*` environment variable name for every scalar `Config` field
#: except `fail_on`, which interacts with `[thresholds]` and is resolved
#: separately (`_resolve_fail_on`).
_GENERIC_SCALAR_ENV_VARS: Mapping[str, str] = MappingProxyType(
    {
        "continue_on_tool_error": "LINCEO_CONTINUE_ON_TOOL_ERROR",
        "strict_normalization": "LINCEO_STRICT_NORMALIZATION",
        "max_expiry_horizon_days": "LINCEO_MAX_EXPIRY_HORIZON_DAYS",
        "report_max_rows": "LINCEO_REPORT_MAX_ROWS",
    }
)

_FAIL_ON_ENV_VAR = "LINCEO_FAIL_ON"

#: Every scalar field a `--flag`, an environment variable, or the file's
#: flat keys may legitimately set — anything else in `cli_overrides` is a
#: typo, rejected loudly. Excludes `thresholds`/`exclusions`/`skipped_tools`,
#: which are file-only (no CLI or environment-variable equivalent, ADR §8).
_OVERRIDABLE_FIELDS = frozenset({"fail_on", *_GENERIC_SCALAR_ENV_VARS})

#: Top-level keys a policy document may declare at all.
_FILE_TOP_LEVEL_KNOWN_KEYS = frozenset(
    {
        "version",
        "fail_on",
        "continue_on_tool_error",
        "strict_normalization",
        "max_expiry_horizon_days",
        "report",
        "thresholds",
        "exclusions",
        "skipped_tools",
        "tool_defaults",
        "tools",
    }
)

_BOOLEAN_FIELDS = frozenset({"continue_on_tool_error", "strict_normalization"})
_INTEGER_FIELDS = frozenset({"max_expiry_horizon_days", "report_max_rows"})
_TRUE_VALUES = frozenset({"true", "1", "yes", "on"})
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})

_DEFAULTS: Mapping[str, object] = MappingProxyType(
    {
        "continue_on_tool_error": False,
        "strict_normalization": False,
        "max_expiry_horizon_days": DEFAULT_MAX_HORIZON_DAYS,
        "report_max_rows": DEFAULT_REPORT_MAX_ROWS,
    }
)

_NO_OVERRIDES: Mapping[str, str] = MappingProxyType({})


class ConfigurationError(Exception):
    """A configuration value, path, or policy document is invalid — maps to exit code 2 (ADR §8)."""


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved settings the orchestration engine runs with.

    `threshold_resolution` replaces a bare `fail_on` field: it is always
    the single source of truth the gate evaluates against
    (`linceo.core.gate.evaluate_gate`), whether it came from a plain
    `--fail-on` cutoff or a policy file's `[thresholds]` table (ADR §8.1).
    `policy` carries this run's exclusions and temporary tool skips (ADR
    §8.2) — the same file, the same precedence chain, but file-only for
    now, with no CLI or environment-variable equivalent. `tool_defaults`
    and `tool_configs` are the two places level 1 per-integration
    configuration can come from (ADR §8.5): `tool_defaults` is the single
    `[tool_defaults]` table, applied to every integration in the run;
    `tool_configs` carries every `[tools.<name>]` table, keyed by tool
    name — level 1 fields it sets itself, plus level 2 passthrough.
    `linceo.core.tool_config.resolve_tool_config` merges the two for one
    named tool, `tool_configs`'s own value winning field by field. Both
    are file-only in exactly the same sense, and for the same reason, as
    `policy`: none of their shapes (a list of patterns, a local path, an
    arbitrary per-tool table) fit a scalar CLI flag or environment
    variable any better than exclusions and tool skips already didn't.

    Every field defaults to the permissive, reporting-only choice the ADR
    documents: no gate configured (§8.1), `continue_on_tool_error = False`
    (§5), `strict_normalization = False` (§6), the default 90-day exclusion
    horizon, the default 20-row console table (§7, §8.2), and no
    integration configured beyond its own built-in defaults (§8.5).
    """

    threshold_resolution: ThresholdResolution = field(
        default_factory=lambda: ThresholdResolution.for_fail_on(None, source=ConfigLayer.DEFAULT)
    )
    continue_on_tool_error: bool = False
    strict_normalization: bool = False
    max_expiry_horizon_days: int = DEFAULT_MAX_HORIZON_DAYS
    report_max_rows: int = DEFAULT_REPORT_MAX_ROWS
    policy: Policy = field(default_factory=Policy)
    tool_defaults: ToolConfig = field(default_factory=ToolConfig)
    tool_configs: Mapping[str, ToolConfig] = field(default_factory=dict)


def _parse_fail_on(raw: str) -> Severity | None:
    """Parse a `fail_on` value: a severity name, or the `none` sentinel.

    Raises:
        ConfigurationError: if `raw` is not `none` and not a known
            severity, or names `Severity.INFO` — ADR §6 guarantees INFO
            never blocks the gate under any threshold configuration, so a
            plain cutoff is not allowed to name it either.
    """
    normalized = raw.strip().lower()
    if normalized == "none":
        return None
    try:
        severity = Severity(normalized.upper())
    except ValueError as exc:
        msg = f"invalid value for fail_on: {raw!r} (expected a severity or 'none')"
        raise ConfigurationError(msg) from exc
    if severity is Severity.INFO:
        msg = "fail_on may not be INFO — ADR §6 guarantees INFO never blocks the gate"
        raise ConfigurationError(msg)
    return severity


def _parse_boolean(field_name: str, raw: str) -> bool:
    """Parse a boolean scalar field's string form.

    Raises:
        ConfigurationError: if `raw` is not a recognized boolean spelling.
    """
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    msg = f"invalid boolean value for {field_name}: {raw!r}"
    raise ConfigurationError(msg)


def _parse_integer(field_name: str, raw: str) -> int:
    """Parse an integer scalar field's string form.

    Raises:
        ConfigurationError: if `raw` cannot be parsed as an integer.
    """
    try:
        return int(raw.strip())
    except ValueError as exc:
        msg = f"invalid integer value for {field_name}: {raw!r}"
        raise ConfigurationError(msg) from exc


def _coerce_scalar(field_name: str, value: object) -> object:
    """Coerce a scalar field's value from whichever layer supplied it.

    `value` is always a string when it came from `cli_overrides` or an
    environment variable; when it came from the config file it is already
    a native TOML type (bool, int, str) and is used as-is when that type
    already matches the field, or otherwise parsed the same way a string
    from any other layer would be — a field resolves to the same typed
    value no matter which layer supplied it.

    Raises:
        ConfigurationError: see `_parse_fail_on`, `_parse_boolean`,
            `_parse_integer`; or if `field_name` is not a known field.
    """
    if field_name == "fail_on":
        return _parse_fail_on(value if isinstance(value, str) else str(value))
    if field_name in _BOOLEAN_FIELDS:
        if isinstance(value, bool):
            return value
        return _parse_boolean(field_name, str(value))
    if field_name in _INTEGER_FIELDS:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return _parse_integer(field_name, str(value))
    msg = f"unknown configuration field: {field_name!r}"
    raise ConfigurationError(msg)


def candidate_config_paths(
    *, explicit_config_path: str | None, workspace_path: str
) -> tuple[str, ...]:
    """List the config file path(s) resolution would consider, in precedence order.

    An explicit `--config` path replaces the conventional workspace
    search entirely rather than adding to it (ADR §5/R5's chain has
    exactly one file-layer winner, never both).
    """
    if explicit_config_path is not None:
        return (explicit_config_path,)
    return (str(Path(workspace_path) / CONVENTIONAL_CONFIG_RELATIVE_PATH),)


def _assert_outside_package(candidates: tuple[str, ...], *, package_root: str) -> None:
    """Reject any `candidates` entry that resolves inside `package_root` (ADR §5/R5).

    Raises:
        ConfigurationError: for the first offending candidate found.
    """
    resolved_root = Path(package_root).resolve()
    for candidate in candidates:
        resolved_candidate = Path(candidate).resolve()
        is_root = resolved_candidate == resolved_root
        is_nested = resolved_root in resolved_candidate.parents
        if is_root or is_nested:
            msg = (
                f"configuration candidate path {candidate!r} resolves inside the installed "
                f"package directory {package_root!r} — no configuration source may live in "
                "this repository (ADR §5/R5)"
            )
            raise ConfigurationError(msg)


def _load_toml_document(path: str) -> Mapping[str, object]:
    """Parse the TOML file at `path`, or return `{}` if it does not exist.

    Raises:
        ConfigurationError: if the file exists but is not valid TOML.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return {}

    try:
        return tomllib.loads(file_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        msg = f"configuration file {path!r} is not valid TOML: {exc}"
        raise ConfigurationError(msg) from exc


def _validate_version(raw_document: Mapping[str, object], *, path: str) -> None:
    """Reject a policy document declaring an unsupported schema version.

    Raises:
        ConfigurationError: if `version` is present and is not
            `SUPPORTED_CONFIG_VERSION`.
    """
    version = raw_document.get("version", SUPPORTED_CONFIG_VERSION)
    if version != SUPPORTED_CONFIG_VERSION:
        msg = (
            f"configuration file {path!r} declares unsupported schema version "
            f"{version!r} (supported: {SUPPORTED_CONFIG_VERSION})"
        )
        raise ConfigurationError(msg)


def _validate_top_level_keys(raw_document: Mapping[str, object], *, path: str) -> None:
    """Reject a policy document with a key this schema does not know about.

    A key that is actually one of `LEVEL_1_FIELD_NAMES` (ADR §8.5) gets a
    specific hint pointing at `[tool_defaults]`/`[tools.<name>]` instead of
    the generic "unknown field" message: `exclude_paths` at the document
    root is a real, easy mistake — level 1's four field names are not
    valid top-level keys on their own, only inside one of those two
    sections — and "unknown field" alone, true as it is, does not say
    where the field actually belongs.

    Raises:
        ConfigurationError: if `raw_document` declares a top-level key
            outside `_FILE_TOP_LEVEL_KNOWN_KEYS`.
    """
    unknown = set(raw_document) - _FILE_TOP_LEVEL_KNOWN_KEYS
    if not unknown:
        return

    msg = f"configuration file {path!r} declares unknown field(s): {sorted(unknown)}"
    misplaced_level1 = sorted(unknown & LEVEL_1_FIELD_NAMES)
    if misplaced_level1:
        msg += (
            f" — {misplaced_level1} look like per-tool configuration (ADR §8.5): declare "
            "them inside [tool_defaults] (applies to every configured tool) or "
            "[tools.<name>] (applies to just that one tool), never at the document root"
        )
    raise ConfigurationError(msg)


def _extract_report_max_rows(raw_document: Mapping[str, object], *, path: str) -> object | None:
    """Pull `report.max_rows` out of the nested `[report]` table, if present.

    Raises:
        ConfigurationError: if `[report]` is not a table, or declares a
            field other than `max_rows`.
    """
    report = raw_document.get("report")
    if report is None:
        return None
    if not isinstance(report, Mapping):
        msg = f"configuration file {path!r}: 'report' must be a table, got {type(report).__name__}"
        raise ConfigurationError(msg)
    unknown = set(report) - {"max_rows"}
    if unknown:
        msg = f"configuration file {path!r}: 'report' declares unknown field(s): {sorted(unknown)}"
        raise ConfigurationError(msg)
    return report.get("max_rows")


def _validate_cli_overrides(cli_overrides: Mapping[str, str]) -> None:
    """Reject a `cli_overrides` mapping naming a field this schema does not know about.

    Raises:
        ConfigurationError: if `cli_overrides` declares a key outside
            `_OVERRIDABLE_FIELDS`.
    """
    unknown = set(cli_overrides) - _OVERRIDABLE_FIELDS
    if unknown:
        msg = f"unknown configuration field(s): {sorted(unknown)}"
        raise ConfigurationError(msg)


def _resolve_scalar(
    field_name: str,
    *,
    cli_overrides: Mapping[str, str],
    env: Mapping[str, str],
    flat_document: Mapping[str, object],
) -> object:
    """Resolve one generic scalar field through the ADR §5/R5 precedence chain."""
    if field_name in cli_overrides:
        return _coerce_scalar(field_name, cli_overrides[field_name])
    env_var = _GENERIC_SCALAR_ENV_VARS[field_name]
    if env_var in env:
        return _coerce_scalar(field_name, env[env_var])
    if field_name in flat_document:
        return _coerce_scalar(field_name, flat_document[field_name])
    return _DEFAULTS[field_name]


def _resolve_fail_on(
    *,
    cli_overrides: Mapping[str, str],
    env: Mapping[str, str],
    raw_document: Mapping[str, object],
) -> tuple[Severity | None, ConfigLayer]:
    """Resolve `fail_on` and which layer of the chain ultimately set it."""
    if "fail_on" in cli_overrides:
        value = _coerce_scalar("fail_on", cli_overrides["fail_on"])
        return cast("Severity | None", value), ConfigLayer.CLI
    if _FAIL_ON_ENV_VAR in env:
        value = _coerce_scalar("fail_on", env[_FAIL_ON_ENV_VAR])
        return cast("Severity | None", value), ConfigLayer.ENV
    if "fail_on" in raw_document:
        value = _coerce_scalar("fail_on", raw_document["fail_on"])
        return cast("Severity | None", value), ConfigLayer.FILE
    return None, ConfigLayer.DEFAULT


def _resolve_threshold_resolution(
    *,
    fail_on: Severity | None,
    fail_on_layer: ConfigLayer,
    file_thresholds: Thresholds | None,
    file_path: str,
) -> ThresholdResolution:
    """Combine the resolved `fail_on` cutoff with a policy file's `[thresholds]` table.

    A `fail_on` set from `CLI` or `ENV` outranks the file entirely and
    replaces `[thresholds]` rather than merging with it (ADR §8.1);
    `superseded`/`superseded_from` record what was replaced so a report can
    announce it. Within the `FILE` layer itself, an explicit `[thresholds]`
    table wins over a flat `fail_on` key when a document declares both —
    the richer declaration, not an override between layers, so nothing is
    announced as superseded.
    """
    if fail_on_layer in (ConfigLayer.CLI, ConfigLayer.ENV):
        resolution = ThresholdResolution.for_fail_on(fail_on, source=fail_on_layer)
        if file_thresholds is not None:
            return ThresholdResolution(
                thresholds=resolution.thresholds,
                source=resolution.source,
                fail_on=resolution.fail_on,
                superseded=file_thresholds,
                superseded_from=file_path,
            )
        return resolution
    if file_thresholds is not None:
        return ThresholdResolution(thresholds=file_thresholds, source=ConfigLayer.FILE)
    if fail_on_layer is ConfigLayer.FILE:
        return ThresholdResolution.for_fail_on(fail_on, source=ConfigLayer.FILE)
    return ThresholdResolution.for_fail_on(None, source=ConfigLayer.DEFAULT)


def load_config(
    *,
    cli_overrides: Mapping[str, str] = _NO_OVERRIDES,
    env: Mapping[str, str] = _NO_OVERRIDES,
    explicit_config_path: str | None,
    workspace_path: str,
    package_root: str,
    today: date,
) -> Config:
    """Resolve a `Config` following the ADR §5/R5 precedence chain.

    `cli_overrides` and `env` carry raw string values — exactly the shape
    a `--flag value` or an environment variable arrives in — parsed here
    into `Config`'s typed fields; this function never reads `os.environ`
    itself, only the mapping the caller already resolved it into. `today`
    is supplied by the caller rather than read from the system clock here
    (ADR R3's determinism corollary): it is the reference date every
    exclusion's and tool skip's `expires_at` is validated against.

    Raises:
        ConfigurationError: if a config file candidate path resolves
            inside `package_root`; the config file is invalid TOML,
            declares an unsupported schema version, or declares an unknown
            field at any level; any layer's scalar value fails to parse
            into its field's type; or the policy document's
            `[thresholds]`/`[[exclusions]]`/`[[skipped_tools]]` sections
            are invalid (see `linceo.core.policy.parse_policy_document`).
    """
    _validate_cli_overrides(cli_overrides)

    candidates = candidate_config_paths(
        explicit_config_path=explicit_config_path, workspace_path=workspace_path
    )
    _assert_outside_package(candidates, package_root=package_root)
    file_path = candidates[0]

    raw_document = _load_toml_document(file_path)
    _validate_version(raw_document, path=file_path)
    _validate_top_level_keys(raw_document, path=file_path)

    report_max_rows_raw = _extract_report_max_rows(raw_document, path=file_path)
    flat_document: dict[str, object] = dict(raw_document)
    if report_max_rows_raw is not None:
        flat_document["report_max_rows"] = report_max_rows_raw

    raw_scalars = {
        field_name: _resolve_scalar(
            field_name, cli_overrides=cli_overrides, env=env, flat_document=flat_document
        )
        for field_name in _GENERIC_SCALAR_ENV_VARS
    }
    continue_on_tool_error = cast("bool", raw_scalars["continue_on_tool_error"])
    strict_normalization = cast("bool", raw_scalars["strict_normalization"])
    max_expiry_horizon_days = cast("int", raw_scalars["max_expiry_horizon_days"])
    report_max_rows = cast("int", raw_scalars["report_max_rows"])

    if max_expiry_horizon_days < 0:
        msg = f"max_expiry_horizon_days must not be negative, got {max_expiry_horizon_days}"
        raise ConfigurationError(msg)
    if report_max_rows < 0:
        msg = f"report.max_rows must not be negative, got {report_max_rows}"
        raise ConfigurationError(msg)

    fail_on, fail_on_layer = _resolve_fail_on(
        cli_overrides=cli_overrides, env=env, raw_document=raw_document
    )

    try:
        policy_document = parse_policy_document(
            raw_document,
            today=today,
            max_horizon_days=max_expiry_horizon_days,
        )
        tool_defaults = parse_tool_defaults(raw_document)
        tool_configs = parse_tool_configs(raw_document)
    except PolicyConfigurationError as exc:
        raise ConfigurationError(str(exc)) from exc

    threshold_resolution = _resolve_threshold_resolution(
        fail_on=fail_on,
        fail_on_layer=fail_on_layer,
        file_thresholds=policy_document.thresholds,
        file_path=file_path,
    )

    return Config(
        threshold_resolution=threshold_resolution,
        continue_on_tool_error=continue_on_tool_error,
        strict_normalization=strict_normalization,
        max_expiry_horizon_days=max_expiry_horizon_days,
        report_max_rows=report_max_rows,
        policy=Policy(exclusions=policy_document.exclusions, tool_skips=policy_document.tool_skips),
        tool_defaults=tool_defaults,
        tool_configs=tool_configs,
    )
