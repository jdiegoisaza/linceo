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
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

from linceo.core.baseline import DEFAULT_MAX_HORIZON_DAYS
from linceo.core.severity import Severity

#: Conventional config file location inside the scanned workspace,
#: resolved only when no explicit `--config` path is given (ADR §5/R5).
CONVENTIONAL_CONFIG_RELATIVE_PATH = ".devsecops/config.toml"

#: `LINCEO_*` environment variable name for each `Config` field (ADR §2).
FIELD_ENV_VARS: Mapping[str, str] = MappingProxyType(
    {
        "fail_on": "LINCEO_FAIL_ON",
        "continue_on_tool_error": "LINCEO_CONTINUE_ON_TOOL_ERROR",
        "strict_normalization": "LINCEO_STRICT_NORMALIZATION",
        "baseline_max_horizon_days": "LINCEO_BASELINE_MAX_HORIZON_DAYS",
    }
)

#: Every field name a config file, environment variable, or CLI override
#: may legitimately set — anything else is a typo, rejected loudly.
_KNOWN_CONFIG_FIELDS = frozenset(FIELD_ENV_VARS)

_BOOLEAN_FIELDS = frozenset({"continue_on_tool_error", "strict_normalization"})
_INTEGER_FIELDS = frozenset({"baseline_max_horizon_days"})
_TRUE_VALUES = frozenset({"true", "1", "yes", "on"})
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})

_NO_OVERRIDES: Mapping[str, str] = MappingProxyType({})


class ConfigurationError(Exception):
    """A configuration value or path is invalid — maps to exit code 2 (ADR §8)."""


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved settings the orchestration engine runs with.

    Every field defaults to the permissive, reporting-only choice the ADR
    documents: `fail_on = None` (§8.1), `continue_on_tool_error = False`
    (§5), `strict_normalization = False` (§6), and the default 90-day
    baseline horizon (§8.2).
    """

    fail_on: Severity | None = None
    continue_on_tool_error: bool = False
    strict_normalization: bool = False
    baseline_max_horizon_days: int = DEFAULT_MAX_HORIZON_DAYS


def _parse_field_value(field_name: str, raw: str) -> object:
    """Parse `raw` into the Python type `Config.field_name` expects.

    Raises:
        ConfigurationError: if `raw` cannot be parsed as that field's type.
    """
    if field_name == "fail_on":
        normalized = raw.strip().lower()
        if normalized == "none":
            return None
        try:
            return Severity(normalized.upper())
        except ValueError as exc:
            msg = f"invalid value for fail_on: {raw!r} (expected a severity or 'none')"
            raise ConfigurationError(msg) from exc

    if field_name in _BOOLEAN_FIELDS:
        normalized = raw.strip().lower()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False
        msg = f"invalid boolean value for {field_name}: {raw!r}"
        raise ConfigurationError(msg)

    if field_name in _INTEGER_FIELDS:
        try:
            return int(raw.strip())
        except ValueError as exc:
            msg = f"invalid integer value for {field_name}: {raw!r}"
            raise ConfigurationError(msg) from exc

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


def _load_config_file(path: str) -> Mapping[str, object]:
    """Parse the TOML file at `path`, or return `{}` if it does not exist.

    Raises:
        ConfigurationError: if the file exists but is not valid TOML, or
            declares a field `Config` does not have.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return {}

    try:
        raw_document = tomllib.loads(file_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        msg = f"configuration file {path!r} is not valid TOML: {exc}"
        raise ConfigurationError(msg) from exc

    unknown_keys = set(raw_document) - _KNOWN_CONFIG_FIELDS
    if unknown_keys:
        msg = f"configuration file {path!r} declares unknown field(s): {sorted(unknown_keys)}"
        raise ConfigurationError(msg)

    return raw_document


def load_config(
    *,
    cli_overrides: Mapping[str, str] = _NO_OVERRIDES,
    env: Mapping[str, str] = _NO_OVERRIDES,
    explicit_config_path: str | None,
    workspace_path: str,
    package_root: str,
) -> Config:
    """Resolve a `Config` following the ADR §5/R5 precedence chain.

    `cli_overrides` and `env` carry raw string values — exactly the shape
    a `--flag value` or an environment variable arrives in — parsed here
    into `Config`'s typed fields; this function never reads `os.environ`
    itself, only the mapping the caller already resolved it into.

    Raises:
        ConfigurationError: if a config file candidate path resolves
            inside `package_root`, the config file is invalid TOML or
            declares an unknown field, or any layer's value fails to
            parse into its field's type.
    """
    candidates = candidate_config_paths(
        explicit_config_path=explicit_config_path, workspace_path=workspace_path
    )
    _assert_outside_package(candidates, package_root=package_root)

    values: dict[str, object] = dict(_load_config_file(candidates[0]))
    if "fail_on" in values:
        # TOML has no severity type of its own — the file layer spells
        # `fail_on` as the same string a CLI flag or env var would use, so
        # it goes through the same string parser as those layers.
        values["fail_on"] = _parse_field_value("fail_on", str(values["fail_on"]))

    for field_name, env_var in FIELD_ENV_VARS.items():
        if env_var in env:
            values[field_name] = _parse_field_value(field_name, env[env_var])

    for field_name, raw in cli_overrides.items():
        values[field_name] = _parse_field_value(field_name, raw)

    defaults = Config()
    # Each value in `values` was produced by `_parse_field_value` (or is a
    # native TOML bool/int already matching its field), so these casts
    # only make explicit a type `load_config`'s own parsing already
    # guarantees — not an assumption introduced here.
    return Config(
        fail_on=cast("Severity | None", values.get("fail_on", defaults.fail_on)),
        continue_on_tool_error=cast(
            "bool", values.get("continue_on_tool_error", defaults.continue_on_tool_error)
        ),
        strict_normalization=cast(
            "bool", values.get("strict_normalization", defaults.strict_normalization)
        ),
        baseline_max_horizon_days=cast(
            "int", values.get("baseline_max_horizon_days", defaults.baseline_max_horizon_days)
        ),
    )
