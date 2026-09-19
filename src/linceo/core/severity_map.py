"""Loads and validates the versioned `severity_map.toml` (ADR §6).

`linceo/data/severity_map.toml` is the declarative artifact ADR §6
requires — the `(tool, native value) -> Severity` map, per-category (and
per-`rule_id`) defaults for a tool that emits no native severity, and the
CVSS multi-source preference order — parsed here from an already-decoded
mapping (`parse_severity_map`), the same shape a future override source
could produce without this function changing (mirroring
`linceo.core.policy.parse_policy_document`'s own design for exactly this
reason). `load_severity_map` reads the one packaged file every real caller
uses; nothing in this module knows or cares that `SeverityNormalizer` is
what eventually consumes its output.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import resources

from linceo.core.findings import Category
from linceo.core.severity import Severity

#: Where the packaged default lives, as an `importlib.resources`
#: package/resource pair — the same lookup mechanism
#: `tests/unit/test_sarif_reporter.py` already uses for the vendored SARIF
#: schema, so a second, different way of finding a packaged data file
#: never needs inventing.
_DEFAULT_PACKAGE = "linceo.data"
_DEFAULT_RESOURCE = "severity_map.toml"

_TOP_LEVEL_KNOWN_KEYS = frozenset({"map_version", "native", "defaults", "cvss_source_preference"})
_CATEGORY_DEFAULT_KNOWN_KEYS = frozenset({"default", "rules"})


class SeverityMapError(Exception):
    """`severity_map.toml` is malformed, or declares something invalid (ADR §6).

    Raised only while parsing the document itself — never at resolution
    time, unlike `linceo.core.normalization.UnresolvedSeverityError`, which
    is about one finding's own missing signal, not about the map being
    malformed.
    """


@dataclass(frozen=True, slots=True)
class CategorySeverityDefault:
    """One category's default severity, escalatable per `rule_id` (ADR §6).

    `default` applies to any finding in this category with no native or
    CVSS signal; `rules` escalates one specific `rule_id` above it — "la
    severidad se asigna por regla, no globalmente". Both still resolve
    through `SeveritySource.CATEGORY_DEFAULT`: a per-`rule_id` escalation
    is a refinement within that one precedence tier (ADR §6's fixed,
    five-value `severity_source` enumeration), never a tier of its own.
    """

    default: Severity
    rules: Mapping[str, Severity] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SeverityMap:
    """The parsed, validated contents of `severity_map.toml` (ADR §6).

    `native_map` and `category_defaults` are exactly the shapes
    `linceo.core.normalization.SeverityNormalizer` already takes as
    constructor arguments (`SeverityNormalizer.from_severity_map` builds
    one from the other) — this module never imports `normalization` itself,
    so a future consumer of this same parsed data that is not a
    `SeverityNormalizer` at all costs nothing to add.
    """

    map_version: str
    native_map: Mapping[tuple[str, str], Severity]
    category_defaults: Mapping[Category, CategorySeverityDefault]
    cvss_source_preference: tuple[str, ...]


def _parse_severity_value(value: object, *, context: str) -> Severity:
    """Parse `value` as a `Severity` name, case-insensitively.

    Raises:
        SeverityMapError: if `value` is not a string, or does not name a
            known `Severity`.
    """
    if not isinstance(value, str):
        msg = f"{context} must be a string naming a severity, got {type(value).__name__}"
        raise SeverityMapError(msg)
    try:
        return Severity(value.strip().upper())
    except ValueError as exc:
        msg = f"{context} names an unknown severity: {value!r}"
        raise SeverityMapError(msg) from exc


def _parse_native_map(raw: object) -> dict[tuple[str, str], Severity]:
    """Parse the `[native.<tool>]` tables into a flat `(tool, native value) -> Severity` map.

    The native value itself (the table's own key, e.g. `"HIGH"`) is kept
    exactly as written — never re-cased — because it must match a tool's
    own raw output byte for byte at resolution time; only the *value* side
    (the severity name) is parsed case-insensitively, for the document
    author's convenience.

    Raises:
        SeverityMapError: if `raw` (or one tool's own table) is present
            but is not a table, or any value is not a known severity.
    """
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        msg = f"native must be a table, got {type(raw).__name__}"
        raise SeverityMapError(msg)

    native_map: dict[tuple[str, str], Severity] = {}
    for tool, values in raw.items():
        if not isinstance(values, Mapping):
            msg = f"native.{tool} must be a table, got {type(values).__name__}"
            raise SeverityMapError(msg)
        for native_value, severity in values.items():
            native_map[(str(tool), str(native_value))] = _parse_severity_value(
                severity, context=f"native.{tool}.{native_value}"
            )
    return native_map


def _parse_category(key: object) -> Category:
    """Resolve a `[defaults.<name>]` table's key to a known `Category`.

    Raises:
        SeverityMapError: if `key` does not name a registered `Category`
            — an unrecognized category is a configuration error, never a
            table silently ignored (mirroring
            `linceo.core.policy`'s own `[thresholds.<name>]` handling).
    """
    try:
        return Category(str(key))
    except ValueError as exc:
        msg = f"unknown category in defaults: {key!r}"
        raise SeverityMapError(msg) from exc


def _parse_category_default(raw: object, *, category: str) -> CategorySeverityDefault:
    """Parse one `[defaults.<category>]` table.

    Raises:
        SeverityMapError: if `raw` is not a table, declares an unknown
            field, is missing `default`, or `rules` (when present) is not
            a table of valid severities.
    """
    if not isinstance(raw, Mapping):
        msg = f"defaults.{category} must be a table, got {type(raw).__name__}"
        raise SeverityMapError(msg)

    unknown = set(raw) - _CATEGORY_DEFAULT_KNOWN_KEYS
    if unknown:
        msg = f"defaults.{category} declares unknown field(s): {sorted(unknown)}"
        raise SeverityMapError(msg)
    if "default" not in raw:
        msg = f"defaults.{category} is missing required field 'default'"
        raise SeverityMapError(msg)

    default = _parse_severity_value(raw["default"], context=f"defaults.{category}.default")

    rules_raw = raw.get("rules", {})
    if not isinstance(rules_raw, Mapping):
        msg = f"defaults.{category}.rules must be a table, got {type(rules_raw).__name__}"
        raise SeverityMapError(msg)
    rules = {
        str(rule_id): _parse_severity_value(value, context=f"defaults.{category}.rules.{rule_id}")
        for rule_id, value in rules_raw.items()
    }
    return CategorySeverityDefault(default=default, rules=rules)


def _parse_defaults(raw: object) -> dict[Category, CategorySeverityDefault]:
    """Parse every `[defaults.<category>]` table. A category absent here has no default at all.

    Raises:
        SeverityMapError: if `raw` is present but is not a table, or any
            entry fails `_parse_category`/`_parse_category_default`.
    """
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        msg = f"defaults must be a table, got {type(raw).__name__}"
        raise SeverityMapError(msg)
    return {
        _parse_category(category): _parse_category_default(value, category=str(category))
        for category, value in raw.items()
    }


def _parse_cvss_source_preference(raw: object) -> tuple[str, ...]:
    """Parse `cvss_source_preference`, or `()` if absent — meaning alphabetical order only.

    Raises:
        SeverityMapError: if present but not a list of strings.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        msg = f"cvss_source_preference must be a list of strings, got {raw!r}"
        raise SeverityMapError(msg)
    return tuple(raw)


def parse_severity_map(document: Mapping[str, object]) -> SeverityMap:
    """Parse and validate an already-decoded `severity_map.toml` document (ADR §6).

    `document` is decoded TOML data today — or any mapping shaped the same
    way, so a future override source (ADR §6, deferred — see the ADR's
    §14 table) produces this same shape without this function changing.

    Raises:
        SeverityMapError: for an unknown top-level field, a missing or
            malformed `map_version`, a malformed `native`/`defaults`
            table, an unrecognized category, an unknown severity name
            anywhere, or a malformed `cvss_source_preference`.
    """
    unknown = set(document) - _TOP_LEVEL_KNOWN_KEYS
    if unknown:
        msg = f"severity_map.toml declares unknown field(s): {sorted(unknown)}"
        raise SeverityMapError(msg)

    map_version = document.get("map_version")
    if not isinstance(map_version, str) or not map_version:
        msg = "severity_map.toml must declare a non-empty string map_version"
        raise SeverityMapError(msg)

    return SeverityMap(
        map_version=map_version,
        native_map=_parse_native_map(document.get("native")),
        category_defaults=_parse_defaults(document.get("defaults")),
        cvss_source_preference=_parse_cvss_source_preference(
            document.get("cvss_source_preference")
        ),
    )


def load_severity_map() -> SeverityMap:
    """Read and parse the packaged `severity_map.toml` (ADR §6).

    The one loader every real caller uses — no override parameter, on
    purpose: whether a client's own policy document should be able to
    extend or replace this file is a question ADR §6 raises but this
    project has not answered yet (see the ADR's §14 deferred-work table);
    until it is, this file is the single source of truth, shipped with
    the package, identical for every run.

    Raises:
        SeverityMapError: if the packaged file is not valid TOML, or
            fails `parse_severity_map`'s validation — both would mean the
            package itself was built wrong, never a client mistake.
    """
    text = resources.files(_DEFAULT_PACKAGE).joinpath(_DEFAULT_RESOURCE).read_text(encoding="utf-8")
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = f"{_DEFAULT_RESOURCE} is not valid TOML: {exc}"
        raise SeverityMapError(msg) from exc
    return parse_severity_map(document)


__all__ = [
    "CategorySeverityDefault",
    "SeverityMap",
    "SeverityMapError",
    "load_severity_map",
    "parse_severity_map",
]
