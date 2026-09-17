"""Minimal version-range compatibility check (ADR R4, §8's `doctor`).

Deliberately not the `packaging` library: the base package's only
third-party dependency is Typer (ADR §8.3, AGENTS.md, "CLI framework"), and
a full PEP 440 specifier parser is far more general than this project's own
`SUPPORTED_VERSION_RANGE` constants (e.g.
`linceo.adapters.gitleaks.SUPPORTED_VERSION_RANGE`, `">=8.18,<9"`) ever
need — a short, comma-separated list of `>=`/`<=`/`>`/`<`/`==` clauses
against a plain dotted version string, which is all either adapter's
`detect_version` ever actually returns.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable

#: The leading run of ASCII digits at the start of a `.`-separated version
#: component, e.g. `"1"` out of `"1-dirty"` or `"1rc2"`.
_LEADING_DIGITS = re.compile(r"^\d+")

_COMPARATORS: dict[str, Callable[[tuple[int, ...], tuple[int, ...]], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    ">": operator.gt,
    "<": operator.lt,
}
#: Checked longest-symbol-first so `>=`/`<=`/`==` match before the bare
#: `>`/`<` prefix each of the first two starts with would.
_COMPARATOR_SYMBOLS = tuple(sorted(_COMPARATORS, key=len, reverse=True))


class InvalidVersionRangeError(ValueError):
    """A version string or a `SUPPORTED_VERSION_RANGE`-shaped range string could not be parsed."""


def parse_version(value: str) -> tuple[int, ...]:
    """Parse the leading dotted-digit run of `value` into a comparable tuple.

    Stops at the first `.`-separated component that is not purely digits —
    a pre-release or build suffix, e.g. `"8.30.1-dirty"` -> `(8, 30, 1)` —
    rather than rejecting it outright: this is a defensive allowance for a
    tool's version string carrying more than this project's own
    `SUPPORTED_VERSION_RANGE` clauses ever need to resolve, not a feature
    either adapter's `detect_version` currently exercises.

    Raises:
        InvalidVersionRangeError: if `value` has no leading digit at all.
    """
    parts: list[int] = []
    for chunk in value.strip().split("."):
        match = _LEADING_DIGITS.match(chunk)
        if match is None:
            break
        parts.append(int(match.group()))
    if not parts:
        msg = f"{value!r} has no leading numeric version component"
        raise InvalidVersionRangeError(msg)
    return tuple(parts)


def _parse_clause(
    clause: str,
) -> tuple[Callable[[tuple[int, ...], tuple[int, ...]], bool], tuple[int, ...]]:
    """Split one `version_satisfies` clause into its comparator and version tuple.

    Raises:
        InvalidVersionRangeError: if `clause` starts with none of
            `_COMPARATOR_SYMBOLS`, or its version part cannot be parsed.
    """
    stripped = clause.strip()
    for symbol in _COMPARATOR_SYMBOLS:
        if stripped.startswith(symbol):
            return _COMPARATORS[symbol], parse_version(stripped[len(symbol) :])
    msg = f"unrecognized version range clause {clause!r} (expected one of {_COMPARATOR_SYMBOLS})"
    raise InvalidVersionRangeError(msg)


def version_satisfies(version: str, version_range: str) -> bool:
    """Whether `version` satisfies every comma-separated clause in `version_range`.

    `version_range` is this project's own `SUPPORTED_VERSION_RANGE` shape
    (e.g. `">=8.18,<9"`): every clause must hold — `AND`, never `OR` — the
    same way a `pyproject.toml` dependency specifier's comma-separated
    clauses do.

    Raises:
        InvalidVersionRangeError: if `version`, or any clause of
            `version_range`, cannot be parsed — including an empty clause
            from a stray comma.
    """
    parsed_version = parse_version(version)
    for clause in version_range.split(","):
        if not clause.strip():
            msg = f"empty clause in version range {version_range!r}"
            raise InvalidVersionRangeError(msg)
        comparator, clause_version = _parse_clause(clause)
        if not comparator(parsed_version, clause_version):
            return False
    return True
