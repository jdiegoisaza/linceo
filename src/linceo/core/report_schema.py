"""Declarative per-category console report table columns (ADR §7).

Every category's console table shares five base columns — ``SEVERITY``,
``ID``, ``LOCATION``, ``TOOL``, ``FP`` — rendered by a single generic
component (`linceo.core.table`) that never branches on category or tool
name. ``LOCATION`` and any category-specific extra columns are the one part
of that table a category is free to shape, and it shapes them as *data*: a
`ReportSchema` value a `ToolIntegration` declares via
`ToolIntegration.report_schema` (ADR §1), never as rendering code the
reporter would need a conditional to call.

A `Column` never carries a callable — only dotted attribute paths resolved
generically against a `Finding` — so a schema is a plain, comparable value
and rendering it is fully deterministic (ADR R3): given the same `Finding`,
resolving the same `Column` twice always yields the same string.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Truncate(StrEnum):
    """Which end of an over-length cell survives truncation (ADR §7).

    ``LEFT`` drops characters from the start and keeps the end — the shape
    a path needs so a truncated `LOCATION` still ends in its file name
    (and, for `secrets`, its line number) instead of an indecipherable
    directory prefix. ``RIGHT`` is the ordinary case for values with no
    meaningful tail, like a long vulnerability description.
    """

    LEFT = "left"
    RIGHT = "right"


@dataclass(frozen=True, slots=True)
class Column:
    """One column's declarative rendering rule (ADR §7).

    `fields` are dotted attribute paths resolved against a `Finding` (e.g.
    ``"location.path"``, ``"package.fixed_version"``); a part that resolves
    to `None` anywhere along the path is dropped from the joined value
    rather than raising, so an optional attribute (like `Location.line`)
    simply does not contribute a separator-joined segment. When *every*
    part resolves to `None`, the cell renders `missing` instead of an empty
    string, so e.g. a `FIXED` cell with no known fix reads ``(none)``
    rather than a blank cell indistinguishable from a rendering bug.
    """

    header: str
    fields: tuple[str, ...]
    separator: str = ""
    max_width: int = 40
    truncate: Truncate = Truncate.RIGHT
    missing: str = "-"


@dataclass(frozen=True, slots=True)
class ReportSchema:
    """A category's full table contract: its `LOCATION` column plus its extras (ADR §7).

    The base columns `SEVERITY`, `ID`, `TOOL`, and `FP` are fixed by
    `linceo.core.table` for every category and never appear here;
    `location` is the one base column a category defines the shape of, and
    `extra` is printed after all five base columns, in the order given —
    never conditioned on which tool produced a given `Finding`, only on its
    `category` (ADR §7).
    """

    location: Column
    extra: tuple[Column, ...] = ()
