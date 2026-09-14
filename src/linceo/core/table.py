"""Generic, deterministic plain-text rendering of one category's findings table (ADR §7).

One table per category, five base columns fixed here for every category —
`SEVERITY`, `ID`, `LOCATION`, `TOOL`, `FP` — followed by whatever extra
columns that category's `ReportSchema` declares. This module contains
**no branch on category or tool name**: every column, base or extra, is
resolved the same generic way, off `Finding` attributes and a
`linceo.core.report_schema.Column` (ADR §7). Column widths are derived
only from the schema and the rows being rendered — never from the
terminal — so the same input always renders to the same bytes (ADR R3):
this module does not call `shutil.get_terminal_size`, `os.get_terminal_size`,
or check `isatty` anywhere, and never will.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from linceo.core.findings import Finding
from linceo.core.report_schema import Column, ReportSchema, Truncate
from linceo.core.severity import SEVERITY_ORDER

_ELLIPSIS = "..."
_COLUMN_GAP = 2


def _resolve_field(finding: Finding, path: str) -> str | None:
    """Resolve a dotted attribute path (e.g. `"package.fixed_version"`) against `finding`."""
    value: object = finding
    for part in path.split("."):
        if value is None:
            return None
        value = getattr(value, part)
    return None if value is None else str(value)


def _raw_cell(column: Column, finding: Finding) -> str:
    """Join `column`'s resolved, non-`None` parts, or `column.missing` if none resolved."""
    resolved = (_resolve_field(finding, field) for field in column.fields)
    parts = [part for part in resolved if part is not None]
    return column.separator.join(parts) if parts else column.missing


def _truncate(value: str, *, max_width: int, truncate: Truncate) -> str:
    """Shorten `value` to `max_width`, keeping the end for `Truncate.LEFT`, the start otherwise."""
    if len(value) <= max_width:
        return value
    if max_width <= len(_ELLIPSIS):
        return value[-max_width:] if truncate is Truncate.LEFT else value[:max_width]
    if truncate is Truncate.LEFT:
        return _ELLIPSIS + value[-(max_width - len(_ELLIPSIS)) :]
    return value[: max_width - len(_ELLIPSIS)] + _ELLIPSIS


def _display_cell(column: Column, finding: Finding) -> str:
    """The truncated, print-ready value of `column` for `finding`."""
    return _truncate(
        _raw_cell(column, finding), max_width=column.max_width, truncate=column.truncate
    )


def sort_key(finding: Finding, *, location: Column) -> tuple[int, str, str]:
    """The ADR §7 table sort key: severity descending, then location, then fingerprint.

    The fingerprint as a final tiebreaker guarantees a total order —
    without it, two findings with equal severity and an identical rendered
    `LOCATION` (e.g. two rules matching the same line) would sort
    arbitrarily depending on the input order (ADR R3).
    """
    severity_rank = SEVERITY_ORDER.index(finding.severity)
    return (severity_rank, _raw_cell(location, finding), finding.fingerprint)


def _row(
    finding: Finding, *, schema: ReportSchema, short_fingerprints: Mapping[str, str]
) -> tuple[str, ...]:
    """The base and extra cells for one `finding`, in column order."""
    return (
        finding.severity.value,
        finding.rule_id,
        _display_cell(schema.location, finding),
        finding.tool,
        short_fingerprints[finding.fingerprint],
        *(_display_cell(column, finding) for column in schema.extra),
    )


def render_category_table(
    findings: Sequence[Finding],
    *,
    schema: ReportSchema,
    short_fingerprints: Mapping[str, str],
) -> str:
    """Render one category's findings as a fixed-width plain-text table (ADR §7).

    `findings` must already be sorted (`sort_key`) and truncated to the
    console's row limit by the caller — this function renders exactly the
    rows it is given, in the order given, and never touches the terminal.
    `short_fingerprints` must have an entry for every finding's
    `fingerprint` (`linceo.core.fingerprint.short_fingerprints`).
    """
    headers = (
        "SEVERITY",
        "ID",
        schema.location.header,
        "TOOL",
        "FP",
        *(column.header for column in schema.extra),
    )
    rows = [
        _row(finding, schema=schema, short_fingerprints=short_fingerprints) for finding in findings
    ]

    widths = [
        max(len(header), *(len(row[i]) for row in rows)) if rows else len(header)
        for i, header in enumerate(headers)
    ]

    lines = [_format_row(headers, widths)]
    lines.extend(_format_row(row, widths) for row in rows)
    return "\n".join(lines)


def _format_row(cells: Sequence[str], widths: Sequence[int]) -> str:
    """Left-justify every cell but the last to its column's width, gapped by `_COLUMN_GAP` spaces.

    The last column is never padded, so a rendered line carries no
    trailing whitespace.
    """
    padded = [cell.ljust(width) for cell, width in zip(cells[:-1], widths[:-1], strict=True)]
    return (" " * _COLUMN_GAP).join([*padded, cells[-1]])
