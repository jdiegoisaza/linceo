"""Shared ASCII box-drawing primitives for the console report (ADR §7, R3).

Both the per-category findings table (`linceo.core.table`) and the report
banner (`linceo.core.banner`) render as bordered boxes; this is the one
place the actual characters and padding rule live, so the two can never
drift into visually inconsistent borders the way two independently
hand-written `"+" + "-" * n + "+"` literals eventually would.

Deliberately plain ASCII (`+`, `-`, `=`, `|` — every one of them ≤ 0x7E),
never the Unicode box-drawing block (`─│┌┐`, U+2500 and up): a byte range
this narrow survives being redirected into a CI log, piped through tools
that assume a single-byte-per-character encoding, or viewed in a terminal
with no Unicode font support, none of which a `docker run`'d pipeline gets
to choose (ADR R2/R4's "runs the same way regardless of which CI platform
invokes it" extends to "renders the same bytes regardless of what reads
them"). Also why this stays "nada de rich": a third-party rendering
library earns its keep by adapting to the terminal it runs in — exactly
the one behavior ADR R3 forbids a report from having.

Widths are supplied by the caller, always derived from content and a
schema (`linceo.core.table`) or from a single string's own length
(`linceo.core.banner`) — never computed here, and never by querying the
terminal: this module does not import `shutil`, `os`, or `sys`, the same
structural guarantee `linceo.core.table` already enforced on its own
before this module existed (`tests/unit/test_ascii_box.py` checks it here
too).
"""

from __future__ import annotations

from collections.abc import Sequence

#: The two horizontal rule characters: `BORDER_CHAR` opens and closes a box
#: (and separates nothing else); `HEADER_RULE_CHAR` is reserved for the one
#: rule a caller wants visually distinct from a plain border — today, only
#: `linceo.core.table`'s rule between a table's header and its body, the
#: "agrupación visual de la cabecera" a plain-bordered table alone would not
#: give a reader.
BORDER_CHAR = "-"
HEADER_RULE_CHAR = "="
_CORNER = "+"
_DIVIDER = "|"


def border(widths: Sequence[int], *, fill: str = BORDER_CHAR) -> str:
    """One horizontal rule spanning `widths`, corners and column joins marked with `+`.

    `fill` is `BORDER_CHAR` for an ordinary top/bottom border, or
    `HEADER_RULE_CHAR` for the rule directly under a table's header row —
    the only two values any caller in this project passes.
    """
    return _CORNER + _CORNER.join(fill * (width + 2) for width in widths) + _CORNER


def row(cells: Sequence[str], widths: Sequence[int]) -> str:
    """One content row: cells left-justified to their column's width, `|`-bordered.

    Each cell gets one space of padding on either side, `|` between and at
    both ends. Every column is padded here, including the last — unlike a border-less
    table, a box's right edge must line up from row to row, so there is no
    "last column is never padded" exception the way a plain-text table
    without a right border could get away with. This still never leaves
    trailing whitespace on the line: the line's own last character is
    always `|`, not a space.

    Raises:
        ValueError: if `cells` and `widths` are not the same length (via
            `zip(..., strict=True)`) — a caller bug, never a data-dependent
            condition either module's own callers can hit in practice.
    """
    padded = (f" {cell.ljust(width)} " for cell, width in zip(cells, widths, strict=True))
    return _DIVIDER + _DIVIDER.join(padded) + _DIVIDER
