"""Tests for the shared ASCII box-drawing primitives (ADR §7, R3)."""

from __future__ import annotations

import pytest

from linceo.core.ascii_box import HEADER_RULE_CHAR, border, row


def test_border_spans_every_column_with_corners_at_joins_and_ends() -> None:
    assert border([3, 5]) == "+-----+-------+"


def test_border_accepts_a_custom_fill_character() -> None:
    assert border([3], fill=HEADER_RULE_CHAR) == "+=====+"


def test_border_of_a_single_zero_width_column_is_still_a_closed_box() -> None:
    assert border([0]) == "+--+"


def test_row_pads_every_cell_including_the_last_with_one_space_each_side() -> None:
    assert row(["a", "bb"], [3, 3]) == "| a   | bb  |"


def test_row_never_omits_padding_for_a_short_final_column() -> None:
    """Unlike the old space-separated table, the last column is bordered and padded too."""
    rendered = row(["x", "y"], [5, 1])
    assert rendered.endswith(" |")
    assert not rendered.endswith("  |")  # exactly one space of padding, not left un-padded


def test_row_rejects_mismatched_cells_and_widths() -> None:
    with pytest.raises(ValueError, match="zip"):
        row(["a", "b"], [1])


def test_module_never_imports_anything_that_could_query_the_terminal() -> None:
    """The same structural guarantee `linceo.core.table` already enforced on itself (ADR R3)."""
    from linceo.core import ascii_box as module

    assert not hasattr(module, "shutil")
    assert not hasattr(module, "os")
    assert not hasattr(module, "sys")
