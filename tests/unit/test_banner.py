"""Tests for the report banner: validation and rendering (ADR §7, §8.4)."""

from __future__ import annotations

import pytest

from linceo.core.banner import (
    DEFAULT_BANNER,
    MAX_BANNER_LENGTH,
    render_banner,
    validate_banner,
)
from linceo.core.policy import PolicyConfigurationError


def test_default_banner_is_linceo() -> None:
    assert DEFAULT_BANNER == "linceo"


def test_a_plain_ascii_banner_validates_and_is_returned_unchanged() -> None:
    assert validate_banner("ACME Corp Security Gate") == "ACME Corp Security Gate"


def test_default_banner_itself_always_validates() -> None:
    """The compiled-in default must never be rejected by its own validator."""
    validate_banner(DEFAULT_BANNER)


def test_a_non_string_banner_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="must be a string"):
        validate_banner(42)


def test_an_empty_banner_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="must not be empty"):
        validate_banner("")


def test_a_banner_at_exactly_the_max_length_is_accepted() -> None:
    banner = "a" * MAX_BANNER_LENGTH
    assert validate_banner(banner) == banner


def test_a_banner_one_character_over_the_max_length_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match=f"{MAX_BANNER_LENGTH}-character maximum"):
        validate_banner("a" * (MAX_BANNER_LENGTH + 1))


def test_an_embedded_newline_is_a_configuration_error() -> None:
    """Rejected as a non-printable character, not by a separate multi-line check (ADR §7)."""
    with pytest.raises(PolicyConfigurationError, match="printable ASCII"):
        validate_banner("ACME\nSecurity Gate")


def test_an_embedded_carriage_return_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="printable ASCII"):
        validate_banner("ACME\rSecurity Gate")


def test_an_ansi_escape_sequence_is_a_configuration_error() -> None:
    """`ESC` (0x1B) is not printable ASCII — this is what actually blocks terminal rewriting."""
    with pytest.raises(PolicyConfigurationError, match="printable ASCII"):
        validate_banner("\x1b[31mACME\x1b[0m")


def test_a_non_ascii_character_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="printable ASCII"):
        validate_banner("ACME Sécurité")


def test_a_tab_character_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="printable ASCII"):
        validate_banner("ACME\tSecurity")


def test_render_banner_boxes_exactly_the_text_width() -> None:
    assert render_banner("linceo") == "+--------+\n| linceo |\n+--------+"


def test_render_banner_has_no_minimum_width() -> None:
    """No artificial minimum: the box only ever promises to fit its own content (ADR R3)."""
    rendered = render_banner("x")
    assert rendered == "+---+\n| x |\n+---+"


def test_render_banner_top_and_bottom_borders_match() -> None:
    lines = render_banner("ACME Corp Security Gate").splitlines()
    assert lines[0] == lines[-1]


def test_render_banner_has_no_trailing_whitespace() -> None:
    for line in render_banner("ACME Corp Security Gate").splitlines():
        assert line == line.rstrip()


def test_banner_module_never_imports_anything_that_could_query_the_terminal() -> None:
    from linceo.core import banner as module

    assert not hasattr(module, "shutil")
    assert not hasattr(module, "os")
    assert not hasattr(module, "sys")
