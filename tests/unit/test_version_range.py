"""Tests for `linceo.core.version_range` (ADR R4, §8's `doctor`)."""

from __future__ import annotations

import pytest

from linceo.core.version_range import InvalidVersionRangeError, parse_version, version_satisfies


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.30.1", (8, 30, 1)),
        ("0.50", (0, 50)),
        ("1", (1,)),
        ("8.30.1-dirty", (8, 30, 1)),
        ("1.2.3+build456", (1, 2, 3)),
    ],
)
def test_parse_version(value: str, expected: tuple[int, ...]) -> None:
    assert parse_version(value) == expected


def test_parse_version_with_no_leading_digit_raises() -> None:
    with pytest.raises(InvalidVersionRangeError, match="no leading numeric"):
        parse_version("dirty")


@pytest.mark.parametrize(
    ("version", "version_range", "expected"),
    [
        ("8.30.1", ">=8.18,<9", True),
        ("8.18", ">=8.18,<9", True),
        ("8.17.9", ">=8.18,<9", False),
        ("9.0.0", ">=8.18,<9", False),
        ("0.50.0", ">=0.50,<1", True),
        ("0.49.9", ">=0.50,<1", False),
        ("1.0.0", ">=0.50,<1", False),
        ("2.0.0", "==2.0.0", True),
        ("2.0.1", "==2.0.0", False),
        ("2.0.0", ">1.0,<3.0", True),
        ("3.0.0", ">1.0,<3.0", False),
        ("1.0.0", "<=1.0.0", True),
        ("1.0.1", "<=1.0.0", False),
    ],
)
def test_version_satisfies(version: str, version_range: str, expected: bool) -> None:
    assert version_satisfies(version, version_range) is expected


def test_version_satisfies_rejects_an_unrecognized_clause() -> None:
    with pytest.raises(InvalidVersionRangeError, match="unrecognized version range clause"):
        version_satisfies("1.0.0", "~=1.0")


def test_version_satisfies_rejects_an_empty_clause() -> None:
    with pytest.raises(InvalidVersionRangeError, match="empty clause"):
        version_satisfies("1.0.0", ">=1.0,,<2.0")


def test_version_satisfies_rejects_an_unparseable_clause_version() -> None:
    with pytest.raises(InvalidVersionRangeError, match="no leading numeric"):
        version_satisfies("1.0.0", ">=dirty")
