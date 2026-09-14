"""Tests for the declarative report table schema (ADR §7)."""

from __future__ import annotations

from linceo.core.report_schema import Column, ReportSchema, Truncate


def test_column_defaults() -> None:
    column = Column(header="LOCATION", fields=("location.path",))

    assert column.separator == ""
    assert column.max_width == 40
    assert column.truncate is Truncate.RIGHT
    assert column.missing == "-"


def test_column_is_a_comparable_value_object() -> None:
    """A `Column` carries no callable — two columns built the same way compare equal."""
    first = Column(header="FIXED", fields=("package.fixed_version",), missing="(none)")
    second = Column(header="FIXED", fields=("package.fixed_version",), missing="(none)")

    assert first == second


def test_report_schema_extra_defaults_to_empty() -> None:
    schema = ReportSchema(location=Column(header="LOCATION", fields=("location.path",)))

    assert schema.extra == ()


def test_report_schema_extra_columns_are_printed_in_declared_order() -> None:
    manifest = Column(header="MANIFEST", fields=("location.path",))
    fixed = Column(header="FIXED", fields=("package.fixed_version",), missing="(none)")
    schema = ReportSchema(
        location=Column(
            header="LOCATION", fields=("package.name", "package.version"), separator="@"
        ),
        extra=(manifest, fixed),
    )

    assert schema.extra == (manifest, fixed)
