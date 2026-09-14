"""Tests for the generic, deterministic table renderer (ADR §7, R3).

The `sca` extra columns (`MANIFEST`, `FIXED`) are exercised here with a
synthetic schema and ordinary `Finding`/`Package` values — proof that
`linceo.core.table` renders them with no category-specific code of its own,
since this module never imports `Category` at all.
"""

from __future__ import annotations

import pytest

from linceo.core.findings import Category, Finding, Location, Package
from linceo.core.report_schema import Column, ReportSchema, Truncate
from linceo.core.severity import Severity, SeveritySource
from linceo.core.table import render_category_table, sort_key

_SECRETS_SCHEMA = ReportSchema(
    location=Column(
        header="LOCATION",
        fields=("location.path", "location.line"),
        separator=":",
        max_width=20,
        truncate=Truncate.LEFT,
    )
)

_SCA_SCHEMA = ReportSchema(
    location=Column(header="LOCATION", fields=("package.name", "package.version"), separator="@"),
    extra=(
        Column(header="MANIFEST", fields=("location.path",), max_width=20, truncate=Truncate.LEFT),
        Column(header="FIXED", fields=("package.fixed_version",), missing="(none)"),
    ),
)


def _secret_finding(*, severity: Severity, rule_id: str, path: str, line: int = 1) -> Finding:
    return Finding(
        fingerprint=f"v1:{rule_id}-{path}-{line}",
        tool="gitleaks",
        category=Category.SECRETS,
        rule_id=rule_id,
        message="AWS access key detected",
        location=Location(path=path, line=line),
        severity=severity,
        raw_severity=None,
        severity_source=SeveritySource.CATEGORY_DEFAULT,
        secret_hash="deadbeef",  # noqa: S106 -- test fixture value, not a credential
    )


def _sca_finding(
    *,
    severity: Severity,
    rule_id: str,
    package: str,
    version: str,
    fixed: str | None,
    manifest: str,
) -> Finding:
    return Finding(
        fingerprint=f"v1:{rule_id}-{package}-{version}",
        tool="trivy",
        category=Category.SCA,
        rule_id=rule_id,
        message="vulnerable dependency",
        location=Location(path=manifest),
        severity=severity,
        raw_severity="HIGH",
        severity_source=SeveritySource.NATIVE,
        package=Package(name=package, version=version, fixed_version=fixed),
    )


def _fps(*fingerprints: str) -> dict[str, str]:
    return {fp: fp for fp in fingerprints}


def test_headers_are_the_five_base_columns_for_a_category_with_no_extras() -> None:
    finding = _secret_finding(severity=Severity.HIGH, rule_id="aws-key", path="src/config.py")

    table = render_category_table(
        [finding], schema=_SECRETS_SCHEMA, short_fingerprints=_fps(finding.fingerprint)
    )

    header = table.splitlines()[0].split()
    assert header[:5] == ["SEVERITY", "ID", "LOCATION", "TOOL", "FP"]


def test_extra_columns_are_appended_after_the_base_five_in_declared_order() -> None:
    """`table.py` never branches on category: an arbitrary schema's extras just render."""
    finding = _sca_finding(
        severity=Severity.CRITICAL,
        rule_id="CVE-2031-40001",
        package="acme-parse",
        version="1.2.0",
        fixed="1.2.4",
        manifest="app/requirements.txt",
    )

    table = render_category_table(
        [finding], schema=_SCA_SCHEMA, short_fingerprints=_fps(finding.fingerprint)
    )

    header = table.splitlines()[0].split()
    assert header == ["SEVERITY", "ID", "LOCATION", "TOOL", "FP", "MANIFEST", "FIXED"]
    row = table.splitlines()[1]
    assert "acme-parse@1.2.0" in row
    assert "1.2.4" in row


def test_missing_extra_value_renders_the_columns_missing_placeholder() -> None:
    finding = _sca_finding(
        severity=Severity.HIGH,
        rule_id="GHSA-qq11-ww22",
        package="tidy-fmt",
        version="0.4.1",
        fixed=None,
        manifest="app/requirements.txt",
    )

    table = render_category_table(
        [finding], schema=_SCA_SCHEMA, short_fingerprints=_fps(finding.fingerprint)
    )

    assert "(none)" in table.splitlines()[1]


def test_location_left_truncation_keeps_the_file_name_and_line() -> None:
    finding = _secret_finding(
        severity=Severity.HIGH,
        rule_id="aws-key",
        path="src/app/very/deeply/nested/module/tree/file.py",
        line=42,
    )

    table = render_category_table(
        [finding], schema=_SECRETS_SCHEMA, short_fingerprints=_fps(finding.fingerprint)
    )

    row = table.splitlines()[1]
    assert "file.py:42" in row
    assert "..." in row


def test_sort_key_orders_by_severity_then_location_then_fingerprint() -> None:
    low = _secret_finding(severity=Severity.LOW, rule_id="low-rule", path="b.py")
    critical = _secret_finding(severity=Severity.CRITICAL, rule_id="crit-rule", path="a.py")

    ordered = sorted([low, critical], key=lambda f: sort_key(f, location=_SECRETS_SCHEMA.location))

    assert ordered == [critical, low]


def test_column_widths_are_derived_from_content_not_the_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3: the same input renders identically regardless of terminal size or TTY state."""
    findings = [
        _secret_finding(severity=Severity.HIGH, rule_id="a-very-long-rule-identifier", path="x.py"),
        _secret_finding(severity=Severity.LOW, rule_id="short", path="y.py"),
    ]
    fps = _fps(*(f.fingerprint for f in findings))

    monkeypatch.setenv("COLUMNS", "10")
    narrow = render_category_table(findings, schema=_SECRETS_SCHEMA, short_fingerprints=fps)
    monkeypatch.delenv("COLUMNS", raising=False)
    default = render_category_table(findings, schema=_SECRETS_SCHEMA, short_fingerprints=fps)

    assert narrow == default


def test_no_trailing_whitespace_on_any_rendered_line() -> None:
    finding = _secret_finding(severity=Severity.HIGH, rule_id="aws-key", path="src/config.py")

    table = render_category_table(
        [finding], schema=_SECRETS_SCHEMA, short_fingerprints=_fps(finding.fingerprint)
    )

    assert all(line == line.rstrip() for line in table.splitlines())


def test_table_module_never_imports_anything_that_could_query_the_terminal() -> None:
    """Structural guarantee: `shutil`/`os`/`sys` are not even bound in this module's namespace.

    Without one of them imported, `table.py` has no way to call
    `shutil.get_terminal_size`, `os.get_terminal_size`, or check `isatty` —
    the module cannot depend on the terminal even by accident (ADR R3).
    """
    from linceo.core import table as table_module

    assert not hasattr(table_module, "shutil")
    assert not hasattr(table_module, "os")
    assert not hasattr(table_module, "sys")


def test_right_truncation_keeps_the_start_and_appends_an_ellipsis() -> None:
    long_id_schema = ReportSchema(
        location=Column(header="LOCATION", fields=("location.path",), max_width=10)
    )
    finding = _secret_finding(
        severity=Severity.HIGH, rule_id="aws-key", path="a-very-long-path-that-overflows.py"
    )

    table = render_category_table(
        [finding], schema=long_id_schema, short_fingerprints=_fps(finding.fingerprint)
    )

    row = table.splitlines()[1]
    assert "a-very-..." in row


def test_truncation_narrower_than_the_ellipsis_hard_cuts_instead() -> None:
    tiny_schema = ReportSchema(
        location=Column(header="LOCATION", fields=("location.path",), max_width=2)
    )
    left_tiny_schema = ReportSchema(
        location=Column(
            header="LOCATION", fields=("location.path",), max_width=2, truncate=Truncate.LEFT
        )
    )
    finding = _secret_finding(severity=Severity.HIGH, rule_id="aws-key", path="deeply/nested.py")

    right = render_category_table(
        [finding], schema=tiny_schema, short_fingerprints=_fps(finding.fingerprint)
    )
    left = render_category_table(
        [finding], schema=left_tiny_schema, short_fingerprints=_fps(finding.fingerprint)
    )

    # Column index 2 is LOCATION (SEVERITY, ID, LOCATION, TOOL, FP); checked
    # positionally, not by substring, since the FP column here happens to
    # embed the full path too (`_fps` maps a fingerprint to itself).
    assert right.splitlines()[1].split()[2] == "de"  # first two chars, hard-cut from the right
    assert left.splitlines()[1].split()[2] == "py"  # last two chars, hard-cut from the left


def test_a_none_intermediate_in_a_dotted_path_resolves_to_missing() -> None:
    """`package.fixed_version` against a `secrets` finding: `package` itself is `None`."""
    schema = ReportSchema(
        location=Column(header="LOCATION", fields=("location.path",)),
        extra=(Column(header="FIXED", fields=("package.fixed_version",), missing="(none)"),),
    )
    finding = _secret_finding(severity=Severity.HIGH, rule_id="aws-key", path="config.py")

    table = render_category_table(
        [finding], schema=schema, short_fingerprints=_fps(finding.fingerprint)
    )

    assert "(none)" in table.splitlines()[1]


def test_empty_findings_renders_only_the_header() -> None:
    table = render_category_table([], schema=_SECRETS_SCHEMA, short_fingerprints={})

    assert table.splitlines() == [table.splitlines()[0]]
    assert "LOCATION" in table
