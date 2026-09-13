"""Tests for `Severity.from_cvss` — the CVSS v3.1 bucketing rule fixed by ADR §6.

The rest of `linceo.core.severity` (the `Severity` and `SeveritySource`
enums themselves) is inert data with no behavior to exercise; only this
classmethod has real logic worth a table-driven test.
"""

from __future__ import annotations

import pytest

from linceo.core.severity import Severity


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_from_cvss_maps_score_to_bucket(score: float, expected: Severity) -> None:
    """Each ADR §6 bucket boundary maps to its declared severity, inclusive on both ends."""
    assert Severity.from_cvss(score) is expected


@pytest.mark.parametrize("score", [-0.1, 10.1, -5.0, 100.0])
def test_from_cvss_rejects_out_of_range_scores(score: float) -> None:
    """A CVSS score outside [0.0, 10.0] is a caller bug, not a bucket to guess at."""
    with pytest.raises(ValueError, match="CVSS base score"):
        Severity.from_cvss(score)
