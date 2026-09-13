"""Normalized severity scale and severity provenance (ADR §6).

``Severity`` is the project's own five-level scale — ``CRITICAL | HIGH |
MEDIUM | LOW | INFO`` — defined by the action each level is expected to
provoke, not by per-tool adjectives. Mapping a tool's native severity value
onto this scale is the job of the (not yet implemented) versioned
``severity_map.toml`` and its ``SeverityNormalizer``; the one piece of that
normalization that is a fixed algorithm rather than tool-specific data is
the CVSS v3.1 base score bucketing, which lives here as ``Severity.from_cvss``.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """The project's normalized severity scale (ADR §6).

    Each level is defined by the action it is expected to provoke:
    ``CRITICAL`` blocks before merge, ``HIGH`` blocks by default on
    protected branches, ``MEDIUM`` is recorded but does not block by
    default, ``LOW`` is hygiene, and ``INFO`` never blocks the gate under
    any threshold configuration.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Map a CVSS v3.1 base score to this project's normalized scale.

        Bucket boundaries, fixed by ADR §6: ``0.0`` -> INFO,
        ``0.1``-``3.9`` -> LOW, ``4.0``-``6.9`` -> MEDIUM, ``7.0``-``8.9``
        -> HIGH, ``9.0``-``10.0`` -> CRITICAL.

        Raises:
            ValueError: if ``score`` falls outside the valid CVSS range
                ``[0.0, 10.0]``.
        """
        if not 0.0 <= score <= 10.0:
            msg = f"CVSS base score must be within [0.0, 10.0], got {score!r}"
            raise ValueError(msg)
        if score == 0.0:
            return cls.INFO
        if score <= 3.9:
            return cls.LOW
        if score <= 6.9:
            return cls.MEDIUM
        if score <= 8.9:
            return cls.HIGH
        return cls.CRITICAL


class SeveritySource(StrEnum):
    """Which precedence-chain signal ultimately decided a finding's severity.

    Fixed precedence order (ADR §6): a client ``override`` always wins;
    otherwise the tool's ``native`` severity is preferred when present;
    otherwise a ``cvss`` base score is bucketed via ``Severity.from_cvss``;
    otherwise a per-category ``category_default`` applies (e.g. HIGH for
    ``secrets``, since Gitleaks emits no native severity at all); and
    ``fallback`` marks a severity that no signal could resolve, made visible
    rather than silently absorbed into one of the other sources.
    """

    NATIVE = "native"
    CVSS = "cvss"
    CATEGORY_DEFAULT = "category_default"
    OVERRIDE = "override"
    FALLBACK = "fallback"
