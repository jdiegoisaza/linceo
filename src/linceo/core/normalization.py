"""`SeverityNormalizer`: the single shared component that resolves `Severity` (ADR §6).

A `ToolIntegration` parser never normalizes severity itself — it emits the
tool's raw value untouched into `RawFinding.raw_severity`. This module is
the one place the fixed precedence chain from ADR §6 runs: a client
`override` always wins; otherwise a tool's `native` severity value, looked
up in an explicit `(tool, raw_severity) -> Severity` map; otherwise a
`cvss` base score bucketed via `Severity.from_cvss`; otherwise a
per-category `category_default`; and if none of those resolve anything, an
explicit `fallback` severity, counted and surfaced rather than absorbed
silently.

The versioned `severity_map.toml` described in ADR §6 — the file a
maintainer reviews as a diff when a tool's native values change — is a
future concern for whoever builds the Gitleaks/Trivy integrations; this
normalizer takes its maps as plain, already-loaded data, independent of
where they came from.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from linceo.core.findings import Category, Finding, RawFinding
from linceo.core.fingerprint import sca_fingerprint, secret_fingerprint
from linceo.core.severity import Severity, SeveritySource

#: Default severity assigned to a category when no other signal resolves
#: one, keyed by category. `secrets` defaults to HIGH (ADR §6): CRITICAL
#: would make `--fail-on CRITICAL` meaningless for Gitleaks findings, and
#: MEDIUM would let a real secret leak through the recommended
#: `--fail-on HIGH` threshold unblocked.
DEFAULT_CATEGORY_SEVERITY: Mapping[Category, Severity] = {
    Category.SECRETS: Severity.HIGH,
}

#: Severity assigned when every precedence-chain signal is unavailable
#: (ADR §6, "`UNKNOWN` nunca llega al gate como un nivel propio"). MEDIUM
#: on purpose: LOW would hide a possibly-real issue behind low-priority
#: noise, CRITICAL would fatigue-alert on cases that may be benign.
DEFAULT_FALLBACK_SEVERITY = Severity.MEDIUM


class UnresolvedSeverityError(Exception):
    """A strict `SeverityNormalizer` found no signal to resolve a severity from (ADR §6).

    Only raised when `SeverityNormalizer.strict` is `True` — the default,
    non-strict behavior is the documented fallback, never an exception.
    """


@dataclass(frozen=True, slots=True)
class SeverityNormalizer:
    """Resolves a `RawFinding`'s `Severity` via the ADR §6 precedence chain.

    `overrides` and `native_map` are both keyed by `(tool, rule_id)` and
    `(tool, raw_severity)` respectively — client overrides act on a
    specific rule, while the native map translates a tool's raw severity
    vocabulary, which is shared across all of that tool's rules.

    `strict` mirrors `--strict-normalization` (ADR §6, §8): when `True`,
    reaching `fallback` raises `UnresolvedSeverityError` instead of
    silently returning it, for an operator who would rather fail closed
    than trust an inferred severity.
    """

    native_map: Mapping[tuple[str, str], Severity] = field(default_factory=dict)
    overrides: Mapping[tuple[str, str], Severity] = field(default_factory=dict)
    category_defaults: Mapping[Category, Severity] = field(
        default_factory=lambda: dict(DEFAULT_CATEGORY_SEVERITY)
    )
    fallback: Severity = DEFAULT_FALLBACK_SEVERITY
    strict: bool = False

    def resolve(self, raw: RawFinding) -> tuple[Severity, SeveritySource]:
        """Resolve `raw`'s normalized severity and which signal decided it.

        Raises:
            UnresolvedSeverityError: if `strict` is `True` and no signal
                but the fallback would resolve a severity.
        """
        override = self.overrides.get((raw.tool, raw.rule_id))
        if override is not None:
            return override, SeveritySource.OVERRIDE

        if raw.raw_severity is not None:
            native = self.native_map.get((raw.tool, raw.raw_severity))
            if native is not None:
                return native, SeveritySource.NATIVE

        if raw.cvss_score is not None:
            return Severity.from_cvss(raw.cvss_score), SeveritySource.CVSS

        category_default = self.category_defaults.get(raw.category)
        if category_default is not None:
            return category_default, SeveritySource.CATEGORY_DEFAULT

        if self.strict:
            msg = (
                f"no severity signal resolved {raw.tool}/{raw.rule_id} and "
                "strict normalization is enabled"
            )
            raise UnresolvedSeverityError(msg)
        return self.fallback, SeveritySource.FALLBACK


def _fingerprint_for(raw: RawFinding) -> str:
    """Compute `raw`'s ADR §5 fingerprint from its category-specific ingredients."""
    if raw.category is Category.SECRETS:
        if raw.secret_hash is None:
            msg = "a secrets RawFinding must set secret_hash to be fingerprinted"
            raise ValueError(msg)
        return secret_fingerprint(
            rule_id=raw.rule_id, path=raw.location.path, secret_hash=raw.secret_hash
        )

    if raw.category is Category.SCA:
        if raw.package is None:
            msg = "an sca RawFinding must set package to be fingerprinted"
            raise ValueError(msg)
        return sca_fingerprint(
            package_name=raw.package.name,
            package_version=raw.package.version,
            vulnerability_id=raw.rule_id,
            manifest_path=raw.location.path,
        )

    msg = f"no fingerprint algorithm defined for category {raw.category!r}"
    raise ValueError(msg)


def normalize_finding(raw: RawFinding, normalizer: SeverityNormalizer) -> Finding:
    """Turn a `RawFinding` into the canonical `Finding`: fingerprint plus resolved severity."""
    severity, severity_source = normalizer.resolve(raw)
    return Finding(
        fingerprint=_fingerprint_for(raw),
        tool=raw.tool,
        category=raw.category,
        rule_id=raw.rule_id,
        message=raw.message,
        location=raw.location,
        severity=severity,
        raw_severity=raw.raw_severity,
        severity_source=severity_source,
        package=raw.package,
        secret_hash=raw.secret_hash,
    )
