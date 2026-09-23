"""`SeverityNormalizer`: the single shared component that resolves `Severity` (ADR §6).

A `ToolIntegration` parser never normalizes severity itself — it emits the
tool's raw value untouched into `RawFinding.raw_severity`. This module is
the one place the fixed precedence chain from ADR §6 runs: a client
`override` always wins; otherwise a tool's `native` severity value, looked
up in an explicit `(tool, raw_severity) -> Severity` map; otherwise a
`cvss` base score bucketed via `Severity.from_cvss`; otherwise a
per-category `category_default` (itself escalatable per `rule_id`); and if
none of those resolve anything, an explicit `fallback` severity, counted
and surfaced rather than absorbed silently.

The versioned `severity_map.toml` ADR §6 requires — the file a maintainer
reviews as a diff when a tool's native values change — lives in
`linceo.core.severity_map`; `SeverityNormalizer.from_severity_map` is how
its parsed output becomes the `native_map`/`category_defaults` this class
resolves against. This module itself still takes plain, already-loaded
data as constructor arguments, independent of where they came from — a
test, or any future caller, can build one directly without ever touching a
TOML file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from linceo.core.findings import Category, Finding, RawFinding
from linceo.core.fingerprint import iac_fingerprint, sca_fingerprint, secret_fingerprint
from linceo.core.severity import Severity, SeveritySource
from linceo.core.severity_map import CategorySeverityDefault, SeverityMap

#: `SeverityNormalizer.map_version`'s value when built directly (not via
#: `from_severity_map`) — a test, or any other caller supplying its own
#: `native_map`/`category_defaults` by hand, was never produced by any
#: real `severity_map.toml` version, so this is neither `"v1"` nor any
#: other value that could be mistaken for one.
UNVERSIONED_SEVERITY_MAP = "unversioned"

#: Severity assigned when every precedence-chain signal is unavailable
#: (ADR §6, "`UNKNOWN` nunca llega al gate como un nivel propio"). MEDIUM
#: on purpose: LOW would hide a possibly-real issue behind low-priority
#: noise, CRITICAL would fatigue-alert on cases that may be benign. Not
#: part of `severity_map.toml` (ADR §6 scopes that file to a tool's own
#: native vocabulary): this is the last-resort catch-all when a finding
#: carries no tool-specific signal to look up at all.
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
    `category_defaults` is keyed by `Category`; each one's own `rules`
    (`CategorySeverityDefault`) escalates a specific `rule_id` above that
    category's flat default — "la severidad se asigna por regla, no
    globalmente" (ADR §6) — without introducing a precedence tier of its
    own: both still resolve as `SeveritySource.CATEGORY_DEFAULT`.

    `strict` mirrors `--strict-normalization` (ADR §6, §8): when `True`,
    reaching `fallback` raises `UnresolvedSeverityError` instead of
    silently returning it, for an operator who would rather fail closed
    than trust an inferred severity. `map_version` is `severity_map.toml`'s
    own `map_version` when this instance was built via `from_severity_map`
    — carried through to `RunResult.severity_map_version` (ADR §6: "un
    reporte declara con qué versión del mapa se produjeron sus
    severidades") — or `UNVERSIONED_SEVERITY_MAP` for one built by hand.
    """

    native_map: Mapping[tuple[str, str], Severity] = field(default_factory=dict)
    overrides: Mapping[tuple[str, str], Severity] = field(default_factory=dict)
    category_defaults: Mapping[Category, CategorySeverityDefault] = field(default_factory=dict)
    fallback: Severity = DEFAULT_FALLBACK_SEVERITY
    strict: bool = False
    map_version: str = UNVERSIONED_SEVERITY_MAP

    @classmethod
    def from_severity_map(
        cls,
        severity_map: SeverityMap,
        *,
        overrides: Mapping[tuple[str, str], Severity] = MappingProxyType({}),
        fallback: Severity = DEFAULT_FALLBACK_SEVERITY,
        strict: bool = False,
    ) -> SeverityNormalizer:
        """Build the shared normalizer from a loaded `severity_map.toml` (ADR §6).

        `overrides` is never part of `severity_map`: it is client
        configuration (ADR §6's precedence tier 1, "vive en la
        configuración de cliente, nunca en este repositorio"), a distinct
        input this classmethod only threads through, deferred as a real
        `.devsecops/config.toml` feature (ADR §14).
        """
        return cls(
            native_map=severity_map.native_map,
            overrides=overrides,
            category_defaults=severity_map.category_defaults,
            fallback=fallback,
            strict=strict,
            map_version=severity_map.map_version,
        )

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
            escalated = category_default.rules.get(raw.rule_id)
            severity = escalated if escalated is not None else category_default.default
            return severity, SeveritySource.CATEGORY_DEFAULT

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

    if raw.category is Category.IAC:
        if raw.resource is None:
            msg = "an iac RawFinding must set resource to be fingerprinted"
            raise ValueError(msg)
        return iac_fingerprint(rule_id=raw.rule_id, path=raw.location.path, resource=raw.resource)

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
        resource=raw.resource,
    )
