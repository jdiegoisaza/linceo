"""The `Finding` model and its supporting value objects (ADR §5, §6).

`Finding` is the project's own normalization target: whatever a
`ToolIntegration` parser emits, it is translated into this shape before
anything downstream (dedup, the gate, reporting) ever sees it. A parser
emits the tool's raw severity value as-is in `raw_severity` and performs no
normalization of its own — normalizing it into `severity` is the job of a
single shared component applying the versioned severity map (ADR §6), not
implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from linceo.core.severity import Severity, SeveritySource


class Category(StrEnum):
    """A finding category, matching the v0.1 reference tool integrations.

    `secrets` (Gitleaks) and `sca` (Trivy) are the only categories in
    scope for v0.1 (ADR §1, §10); a third category is out-of-scope work
    that would first need its own fingerprint ingredients defined in ADR §5.
    """

    SECRETS = "secrets"
    SCA = "sca"


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding was detected within the scanned workspace.

    `path` is always relative to the workspace root: the fingerprint must
    survive scanning the same repository from two different machines, so
    an absolute path never enters this model (ADR §5). `line` and `column`
    are optional, human-oriented positioning only — neither ever
    contributes to a fingerprint (ADR §5).
    """

    path: str
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True, slots=True)
class Package:
    """The package identity an `sca` finding's vulnerability was found in.

    `name` and `version` are the installed package's identity, not the
    vulnerability's — they are two of the four ingredients of the `sca`
    fingerprint (ADR §5); the vulnerability identifier itself travels as
    `Finding.rule_id`.
    """

    name: str
    version: str


@dataclass(frozen=True, slots=True)
class RawFinding:
    """A finding exactly as a `ToolIntegration` parser emitted it, before severity normalization.

    `raw_severity` is the tool's native value untouched — `None` when the
    tool emits no native severity at all, as Gitleaks does not — and
    `cvss_score`, when present, is a CVSS v3.1 base score a parser found
    alongside it. A parser never resolves either of these into the
    project's normalized `Severity` scale itself; that is the
    `SeverityNormalizer`'s sole job (ADR §6, `linceo.core.normalization`),
    which turns a `RawFinding` into the canonical `Finding`.

    Carries every field the fingerprint of its category needs
    (`linceo.core.fingerprint`) plus a human-readable `message`, but no
    `fingerprint` field of its own: computing it is the normalization
    step's responsibility, not the parser's.
    """

    tool: str
    category: Category
    rule_id: str
    message: str
    location: Location
    raw_severity: str | None
    cvss_score: float | None = None
    package: Package | None = None
    secret_hash: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """A single normalized finding, the unit both dedup and the gate act on.

    `fingerprint` is a `v1:<hex>` value produced by
    `linceo.core.fingerprint`; this class does not compute it, so that the
    same category-specific ingredients are visibly the ones fed to that
    module rather than re-derived implicitly.

    `tool` records which tool reported this specific finding — provenance
    that is always kept (ADR §5, "Deduplicación") — but is never an
    ingredient of `fingerprint`: two tools reporting the same fact must
    produce the same fingerprint for intra-run deduplication to be possible
    at all (ADR §5, "Decisión: la herramienta no entra en la huella").

    `severity` is the normalized value; `raw_severity` is the tool's native
    value untouched (`None` when the tool emits no native severity at all,
    as Gitleaks does not); `severity_source` names which precedence-chain
    signal decided `severity` (ADR §6), making the gate's decision
    auditable without reconstructing the precedence chain by hand.

    `package` is populated for `Category.SCA` findings and `None`
    otherwise; `secret_hash` is populated for `Category.SECRETS` findings
    and `None` otherwise — each category populates exactly the fields its
    own fingerprint ingredients and reporting need.
    """

    fingerprint: str
    tool: str
    category: Category
    rule_id: str
    message: str
    location: Location
    severity: Severity
    raw_severity: str | None
    severity_source: SeveritySource
    package: Package | None = None
    secret_hash: str | None = None
