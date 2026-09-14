"""Gate policy: thresholds, exclusions, and temporary tool skips (ADR §8, §8.1, §8.2).

Three mechanisms share one document, parsed here from an already-decoded
mapping (`parse_policy_document`) so the same schema serves a local file
today and a remote source later without changing (ADR §8):

- **Thresholds** — a maximum finding count allowed per severity. A plain
  `--fail-on X` is the simple case of this mechanism, not a separate one
  (`thresholds_from_fail_on`): it sets a maximum of `0` for every severity
  at or above `X` and leaves the rest unconstrained. `Severity.INFO` can
  never be constrained (ADR §6): the escalation from a plain scalar cutoff
  to a per-severity table must not be able to defeat that guarantee.
- **Exclusions** — the generalized form of what the ADR calls the
  baseline: a fingerprint (or an unambiguous prefix of one, ADR §7's `FP`
  column), why it is suppressed, by whom, until when, and an optional
  scope of repositories it applies to (empty/absent means global).
- **Tool skips** — a declared, caducable reason not to run a given tool at
  all for now, distinct from a tool simply failing (ADR §5).

Every entry in the last two carries a mandatory `expires_at` within a
configured maximum horizon; a document that violates that, or declares an
unknown field, unknown severity, or unsupported shape anywhere in these
three sections, never produces a `Policy` at all (`PolicyConfigurationError`,
mapped by `core.config` to exit code 2).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from enum import StrEnum

from linceo.core.findings import Finding
from linceo.core.severity import SEVERITY_ORDER, Severity

#: Maps a severity to the highest finding count still allowed at that level;
#: a severity absent from the mapping is unconstrained. `Severity.INFO` may
#: never be a key (ADR §6) — enforced by `validate_thresholds`.
Thresholds = Mapping[Severity, int]

#: Default maximum distance between the day a policy document is loaded and
#: any entry's `expires_at`, in days (ADR §8.2) — an `expires_at` fixed
#: arbitrarily far in the future (e.g. "2099-01-01") is eternal debt with
#: extra steps, so exceeding this horizon is a configuration error.
DEFAULT_MAX_HORIZON_DAYS = 90

#: Default number of rows a console table shows before summarizing the rest
#: (ADR §7) — a presentation setting only; JSON (and, later, SARIF) always
#: carry every finding.
DEFAULT_REPORT_MAX_ROWS = 20


class PolicyConfigurationError(Exception):
    """A policy document, or how it interacts with the current run, is invalid.

    Raised both when parsing a document (a missing required field, an
    `expires_at` beyond the configured horizon, `INFO` named in
    `[thresholds]`) and, at apply time, when an exclusion's fingerprint
    prefix matches more than one finding in the current run (ADR §7's `FP`
    column) — both map to exit code 2 (`core.config.ConfigurationError`,
    which wraps this one at the point a `Config` is assembled).
    """


class ConfigLayer(StrEnum):
    """Which layer of the ADR §5/R5 precedence chain ultimately set a value.

    Recorded on `ThresholdResolution` so a report can say *why* the active
    thresholds are what they are, and — when a higher layer replaced a
    policy file's own `[thresholds]` table — name that layer explicitly
    rather than silently overriding it (ADR §8.1).
    """

    CLI = "cli"
    ENV = "env"
    FILE = "file"
    DEFAULT = "default"


def thresholds_from_fail_on(fail_on: Severity) -> Thresholds:
    """Translate a single `--fail-on` cutoff into per-severity maximum counts (ADR §8.1).

    Every severity at or above `fail_on` on the ADR §6 ordered scale gets a
    maximum of `0`; every severity below it is left unconstrained (absent
    from the mapping). This is the one gate mechanism the project has —
    `--fail-on` is simply the case of it expressible as a single cutoff.
    """
    threshold_rank = SEVERITY_ORDER.index(fail_on)
    return {
        severity: 0
        for severity in SEVERITY_ORDER
        if SEVERITY_ORDER.index(severity) <= threshold_rank
    }


def validate_thresholds(thresholds: Thresholds) -> None:
    """Reject a thresholds mapping that constrains `Severity.INFO` (ADR §6).

    Raises:
        PolicyConfigurationError: if `Severity.INFO` is a key — ADR §6
            guarantees INFO never blocks the gate under any threshold
            configuration, so allowing it here would make that guarantee
            false the moment someone wrote `[thresholds] info = 0`.
    """
    if Severity.INFO in thresholds:
        msg = (
            "thresholds may not constrain INFO — ADR §6 guarantees INFO never "
            "blocks the gate under any threshold configuration"
        )
        raise PolicyConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class ThresholdResolution:
    """Where the gate's active thresholds came from, and what a higher layer replaced (ADR §8.1).

    `fail_on` is the scalar cutoff that produced `thresholds` via
    `thresholds_from_fail_on`, when that is how they were produced — `None`
    when `thresholds` came directly from a policy file's `[thresholds]`
    table instead. `superseded` is the policy file's own `[thresholds]`
    table when a CLI flag or environment variable outranked it entirely
    (ADR §8.1's "the flag replaces the file's table, never merges with it");
    `None` when nothing was overridden. `superseded_from` names the file
    path that declared it, for the report to point at.
    """

    thresholds: Thresholds
    source: ConfigLayer
    fail_on: Severity | None = None
    superseded: Thresholds | None = None
    superseded_from: str | None = None

    @classmethod
    def for_fail_on(cls, fail_on: Severity | None, *, source: ConfigLayer) -> ThresholdResolution:
        """Build the resolution for a plain `--fail-on` value (or `None` for "no gate")."""
        thresholds = thresholds_from_fail_on(fail_on) if fail_on is not None else {}
        return cls(thresholds=thresholds, source=source, fail_on=fail_on)


@dataclass(frozen=True, slots=True)
class Exclusion:
    """One suppression: a fingerprint (or unambiguous prefix), why, by whom, until when, where.

    `reason` and `owner` have no default — an entry omitting either is
    invalid and must never be constructed at all (ADR §8.2). `repositories`
    empty (the default) means the exclusion is global; non-empty scopes it
    to those repositories only (ADR §8, "Alcance de las exclusiones") —
    matched against `ExecutionContext.repository`.
    """

    fingerprint: str
    reason: str
    owner: str
    expires_at: date
    repositories: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolSkip:
    """A declared, caducable reason not to run a tool at all for now (ADR §5, §8).

    Distinct from a tool that failed or whose binary is missing: this is a
    sanctioned, named absence with an owner and a deadline, so it does not
    count as the "absence of evidence" ADR §5 fails a run over — a run with
    an active `ToolSkip` still completes and its gate is still evaluated.
    Once `expires_at` has passed, the tool runs again; nothing re-suppresses
    it automatically.
    """

    tool: str
    reason: str
    owner: str
    expires_at: date


@dataclass(frozen=True, slots=True)
class Policy:
    """A run's exclusions and temporary tool skips — the non-scalar half of the policy document.

    Kept separate from `linceo.core.config.Config` (which carries the
    scalar settings, including the resolved `ThresholdResolution`) the same
    way the ADR §8.2 baseline was always a value distinct from the rest of
    configuration — this is that same mechanism, generalized, not a new one
    (ADR §8.2).
    """

    exclusions: tuple[Exclusion, ...] = ()
    tool_skips: tuple[ToolSkip, ...] = ()


@dataclass(frozen=True, slots=True)
class ExclusionOutcome:
    """The result of applying a `Policy`'s exclusions to a run's deduplicated findings.

    `active` is what the gate evaluates; `suppressed` and `expired` are
    kept separate so a report can show both a suppression count and,
    distinctly and prominently, which exclusions lapsed and need a decision
    (ADR §8.2) — an expired entry's finding is *also* included in `active`,
    since a lapsed exclusion counts against the gate again.
    """

    active: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]
    expired: tuple[Exclusion, ...]


def _match_fingerprint(
    pattern: str, findings_by_fingerprint: Mapping[str, Finding]
) -> Finding | None:
    """Resolve `pattern` (a full fingerprint or an unambiguous prefix) against this run's findings.

    Raises:
        PolicyConfigurationError: if `pattern` is a prefix of more than one
            distinct fingerprint present in `findings_by_fingerprint` — the
            risk the ADR §7 `FP` column's uniqueness is only ever guaranteed
            *within one run*, made loud instead of silently suppressing the
            wrong finding.
    """
    matches = {
        fingerprint: finding
        for fingerprint, finding in findings_by_fingerprint.items()
        if fingerprint.startswith(pattern)
    }
    if len(matches) > 1:
        msg = f"exclusion fingerprint {pattern!r} is ambiguous: matches {sorted(matches)}"
        raise PolicyConfigurationError(msg)
    return next(iter(matches.values()), None)


def apply_exclusions(
    findings: tuple[Finding, ...],
    exclusions: tuple[Exclusion, ...],
    *,
    today: date,
    repository: str,
) -> ExclusionOutcome:
    """Split `findings` into active, suppressed, and expired against `exclusions` (ADR §8.2).

    An exclusion whose `repositories` is non-empty and does not include
    `repository` simply does not apply — it neither suppresses anything nor
    counts as expired for this run. `expires_at` is assumed already
    validated against the configured horizon (`parse_policy_document` does
    that once, at load time); this function only classifies.

    Raises:
        PolicyConfigurationError: if an exclusion's `fingerprint` prefix
            matches more than one finding in `findings` (see
            `_match_fingerprint`).
    """
    findings_by_fingerprint = {finding.fingerprint: finding for finding in findings}

    suppressed_fingerprints: set[str] = set()
    expired: list[Exclusion] = []

    applicable = (
        exclusion
        for exclusion in exclusions
        if not exclusion.repositories or repository in exclusion.repositories
    )
    for exclusion in applicable:
        match = _match_fingerprint(exclusion.fingerprint, findings_by_fingerprint)
        if match is None:
            continue
        if exclusion.expires_at < today:
            expired.append(exclusion)
        else:
            suppressed_fingerprints.add(match.fingerprint)

    active = tuple(f for f in findings if f.fingerprint not in suppressed_fingerprints)
    suppressed = tuple(f for f in findings if f.fingerprint in suppressed_fingerprints)
    return ExclusionOutcome(active=active, suppressed=suppressed, expired=tuple(expired))


def split_tool_skips(
    tool_skips: tuple[ToolSkip, ...], *, today: date
) -> tuple[tuple[ToolSkip, ...], tuple[ToolSkip, ...]]:
    """Split `tool_skips` into those still active today and those that have lapsed (ADR §5, §8).

    A lapsed `ToolSkip` is not an error: the tool simply runs again, and the
    lapsed entry is only surfaced for visibility, not re-validated.
    """
    active = tuple(skip for skip in tool_skips if skip.expires_at >= today)
    expired = tuple(skip for skip in tool_skips if skip.expires_at < today)
    return active, expired


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """Everything a document's `[thresholds]`/`[[exclusions]]`/`[[skipped_tools]]` resolve to.

    Produced by `parse_policy_document` from already-decoded data — a local
    TOML file today, any other source later without this shape changing
    (ADR §8). `thresholds` is `None` when the document declares no
    `[thresholds]` table at all, distinct from an empty one (which is not
    expressible in TOML anyway, but kept `None` rather than `{}` so
    `core.config` can tell "absent" from "present and empty").
    """

    thresholds: Thresholds | None
    exclusions: tuple[Exclusion, ...]
    tool_skips: tuple[ToolSkip, ...]


_EXCLUSION_REQUIRED_FIELDS = frozenset({"fingerprint", "reason", "owner", "expires_at"})
_EXCLUSION_KNOWN_FIELDS = _EXCLUSION_REQUIRED_FIELDS | {"repositories"}
_TOOL_SKIP_REQUIRED_FIELDS = frozenset({"tool", "reason", "owner", "expires_at"})


def _parse_date(value: object, *, field: str) -> date:
    """Accept a native TOML date or an ISO-8601 string for `field`.

    Raises:
        PolicyConfigurationError: if `value` is neither.
    """
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            msg = f"{field} is not a valid ISO-8601 date: {value!r}"
            raise PolicyConfigurationError(msg) from exc
    msg = f"{field} must be a date, got {type(value).__name__}"
    raise PolicyConfigurationError(msg)


def _validate_horizon(
    identifier: str, expires_at: date, *, today: date, max_horizon_days: int
) -> None:
    """Reject an `expires_at` set further out than `max_horizon_days` from `today`."""
    horizon = today + timedelta(days=max_horizon_days)
    if expires_at > horizon:
        msg = (
            f"{identifier!r} expires_at={expires_at} is beyond the "
            f"{max_horizon_days}-day maximum horizon (today={today})"
        )
        raise PolicyConfigurationError(msg)


def _as_table_list(value: object | None, *, name: str) -> Sequence[Mapping[str, object]]:
    """Coerce `value` into a sequence of tables, or reject it.

    Raises:
        PolicyConfigurationError: if `value` is present but is not a list
            of tables.
    """
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        msg = f"{name} must be a list of tables"
        raise PolicyConfigurationError(msg)
    return value


def _parse_thresholds(raw: object | None) -> Thresholds | None:
    """Parse the `[thresholds]` table, or return `None` if absent.

    Raises:
        PolicyConfigurationError: for a non-table value, an unknown
            severity name, a non-integer or negative count, or a count for
            `Severity.INFO`.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        msg = f"thresholds must be a table, got {type(raw).__name__}"
        raise PolicyConfigurationError(msg)

    thresholds: dict[Severity, int] = {}
    for key, value in raw.items():
        try:
            severity = Severity(str(key).strip().upper())
        except ValueError as exc:
            msg = f"unknown severity in thresholds: {key!r}"
            raise PolicyConfigurationError(msg) from exc
        if not isinstance(value, int) or isinstance(value, bool):
            msg = f"thresholds.{key} must be an integer, got {value!r}"
            raise PolicyConfigurationError(msg)
        if value < 0:
            msg = f"thresholds.{key} must not be negative, got {value}"
            raise PolicyConfigurationError(msg)
        thresholds[severity] = value

    validate_thresholds(thresholds)
    return thresholds


def _parse_exclusion(
    entry: Mapping[str, object], *, today: date, max_horizon_days: int
) -> Exclusion:
    """Parse and validate one `[[exclusions]]` entry.

    `entry` is already known to be a table — `_as_table_list` guarantees
    that for every item it returns — so this only validates its fields.

    Raises:
        PolicyConfigurationError: for an unknown or missing field, an
            invalid `repositories` value, or an `expires_at` beyond
            `max_horizon_days`.
    """
    unknown = set(entry) - _EXCLUSION_KNOWN_FIELDS
    if unknown:
        msg = f"exclusions entry declares unknown field(s): {sorted(unknown)}"
        raise PolicyConfigurationError(msg)
    missing = _EXCLUSION_REQUIRED_FIELDS - set(entry)
    if missing:
        msg = f"exclusions entry is missing required field(s): {sorted(missing)}"
        raise PolicyConfigurationError(msg)

    repositories_raw = entry.get("repositories", ())
    if not isinstance(repositories_raw, list | tuple) or not all(
        isinstance(item, str) for item in repositories_raw
    ):
        msg = "exclusions.repositories must be a list of strings"
        raise PolicyConfigurationError(msg)

    expires_at = _parse_date(entry["expires_at"], field="exclusions.expires_at")
    exclusion = Exclusion(
        fingerprint=str(entry["fingerprint"]),
        reason=str(entry["reason"]),
        owner=str(entry["owner"]),
        expires_at=expires_at,
        repositories=tuple(repositories_raw),
    )
    _validate_horizon(
        exclusion.fingerprint, expires_at, today=today, max_horizon_days=max_horizon_days
    )
    return exclusion


def _parse_tool_skip(
    entry: Mapping[str, object], *, today: date, max_horizon_days: int
) -> ToolSkip:
    """Parse and validate one `[[skipped_tools]]` entry.

    `entry` is already known to be a table — `_as_table_list` guarantees
    that for every item it returns — so this only validates its fields.

    Raises:
        PolicyConfigurationError: for an unknown or missing field, or an
            `expires_at` beyond `max_horizon_days`.
    """
    unknown = set(entry) - _TOOL_SKIP_REQUIRED_FIELDS
    if unknown:
        msg = f"skipped_tools entry declares unknown field(s): {sorted(unknown)}"
        raise PolicyConfigurationError(msg)
    missing = _TOOL_SKIP_REQUIRED_FIELDS - set(entry)
    if missing:
        msg = f"skipped_tools entry is missing required field(s): {sorted(missing)}"
        raise PolicyConfigurationError(msg)

    expires_at = _parse_date(entry["expires_at"], field="skipped_tools.expires_at")
    tool_skip = ToolSkip(
        tool=str(entry["tool"]),
        reason=str(entry["reason"]),
        owner=str(entry["owner"]),
        expires_at=expires_at,
    )
    _validate_horizon(tool_skip.tool, expires_at, today=today, max_horizon_days=max_horizon_days)
    return tool_skip


def parse_policy_document(
    document: Mapping[str, object], *, today: date, max_horizon_days: int
) -> PolicyDocument:
    """Parse and validate the policy sections of an already-decoded document (ADR §8).

    `document` is decoded TOML data today — or any mapping shaped the same
    way, so a future remote source produces this same shape without this
    function changing (ADR §8). Only the keys `thresholds`, `exclusions`,
    and `skipped_tools` are read; an unknown top-level key is
    `linceo.core.config`'s concern, not this function's.

    Raises:
        PolicyConfigurationError: see `_parse_thresholds`, `_parse_exclusion`,
            and `_parse_tool_skip`.
    """
    thresholds = _parse_thresholds(document.get("thresholds"))
    exclusions = tuple(
        _parse_exclusion(entry, today=today, max_horizon_days=max_horizon_days)
        for entry in _as_table_list(document.get("exclusions"), name="exclusions")
    )
    tool_skips = tuple(
        _parse_tool_skip(entry, today=today, max_horizon_days=max_horizon_days)
        for entry in _as_table_list(document.get("skipped_tools"), name="skipped_tools")
    )
    return PolicyDocument(thresholds=thresholds, exclusions=exclusions, tool_skips=tool_skips)
