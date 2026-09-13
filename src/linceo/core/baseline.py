"""Baseline suppressions: adoption and ongoing triage over the gate (ADR §8.2).

A baseline entry suppresses a finding by `fingerprint` — never by path and
line, which breaks under the first reformat — and must carry a mandatory
`expires_at`: an entry without one is a configuration error (exit code 2),
not a silent permissive default, because a suppression with no expiry is
debt that never comes back for review. An entry whose expiry has passed
counts actively against the gate again rather than staying silently
suppressed, and is surfaced separately so a report can call out exactly
which suppressions need a human decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from linceo.core.findings import Finding

#: Default maximum distance between the day a baseline is evaluated and an
#: entry's `expires_at`, in days (ADR §8.2) — an `expires_at` fixed
#: arbitrarily far in the future (e.g. "2099-01-01") is eternal debt with
#: extra steps, so exceeding this horizon is also a configuration error.
DEFAULT_MAX_HORIZON_DAYS = 90


class BaselineConfigurationError(Exception):
    """A baseline entry violates a hard ADR §8.2 rule — maps to exit code 2.

    Raised for a missing `reason`/`owner` (enforced by `BaselineEntry`
    itself being a dataclass with no defaults for either) is not this
    exception's concern; this one is for the rule `BaselineEntry` cannot
    enforce on its own: an `expires_at` beyond the configured horizon.
    """


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One suppression: a fingerprint, why it is suppressed, by whom, and until when.

    `reason` and `owner` have no default — a suppression entry that omits
    either is invalid and must never be constructed at all (ADR §8.2).
    """

    fingerprint: str
    reason: str
    owner: str
    expires_at: date


@dataclass(frozen=True, slots=True)
class Baseline:
    """A run's full set of baseline suppressions (ADR §8.2).

    Client configuration, subject to R5: a `Baseline` is always
    constructed from a file living in the scanned workspace, never from
    anything shipped in this repository.
    """

    entries: tuple[BaselineEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    """The result of applying a `Baseline` to a run's deduplicated findings.

    `active` is what the gate evaluates; `suppressed` and `expired` are
    kept separate so a report can show both a suppression count and,
    distinctly and prominently, which suppressions lapsed and need a
    decision (ADR §8.2) — an expired entry's finding is *also* included in
    `active`, since a lapsed suppression counts against the gate again.
    """

    active: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]
    expired: tuple[BaselineEntry, ...]


def _validate_horizon(entry: BaselineEntry, *, today: date, max_horizon_days: int) -> None:
    """Reject an `expires_at` set further out than `max_horizon_days` from `today`."""
    horizon = today + timedelta(days=max_horizon_days)
    if entry.expires_at > horizon:
        msg = (
            f"baseline entry for {entry.fingerprint!r} expires_at={entry.expires_at} "
            f"is beyond the {max_horizon_days}-day maximum horizon (today={today})"
        )
        raise BaselineConfigurationError(msg)


def apply_baseline(
    findings: tuple[Finding, ...],
    baseline: Baseline,
    *,
    today: date,
    max_horizon_days: int = DEFAULT_MAX_HORIZON_DAYS,
) -> BaselineOutcome:
    """Split `findings` into active, suppressed, and expired against `baseline` (ADR §8.2).

    Raises:
        BaselineConfigurationError: if any entry's `expires_at` exceeds
            `max_horizon_days` from `today`.
    """
    for baseline_entry in baseline.entries:
        _validate_horizon(baseline_entry, today=today, max_horizon_days=max_horizon_days)

    entries_by_fingerprint = {entry.fingerprint: entry for entry in baseline.entries}

    active: list[Finding] = []
    suppressed: list[Finding] = []
    expired: list[BaselineEntry] = []
    seen_expired_fingerprints: set[str] = set()

    for finding in findings:
        entry = entries_by_fingerprint.get(finding.fingerprint)
        if entry is None:
            active.append(finding)
        elif entry.expires_at < today:
            active.append(finding)
            if entry.fingerprint not in seen_expired_fingerprints:
                expired.append(entry)
                seen_expired_fingerprints.add(entry.fingerprint)
        else:
            suppressed.append(finding)

    return BaselineOutcome(
        active=tuple(active),
        suppressed=tuple(suppressed),
        expired=tuple(expired),
    )
