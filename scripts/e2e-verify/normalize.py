"""Normalization rules for captured output — as data, not logic scattered per case.

Same reasoning ADR §6 already gives for `severity_map.toml`: a rule you can
read as a diff beats one buried inside whichever case happened to produce
the value that needed hiding. Without this, two runs of the same case never
produce byte-identical `cases/*.md` files — a `run_id`, an absolute temp
path, a wall-clock timestamp, or a baseline `expires_at` (computed from
"today", genuinely different every run) would show up as diff noise on
every single run, and nobody keeps regenerating documentation that always
shows a diff.

What is deliberately *not* normalized: tool versions (`gitleaks 8.30.1`),
rule/check ids (`CKV2_AWS_61`), severities, exit codes, package versions —
anything that is real, stable content for a given release and exactly what
a reader of the documentation wants to see verbatim.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date

#: A rule either substitutes a fixed placeholder, or computes one from the
#: match and the run's own `today` (for a date that is a function of when
#: the run happened, e.g. `expires_at` — a bare placeholder would throw away
#: real information a "+30d" style delta keeps).
_Replacement = str | Callable[[re.Match[str], date], str]


@dataclass(frozen=True, slots=True)
class Rule:
    """One normalization rule: a compiled pattern and what replaces each match."""

    name: str
    pattern: re.Pattern[str]
    replacement: _Replacement


def _relative_date(match: re.Match[str], today: date) -> str:
    """Render an ISO date found in the text as an offset from `today` (e.g. `<today+30d>`).

    Keeps the *information* (how far out this expiry actually is — the
    thing baseline_wave_expiry's own staggering is about, ADR §8.2) while
    dropping the part that would otherwise change on every run: the literal
    calendar date.
    """
    found = date.fromisoformat(match.group(0))
    delta = (found - today).days
    sign = "+" if delta >= 0 else ""
    return f"<today{sign}{delta}d>"


#: Applied in order — a rule earlier in this list runs before a later one
#: sees the text, which matters where one pattern's match could otherwise
#: overlap another's (none do today, but the order is still declared
#: explicitly rather than left to rely on that never changing, ADR R3's own
#: "never dict/iteration order" principle applied here to a list instead).
RULES: tuple[Rule, ...] = (
    Rule(
        "run_id_json",
        re.compile(r'"run_id":\s*"[0-9a-f]{32}"'),
        '"run_id": "<RUN_ID>"',
    ),
    # The console report's own `Run <hex32>` line — a bare 32-hex-char
    # token, distinct in length from the 40-char commit hash below and the
    # 64-char cache-key hashes `azure_policy.cache_key` produces, so this
    # cannot collide with either.
    Rule(
        "run_id_console",
        re.compile(r"\b[0-9a-f]{32}\b"),
        "<RUN_ID>",
    ),
    Rule(
        "commit_hex",
        re.compile(r"\b[0-9a-f]{40}\b"),
        "<COMMIT>",
    ),
    Rule(
        "iso_timestamp",
        re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"),
        "<TIMESTAMP>",
    ),
    # `expires_at = 2026-10-22` / `built 2026-09-14` / "expiring between
    # X and Y" — any bare ISO date left after the timestamp rule above has
    # already consumed every date-with-time. Rewritten relative to `today`
    # rather than blanked, so a reader can still tell a CRITICAL finding's
    # window from an INFO one's (ADR §8.2's own staggering) without the
    # exact day making every run's capture differ.
    Rule(
        "bare_iso_date",
        re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
        _relative_date,
    ),
    # `uv`'s own install/resolve summary lines carry a real wall-clock
    # duration inline in their text (`Resolved 4 packages in 216ms`) — the
    # package *count* is real, stable content worth keeping (it changes
    # exactly when a release's dependency closure changes, real signal for
    # a diff); the duration after "in" never is. Drops only that clause,
    # never the whole line.
    Rule(
        "uv_timing_suffix",
        re.compile(r"(\bpackages?) in [\d.]+(?:ms|s)\b"),
        r"\1",
    ),
)


def normalize(text: str, *, today: date) -> str:
    """Apply every `RULES` entry to `text`, in order."""
    for rule in RULES:
        if callable(rule.replacement):
            replacement = rule.replacement
            text = rule.pattern.sub(lambda m, r=replacement: r(m, today), text)
        else:
            text = rule.pattern.sub(rule.replacement, text)
    return text


def normalize_path(text: str, *, real_path: str, placeholder: str) -> str:
    """Replace every occurrence of `real_path` with `placeholder`.

    A separate pass from `RULES`, since the value to strip is only known at
    call time (a temp directory this specific run created) rather than a
    fixed pattern.
    """
    if not real_path:
        return text
    return text.replace(real_path, placeholder)


def apply_path_substitutions(text: str, substitutions: Sequence[tuple[str, str]]) -> str:
    """Apply every `(real_path, placeholder)` pair in `substitutions`, in order.

    Order matters: `run.py` puts the most specific real paths first (the
    installed `linceo` executable itself, the generated repository) and
    the run's own top-level temp directory last, since that directory is a
    *prefix* of the others — replacing it first would leave the more
    specific paths only partially matched (their own prefix already gone),
    so nothing built on top of this order should reorder the list it
    passes in without re-checking that constraint still holds.
    """
    for real_path, placeholder in substitutions:
        text = normalize_path(text, real_path=real_path, placeholder=placeholder)
    return text
