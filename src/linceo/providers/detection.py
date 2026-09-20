"""Deterministic `auto` platform detection (ADR §4 R1, §8).

R1 requires the check order behind `--platform auto` to be declared and
deterministic — documented here, not left implicit in the order of a chain
of `if`/`elif` scattered wherever platform selection happens to be needed.
Every platform this project adds in the future earns one more explicit,
ordered branch in `detect_platform`, never a fallthrough inferred from
which `ContextProvider` happened to be tried first.
"""

from __future__ import annotations

from collections.abc import Mapping

from linceo.core.context import Platform

#: The sentinel Azure Pipelines sets to the literal string `"True"` on every
#: agent run, regardless of trigger (branch, PR, schedule, manual). It is
#: Microsoft's own documented way to ask "am I running inside Azure
#: Pipelines at all" — a single, stable check, rather than inferring the
#: platform from the presence of one of the more specific `BUILD_*` /
#: `SYSTEM_*` variables `linceo.providers.azure_devops` reads afterwards,
#: several of which are themselves conditional on the trigger type and so
#: cannot double as a reliable platform sentinel.
AZURE_DEVOPS_SENTINEL_ENV_VAR = "TF_BUILD"

#: The sentinel GitHub Actions sets to the literal string `"true"` (lower
#: case — unlike Azure Pipelines' `"True"`) on every workflow run,
#: regardless of trigger. GitHub's own documented way to ask "am I running
#: inside GitHub Actions at all" — the same role `AZURE_DEVOPS_SENTINEL_ENV_VAR`
#: plays for Azure Pipelines, and preferred over any of the more specific
#: `GITHUB_*` variables `linceo.providers.github_actions` reads afterwards
#: for the same reason: several of those are conditional on the trigger
#: type and so cannot double as a reliable platform sentinel.
GITHUB_ACTIONS_SENTINEL_ENV_VAR = "GITHUB_ACTIONS"


def detect_platform(env: Mapping[str, str]) -> Platform:
    """Detect which `Platform` a run is executing under, from `env` alone.

    Declared, deterministic order (ADR §4 R1, §8): Azure Pipelines is
    checked first, via its `TF_BUILD` sentinel, then GitHub Actions, via
    its `GITHUB_ACTIONS` sentinel — the two are mutually exclusive in
    practice (a runner sets at most one), so their relative order carries
    no real consequence, but R1 requires one fixed, declared order
    regardless. `local` is the fallback when nothing more specific
    matches — it is the only platform every scope of this project must
    support (ADR §10), so it is the correct default for a process that
    turns out not to be running under any known CI runner at all. Always
    overridable by an explicit `--platform`, which never calls this
    function in the first place.
    """
    if env.get(AZURE_DEVOPS_SENTINEL_ENV_VAR) == "True":
        return Platform.AZURE_DEVOPS
    if env.get(GITHUB_ACTIONS_SENTINEL_ENV_VAR) == "true":
        return Platform.GITHUB_ACTIONS
    return Platform.LOCAL
