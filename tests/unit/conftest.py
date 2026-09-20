"""Shared fixtures for `tests/unit/` (ADR §4 R1, §10): a hermetic process environment.

The incident this file exists to prevent: `tests/unit/test_cli_scan.py`,
`tests/unit/test_cli_scan_sca.py`, and `tests/unit/test_cli_baseline.py` all
invoke `linceo scan <category>`/`linceo baseline` through `CliRunner` with no
`--platform` flag, relying on `auto` resolving `local` — true on a
developer's laptop, and true on this project's own GitHub Actions runner
*only by accident*, because nothing in this repository's CI used to set a
recognized CI-platform sentinel. The moment `github_actions` became a real
`ContextProvider` (ADR §1, §10) and this project's own CI started dogfooding
`--platform auto` (`.github/workflows/ci.yml`), that accident stopped
holding: every job the test suite (`uv run pytest`) runs *inside* already
has `GITHUB_ACTIONS=true` set by the runner itself, so `auto` resolves
`github_actions` there — and `GitHubActionsContextProvider.resolve()` reads
the real `GITHUB_REPOSITORY`/`GITHUB_SHA` of *this* repository's own
checkout, not the throwaway git repository a test built under `tmp_path`,
with no error at all (both required variables are genuinely present on a
real runner). A test asserting `platform == "local"`, or expecting
`ContextResolutionError` from a deliberately non-git `tmp_path`, then either
fails loudly or — worse — passes for the wrong reason, quietly checking the
real linceo repository's own context instead of the fixture it built.

This mirrors the determinism principle ADR R3 already applies to the
system clock (no core module calls `datetime.now()` directly; `now` is
always threaded in explicitly): a test suite's own correctness must not
depend on which real machine or CI platform happens to run it. The fix is
the same shape here — every test in this package gets a clean slate for
every environment variable any reference `ContextProvider`/`PolicySource`
either reads or checks as its `auto`-detection sentinel, gathered from the
provider modules themselves (`ENV_VARS`, the sentinels,
`REMOTE_POLICY_ENV_VARS`) rather than a hand-copied literal list — the
exact kind of list that already drifted once (`test_cli_scan_platform.py`'s
own `_clean_azure_environment` predates `github_actions` and never learned
about `GITHUB_ACTIONS`). A test that needs one of these variables set
still does so explicitly, via `monkeypatch.setenv`, in its own body or its
own additional fixture — this only guarantees the starting point is always
clean, never that a test can't opt into a specific scenario.

Deliberately placed at `tests/unit/`, not the repository root: nothing in
`tests/integration/` (real tool binaries, ADR §11) exercises platform
detection this way, and those tests are meant to run against whatever real
environment they are invoked from in the first place.

A handful of test files (`test_cli_context.py`, `test_cli_scan_platform.py`,
`test_azure_devops_provider.py`, `test_github_actions_provider.py`) already
declare their own autouse fixture covering this same ground, for a file-local
reason (e.g. also clearing `BUILD_SOURCESDIRECTORY`/`GITHUB_WORKSPACE`, which
this fixture deliberately does not, since a provider *not* reading those is
exactly what those two files test). Autouse fixtures compose without
conflict — this one simply guarantees every other test file gets the same
guarantee without having to know to ask for it.
"""

from __future__ import annotations

import pytest

from linceo.providers.azure_devops import ENV_VARS as AZURE_DEVOPS_ENV_VARS
from linceo.providers.azure_devops import REMOTE_POLICY_ENV_VARS
from linceo.providers.detection import (
    AZURE_DEVOPS_SENTINEL_ENV_VAR,
    GITHUB_ACTIONS_SENTINEL_ENV_VAR,
)
from linceo.providers.github_actions import ENV_VARS as GITHUB_ACTIONS_ENV_VARS

#: Every environment variable a reference `ContextProvider`/`PolicySource`
#: reads, or `auto` detection checks as a platform sentinel — sourced from
#: the provider modules themselves so a future platform's own `ENV_VARS`
#: and sentinel are picked up here automatically the moment it registers
#: them, with nothing further to remember to update in this file.
KNOWN_CI_PLATFORM_ENV_VARS = (
    AZURE_DEVOPS_SENTINEL_ENV_VAR,
    GITHUB_ACTIONS_SENTINEL_ENV_VAR,
    *AZURE_DEVOPS_ENV_VARS,
    *REMOTE_POLICY_ENV_VARS,
    *GITHUB_ACTIONS_ENV_VARS,
)


@pytest.fixture(autouse=True)
def _hermetic_ci_platform_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear every known CI-platform environment variable before each unit test runs.

    Applies to every test under `tests/unit/`, with no opt-in required —
    see this module's own docstring for the incident this exists to catch
    at the source rather than one failing assertion at a time. A test that
    needs a specific variable set does so itself, afterward, via
    `monkeypatch.setenv` (its own fixture, or inline in the test body);
    this fixture only guarantees the environment it starts from is clean,
    the same guarantee `--platform local`'s absence used to get by luck.
    """
    for var in KNOWN_CI_PLATFORM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
