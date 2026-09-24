"""The one real remote-policy target this script exercises, and its degradation helpers.

Real, not invented: Azure DevOps organization `juandiego-13`, project
`fast_Api`, repository `linceo-policy`, document at `.devsecops/policy.toml`
— an already-working remote policy source, named directly by the project's
maintainer for this purpose. Never a secret itself; only the bearer token
that reads it is (ADR §9), and that value is read from `PAT_ENV_VAR`'s own
environment variable, never accepted as a script argument or written to
disk anywhere this module touches.

`cache_key` below reimplements the formula
`linceo.providers.azure_devops.AzureDevOpsPolicySource.cache_key` documents
in its own docstring verbatim (`sha256("{org}/{project}/{repo}/{path}")`) —
a public, stable, ADR-governed algorithm, not an internal format this
script reverse-engineers by inspection (contrast the Trivy `bbolt` case
this project already decided *not* to touch, ADR §10 amendment
2026-09-23). If that formula ever changes, `fabricate_cache` below breaks
loudly — the degraded run reports "no cache" instead of the fabricated one
being read — never silently.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

#: Real, working target (per the project maintainer, 2026-09-23) — not a
#: placeholder pending someone filling it in.
ORG_URL = "https://dev.azure.com/juandiego-13/"
PROJECT = "fast_Api"
REPOSITORY = "linceo-policy"
DOCUMENT_PATH = ".devsecops/policy.toml"

#: The one deliberately-never-resolving host this script points the
#: *installed-package* degraded cases at, instead of touching the real
#: host's network configuration (see `run.py`'s own module docstring for
#: why container-mode degradation uses `docker run --network none` instead,
#: a real network cut, while this mode only simulates one specific
#: endpoint being unreachable). `.invalid` is reserved by RFC 2606 to never
#: resolve — a fast, deterministic DNS failure, not a connection that hangs
#: until some timeout.
UNREACHABLE_ORG_URL = "https://policy.invalid/"

#: The environment variable this script reads the real PAT from — never a
#: `--token`/`--pat` argument (ADR §9: visible in `ps`, in shell history, in
#: any process listing; an environment variable set with `export` in the
#: operator's own shell is not). `run.py` never logs, prints, or otherwise
#: persists its value; it only forwards the *name* into a child process's
#: environment (`-e PAT_ENV_VAR` with no `=value` for `docker run`, the same
#: pattern `azure-pipelines/templates/linceo-scan.yml` already uses for a
#: real pipeline's own secret variables).
PAT_ENV_VAR = "LINCEO_E2E_AZURE_PAT"

#: `[remote_policy]` table this script writes into the generated sample
#: repository — referenced via `--config`, never the default
#: `.devsecops/config.toml` path, so the "no remote policy" cases in the
#: scan matrix are unaffected by its mere presence on disk.
REMOTE_POLICY_TOML = f"""version = 1

[remote_policy]
repository = "{REPOSITORY}"
project = "{PROJECT}"
path = "{DOCUMENT_PATH}"
token_env = "{PAT_ENV_VAR}"
"""

#: Fabricated cache content for the "cache present" degraded cases — a
#: single governed key (`banner`), deliberately distinctive, so a degraded
#: run's console report visibly proving this exact string is what confirms
#: the fabricated cache was actually read, not merely that the run fell
#: back to "local only" some other way.
FABRICATED_CACHE_BANNER = "e2e-verify fabricated cache entry"
FABRICATED_CACHE_CONTENT = f'banner = "{FABRICATED_CACHE_BANNER}"\n'


def pat_from_environment() -> str | None:
    """The real PAT, if the operator's own shell has it set — never read from an argument."""
    return os.environ.get(PAT_ENV_VAR) or None


def cache_key(*, org_url: str) -> str:
    """Reimplements `AzureDevOpsPolicySource.cache_key`'s own documented formula.

    `org_url` varies by case (the real org for the happy path and the
    container-mode degraded cases, `UNREACHABLE_ORG_URL` for the
    installed-mode degraded cases) — everything else is fixed, this
    script's one real target.
    """
    canonical = f"{org_url.rstrip('/')}/{PROJECT}/{REPOSITORY}/{DOCUMENT_PATH}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fabricate_cache(cache_dir: Path, *, org_url: str) -> None:
    """Write `FABRICATED_CACHE_CONTENT` at the path a real successful fetch would have used.

    Lets the "cache present" degraded cases run without ever needing a real
    successful fetch first — which matters because the degraded cases must
    run unconditionally, without `PAT_ENV_VAR` set (see `run.py`'s own
    case-gating). Permissions mirror `write_cached_policy`'s own
    owner-only default (ADR §9) — not load-bearing for a fabricated,
    non-secret value, but there is no reason for this script's own output
    to look laxer than what the real code path produces.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.chmod(0o700)
    path = cache_dir / f"{cache_key(org_url=org_url)}.toml"
    path.write_text(FABRICATED_CACHE_CONTENT, encoding="utf-8")
    path.chmod(0o600)
