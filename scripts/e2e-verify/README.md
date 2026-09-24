# End-to-end verification

Verifies linceo's real, published artifacts — a `uv tool install` from
PyPI, a `docker pull` of the published image, both tool-execution modes
against real binaries, a real network failure — everything the 791-test
unit suite and `pytest -m integration` cannot, because both of those run
against fakes or against binaries already on `PATH`, never against the
actual thing an adopter downloads.

Lives here, run by a person, on demand:

```bash
uv run scripts/e2e-verify/run.py
```

Not wired into `.github/workflows/release.yml` — that decision is
deliberately deferred until a few real runs show whether this is fast
enough to belong there.

## What it needs, and what it does instead when something is missing

**Nothing is required.** Every prerequisite below is checked once, up
front; missing one turns the cases that depend on it into a reported
*omission*, named with its reason — never a crashed run.

| Missing | What gets omitted |
|---|---|
| `docker` (binary absent, or daemon not answering) | every container-mode case — install/pull/scan cases in the *installed* mode, and the `installed`-mode degradation cases, still run |
| `LINCEO_E2E_AZURE_PAT` not set | only the "remote policy, happy path" scan-matrix cases (`scan-<category>-<mode>-remote`) — the degradation cases run regardless, by design (see below) |
| this linceo release predates `scan iac` (< 0.9.0) | only the `iac` row of the scan matrix, reported as "not available in this release" |
| `checkov` not on `PATH` in this environment | not an omission — a real, captured `SKIPPED` result from the tool itself, exactly what an adopter who has not installed Checkov yet would see |

`git` and `uv` are the only two hard requirements — both already required
to work on this repository at all.

## The one real credential this script can use

The Azure DevOps organization this script's remote-policy cases point at
is real: `juandiego-13`, project `fast_Api`, repository `linceo-policy`,
document at `.devsecops/policy.toml` — already working, per the project
maintainer. Reading it for real requires a Personal Access Token with
`Code (Read)` on that repository, exported as:

```bash
export LINCEO_E2E_AZURE_PAT=...
```

Never passed as a script argument (would appear in `ps`, in shell
history — ADR §9); read from the environment once, forwarded into a child
process's own environment (`-e LINCEO_E2E_AZURE_PAT` with no `=value` for
the container-mode cases), never logged, never written to disk.

**The degradation cases (`remote-policy-degraded-*`) never need this
token, on purpose — they always run.** A verification script that requires
a credential to prove what happens *without* one is not a script anyone
would trust the failure path of. They simulate "network unreachable" two
different ways, honestly labeled as different in `cases/`:

- **Container mode:** `docker run --network none` — a real, complete
  network cut, no packets leave at all.
- **Installed-package mode:** this script never touches the host's own
  network configuration (that would be invasive for something meant to be
  run casually). Instead it points `SYSTEM_COLLECTIONURI` at
  `https://policy.invalid/` — a hostname RFC 2606 reserves to never
  resolve — which fails fast and deterministically without changing
  anything about the machine it runs on.

Both a "cache present" and a "cache absent" variant run for each — the
"present" one by writing a fabricated (but validly-shaped) cached document
directly at the path a real successful fetch would have used
(`azure_policy.fabricate_cache`, which reimplements
`AzureDevOpsPolicySource.cache_key`'s own documented formula — if that
formula ever changes, this fabrication breaks loudly, a cache miss, never
silently).

## Output

- **`cases/*.md`** — one normalized snippet per case, **versioned**. This
  is the evidence that README.md/docs/ADOPTION.md's own examples still
  match the real binary; its diff between two runs against two different
  releases is itself useful (a changed reporter format shows up here as a
  diff, not as a surprise later). Never auto-pasted into those documents —
  a person reviews and decides where each one goes. **Never carries a
  measured wall-clock number** — no `Duration`, no per-sample timing, no
  median — on purpose: those change on every single run regardless of
  anything about linceo, so keeping them here would turn every diff into
  "this run was 40ms slower" instead of "the reporter changed", exactly
  the failure mode this file exists to avoid. `container-startup.md`
  shows one real sample's actual output (the version string) for this
  reason — never the timing table its own median is computed from.
  `image_size_bytes` is the one number kept here regardless: not a
  measurement of *this run*, a property of *the release being pulled*.
- **`out/manifest.json`** — everything raw: absolute paths, real
  timestamps, complete stdout/stderr, and every measured duration this
  script took — total, per-case, and (for container-startup) every
  individual sample plus the median/min/max computed from them.
  Gitignored — different on every run by construction, so versioning it
  would be pure diff noise; this is where a real timing number belongs
  instead of `cases/*.md`.
- **`out/ad-hoc/`** — where `--repo <path>` writes instead of `cases/`,
  because a real repository is never reproducible run to run (see
  `sample_repo.py`'s own docstring) and its output is for your own
  exploration, never for pasting into documentation.

## What is deliberately *not* measured further

The timing breakdown separates a scan's total wall time from the tool
subprocess's own time (already in the JSON report's
`executions[].started_at`/`finished_at` — no new instrumentation needed).
"linceo's own overhead" is reported as the remainder of that subtraction,
labeled as such — nothing in the current code separates config loading,
normalization, dedup, or gate evaluation into their own measured phases,
so this script does not invent numbers for them.

## The sample repository

Generated fresh on every run, from the small, disposable, synthetic tree
checked in at `fixtures/sample-repo/` — one real finding per category
(`CKV2_AWS_61`, `CVE-2023-37920`, a synthetic AWS-key-shaped string for
gitleaks), each already validated against the real pinned tool versions
this project tests against. See `sample_repo.py`'s own docstring for why
generated, not a real repository pointed at by a path.
