# linceo

A DevSecOps tool orchestrator: it runs one or more security tools against a
workspace, normalizes their output into a single `Finding` model, and
produces one verdict — one exit code — for the entire run, instead of one
report per tool that a pipeline has to reconcile by hand.

The full architecture and scope of the current version are recorded in
[`docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`](docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md).
That document is the contract for this project; anything below is a summary
of it, not a replacement.

## Status

Pre-release (`0.1.0.dev0`). The engine, all three reference tool
integrations across all three categories (Gitleaks for `secrets`, Trivy for
`sca`, Checkov for `iac`), the reference context providers (`local`,
`azure_devops`, `github_actions`), console/JSON/SARIF reporting, the
`doctor` command, and the reference container image are in place. See the
ADR's build order for what ships next.

## Non-negotiable constraints

- Runs the same way regardless of which CI platform invokes it.
- The happy path makes no network call.
- No shared state or backend of its own: one run is one self-contained
  execution.
- The container image is the primary distribution unit; PyPI supports local
  development, bring-your-own tool binaries.
- No client-specific configuration ever lives in this repository.

> **About the output blocks in this document.** Every one below marked
> **source:** is not hand-written — it is copied verbatim from a real,
> captured snippet under
> [`scripts/e2e-verify/cases/`](scripts/e2e-verify/cases/), the versioned
> evidence that this file still matches what the real binary produces
> (`scripts/e2e-verify/README.md`). The day the reporter's format changes,
> that is where to regenerate the example from — `uv run
> scripts/e2e-verify/run.py` — never by editing the block here by hand.

## Quickstart

Nothing beyond Docker, against a real repository, in two commands:

```bash
docker pull ghcr.io/jdiegoisaza/linceo:latest
docker run --rm -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan secrets
```

Real output, against a repository with one real secret finding (**source:**
[`scripts/e2e-verify/cases/scan-secrets-container-local.md`](scripts/e2e-verify/cases/scan-secrets-container-local.md)):

```
+--------+
| linceo |
+--------+

Run <RUN_ID> — platform=local repository=workspace commit=<COMMIT>
Status: completed
Severity map: v1

Executions:
  - gitleaks 8.30.1 [secrets]: completed (1 findings)

secrets:
  +----------+------------------+-------------+----------+-------------+
  | SEVERITY | ID               | LOCATION    | TOOL     | FP          |
  +==========+==================+=============+==========+=============+
  | HIGH     | aws-access-token | config.py:9 | gitleaks | v1:f76ea3ac |
  +----------+------------------+-------------+----------+-------------+

Suppressed by policy: 0
Expired exclusions: 0

Severity overrides applied: 0

Gate: not enforced (no thresholds configured). With --fail-on high this run would have failed: secrets: 1 HIGH
```

`<RUN_ID>` and `<COMMIT>` are placeholders, not literal output — the
captured snippet normalizes both (they differ on every real run) so its own
diff, versioned alongside this file, stays meaningful (`scripts/e2e-verify/normalize.py`).
Everything else above — the table, the columns, the gate verdict line — is
exactly what a real run prints.

`scan sca` and `scan iac` work the same way — a different tool runs behind
them (Trivy, Checkov) — but `iac` also adds one column, `RESOURCE`
(ADR §5 amendment, 2026-09-21: a Terraform resource, not just a file and
line, is what identifies an iac finding). Real output, one Terraform
resource with several real misconfigurations (**source:**
[`scripts/e2e-verify/cases/scan-iac-container-local.md`](scripts/e2e-verify/cases/scan-iac-container-local.md),
truncated here — the marked rows are cut, nothing else is edited):

```
iac:
  +----------+-------------+-----------+---------+-------------+--------------------+
  | SEVERITY | ID          | LOCATION  | TOOL    | FP          | RESOURCE           |
  +==========+=============+===========+=========+=============+====================+
  | MEDIUM   | CKV2_AWS_6  | main.tf:4 | checkov | v1:01ed8bbe | aws_s3_bucket.logs |
  | MEDIUM   | CKV_AWS_145 | main.tf:4 | checkov | v1:0eccd1a4 | aws_s3_bucket.logs |
  [... 4 more rows cut — full 7-row table in the source snippet above ...]
  +----------+-------------+-----------+---------+-------------+--------------------+
```

Seven findings from one resource, one file, one Terraform block — this is
also why `iac` is the slowest of the three categories (see below):
Checkov runs many independent rule checks against every resource it graphs,
where Gitleaks and Trivy each run one pass over the input.

### What it costs, measured on a real agent

| Step | Measured |
|---|---|
| Container startup (fixed cost, `docker run --rm <image> --version`) | ~0.87s |
| `scan secrets` | ~2.2s |
| `scan sca` | ~1.5s |
| `scan iac` | ~10.3s |

Measured on a real Azure Pipelines agent (two separate runs), not a local
dev machine — the absolute numbers will move with the hardware; the
relative gap between `iac` and the other two is the number that matters.

**`scan iac` is not slow by accident — it is the real cost of Checkov, and
it is worth knowing before a pipeline with all three categories in
parallel ends up waiting on it.** Gitleaks and Trivy are native Go
binaries with no interpreter to start; Checkov is Python, running from its
own isolated venv (ADR §10), and its graph-analysis engine
(`numpy`/`networkx`/`rustworkx`) starts up and builds a graph even for one
small file. ~5x the other two's cost is the accepted, understood price of
that architecture, not a regression to chase — see the ADR §10 amendment
(2026-09-21) for the full accounting of what that venv actually contains.

## Installation

### Container image (primary distribution, ADR §4/R4)

The container image is the unit of compatibility between the orchestrator
and the exact tool versions it invokes: it bundles pinned, checksum-verified
builds of Gitleaks and Trivy, Checkov in its own isolated environment
(ADR §10, §8.3), plus Trivy's vulnerability database pre-fetched at build
time, so a scan runs fully offline by default. It also installs the
`linceo[remote-config]` extra (see "Remote policy" below) — being the
primary distribution vehicle (ADR R4) is exactly why remote policy
resolution, a pipeline feature, needs to work out of the box here;
`pip install linceo` on its own still gains no HTTP client at all (ADR R2).

Pull a published release — built and pushed by
[`.github/workflows/release.yml`](.github/workflows/release.yml), no
authentication needed (see [`docs/RELEASING.md`](docs/RELEASING.md)):

```bash
docker pull ghcr.io/jdiegoisaza/linceo:latest    # or a specific version, e.g. :0.2.0
```

**The image is large — about 2.37 GB — because of what R2 (offline by
default) actually costs, not because of bloat.** Measured breakdown (`docker
history`, ADR §10 amendment for the full analysis):

| Layer | Size | What it is |
|---|---|---|
| Trivy's vulnerability database | 1.4 GB | Baked in at build time so a scan never touches the network (ADR §5). Most of it is OS-package coverage `trivy fs` (the only mode this project uses, ADR §10) never queries — see the ADR amendment for why that isn't easily trimmed. |
| Checkov's isolated venv | 196 MB | Its graph-analysis engine and AWS IAM-policy checks — used by the frameworks this integration keeps, not bloat from the ones it skips. |
| Gitleaks + Trivy binaries | 190 MB | The two Go binaries themselves. |
| `git` (+ its Perl dependency) | ~114 MB | Debian's `git` package hard-depends on Perl; there is no lighter split package. |

Expect that on the first `docker pull`, not a slow subsequent one — it's
worth knowing before you budget CI cache space or a cold-start pull, not
after.

Run it against a workspace by mounting it and appending a subcommand —
exactly as you would to the `linceo` binary itself:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan secrets
docker run --rm -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan sca --fail-on high
docker run --rm -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan iac
docker run --rm ghcr.io/jdiegoisaza/linceo doctor
```

`docker run --rm ghcr.io/jdiegoisaza/linceo` alone (no subcommand) prints
`--help`. The image runs as a fixed non-root user (uid/gid `1000`); if the
mounted workspace's files are owned by a different uid on the host, add
`--user "$(id -u):$(id -g)"` to the `docker run` invocation.

To build it yourself instead — for local development, or to reproduce a
published image bit-for-bit from source — from the repository root:

```bash
docker build \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t linceo:local .
```

(swap `ghcr.io/jdiegoisaza/linceo` for `linceo:local` in the `docker run`
examples above). Omitting `LINCEO_VERSION` here is expected for a local
build — it's the release workflow that passes the real one; see
`docs/RELEASING.md`, "Container image".

Which exact versions of Gitleaks, Trivy, and Checkov — and how old Trivy's
vulnerability database is — a given image carries is queryable two ways,
and both describe the same pinned reality (see `Dockerfile` and
`src/linceo/cli/doctor.py`):

- **Without starting the container:** `docker inspect
  ghcr.io/jdiegoisaza/linceo:latest` (or `linceo:local`, or `skopeo
  inspect` against any pushed image) shows the OCI labels the build
  embeds — `dev.linceo.tool.gitleaks.version`, `dev.linceo.tool.trivy.version`,
  `dev.linceo.tool.checkov.version`, `dev.linceo.trivy-db.built-at`, plus
  the standard `org.opencontainers.image.*` set.
- **From inside it:** `linceo doctor` — the same command works identically
  for a `pip install`ed, bring-your-own-tool setup. Real output (**source:**
  [`scripts/e2e-verify/cases/doctor-container.md`](scripts/e2e-verify/cases/doctor-container.md)):

  ```
  gitleaks (secrets):
    binary:  gitleaks — found on PATH
    version: 8.30.1 (supported: >=8.18,<9) — OK
    data sources: none declared

  trivy (sca):
    binary:  trivy — found on PATH
    version: 0.74.0 (supported: >=0.50,<1) — OK
    data sources:
      - trivy-vulnerability-db: version 2, built <today-1d> (1 days old) — OK

  checkov (iac):
    binary:  checkov — found on PATH
    version: 3.3.19 (supported: >=3.2,<4) — OK
    data sources: none declared

  All configured tools are available and within their supported range.
  ```

  (`<today-1d>` stands in for a real calendar date, normalized because it
  moves with the day the image was built relative to when it's pulled —
  everything else is verbatim.)

#### Context providers inside the container: which environment variables cross the boundary

`docker run` does not inherit the invoking process's environment — nothing
reaches `linceo` inside the container unless passed explicitly with `-e
VAR` (or `--env-file`). Which variables matter depends on `--platform` (or
its `auto` detection, ADR §4 R1):

- **`local`** (the default outside any recognized CI platform) needs
  nothing extra: it resolves everything from the mounted git checkout
  itself (`git rev-parse`, `git remote get-url origin`) — no environment
  variable read at all.
- **`azure_devops`** needs the Azure Pipelines agent's own variables
  forwarded explicitly — all standard, non-secret predefined variables
  (canonical list: `src/linceo/providers/azure_devops.py`, `ENV_VARS`,
  plus the `auto`-detection sentinel below):

  | Variable | Required? | Resolves |
  |---|---|---|
  | `TF_BUILD` | — | `auto` detection's own sentinel (`linceo.providers.detection`) |
  | `BUILD_REPOSITORY_NAME` | required | `repository` |
  | `BUILD_SOURCEVERSION` | required | `commit` |
  | `BUILD_SOURCEBRANCH` | optional | `branch` (non-PR trigger) |
  | `SYSTEM_PULLREQUEST_SOURCEBRANCH` | optional | `branch` (PR trigger) |
  | `SYSTEM_PULLREQUEST_PULLREQUESTID` | optional | `pull_request_id` (Azure DevOps' own internal id) |
  | `SYSTEM_PULLREQUEST_PULLREQUESTNUMBER` | optional | `pull_request_id` (GitHub-backed repository, human-facing number — preferred over the internal id when both are set) |
  | `BUILD_BUILDID` | optional | `build_id` |
  | `BUILD_REPOSITORY_URI` | optional | `source_url` |

  ```bash
  docker run --rm \
    -e TF_BUILD -e BUILD_REPOSITORY_NAME -e BUILD_SOURCEVERSION \
    -e BUILD_SOURCEBRANCH -e SYSTEM_PULLREQUEST_SOURCEBRANCH \
    -e SYSTEM_PULLREQUEST_PULLREQUESTID -e SYSTEM_PULLREQUEST_PULLREQUESTNUMBER \
    -e BUILD_BUILDID -e BUILD_REPOSITORY_URI \
    -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan secrets
  ```

  The reference `azure-pipelines/templates/linceo-scan.yml` already does
  this by default (see `docs/ADOPTION.md`) — nothing to configure if you
  use it. The snippet above only matters if you invoke the image directly,
  outside that template.

  **Deliberately an explicit allowlist, never the whole environment**: a
  real Azure Pipelines job's process environment routinely carries far
  more than this — feed credentials, mapped secret variables, other
  steps' exports — none of which `linceo` has any business seeing inside
  the container.

  **Diagnosing this from inside a container**: `docker run --rm -e
  TF_BUILD -e BUILD_REPOSITORY_NAME ... ghcr.io/jdiegoisaza/linceo
  context` shows exactly which platform got selected, why, and the value
  (or absence) of every variable above — run it before a real scan if
  `auto` seems to be picking the wrong platform.
- **`github_actions`** needs the runner's own default variables forwarded
  explicitly — every one this project reads (canonical list:
  `src/linceo/providers/github_actions.py`, `ENV_VARS`, plus the
  `auto`-detection sentinel below):

  | Variable | Required? | Resolves |
  |---|---|---|
  | `GITHUB_ACTIONS` | — | `auto` detection's own sentinel (`linceo.providers.detection`) |
  | `GITHUB_REPOSITORY` | required | `repository` |
  | `GITHUB_SHA` | required | `commit` — the ephemeral merge commit GitHub Actions creates on a `pull_request` trigger, used as-is (see the module's docstring for why) |
  | `GITHUB_REF` | optional | `branch`/tag (non-PR trigger) |
  | `GITHUB_HEAD_REF` | optional | `branch` (PR trigger) |
  | `GITHUB_RUN_ID` | optional | `build_id` |
  | `GITHUB_SERVER_URL` | optional | `source_url` (combined with `GITHUB_REPOSITORY`) |

  ```bash
  docker run --rm \
    -e GITHUB_ACTIONS -e GITHUB_REPOSITORY -e GITHUB_SHA -e GITHUB_REF \
    -e GITHUB_HEAD_REF -e GITHUB_RUN_ID -e GITHUB_SERVER_URL \
    -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan secrets
  ```

  These are GitHub Actions' own default environment variables — every job
  already has them, with nothing to configure, unlike Azure Pipelines'
  agent-specific predefined variables above; the snippet only matters when
  invoking the image directly inside a container-based step.

  **Diagnosing this from inside a container**: `docker run --rm -e
  GITHUB_ACTIONS -e GITHUB_REPOSITORY ... ghcr.io/jdiegoisaza/linceo
  context` shows the same breakdown as for `azure_devops` above.

### `pip install` (local development, bring-your-own tool binaries)

```bash
pip install linceo
```

Requires Python 3.11 or later. Gitleaks, Trivy, and Checkov are not bundled
via PyPI — install them yourself and run `linceo doctor` to confirm each
one is on `PATH`, at a compatible version, and (for Trivy) how old its
vulnerability database is; a missing or incompatible tool gets an
actionable install/upgrade hint printed right there.

### Remote policy (optional, ADR R2, §8.4)

Thresholds, per-tool configuration, and the report banner (see below) can
be governed centrally instead of per-repository — the case where security
maintains one policy document and every pipeline inherits it. Declare it
in the scanned repository's own `.devsecops/config.toml` (never in this
repository, R5):

```toml
[remote_policy]
repository = "security-baseline"   # name only, never a URL
# path, project, token_env are all optional — see the ADR amendment for defaults
```

Fetching one requires the `linceo[remote-config]` extra — already bundled
in the reference container image (ADR R4: the primary distribution
vehicle, and remote policy resolution is a pipeline feature). Only a
`pip install`ed `linceo` needs it added explicitly:

```bash
pip install 'linceo[remote-config]'
```

Today's one reference source is Azure DevOps
(`linceo.providers.azure_devops.AzureDevOpsPolicySource`): it resolves the
organization and project from the same Azure Pipelines variables
`azure_devops` context resolution already reads
(`SYSTEM_COLLECTIONURI`/`SYSTEM_TEAMPROJECT`), and authenticates via a
bearer token read from the environment variable `token_env` names — never a
value in the file itself (ADR §9). `token_env` defaults to
`SYSTEM_ACCESSTOKEN` — the running build's own OAuth identity, which the
reference `azure-pipelines/templates/linceo-scan.yml` already maps and
forwards by default, so the common case (a policy repository in the same
organization) needs nothing declared here at all; a repository outside
that organization needs a Personal Access Token instead, via a custom
`token_env` and the template's own `policyRepoToken` parameter — see
`docs/ADOPTION.md`, "Fuente remota de la política", for both modes with
examples. `[[exclusions]]`, `[[skipped_tools]]`, and `[[severity_overrides]]`
stay local-only always; a remote document declaring any of the three is a
configuration error, not a silently-ignored one.

A failed fetch never fails a run: it falls back to the last successfully
fetched copy (cached under `~/.cache/linceo/remote-policy` by default, or
`$LINCEO_POLICY_CACHE_DIR`, owner-only permissions, keyed by the source's
own resolved organization/project/repository/path so two tenants of a
shared runner never collide), or to the local document alone if there is no
cache yet — always declared prominently in the report, with the cached
copy's own age, the same `stale_data` principle §5 already applies to a
tool's own vulnerability database. That fallback only ever has something to
use if the cache directory itself survives between runs — the reference
template mounts a persistent one by default (`docs/ADOPTION.md`, "La caché
local, y por qué la plantilla monta un volumen para ella"); a bare
`docker run --rm` with no such mount starts every run with an empty cache.
A 404 from Azure DevOps is reported with all four of its possible causes
named explicitly (repository, path, branch, permissions — see the same
doc, "Diagnosticando un 404"), never just the bare HTTP status. The bearer
token itself is never logged,
cached, or otherwise persisted (ADR §9).

Both fallback paths, captured against a real unreachable Azure DevOps
endpoint (`--network none`, no PAT): with a cache to fall back to
(**source:** [`scripts/e2e-verify/cases/remote-policy-degraded-with-cache-container.md`](scripts/e2e-verify/cases/remote-policy-degraded-with-cache-container.md)) —

```
Remote policy: linceo-policy/.devsecops/policy.toml — WARN: fetch failed (failed to fetch linceo-policy/.devsecops/policy.toml from Azure DevOps: [Errno -3] Temporary failure in name resolution), using a cached copy from <TIMESTAMP> (0 days old) [OK]
```

— and with none (**source:** [`scripts/e2e-verify/cases/remote-policy-degraded-no-cache-container.md`](scripts/e2e-verify/cases/remote-policy-degraded-no-cache-container.md)):

```
Remote policy: linceo-policy/.devsecops/policy.toml — WARN: unreachable and no cached copy (failed to fetch linceo-policy/.devsecops/policy.toml from Azure DevOps: [Errno -3] Temporary failure in name resolution); this run's thresholds and tool configuration are the local document alone
```

Both runs still complete and still gate on whatever thresholds end up in
effect — a remote policy source degrading is never, on its own, a reason to
fail the run. The happy-path fetch (a reachable organization, a valid
token) is exercised by this project's own Azure Pipelines CI against the
real `linceo-policy` repository rather than by `scripts/e2e-verify/`, which
deliberately never carries a credential (ADR §9) — so unlike every other
block on this page, that specific case has no snippet under
`scripts/e2e-verify/cases/` to link to here.

### Report banner (ADR §7, §8.4)

The console report opens with a one-line ASCII box naming the product —
`"linceo"` unless a policy document overrides it:

```toml
banner = "ACME Corp Security Gate"
```

Governed, like `[thresholds]`/`[tool_defaults]`: it can be set locally, or
centrally in a remote policy document (see above), where it replaces the
local one entirely for every pipeline that inherits it — never a
per-invocation CLI flag or environment variable, since a name an
organization picks a few times a year has no use for one. Constrained to
printable ASCII (0x20-0x7E) and at most 72 characters — no control
characters, no ANSI escape sequences, no embedded newline, since an
org-wide remote document's content reaches every consuming pipeline's own
terminal verbatim. An invalid *local* banner is a configuration error like
any other; an invalid *remote* one degrades to the cached or local banner
instead of failing every pipeline in the organization over a cosmetic
mistake — see the ADR amendment for the full reasoning behind that
asymmetry. Console-only: `--max-rows`'s own reasoning applies here too, so
neither the JSON report nor SARIF ever carries it.

## Development

```bash
uv sync
uv run linceo --version
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full set of task commands,
and [`AGENTS.md`](AGENTS.md) for repository conventions and hard rules.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
