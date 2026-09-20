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

Pre-release (`0.1.0.dev0`). The engine, both v0.1 reference tool
integrations (Gitleaks, Trivy), both reference context providers (`local`,
`azure_devops`), console/JSON/SARIF reporting, the `doctor` command, and
the reference container image are in place. See the ADR's build order for
what ships next.

## Non-negotiable constraints

- Runs the same way regardless of which CI platform invokes it.
- The happy path makes no network call.
- No shared state or backend of its own: one run is one self-contained
  execution.
- The container image is the primary distribution unit; PyPI supports local
  development, bring-your-own tool binaries.
- No client-specific configuration ever lives in this repository.

## Installation

### Container image (primary distribution, ADR §4/R4)

The container image is the unit of compatibility between the orchestrator
and the exact tool versions it invokes: it bundles pinned, checksum-verified
builds of Gitleaks and Trivy, plus Trivy's vulnerability database
pre-fetched at build time, so a scan runs fully offline by default. It also
installs the `linceo[remote-config]` extra (see "Remote policy" below) —
being the primary distribution vehicle (ADR R4) is exactly why remote
policy resolution, a pipeline feature, needs to work out of the box here;
`pip install linceo` on its own still gains no HTTP client at all (ADR R2).

Pull a published release — built and pushed by
[`.github/workflows/release.yml`](.github/workflows/release.yml), no
authentication needed (see [`docs/RELEASING.md`](docs/RELEASING.md)):

```bash
docker pull ghcr.io/jdiegoisaza/linceo:latest    # or a specific version, e.g. :0.2.0
```

Run it against a workspace by mounting it and appending a subcommand —
exactly as you would to the `linceo` binary itself:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan secrets
docker run --rm -v "$PWD:/workspace" ghcr.io/jdiegoisaza/linceo scan sca --fail-on high
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

Which exact versions of Gitleaks and Trivy — and how old its vulnerability
database is — a given image carries is queryable two ways, and both
describe the same pinned reality (see `Dockerfile` and
`src/linceo/cli/doctor.py`):

- **Without starting the container:** `docker inspect
  ghcr.io/jdiegoisaza/linceo:latest` (or `linceo:local`, or `skopeo
  inspect` against any pushed image) shows the OCI labels the build
  embeds — `dev.linceo.tool.gitleaks.version`, `dev.linceo.tool.trivy.version`,
  `dev.linceo.trivy-db.built-at`, plus the standard `org.opencontainers.image.*`
  set.
- **From inside it:** `linceo doctor` (see below) — the same command works
  identically for a `pip install`ed, bring-your-own-tool setup.

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

### `pip install` (local development, bring-your-own tool binaries)

```bash
pip install linceo
```

Requires Python 3.11 or later. Gitleaks and Trivy are not bundled via
PyPI — install them yourself and run `linceo doctor` to confirm each one
is on `PATH`, at a compatible version, and (for Trivy) how old its
vulnerability database is; a missing or incompatible tool gets an
actionable install/upgrade hint printed right there.

### Remote policy (optional, ADR R2, §8.4)

Thresholds and per-tool configuration can be governed centrally instead of
per-repository — the case where security maintains one policy document and
every pipeline inherits it. Declare it in the scanned repository's own
`.devsecops/config.toml` (never in this repository, R5):

```toml
[remote_policy]
repository = "security-baseline"   # name only, never a URL
# path, project, token_env are all optional — see the ADR amendment for defaults
```

Fetching one requires the `linceo[remote-config]` extra:

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
examples. `[[exclusions]]` and `[[skipped_tools]]` stay local-only always;
a remote document declaring either is a configuration error, not a
silently-ignored one.

A failed fetch never fails a run: it falls back to the last successfully
fetched copy (cached under `~/.cache/linceo/remote-policy` by default, or
`$LINCEO_POLICY_CACHE_DIR`, owner-only permissions, keyed by the source's
own resolved organization/project/repository/path so two tenants of a
shared runner never collide), or to the local document alone if there is no
cache yet — always declared prominently in the report, with the cached
copy's own age, the same `stale_data` principle §5 already applies to a
tool's own vulnerability database. The bearer token itself is never logged,
cached, or otherwise persisted (ADR §9).

## Development

```bash
uv sync
uv run linceo --version
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full set of task commands,
and [`AGENTS.md`](AGENTS.md) for repository conventions and hard rules.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
