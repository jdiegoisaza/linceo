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
pre-fetched at build time, so a scan runs fully offline by default.

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

### `pip install` (local development, bring-your-own tool binaries)

```bash
pip install linceo
```

Requires Python 3.11 or later. Gitleaks and Trivy are not bundled via
PyPI — install them yourself and run `linceo doctor` to confirm each one
is on `PATH`, at a compatible version, and (for Trivy) how old its
vulnerability database is; a missing or incompatible tool gets an
actionable install/upgrade hint printed right there.

## Development

```bash
uv sync
uv run linceo --version
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full set of task commands,
and [`AGENTS.md`](AGENTS.md) for repository conventions and hard rules.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
