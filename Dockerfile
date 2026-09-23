# syntax=docker/dockerfile:1
#
# linceo reference container image (ADR §4/R4 — "el contenedor de imagen
# como vía de distribución principal"). This is the unit of compatibility
# between the orchestrator and the exact tool versions it invokes: the
# image, not the operator's own PATH, decides which Gitleaks, Trivy, and
# Checkov build actually runs.
#
# Five stages:
#   1. python-build  — builds the linceo wheel with uv and installs it,
#      with no dev dependencies, into a throwaway venv.
#   2. checkov-build — installs checkov into its *own* venv, entirely
#      separate from linceo's own (AGENTS.md §8.3): checkov is a bundled
#      external tool, like Gitleaks/Trivy, not a linceo dependency — its
#      ~220MB dependency tree must never enter linceo's installed
#      environment.
#   3. tools         — downloads Gitleaks and Trivy, checksum-verifies each
#      against a value copied from that release's own published checksums
#      file, then bakes Trivy's vulnerability database in at build time.
#   4. final         — assembles the outputs of the three stages above onto
#      a minimal Python base, as a non-root user, with nothing left over
#      from any build stage (no uv, no curl, no build tooling).
#
# Build (from the repository root):
#
#   docker build \
#     --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     --build-arg VCS_REF="$(git rev-parse HEAD)" \
#     -t linceo:local .
#
# `BUILD_DATE`/`VCS_REF` are metadata only (OCI labels, below) — omitting
# them still produces a working image, just with less precise provenance.
# `LINCEO_VERSION` defaults to this project's pre-release placeholder; the
# release workflow (.github/workflows/release.yml) is what passes the real
# one, derived from the git tag — see docs/RELEASING.md. See README.md,
# "Container image", for how to run it.

# ---------------------------------------------------------------------------
# Base images, pinned by digest (ADR R4: "nunca por tag") — a tag can move
# under a fixed Dockerfile; a digest cannot. Both resolved from the
# upstream registries' own manifest indexes (multi-arch: Docker picks the
# right platform's manifest under this same digest automatically).
#   python:3.12-slim  -> docker.io/library/python:3.12-slim
#   debian:bookworm-slim -> docker.io/library/debian:bookworm-slim
# ---------------------------------------------------------------------------
ARG PYTHON_BASE_DIGEST=sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
ARG DEBIAN_BASE_DIGEST=sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Tool versions this image pins (ADR R4: "anclados a una versión
# específica") — the exact versions each adapter's `SUPPORTED_VERSION_RANGE`
# was built and golden-fixture-tested against
# (src/linceo/adapters/gitleaks.py, src/linceo/adapters/trivy.py,
# src/linceo/adapters/checkov.py).
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG CHECKOV_VERSION=3.3.19
ARG UV_VERSION=0.12.15

# Derived from the release tag by CI (.github/workflows/release.yml),
# never hand-edited — see docs/RELEASING.md. Declared here, before the
# first FROM, so both `python-build` (bakes it into the installed wheel's
# own version metadata, since that stage's build context carries no `.git`
# for hatch-vcs to read) and `final` (OCI label) resolve the exact same
# value.
#
# The literal default below is this project's own pre-release placeholder
# — the exact same one hatch-vcs itself falls back to
# (`[tool.hatch.version.raw-options].fallback_version` in pyproject.toml)
# when no git tag is in scope, so a local `docker build` with no override
# behaves exactly like a local `uv build` with no tag in scope, the same
# fallback either way rather than a second, independently invented one.
# It is still a second literal, not a computed reference to the first —
# Docker has no mechanism for an `ARG` default to read another file at
# build time — so it is not "derived from" pyproject.toml so much as
# "asserted equal to it": `tests/unit/test_dockerfile_version.py` fails
# the moment the two drift apart, which is what actually keeps this
# honest, not the comment you are reading right now.
ARG LINCEO_VERSION=0.1.0.dev0

# ---------------------------------------------------------------------------
# Stage: python-build — build the linceo wheel and install it, with no dev
# dependencies, into a standalone venv. No `--platform=$BUILDPLATFORM`
# shortcut here on purpose: the venv this stage produces embeds a
# reference to *this stage's own* Python interpreter, so it must be built
# for the same target platform the final image ships as.
# ---------------------------------------------------------------------------
FROM python:3.12-slim@${PYTHON_BASE_DIGEST} AS python-build

ARG UV_VERSION
ARG LINCEO_VERSION
ENV PIP_NO_CACHE_DIR=1 \
    UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src/ src/

# `uv build` (not `uv sync`) on purpose: a built wheel carries only
# `[project.dependencies]` — never the `dev` dependency-group uv.lock also
# resolves — so installing *that* into a fresh venv is what actually keeps
# linting/testing tooling out of the shipped image, the same thing this
# project's own CI verifies against a clean environment
# (.github/workflows/ci.yml, "Install the built wheel into a clean
# environment").
#
# `SETUPTOOLS_SCM_PRETEND_VERSION`: this build context carries no `.git`
# (only the files COPYed above), so hatch-vcs — the same version source
# `uv build` uses outside this image, see pyproject.toml — would have no
# tag to read here and would always fall back to the placeholder version.
# Pinning it to `LINCEO_VERSION` explicitly is what makes `linceo
# --version` inside the running container agree with the image's own
# `org.opencontainers.image.version` label (`final` stage, below) instead
# of silently disagreeing with it on every real release. The plain
# (package-name-less) form is what hatch-vcs actually honors here — its
# per-package `_FOR_LINCEO` variant is a setuptools-scm feature hatch-vcs
# does not forward the distribution name for, verified empirically against
# this exact build context; safe to rely on regardless, since this
# `uv build` only ever builds the one package in it.
#
# `[remote-config]`: installed into the image on purpose, not left to
# whoever runs it (ADR R2, §8.4). R4 makes the container image the primary
# distribution vehicle, and remote policy resolution is a *pipeline*
# feature — the container is exactly where a pipeline runs it. R2's own
# invariant is unaffected by this: it governs the base *wheel* built above
# (`uv build --wheel`, no extras — `pip install linceo` alone still gains
# no HTTP client), not what a downstream distribution of that wheel chooses
# to bundle. Omitting this was a real bug, not a hypothetical one: a
# `[remote_policy]`-declaring pipeline running the reference image degraded
# to `unavailable` on every single run, unconditionally, with a WARN whose
# own suggested fix (`pip install 'linceo[remote-config]'`) cannot even be
# carried out inside this image (no writable venv for an unprivileged
# `USER 1000:1000` to install into, and no expectation that an operator
# ever shells into a running container to begin with). `set -- /dist/*.whl`
# first, rather than inlining the glob into the extras expression
# directly: `/dist/*.whl[remote-config]` would hand the shell a
# bracket-expression glob instead of a plain suffix, matching some
# unrelated single character instead of appending the extras marker to the
# resolved filename. `$1` is exactly the one wheel `uv build` above always
# produces for this one package.
RUN SETUPTOOLS_SCM_PRETEND_VERSION="${LINCEO_VERSION}" \
      uv build --wheel --out-dir /dist \
    && uv venv --python python3.12 /opt/linceo/venv \
    && set -- /dist/*.whl \
    && uv pip install --python /opt/linceo/venv/bin/python "${1}[remote-config]"

# ---------------------------------------------------------------------------
# Stage: checkov-build — install checkov into its *own* venv, entirely
# separate from `/opt/linceo/venv` above (AGENTS.md §8.3: Typer is the base
# package's only third-party dependency — checkov's own dependency tree,
# confirmed against the real 3.3.19 release to unpack to roughly 220MB of
# site-packages — numpy, networkx, rustworkx, pydantic, and dozens more —
# must never become part of *linceo's* installed environment, the same way
# it never becomes a line in this project's own `pyproject.toml`/`uv.lock`).
# checkov is, architecturally, a bundled external tool exactly like Gitleaks
# and Trivy (ADR R4) — it just happens to be distributed as a Python
# package instead of a compiled binary, which is why it needs a build stage
# of its own instead of a `curl`+checksum step in the `tools` stage below.
# No manual checksum pin here unlike Gitleaks/Trivy's raw GitHub release
# tarballs: `uv pip install` resolves and verifies checkov against PyPI's
# own package index (TLS-fetched, hash-checked against the index metadata)
# — a different, already-authenticated trust chain, not the unauthenticated
# download Gitleaks/Trivy's own checksum pinning exists to compensate for
# (ADR R4). Pinning the exact version string is still the "anclado a una
# versión específica" part of that same requirement.
# ---------------------------------------------------------------------------
FROM python:3.12-slim@${PYTHON_BASE_DIGEST} AS checkov-build

ARG UV_VERSION
ARG CHECKOV_VERSION
ENV PIP_NO_CACHE_DIR=1 \
    UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir "uv==${UV_VERSION}"

RUN uv venv --python python3.12 /opt/linceo/checkov-venv \
    && uv pip install --python /opt/linceo/checkov-venv/bin/python "checkov==${CHECKOV_VERSION}"

# ---------------------------------------------------------------------------
# Stage: tools — fetch and checksum-verify the pinned Gitleaks and Trivy
# binaries (ADR R4: "un binario de seguridad descargado sin verificar es
# el problema que esta herramienta existe para evitar"), then bake Trivy's
# vulnerability database in at build time (ADR §5) so the shipped image
# scans fully offline by default (ADR R2). `--platform=$BUILDPLATFORM`:
# this stage only downloads pre-built binaries and unpacks them — nothing
# here compiles for the host it runs on, so it always runs natively even
# when building for a foreign target architecture, and `TARGETARCH` alone
# (not the build host's own architecture) picks which binary gets fetched.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM debian:bookworm-slim@${DEBIAN_BASE_DIGEST} AS tools

ARG TARGETARCH
ARG GITLEAKS_VERSION
ARG TRIVY_VERSION

# One checksum per architecture per tool, copied verbatim from that
# release's own published `*_checksums.txt` — never computed by this
# Dockerfile, and never trusted from the download itself (ADR R4).
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG TRIVY_SHA256_AMD64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5

ENV TRIVY_CACHE_DIR=/opt/linceo/trivy-cache

# Deliberately not pinning exact apt package versions here: these come
# from Debian's own signed repository (apt verifies that signature
# itself), unlike Gitleaks/Trivy below, which come from an unauthenticated
# GitHub release and are exactly the download this Dockerfile does need to
# checksum-verify (ADR R4). Pinning an exact Debian point-release version
# would trade a real, cheap integrity guarantee we already have for a
# reproducibility guarantee that goes stale (and can 404) the moment that
# package updates upstream.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) \
        GITLEAKS_ASSET="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
        GITLEAKS_SHA256="${GITLEAKS_SHA256_AMD64}"; \
        TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
        TRIVY_SHA256="${TRIVY_SHA256_AMD64}" \
        ;; \
      arm64) \
        GITLEAKS_ASSET="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; \
        GITLEAKS_SHA256="${GITLEAKS_SHA256_ARM64}"; \
        TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"; \
        TRIVY_SHA256="${TRIVY_SHA256_ARM64}" \
        ;; \
      *) \
        echo "unsupported TARGETARCH: ${TARGETARCH} (only amd64/arm64 are pinned)" >&2; \
        exit 1 \
        ;; \
    esac; \
    curl -fsSL -o gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GITLEAKS_ASSET}"; \
    printf '%s  gitleaks.tar.gz\n' "${GITLEAKS_SHA256}" > gitleaks.tar.gz.sha256; \
    sha256sum -c gitleaks.tar.gz.sha256; \
    tar -xzf gitleaks.tar.gz gitleaks; \
    chmod 0755 gitleaks; \
    curl -fsSL -o trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_ASSET}"; \
    printf '%s  trivy.tar.gz\n' "${TRIVY_SHA256}" > trivy.tar.gz.sha256; \
    sha256sum -c trivy.tar.gz.sha256; \
    tar -xzf trivy.tar.gz trivy; \
    chmod 0755 trivy; \
    rm -f ./*.tar.gz ./*.sha256

# Bake the vulnerability database in at build time (ADR §5) — the exact
# command `TRIVY_DB_NOT_READY_HINT`
# (src/linceo/adapters/trivy.py) already tells an operator to run by hand
# on a machine with no image available; done here instead so the shipped
# image never needs it run at all. `linceo`'s own `--skip-db-update`
# (always on, ADR R2/§5) only needs read access to this directory
# afterwards, confirmed against the real 0.74.0 binary this image pins.
RUN mkdir -p "${TRIVY_CACHE_DIR}" \
    && ./trivy fs --cache-dir "${TRIVY_CACHE_DIR}" --download-db-only .

# ---------------------------------------------------------------------------
# Stage: final — the shipped image. No uv, no curl, no compiler: only
# linceo's own venv, checkov's separate venv, the two pinned binaries, the
# pre-fetched database, and `git` (needed by the `local` context provider,
# ADR §10, to read the mounted workspace's history).
# ---------------------------------------------------------------------------
FROM python:3.12-slim@${PYTHON_BASE_DIGEST} AS final

ARG GITLEAKS_VERSION
ARG TRIVY_VERSION
ARG CHECKOV_VERSION
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG LINCEO_VERSION

# The "embedded, queryable version manifest" ADR R4 asks for — its
# externally queryable half: readable with `docker inspect` or `skopeo
# inspect`, no need to start the container at all. `linceo doctor`
# (src/linceo/cli/doctor.py) is the same manifest's internal half, read
# live from inside a running container instead — both describe the same
# pinned reality, so they cannot silently disagree. `trivy-db.built-at`
# is this build's own date, not Trivy's self-reported `UpdatedAt`: the
# database above is always freshly fetched in the very same build (ADR
# §5), so the two are the same fact either way, and this one is knowable
# before the build ever runs `trivy` at all.
LABEL org.opencontainers.image.title="linceo" \
      org.opencontainers.image.description="DevSecOps tool orchestrator: N tool executions, one verdict." \
      org.opencontainers.image.version="${LINCEO_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/jdiegoisaza/linceo" \
      dev.linceo.tool.gitleaks.version="${GITLEAKS_VERSION}" \
      dev.linceo.tool.trivy.version="${TRIVY_VERSION}" \
      dev.linceo.tool.checkov.version="${CHECKOV_VERSION}" \
      dev.linceo.trivy-db.built-at="${BUILD_DATE}"

# `git`: the `local` ContextProvider (ADR §10) shells out to it to resolve
# repository/commit/branch from the mounted workspace — without it, every
# run under `--platform local` (the default when nothing Azure-specific is
# detected, ADR §4 R1) would fail outright. `ca-certificates` is
# deliberately *not* installed here, even though it is needed by the two
# explicit, opt-in escape hatches that do touch the network (`--update-db`,
# `TRIVY_DB_REPOSITORY`, ADR §5): `python:3.12-slim` already ships it
# (confirmed against the real base image — `dpkg -l ca-certificates`
# reports it present before this `RUN` ever executes), so installing it
# again was a dead argument that cost nothing but read as if this stage
# were the one providing it. Not pinning exact apt package versions here
# either, for the same reason as the `tools` stage above.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Every CI platform mounting a checkout into this image does so as
# whichever uid its own agent runs as, almost never uid 1000 (below) —
# without this, git >= 2.35.2's own ownership check (CVE-2022-24765)
# refuses to touch a repository it does not own ("detected dubious
# ownership"), which would break `local`'s `git rev-parse` calls (ADR §10)
# for essentially every real caller of this image. `--system` (not
# `--global`): applies regardless of which uid actually runs git, so this
# does not depend on `$HOME` resolving to a writable, per-user gitconfig.
# Scoped to `/workspace` specifically — the one mount point this image's
# own documented usage (README.md, "Container image") establishes — rather
# than a blanket wildcard.
RUN git config --system --add safe.directory /workspace

# Fixed uid/gid (ADR R4): a non-root user, never root, running the
# orchestrator and the tools it invokes.
RUN groupadd --system --gid 1000 linceo \
    && useradd --system --uid 1000 --gid linceo --home-dir /home/linceo --create-home linceo

COPY --from=python-build /opt/linceo/venv /opt/linceo/venv
COPY --from=checkov-build /opt/linceo/checkov-venv /opt/linceo/checkov-venv
COPY --from=tools /tools/gitleaks /tools/trivy /opt/linceo/bin/
COPY --from=tools /opt/linceo/trivy-cache /opt/linceo/trivy-cache

# Binary names are looked up on PATH, never baked in as an absolute path
# (see `GITLEAKS_BINARY`/`TRIVY_BINARY`/`CHECKOV_BINARY`,
# src/linceo/adapters/*.py) — this is the one place that resolution
# actually happens for this image. `checkov-venv/bin` is listed after
# linceo's own `venv/bin` deliberately: linceo's own entry point and
# interpreter always resolve first, and checkov's isolated venv contributes
# only the one name (`checkov`) that does not exist in linceo's venv at all
# — the two environments' dependency trees never merge, on disk or on
# `PATH` resolution order (AGENTS.md §8.3).
ENV PATH="/opt/linceo/venv/bin:/opt/linceo/checkov-venv/bin:/opt/linceo/bin:${PATH}" \
    TRIVY_CACHE_DIR=/opt/linceo/trivy-cache

RUN chmod -R a+rX /opt/linceo \
    && mkdir -p /workspace \
    && chown linceo:linceo /workspace

USER 1000:1000
WORKDIR /workspace

# `docker run --rm linceo:local` alone prints `--help`, exactly like
# running the console script with no arguments would; append a real
# subcommand the same way you would to the bare `linceo` binary, e.g.
# `docker run --rm -v "$PWD:/workspace" linceo:local scan secrets`.
ENTRYPOINT ["linceo"]
CMD ["--help"]
