# Releasing linceo

This document describes how a release reaches PyPI *and* GHCR (both from
the same tag), and — separately — what to do when one fails partway
through. It is a day-to-day operating procedure, not an architectural
decision; the container image is the project's *primary* distribution
channel (ADR §4/[R4](adr/ADR-000-arquitectura-base-y-alcance-v0.1.md)),
PyPI its local-development counterpart (README, "Installation") — this
workflow treats both as equally real publish targets of the same release,
not one as an afterthought of the other.

## How it works

Publishing is driven entirely by [`.github/workflows/release.yml`](../.github/workflows/release.yml),
triggered by pushing a tag matching `v*.*.*` (e.g. `v0.2.0`). There is no
manual "run release" button and no version field to edit by hand — see
"Versioning" below.

The workflow has three phases:

1. **`version`**: derives the release version once from the pushed tag
   (`v0.2.0` → `0.2.0`) and exposes it as a job output. Both publish jobs
   below consume this same output rather than each re-deriving it, so
   "what version is this release" has exactly one answer in the workflow.
2. **Gate**: `lint`, `types`, and `test` (the same checks as `ci.yml`, run
   again here — a tag can point at any commit, not necessarily one that
   already passed `ci.yml` on `main`). All three must succeed.
3. Two independent publish jobs, both gated on the same `lint`/`types`/`test`
   trio and running in parallel — one target failing doesn't block or roll
   back the other (see "When a release fails partway through" for what
   that implies for recovery):
   - **`publish-pypi`**: checks out the tagged commit with full history,
     builds the package with `uv build`, verifies that the git tag and the
     version just built actually match, and — only if that check passes —
     uploads to PyPI with
     [`pypa/gh-action-pypi-publish`](https://github.com/pypa/gh-action-pypi-publish)
     using **Trusted Publishing (OIDC)**: the job requests a short-lived
     OpenID Connect token (`permissions: id-token: write`) that PyPI
     exchanges for a one-time upload credential itself. No
     `PYPI_API_TOKEN` or any other long-lived secret is stored in this
     repository.
   - **`publish-ghcr`**: builds the reference container image
     (`Dockerfile`) and pushes it to `ghcr.io/jdiegoisaza/linceo`,
     authenticating with the workflow's own `GITHUB_TOKEN`
     (`permissions: packages: write`) — again, no stored secret. See
     "Container image" below for tags and labels.

Trusted Publishing authenticates by matching four things exactly against
what's registered on PyPI for the `linceo` project: the repository owner
(`jdiegoisaza`), the repository (`linceo`), the workflow filename
(`release.yml`), and the GitHub Environment the job runs under (`pypi`).
That PyPI-side registration already exists. What must additionally exist
on the **GitHub** side, and isn't created by any file in this repository,
is the environment itself:

- Repository → Settings → Environments → New environment named exactly
  `pypi`.
- Protection rules (required reviewers, wait timers, branch restrictions)
  are optional — Trusted Publishing itself only cares about the name — but
  a required-reviewer rule here is a reasonable extra gate before a tag
  push can reach PyPI, since a tag push is not otherwise reviewed the way
  a pull request is.

`publish-ghcr` needs no such registration — `GITHUB_TOKEN` is scoped to
this repository's own GHCR namespace by the `packages: write` permission
declared on that job, nothing more to set up on either side. It does need
its published package's *visibility* set to public by hand, once — see
"Container image" and the prerequisites checklist below.

## Versioning: the tag is the only source of truth

Before this workflow existed, the package version was a hand-written
string in `pyproject.toml` (`0.1.0.dev0`), which could drift from
whatever a release tag said if someone forgot to bump it. That field is
gone. `pyproject.toml` now declares `dynamic = ["version"]`, and
`[tool.hatch.version]` (`source = "vcs"`, via the `hatch-vcs` build
dependency) derives the version straight from git at build time — a
concrete instance of the "versioned mapping, not a hand-maintained
duplicate" principle this project already applies elsewhere (ADR §6):

- **On a clean checkout exactly at a tag `vX.Y.Z`**, the built version is
  exactly `X.Y.Z`. This is the case the `publish-pypi` job builds under.
- **Anywhere else** (a normal local checkout, a feature branch, `ci.yml`'s
  own `build` job) — no tag in scope, or commits/uncommitted changes past
  one — the build derives a PEP 440 pre-release version instead of
  failing, so nothing about local development or non-release CI depends
  on a tag existing at all.

Because the version is derived, "does the tag match the package version"
is normally guaranteed by construction, not by discipline. The
**`publish-pypi` job still verifies it explicitly anyway**, comparing the
`version` job's output against the version encoded in the built wheel's
filename before the upload step runs. This is deliberate, not redundant:
it is the one check that catches the actual failure mode of this
approach, which is git-metadata-shaped, not human-shaped — e.g. a checkout
that silently lost tag history and fell back to a dev version instead of
the real one. If that check fails, the workflow stops before anything is
uploaded.

**Tag format**: `vMAJOR.MINOR.PATCH`, optionally with a PEP 440-compatible
pre-release suffix (e.g. `v0.2.0`, `v1.0.0`, `v0.3.0-rc1`). A tag that
doesn't match the `v*.*.*` pattern will not trigger the workflow at all —
nothing publishes, and nothing needs cleaning up.

Version numbers themselves follow semver, per the public contract already
recorded in the ADR (§8: CLI flags and exit codes are covered by semver —
a breaking change to either requires a major bump).

## Container image: version, tags, and OCI labels

The same problem "Versioning" solves for the PyPI package — a
hand-maintained version field that can silently drift from the tag — used
to apply to the image too: `Dockerfile`'s `ARG LINCEO_VERSION` was, until
this workflow existed, "kept in sync by hand." It no longer is.
`publish-ghcr` passes `--build-arg LINCEO_VERSION=<version>` using the same
`version` job output the PyPI job verifies against, so the image and the
package are, structurally, describing the same release — not two builds
that happen to usually agree.

That build-arg does two things inside `Dockerfile`, both load-bearing:

- Sets the `org.opencontainers.image.version` OCI label — readable without
  starting the container (`docker inspect`, or `skopeo inspect` against
  the pushed image).
- Sets `SETUPTOOLS_SCM_PRETEND_VERSION` for the `uv build --wheel` call in
  the `python-build` stage. That build context has no `.git` in it (only
  the files the Dockerfile explicitly `COPY`s), so hatch-vcs — the same
  version source `uv build` uses outside the image — would have no tag to
  read and would silently fall back to the pre-release placeholder
  instead. Without this, `docker inspect`'s version label and `linceo
  --version` run *inside the very same container* could disagree; with
  it, both always say the same thing, verified by building the image
  locally with an explicit version and checking both.

**Tags**: `ghcr.io/jdiegoisaza/linceo:<version>` always; also
`ghcr.io/jdiegoisaza/linceo:latest`, but only when `<version>` is a plain
`X.Y.Z` with no pre-release suffix — a tag like `v0.3.0-rc1` publishes
`...linceo:0.3.0-rc1` and leaves `latest` pointing at whatever the last
real release was, on purpose, so a pre-release can never become what an
unpinned `docker pull ghcr.io/jdiegoisaza/linceo` resolves to.

**OCI labels landing on the published image** (`Dockerfile`, `final`
stage) — all of them, not just the version:

| Label | Source |
|---|---|
| `org.opencontainers.image.version` | the `version` job (this tag) |
| `org.opencontainers.image.created` | `publish-ghcr`'s own build timestamp (UTC) |
| `org.opencontainers.image.revision` | `github.sha` — the commit the tag points at |
| `dev.linceo.tool.gitleaks.version` | `Dockerfile`'s own pinned `GITLEAKS_VERSION` default (ADR R4) |
| `dev.linceo.tool.trivy.version` | `Dockerfile`'s own pinned `TRIVY_VERSION` default (ADR R4) |
| `dev.linceo.trivy-db.built-at` | this build's own timestamp — the vulnerability DB is always freshly fetched in the same build (ADR §5), so this and `image.created` are the same fact either way |

The two tool-version labels come from `Dockerfile`'s own defaults, not
from anything `release.yml` passes in — this workflow publishes the image
the rest of the project already pins and golden-fixture-tests against, it
doesn't get to pick different tool versions for a release build.

**Multi-arch**: not yet. `Dockerfile` already supports `linux/amd64` and
`linux/arm64` (see its `tools` stage, pinned checksums for both), but
`publish-ghcr` only builds for the runner's own platform (`linux/amd64`)
today. Building `arm64` too means adding QEMU emulation to the job, which
would make every release noticeably slower and is a real cost to weigh —
deliberately left out of this pass rather than decided silently either way.

## Cutting a release

1. Confirm `main` is at the commit you want to release, and that `ci.yml`
   is green on it.
2. Decide the next version per semver.
3. Tag it and push the tag (the annotated form is recommended for the
   tagger/date metadata it carries, but not required — lightweight tags
   work identically for version derivation):
   ```bash
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```
4. Watch the `Release` workflow run in the Actions tab. It derives the
   version, runs `lint`/`types`/`test`, then `publish-pypi` and
   `publish-ghcr` run in parallel.
5. Once both are green, confirm both artifacts actually landed:
   - PyPI: `https://pypi.org/project/linceo/0.2.0/`, and optionally
     install it into a scratch environment (`uv venv /tmp/linceo-check &&
     uv pip install --python /tmp/linceo-check/bin/python linceo==0.2.0`).
   - GHCR: `docker pull ghcr.io/jdiegoisaza/linceo:0.2.0` (no login needed
     once the package is public — see the prerequisites checklist) and
     `docker inspect ghcr.io/jdiegoisaza/linceo:0.2.0 --format
     '{{json .Config.Labels}}'` to confirm the version/tool/date labels
     from "Container image" above.

Nothing else needs updating for the publish itself — not `pyproject.toml`,
not a lockfile entry, not `Dockerfile`'s `LINCEO_VERSION` default (that
default is only ever what a plain local `docker build` gets; the release
workflow always overrides it). The README's "Status" line is prose,
tracked and updated separately, and doesn't feed either publish pipeline.

## When a release fails partway through

**PyPI and GHCR do not fail the same way, and `publish-pypi` and
`publish-ghcr` run independently — one can succeed while the other
fails.** Handle each on its own terms rather than assuming a single
recovery procedure covers both:

- **PyPI does not allow re-uploading a given version, ever — not even
  after deleting or yanking it.** Once `X.Y.Z` has existed on PyPI,
  `X.Y.Z` is permanently unavailable, even to the same project.
- **GHCR tags are mutable, ordinarily.** Pushing `ghcr.io/.../linceo:X.Y.Z`
  again simply overwrites what that tag points to — there is no PyPI-style
  permanent burn. A failed or wrong `publish-ghcr` run is fixed by running
  it again for the *same* version, not by inventing a new one.

Whether it's safe to retry PyPI with the *same* tag, or you must move to a
*new* version, depends entirely on whether the version ever actually
reached PyPI — not on how far the workflow run got before failing.

**Find out which side of that line you're on**: open the failed run in
the Actions tab (check `publish-pypi` and `publish-ghcr` separately — they
can disagree) and check `https://pypi.org/project/linceo/#history` (or
`/X.Y.Z/` directly).

### Only `publish-ghcr` failed (PyPI succeeded)

The simplest case, precisely because GHCR imposes no immutability: fix the
underlying cause and **re-run just the failed `publish-ghcr` job** from
the same workflow run (Actions tab → the run → *Re-run failed jobs*) — it
rebuilds and pushes the same version tag, which is a normal overwrite, not
a new release. There's no need to touch PyPI, and no need for a new tag.

### Only `publish-pypi` failed (GHCR succeeded)

Follow "The version never reached PyPI" or "The version did reach PyPI"
below, whichever applies, to fix PyPI. If that ends up requiring a *new*
version number (PyPI partially published, so `X.Y.Z` is burned), the GHCR
image already pushed as `X.Y.Z` now describes a release that doesn't exist
on PyPI — ship the corrected release under the new tag (which republishes
GHCR too, at the new version, superseding `latest`) and, optionally,
delete the orphaned `X.Y.Z` version from the GHCR package's *Manage
versions* page — not required for safety, since it isn't going to be
confused with a real release once `latest` and the docs point past it, but
useful to avoid it sitting there as a trap for someone pulling it by exact
tag.

### The version never reached PyPI

This covers `lint`, `types`, or `test` failing, `uv build` failing, the
tag/version verification step failing, or the publish step itself failing
outright (e.g. a network error, or a Trusted Publisher configuration
mismatch) with PyPI's project history confirming no such version exists.

Nothing was published — there is no PyPI state to reconcile. Fix the
underlying cause, then either re-run the failed workflow (fine for a
transient failure like a network blip) or, if the fix requires a code
change:

```bash
git push origin :refs/tags/v0.2.0   # delete the remote tag
git tag -d v0.2.0                   # delete it locally
# ... fix the issue, commit it to main ...
git tag -a v0.2.0 -m "v0.2.0"       # re-tag
git push origin v0.2.0              # try again
```

Reusing the same version number here is safe by construction, not just by
convention: if the upload had actually landed despite appearances, PyPI
would reject the second attempt outright ("File already exists") rather
than silently overwriting it — there is no way for this path to corrupt a
release that actually succeeded.

### The version did reach PyPI, but something after that was still wrong

This is the case where the `publish-pypi` job itself succeeded (or the
history check shows the version exists) but you don't want that release
standing — e.g. it turns out to be broken, or a later step you might add
to this job in the future fails after the upload already happened.

The version number `X.Y.Z` is burned permanently. There is no delete, no
force-push equivalent, no re-upload:

1. **Yank it** if it's actually broken and installing it would hurt
   someone: on [pypi.org](https://pypi.org), sign in →
   `linceo` project → *Release history* → select `X.Y.Z` → *Options* →
   *Yank release*, with a reason. Yanking does not delete the release —
   anyone already pinned to `linceo==X.Y.Z` keeps working — it only
   removes it from being selected by an unpinned resolver
   (`pip install linceo`).
2. **Ship the fix as the next version.** Bump to the next patch (or
   whatever semver calls for), fix the actual problem, and tag/push as
   in "Cutting a release" above. There's no shortcut around this: even a
   one-character difference must go out as a new version number.

## Prerequisites checklist

- [x] PyPI: Trusted Publisher registered for owner `jdiegoisaza`,
  repository `linceo`, workflow `release.yml`, environment `pypi`.
- [ ] GitHub: repository Environment named `pypi` exists (Settings →
  Environments) — confirm this before the first tag push; it is not
  created by anything in this repository.
- [ ] GHCR: after the *first* `publish-ghcr` run (a GHCR package doesn't
  exist, and so can't be configured, before something has been pushed to
  it), set its visibility to **Public**. It defaults to private
  regardless of this repository's own visibility, and `GITHUB_TOKEN` has
  no permission to change it — this is a one-time, human, web-UI step:
  the package's page (linked from the repo sidebar once pushed, or
  `https://github.com/users/jdiegoisaza/packages/container/linceo/settings`)
  → *Danger Zone* → *Change visibility* → *Public*. Skipping this is the
  one way this whole setup could still leave a CI agent unable to `docker
  pull` it without credentials, which is the entire point of publishing it
  to begin with.
