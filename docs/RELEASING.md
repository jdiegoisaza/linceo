# Releasing linceo to PyPI

This document describes how a release reaches PyPI, and — separately —
what to do when one fails partway through. It is a day-to-day operating
procedure, not an architectural decision; the container image described in
[`docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`](adr/ADR-000-arquitectura-base-y-alcance-v0.1.md)
(§R4) remains the project's *primary* distribution channel. PyPI supports
local development and CI usage outside a container (README, "Installation").

## How it works

Publishing is driven entirely by [`.github/workflows/release.yml`](../.github/workflows/release.yml),
triggered by pushing a tag matching `v*.*.*` (e.g. `v0.2.0`). There is no
manual "run release" button and no version field to edit by hand — see
"Versioning" below.

The workflow has two phases:

1. **Gate**: `lint`, `types`, and `test` (the same checks as `ci.yml`,
   run again here — a tag can point at any commit, not necessarily one
   that already passed `ci.yml` on `main`). All three must succeed.
2. **`publish`** (only if the gate passes): checks out the tagged commit
   with full history, builds the package with `uv build`, verifies that
   the git tag and the version just built actually match, and — only if
   that check passes — uploads to PyPI with
   [`pypa/gh-action-pypi-publish`](https://github.com/pypa/gh-action-pypi-publish)
   using **Trusted Publishing (OIDC)**: the `publish` job requests a
   short-lived OpenID Connect token (`permissions: id-token: write`) that
   PyPI exchanges for a one-time upload credential itself. No
   `PYPI_API_TOKEN` or any other long-lived secret is stored in this
   repository.

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
  exactly `X.Y.Z`. This is the case the `publish` job builds under.
- **Anywhere else** (a normal local checkout, a feature branch, `ci.yml`'s
  own `build` job) — no tag in scope, or commits/uncommitted changes past
  one — the build derives a PEP 440 pre-release version instead of
  failing, so nothing about local development or non-release CI depends
  on a tag existing at all.

Because the version is derived, "does the tag match the package version"
is normally guaranteed by construction, not by discipline. The
**`publish` job still verifies it explicitly anyway**, comparing
`${GITHUB_REF_NAME}` against the version encoded in the built wheel's
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
4. Watch the `Release` workflow run in the Actions tab. It runs `lint`,
   `types`, and `test`, then builds, verifies, and publishes.
5. Once it's green, confirm the release landed:
   `https://pypi.org/project/linceo/0.2.0/`, and optionally install it
   into a scratch environment (`uv venv /tmp/linceo-check && uv pip
   install --python /tmp/linceo-check/bin/python linceo==0.2.0`).

Nothing else needs updating for the publish itself — not `pyproject.toml`,
not a lockfile entry. (The README's "Status" line and the Dockerfile's
`LINCEO_VERSION` build arg default are prose/documentation, tracked and
updated separately; they don't feed the publish pipeline and are outside
this document's scope.)

## When a release fails partway through

**PyPI does not allow re-uploading a given version, ever — not even after
deleting or yanking it.** Once `X.Y.Z` has existed on PyPI, `X.Y.Z` is
permanently unavailable, even to the same project. This is the one fact
that determines everything below: whether it's safe to retry with the
*same* tag, or you must move to a *new* version, depends entirely on
whether the version ever actually reached PyPI — not on how far the
workflow run got before failing.

**Find out which side of that line you're on**: open the failed run in
the Actions tab and check `https://pypi.org/project/linceo/#history` (or
`/X.Y.Z/` directly).

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

This is the case where the `publish` step itself succeeded (or the
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

## Prerequisites checklist (one-time, already done for `linceo`)

- [x] PyPI: Trusted Publisher registered for owner `jdiegoisaza`,
  repository `linceo`, workflow `release.yml`, environment `pypi`.
- [ ] GitHub: repository Environment named `pypi` exists (Settings →
  Environments) — confirm this before the first tag push; it is not
  created by anything in this repository.
