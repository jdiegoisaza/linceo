# Contributing

This project uses [`uv`](https://docs.astral.sh/uv/) for dependency
management, environments, and Python interpreter management — there is no
Makefile; every task below runs through `uv run` (see
[`docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`](docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md),
§3). Repository conventions and hard rules live in
[`AGENTS.md`](AGENTS.md); read it before making a change.

## Setup

```bash
uv sync                          # installs the project and dev dependency group
uv run pre-commit install        # installs the git hooks used by this repository
```

`uv sync` reads `uv.lock`. If `pyproject.toml` and `uv.lock` disagree, `uv
sync --frozen` (used in CI) fails loudly instead of silently re-resolving —
run `uv lock` locally and commit the updated lockfile if that happens.

## Task commands

| Task | Command |
|---|---|
| Lint | `uv run ruff check .` |
| Format check | `uv run ruff format --check .` |
| Apply formatting | `uv run ruff format .` |
| Type-check (project) | `uv run mypy -p linceo` |
| Type-check (tests) | `uv run mypy tests` |
| Type-check (`core/`, strict) | `uv run mypy --strict -p linceo.core` |
| Unit tests + coverage | `uv run pytest` |
| Integration tests | `uv run pytest -m integration` (requires real tool binaries on `PATH`; see `tests/integration/README.md`) |
| Build the package | `uv build` |
| Run all pre-commit hooks | `uv run pre-commit run --all-files` |

`uv run pytest` deselects the `integration` marker by default and enforces
full coverage of `src/linceo` (`--cov-fail-under=100`, set in
`pyproject.toml`). `core/` is checked with `mypy --strict` as a separate
invocation from the rest of the project, rather than as a per-module
override, because mypy has no `strict = true` config-file flag scoped to a
single module — expanding `--strict`'s flag set by hand would silently
drift from it whenever mypy changes what `--strict` means.

## Before opening a pull request

- `uv run pre-commit run --all-files` passes clean.
- New code in `core/`, `adapters/`, `providers/`, or `cli/` includes tests;
  coverage does not regress.
- Commit messages are in English and describe the reasoning behind a
  change, not just its mechanics.
- Changes to the architectural contract in `docs/adr/` are proposed as a
  new ADR or an explicit amendment to an existing one — never as a silent
  edit that erases the record of what was previously decided and why.
