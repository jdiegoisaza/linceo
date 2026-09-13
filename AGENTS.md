# Repository conventions

This document describes how this repository is organized and the hard rules
that apply to any change made to it. The architectural contract itself lives
in [`docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`](docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md);
this file is the day-to-day operating summary of that contract, not a
substitute for it. Where the two disagree, the ADR wins.

## Layout

```
src/linceo/
  core/       Domain and ports. No third-party dependencies, no imports
              from adapters/, providers/, or cli/. See "Layer boundaries"
              below.
  adapters/   Concrete ToolIntegration implementations (Gitleaks, Trivy).
  providers/  Concrete ContextProvider implementations (local, azure_devops).
              The only layer allowed to read os.environ.
  testing/    Permanent test doubles and fixtures (FakeContextProvider,
              FakeToolExecutor, golden fixtures). Public API, versioned with
              the same backward-compatibility guarantees as any other
              public module — see ADR §11.
  cli/        Console entry point. Argument parsing and translation into
              domain objects only; no orchestration logic of its own.

tests/unit/         Fast tests, no real tool binaries required.
tests/integration/  Tests that require real tool binaries on PATH. See
                     tests/integration/README.md. Deselected by default
                     (pytest marker `integration`); always run in this
                     project's own CI.
docs/adr/            Architecture decision records.
```

## Layer boundaries (hard rule)

- `core/` imports nothing beyond the standard library and other `core`
  modules. No `adapters`, `providers`, `cli`, or third-party package —
  Typer included.
- `adapters/` and `providers/` never import `typer`, `click`, or
  `linceo.cli`.
- `os.environ` is read only inside `providers/`, and only within that
  package.

`tests/unit/test_import_boundaries.py` enforces this by walking the AST of
every module under `src/linceo/`. A change that violates a boundary fails
that test, not just code review.

## No placeholder code

Nothing is committed as `pass`-only, a bare `...`, or a `TODO` / `FIXME`
comment standing in for real logic. If a piece of functionality is not
implemented, it is not created — including its empty function, its stub
class, or its unused parameter. `ruff`'s `FIX` rule set enforces the
TODO/FIXME/XXX/HACK part of this in CI; the rest is a review responsibility.

A package `__init__.py` containing only a module docstring is not a
placeholder — it documents what the package holds and makes it importable.

## Language

README, source code, docstrings, and commit messages are written in
English. This applies to every file in the repository except the ADRs
under `docs/adr/`, which are written in the language they were originally
recorded in.

Documentation in this repository is written for whoever reads the codebase
next — it describes the project, not the process that produced a given
change.

## CLI framework: Typer, confined to `cli/`

Typer is the only third-party dependency of the base package (see
ADR §8.3 for the full decision record). Three rules follow directly from
that decision:

1. Typer is imported only inside `cli/`.
2. The CLI layer translates arguments into domain objects and contains no
   logic of its own — a full run must be executable from Python without
   going through Typer.
3. It is pinned to a major version range (`>=0.12,<1.0`) and its lockfile
   entry is reviewed like any other dependency change.

## Testing

- `pytest` runs with coverage and the `integration` marker deselected by
  default; see `tests/integration/README.md` for what belongs there.
- Test doubles under `linceo.testing` are permanent, versioned public API —
  not scaffolding to delete once real adapters exist (ADR §11).
- `FakeToolExecutor` replays previously recorded output from a real tool
  rather than simulating it from scratch, to minimize drift between what
  the fake allows and what the real tool produces.

## Plugin entry points

Third-party tool integrations and context providers register under the
`linceo.tool_integrations` and `linceo.context_providers` entry point
groups declared in `pyproject.toml`. These groups exist from the first
commit, even before any third-party plugin uses them, so the extension
point is a stable part of the package's public contract rather than
something bolted on later.

## Task commands

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full list of `uv run`
commands used to lint, type-check, test, and build this project. There is
no Makefile — `uv` is already the project's task runner (ADR §3).
