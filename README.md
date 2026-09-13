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

Pre-release (`0.1.0.dev0`). This repository currently holds the project
skeleton — packaging, tooling, and CI — with no orchestration logic yet. See
the ADR's build order for what ships next.

## Non-negotiable constraints

- Runs the same way regardless of which CI platform invokes it.
- The happy path makes no network call.
- No shared state or backend of its own: one run is one self-contained
  execution.
- The container image is the primary distribution unit; PyPI supports local
  development, bring-your-own tool binaries.
- No client-specific configuration ever lives in this repository.

## Installation

```bash
pip install linceo
```

Requires Python 3.11 or later. Tool binaries (Gitleaks, Trivy) are not
bundled via PyPI — see `linceo doctor` once implemented.

## Development

```bash
uv sync
uv run linceo --version
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full set of task commands,
and [`AGENTS.md`](AGENTS.md) for repository conventions and hard rules.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
