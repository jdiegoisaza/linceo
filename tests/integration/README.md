# Integration tests

Tests in this directory require real tool binaries (Gitleaks, Trivy) present
on `PATH`, rather than the fakes in `linceo.testing`. They are marked with
the pytest marker `integration`.

`pytest`'s default configuration (`pyproject.toml`, `[tool.pytest.ini_options]`)
deselects this marker, so `uv run pytest` skips this directory in local
development unless the required binaries happen to be installed. Only
`test_offline_guarantee.py` has a CI job today (`offline` in
`.github/workflows/ci.yml`, against the tool versions pinned in the reference
container image — see `docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`,
§11); the other files here run on a developer machine.

To run this suite locally with the required binaries installed:

```bash
uv run pytest -m integration
```

`test_gitleaks_integration.py` and `test_trivy_integration.py` exercise
each of this project's two reference `ToolIntegration` implementations
(see `src/linceo/adapters/`) against its real binary. A test is added here
alongside each new `ToolIntegration` implementation, not before.

`test_trivy_integration.py` additionally requires a vulnerability database
already fetched at least once (`trivy fs --download-db-only`, or an
equivalent already-populated `--cache-dir`) — the reference container
image bakes one in at build time (ADR §4/R4, §5); a bare `trivy` install
with no database yet only satisfies the subset of tests that do not
require one (`test_detect_version_reports_the_real_installed_trivy_version`).

`test_trivy_image_integration.py` additionally needs a reachable Docker
daemon holding `hello-world:latest` (`docker pull hello-world`); its tests
are skipped when no daemon is reachable.

`test_offline_guarantee.py` runs every discovered `ToolIntegration` for real
inside an isolated network namespace (`network_probe.py`) and fails if any of
them attempts a connection (ADR R2). It needs `unshare` with unprivileged user
namespaces, all three tool binaries, a vulnerability database already fetched,
and a Docker daemon (it pulls `alpine:3.19` if absent). It fails, never skips,
when one of those is missing.
