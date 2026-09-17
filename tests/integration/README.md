# Integration tests

Tests in this directory require real tool binaries (Gitleaks, Trivy) present
on `PATH`, rather than the fakes in `linceo.testing`. They are marked with
the pytest marker `integration`.

`pytest`'s default configuration (`pyproject.toml`, `[tool.pytest.ini_options]`)
deselects this marker, so `uv run pytest` skips this directory in local
development unless the required binaries happen to be installed. This
project's own CI runs the full suite, including these tests, against the
tool versions pinned in the reference container image (see
`docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`, §11).

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
