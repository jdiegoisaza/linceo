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

No test currently lives in this directory: there is no tool integration
implemented yet for it to exercise (see `src/linceo/adapters/`). A test is
added here alongside the first `ToolIntegration` implementation, not before.
