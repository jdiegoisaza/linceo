"""Static data files distributed with the package, not Python modules.

``sarif-schema-2.1.0.json`` is the official OASIS SARIF 2.1.0 JSON Schema
(with Errata 01, the current version of the ratified standard), vendored
here so `tests/unit/test_sarif_reporter.py` can validate
`linceo.core.sarif.render_sarif`'s output against it without any network
access (ADR §7's verification requirement; ADR R2 — validating against a
remote copy of the schema would make the project's own test suite reach
the network). Fetched verbatim, byte-for-byte, from
``https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json``
on 2026-09-17 — kept exactly as published, never reformatted, so a future
diff against that URL stays meaningful.
"""
