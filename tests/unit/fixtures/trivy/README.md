# Trivy golden fixtures (ADR §11)

Captured against **trivy 0.74.0** (installed release binary), by running

```
trivy fs --scanners vuln --format json --skip-db-update .
```

against small, disposable `requirements.txt` files pinning real, long-patched
PyPI packages to old, genuinely vulnerable versions — none of these are
synthetic CVEs, unlike the gitleaks fixtures' synthetic secrets, because a
vulnerability identifier cannot be synthesized the way a fake credential
can. Every field these fixtures carry is trivy's own real output; the only
change from the raw capture is dropping fields `TrivyIntegration.
parse_output` never reads (`References`, `Description`, `CweIDs`,
`VendorIDs`, `DataSource`, `Fingerprint`, `PublishedDate`,
`LastModifiedDate`, `PkgIdentifier`) to keep each file small and readable.

- `empty.json` — `six==1.16.0`, a package version with no known
  vulnerabilities: trivy still lists `requirements.txt` as a scanned
  target (it lists every analyzed manifest, not just vulnerable ones) but
  the entry carries no `Vulnerabilities` key at all — trivy omits the key
  entirely rather than emitting an empty list, which is why
  `TrivyIntegration.parse_output` treats a missing key as `()`, the same
  way it treats a missing top-level `Results` key for a workspace with no
  dependency manifests at all.
- `one_finding.json` — `certifi==2015.4.28`, one real CVE
  (`CVE-2023-37920`). Its `CVSS` block carries three real, disagreeing
  sources (`ghsa` 7.5, `nvd` 9.8, `redhat` 9.1) — useful on its own for
  testing the CVSS source-preference order (`nvd` first, ADR §6's own
  example), even though this entry's native `Severity` (`HIGH`) resolves
  before CVSS is ever consulted.
- `many_findings.json` — `certifi==2015.4.28` plus `PyYAML==5.3` in one
  `requirements.txt`: three real CVEs across two packages
  (`CVE-2020-14343` and `CVE-2020-1747`, both CRITICAL, PyYAML; and
  `CVE-2023-37920`, HIGH, certifi again) — exercises sorting across
  severities and packages sharing one manifest path.

Two fixtures are **not** captured output — trivy does not produce
malformed JSON, so these encode failure modes `TrivyIntegration.
parse_output` must still handle safely, the same pattern the gitleaks
fixtures already establish:

- `malformed_truncated.json` — a hand-truncated, syntactically invalid
  JSON document, simulating a killed process or a truncated pipe.
- `missing_field.json` — syntactically valid JSON, missing a field
  (`PkgName`) `parse_output` requires to build a finding's `Package`.

The `UNKNOWN`-severity/CVSS-fallback case and the "trivy exits non-zero
because its vulnerability database was never downloaded" case are not
fixture files: neither occurred naturally in these small, disposable
scans, so `tests/unit/test_trivy.py` constructs them inline instead —
the first as a hand-built vulnerability entry (still shaped exactly like
a real one), the second as a real, literally-reproduced `stderr` string
captured by running `trivy fs --skip-db-update` against an empty
`--cache-dir` once, by hand, before this integration existed.
