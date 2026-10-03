# Trivy image golden fixtures (ADR §11)

Captured against **trivy 0.74.0** with the exact flags
`TrivyImageIntegration.build_command` emits, against public images already
in a local Docker daemon, then trimmed to the fields the parser reads
(`VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`,
`PkgPath`, `Layer`, `Title`, `Severity`, `CVSS`) and to a few entries per
result:

- `os_and_gobinary.json` — `zricethezav/gitleaks:v8.24.2`: an `os-pkgs`
  result (alpine; its `Target` embeds the image reference, no `PkgPath`)
  and a `lang-pkgs` result whose `Target` is itself a file path
  (`usr/bin/gitleaks`).
- `os_and_python.json` — an untagged `python` image scanned by ID: a
  Debian `os-pkgs` entry with no fixed version, and a `python-pkg` result
  whose `Target` is the generic `Python` and whose real location is each
  vulnerability's `PkgPath`.
- `empty.json` — `hello-world`: no OS, no packages, so no `Results` key.

The stderr strings used in `tests/unit/test_trivy_image.py` for a missing
image and an unreachable daemon were captured from the same binary with
`nosuch/image:1.0`, `DOCKER_HOST=unix:///nonexistent.sock`, and a socket
mounted without group access.
