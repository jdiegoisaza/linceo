# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/jdiegoisaza/linceo/security/advisories/new)
for this repository. This keeps the report out of public issues and pull
requests while it is triaged.

If you cannot use GitHub Security Advisories, email
juan.diego-13@hotmail.com with a description of the issue, the affected
version, and steps to reproduce it. Do not open a public issue for a
suspected vulnerability.

## Supported versions

This project is pre-1.0. Until a `1.0` release, only the latest published
release receives security fixes.

## Scope

In scope: the orchestrator itself — the core domain, the CLI, and the
reference adapters and providers distributed in this repository. The
detection quality of third-party tools it invokes (Gitleaks, Trivy) is out
of scope; report those upstream.

This project makes no network call on its happy path and holds no
credentials, telemetry, or client configuration in the repository itself
(see `docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md`, §R2 and §R5) —
a report that depends on either of those existing is likely reporting a
regression against that contract, which is itself worth flagging.
