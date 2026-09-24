# linceo doctor

**Status:** ok
**Exit code:** 0

```bash
linceo doctor
```

```
gitleaks (secrets):
  binary:  gitleaks — found on PATH
  version: 8.30.1 (supported: >=8.18,<9) — OK
  data sources: none declared

trivy (sca):
  binary:  trivy — found on PATH
  version: 0.74.0 (supported: >=0.50,<1) — OK
  data sources:
    - trivy-vulnerability-db: version 2, built <today-10d> (10 days old) — STALE

checkov (iac):
  binary:  checkov — found on PATH
  version: 3.3.19 (supported: >=3.2,<4) — OK
  data sources: none declared

All configured tools are available and within their supported range.
```
