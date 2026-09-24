# docker run --rm ghcr.io/jdiegoisaza/linceo:latest doctor

**Status:** ok
**Exit code:** 0

```bash
docker run --rm ghcr.io/jdiegoisaza/linceo:latest doctor
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
    - trivy-vulnerability-db: version 2, built <today-1d> (1 days old) — OK

checkov (iac):
  binary:  checkov — found on PATH
  version: 3.3.19 (supported: >=3.2,<4) — OK
  data sources: none declared

All configured tools are available and within their supported range.
```
