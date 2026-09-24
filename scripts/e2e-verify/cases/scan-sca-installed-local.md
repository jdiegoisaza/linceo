# linceo scan sca --path <repo>

**Status:** ok
**Exit code:** 0

```bash
linceo scan sca --path '<WORKSPACE>'
```

```
+--------+
| linceo |
+--------+

Run <RUN_ID> — platform=local repository=sample-repo commit=<COMMIT>
Status: completed
Severity map: v1

Executions:
  - trivy 0.74.0 [sca]: completed (1 findings)

sca:
  +----------+----------------+-------------------+-------+-------------+------------------+-----------+
  | SEVERITY | ID             | LOCATION          | TOOL  | FP          | MANIFEST         | FIXED     |
  +==========+================+===================+=======+=============+==================+===========+
  | HIGH     | CVE-2023-37920 | certifi@2015.4.28 | trivy | v1:6fbe3a46 | requirements.txt | 2023.7.22 |
  +----------+----------------+-------------------+-------+-------------+------------------+-----------+

Suppressed by policy: 0
Expired exclusions: 0

Severity overrides applied: 0

Gate: not enforced (no thresholds configured). With --fail-on high this run would have failed: sca: 1 HIGH
```
