# linceo scan secrets --path <repo>

**Status:** ok
**Exit code:** 0

```bash
linceo scan secrets --path '<WORKSPACE>'
```

```
+--------+
| linceo |
+--------+

Run <RUN_ID> — platform=local repository=sample-repo commit=<COMMIT>
Status: completed
Severity map: v1

Executions:
  - gitleaks 8.30.1 [secrets]: completed (1 findings)

secrets:
  +----------+------------------+-------------+----------+-------------+
  | SEVERITY | ID               | LOCATION    | TOOL     | FP          |
  +==========+==================+=============+==========+=============+
  | HIGH     | aws-access-token | config.py:9 | gitleaks | v1:f76ea3ac |
  +----------+------------------+-------------+----------+-------------+

Suppressed by policy: 0
Expired exclusions: 0

Severity overrides applied: 0

Gate: not enforced (no thresholds configured). With --fail-on high this run would have failed: secrets: 1 HIGH
```
