# docker run --network none ... scan secrets --config <remote>, with cache

**Status:** ok
**Exit code:** 0

```bash
docker run --rm --network none -v '<WORKSPACE>:/workspace' -v '<RUNDIR>/policy-cache-remote-policy-degraded-with-cache-container:/policy-cache' -e SYSTEM_COLLECTIONURI=https://dev.azure.com/juandiego-13/ -e LINCEO_POLICY_CACHE_DIR=/policy-cache ghcr.io/jdiegoisaza/linceo:latest scan secrets --config /workspace/.devsecops/policy-remote.toml
```

```
+-----------------------------------+
| e2e-verify fabricated cache entry |
+-----------------------------------+

Run <RUN_ID> — platform=local repository=workspace commit=<COMMIT>
Status: completed
Severity map: v1

Executions:
  - gitleaks 8.30.1 [secrets]: completed (1 findings)

Remote policy: linceo-policy/.devsecops/policy.toml — WARN: fetch failed (failed to fetch linceo-policy/.devsecops/policy.toml from Azure DevOps: [Errno -3] Temporary failure in name resolution), using a cached copy from <TIMESTAMP> (0 days old) [OK]

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
