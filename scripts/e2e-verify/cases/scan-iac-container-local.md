# docker run ... ghcr.io/jdiegoisaza/linceo:latest scan iac

**Status:** ok
**Exit code:** 0

```bash
docker run --rm -v '<WORKSPACE>:/workspace' ghcr.io/jdiegoisaza/linceo:latest scan iac
```

```
+--------+
| linceo |
+--------+

Run <RUN_ID> — platform=local repository=workspace commit=<COMMIT>
Status: completed
Severity map: v1

Executions:
  - checkov 3.3.19 [iac]: completed (7 findings)

iac:
  +----------+-------------+-----------+---------+-------------+--------------------+
  | SEVERITY | ID          | LOCATION  | TOOL    | FP          | RESOURCE           |
  +==========+=============+===========+=========+=============+====================+
  | MEDIUM   | CKV2_AWS_6  | main.tf:4 | checkov | v1:01ed8bbe | aws_s3_bucket.logs |
  | MEDIUM   | CKV_AWS_145 | main.tf:4 | checkov | v1:0eccd1a4 | aws_s3_bucket.logs |
  | MEDIUM   | CKV_AWS_18  | main.tf:4 | checkov | v1:7bc832ba | aws_s3_bucket.logs |
  | MEDIUM   | CKV2_AWS_61 | main.tf:4 | checkov | v1:a46c996b | aws_s3_bucket.logs |
  | MEDIUM   | CKV_AWS_21  | main.tf:4 | checkov | v1:deb7f80a | aws_s3_bucket.logs |
  | MEDIUM   | CKV_AWS_144 | main.tf:4 | checkov | v1:f0b08438 | aws_s3_bucket.logs |
  | MEDIUM   | CKV2_AWS_62 | main.tf:4 | checkov | v1:f2a9d8c2 | aws_s3_bucket.logs |
  +----------+-------------+-----------+---------+-------------+--------------------+

Suppressed by policy: 0
Expired exclusions: 0

Severity overrides applied: 0

Gate: not enforced (no thresholds configured). With --fail-on high this run would have passed.
```
