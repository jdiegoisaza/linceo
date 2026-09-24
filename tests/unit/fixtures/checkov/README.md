# Checkov golden fixtures (ADR §11)

Captured against **checkov 3.3.19** (installed from PyPI), by running

```
checkov -d . -o json \
  --skip-framework secrets,sca_package,sca_image,sast,sast_python,sast_java,sast_javascript,sast_typescript,sast_golang \
  -c <check id(s)>
```

against small, disposable Terraform/Dockerfile trees created for this purpose. Every
field these fixtures carry is checkov's own real output; the only change from the raw
capture is dropping fields `CheckovIntegration.parse_output` never reads (`bc_check_id`,
`check_result`, `code_block`, `file_abs_path`, `repo_file_path`, `evaluations`,
`check_class`, `fixed_definition`, `entity_tags`, `caller_file_path`,
`caller_file_line_range`, `resource_address`, `bc_category`, `benchmarks`,
`description`, `short_description`, `vulnerability_details`, `connected_node`,
`guideline`, `details`, `check_len`, `definition_context_file_path`, and, at the top
level, `results.passed_checks`, `results.skipped_checks`, `results.parsing_errors`,
`summary`, `url`) — the same "keep it small and readable" pruning the trivy fixtures
already establish. `-c` (real, stable check IDs — `CKV2_AWS_61`, `CKV_DOCKER_8` —
never synthesized, the same standard the trivy fixtures hold real CVE identifiers to)
narrows each capture to a small, deterministic set of findings instead of the dozens a
default scan of even a tiny Terraform file produces.

**Checkov's JSON report has three distinct top-level shapes**, all real and all
exercised here, not just one like gitleaks/trivy:

- **Zero findings**: a bare summary object with no `results` key at all —
  `empty.json`. This is also what a scan of a directory with no matching IaC files (or
  one that does not exist) produces; checkov does not treat either as an error.
- **Exactly one framework produced results** (e.g. only Terraform files were scanned):
  a single object, `{"check_type": ..., "results": {"failed_checks": [...]}}` —
  `one_finding.json`.
- **More than one framework produced results** (e.g. a repository with both Terraform
  and a Dockerfile): a JSON **array** of that same per-framework object shape, one
  entry per `check_type` — `many_findings.json`. `CheckovIntegration.parse_output`
  normalizes both the single-object and the array case into the same list of
  per-framework documents before parsing `failed_checks` out of each.

`file_path` is checkov's own path relative to the `-d` root, but prefixed with a
leading `/` (`"/main.tf"`, `"/subdir/main.tf"`) — confirmed against the real binary,
not assumed from documentation — which `CheckovIntegration.parse_output` strips to
match every other category's repository-relative, no-leading-slash convention
(`Location.path`).

- `one_finding.json` — one Terraform file, one `aws_s3_bucket` resource missing a
  lifecycle configuration (`CKV2_AWS_61`).
- `many_findings.json` — two frameworks in one repository. The Terraform entry is the
  reason `resource` has to be part of the `iac` fingerprint (ADR §5 amendment,
  2026-09-21): two distinct `aws_s3_bucket` resources (`logs`, `assets`) in the *same
  file*, flagged by the *same rule* (`CKV2_AWS_61`) — without `resource`, both would
  collide onto one fingerprint and one would silently disappear during dedup. The
  Dockerfile entry (`CKV_DOCKER_8`) exercises the array-of-frameworks shape and shows
  that a non-Terraform framework still populates `resource` — checkov synthesizes one
  (`/Dockerfile.USER`) even where there is no HCL resource block to name.
- `empty.json` — a directory with no IaC files checkov's active frameworks recognize.

Two fixtures are **not** captured output — checkov does not produce malformed JSON, so
these encode failure modes `CheckovIntegration.parse_output` must still handle safely,
the same pattern the gitleaks/trivy fixtures already establish:

- `malformed_truncated.json` — a hand-truncated, syntactically invalid JSON document,
  simulating a killed process or a truncated pipe.
- `missing_field.json` — syntactically valid JSON, missing the `resource` field
  `parse_output` requires to compute an `iac` fingerprint (ADR §5).

**Every native `severity` value observed across every real capture used for these
fixtures was `null`.** Checkov's open-source edition does not emit a native severity
at all — it is populated only when a run is connected to the Bridgecrew/Prisma Cloud
platform via `--bc-api-key`, which this integration never passes (ADR §6, the same
case Gitleaks is already documented for) — which is why `severity` is kept, and always
`null`, in every fixture above: it is real output, not an omission.

**Offline behavior (ADR R2), verified against the real 3.3.19 source, not assumed:**
importing `checkov.common.util.banner` — unconditionally done by `checkov`'s own CLI
entry point on every invocation — calls PyPI's JSON API to check for a newer release
unless the `CKV_SKIP_PACKAGE_UPDATE_CHECK` environment variable is truthy; there is no
CLI flag equivalent. `CheckovIntegration.build_env` sets it on every invocation this
integration makes (see `checkov.py`'s module docstring for why this needed a new
`ToolIntegration.build_env` contract method, ADR §1 amendment). Separately,
A second, separate network path exists that no `--help` text reveals: checkov's own
`main.py` calls `bc_integration.get_platform_run_config()` and
`get_prisma_build_policies(...)` unconditionally — outside the `--bc-api-key` check
entirely — attempting to reach `api0.prismacloud.io` on every invocation, with or
without a key. Found only by running the real integration test
(`tests/integration/test_checkov_integration.py`) under a network-denying sandbox, not
by reading documentation. `--skip-download` is the only thing that stops it (both
methods `return` immediately when it is set, confirmed by reading
`platform_integration.py`) — `CheckovIntegration.build_command` now passes it
unconditionally, the same way it always passes `--skip-framework`.
`--download-external-modules` is, separately, never passed (confirmed empirically:
omitting it logs a warning and skips the fetch instead of touching the network, the
same offline default Terraform module resolution already has without any flag from
this integration at all), and `--bc-api-key`/`--docker-image` are never passed either,
for the same reason `TrivyIntegration` never scans authenticated registries (ADR §10).
