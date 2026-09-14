# Gitleaks golden fixtures (ADR §11)

Captured against **gitleaks 8.30.1** (linux_x64 release binary), by running

```
gitleaks detect --source . --report-format json --report-path - --exit-code 0 --no-banner
```

against small, disposable git repositories created for this purpose, each
containing only synthetic values that match gitleaks' default detection
rules — none of these are real credentials.

- `empty.json` — a clean repository with no secrets at all.
- `one_finding.json` — one repository, one commit adding a synthetic
  AWS-access-key-shaped string (`aws-access-token` rule).
- `many_findings.json` — a repository whose history accumulates two
  different synthetic secrets across two commits; one of them (a
  GitHub-PAT-shaped string) is matched by two different rules
  (`github-pat` and `generic-api-key`) on the same line, which is why this
  fixture has three entries from two secrets — a real behavior of the
  tool, not an artifact of how the fixture was constructed.

Two fixtures are **not** captured output — gitleaks does not produce
malformed JSON, so these encode failure modes `GitleaksIntegration.
parse_output` must still handle safely:

- `malformed_truncated.json` — a hand-truncated, syntactically invalid
  JSON document, simulating a killed process or a truncated pipe.
- `missing_field.json` — syntactically valid JSON, missing a field
  (`Secret`) `parse_output` requires to compute a fingerprint.
