"""End-to-end test of the Checkov integration against the real binary (ADR §11).

Unlike `tests/unit/test_checkov.py` (golden fixtures, no binary required), this
exercises the real `checkov` binary through `SubprocessToolExecutor`,
`LocalContextProvider`, and `linceo.core.engine.run` together — the same
composition `linceo scan iac` wires up — against a small, disposable Terraform
file with a real, checkov-flagged misconfiguration. Added alongside
`CheckovIntegration` itself (ADR §1 amendment, 2026-09-21) — this file closed a
real gap: `tests/integration/README.md` already promised one per
`ToolIntegration`, and this one did not exist yet.

Every `executor.run(...)` call below passes `integration.build_env()`, not
`env={}` like `test_gitleaks_integration.py`/`test_trivy_integration.py` do —
those two integrations need no environment variables at all (ADR §1
amendment), but checkov's own offline default (suppressing its per-invocation
PyPI version check, ADR R2) depends on one. Omitting it here would mean this
project's own test suite reaches the network on every run against the real
binary — exactly what R2's test-level `socket`-poisoning guard exists to catch
for `core/`, extended here, deliberately, to this integration test too.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.adapters.checkov import CheckovIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.core.config import Config
from linceo.core.engine import run
from linceo.core.execution import ExecutionStatus
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.results import RunStatus
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError
from linceo.providers.local import LocalContextProvider

pytestmark = pytest.mark.integration

#: A minimal S3 bucket resource missing a lifecycle configuration —
#: `CKV2_AWS_61`, the same real check `tests/unit/fixtures/checkov/` already
#: captures against this same pinned version, and the same synthetic tree
#: `scripts/e2e-verify/fixtures/sample-repo/main.tf` uses.
_MISCONFIGURED_BUCKET = 'resource "aws_s3_bucket" "logs" {\n  bucket = "example-logs-bucket"\n}\n'


def _git(*args: str, cwd: Path) -> None:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    return path


def _commit_all(path: Path, message: str) -> None:
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", message, cwd=path)


def test_detect_version_reports_the_real_installed_checkov_version() -> None:
    executor = SubprocessToolExecutor()

    version = CheckovIntegration.detect_version(executor)

    assert version
    assert version[0].isdigit()


def test_an_empty_workspace_produces_no_findings(tmp_path: Path) -> None:
    """The bare-summary JSON shape (no `results` key at all) — no IaC files to flag."""
    repo = tmp_path / "empty-repo"
    repo.mkdir()

    executor = SubprocessToolExecutor()
    integration = CheckovIntegration(version=CheckovIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo), config=ToolConfig()),
        env=integration.build_env(),
        cwd=str(repo),
        timeout=None,
    )

    findings = integration.parse_output(process_result)

    assert findings == ()


def test_a_misconfigured_resource_is_detected_with_its_real_resource_identity(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "misconfigured-repo"
    repo.mkdir()
    (repo / "main.tf").write_text(_MISCONFIGURED_BUCKET)

    executor = SubprocessToolExecutor()
    integration = CheckovIntegration(version=CheckovIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo), config=ToolConfig()),
        env=integration.build_env(),
        cwd=str(repo),
        timeout=None,
    )

    findings = integration.parse_output(process_result)

    assert len(findings) >= 1
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "CKV2_AWS_61" in by_rule
    finding = by_rule["CKV2_AWS_61"]
    assert finding.resource == "aws_s3_bucket.logs"
    assert finding.location.path == "main.tf"
    assert finding.raw_severity is None  # ADR §6: checkov's open-source edition emits none


def test_two_resources_sharing_a_rule_and_file_stay_distinct(tmp_path: Path) -> None:
    """The real case ADR §5's 2026-09-21 amendment added `resource` to the fingerprint for."""
    repo = tmp_path / "two-buckets-repo"
    repo.mkdir()
    (repo / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n  bucket = "example-logs-bucket"\n}\n\n'
        'resource "aws_s3_bucket" "assets" {\n  bucket = "example-assets-bucket"\n}\n'
    )

    executor = SubprocessToolExecutor()
    integration = CheckovIntegration(version=CheckovIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo), config=ToolConfig()),
        env=integration.build_env(),
        cwd=str(repo),
        timeout=None,
    )

    findings = integration.parse_output(process_result)

    resources = {f.resource for f in findings if f.rule_id == "CKV2_AWS_61"}
    assert resources == {"aws_s3_bucket.logs", "aws_s3_bucket.assets"}


def test_scan_iac_end_to_end_through_the_engine_against_a_real_workspace(tmp_path: Path) -> None:
    """The same composition `linceo scan iac` wires up (ADR §8, §10), run for real."""
    repo = _init_repo(tmp_path / "widgets")
    (repo / "main.tf").write_text(_MISCONFIGURED_BUCKET)
    _commit_all(repo, "add a real, checkov-flagged S3 bucket misconfiguration")

    executor = SubprocessToolExecutor()
    integration = CheckovIntegration(version=CheckovIntegration.detect_version(executor))

    result = run(
        run_id="integration-test-run",
        context_provider=LocalContextProvider(workspace_path=str(repo)),
        integrations={Category.IAC: integration},
        executor=executor,
        normalizer=SeverityNormalizer(),
        config=Config(),
        now=datetime.now(UTC),
    )

    assert result.status is RunStatus.COMPLETED
    assert result.executions[0].status is ExecutionStatus.COMPLETED
    assert len(result.findings) >= 1
    assert result.findings[0].resource is not None


# --- per-integration configuration against the real binary (ADR §8.5) --------


def test_exclude_paths_skips_a_misconfigured_resource_in_that_directory(tmp_path: Path) -> None:
    """`exclude_paths` -> `--skip-path`, the repeatable-flag shape trivy's own `--skip-dirs` has."""
    repo = tmp_path / "skip-path-repo"
    (repo / "vendor").mkdir(parents=True)
    (repo / "vendor" / "main.tf").write_text(_MISCONFIGURED_BUCKET)

    executor = SubprocessToolExecutor()
    integration = CheckovIntegration(version=CheckovIntegration.detect_version(executor))

    def _scan(*, config: ToolConfig) -> tuple[object, ...]:
        process_result = executor.run(
            integration.build_command(workspace_path=str(repo), config=config),
            env=integration.build_env(),
            cwd=str(repo),
            timeout=None,
        )
        return tuple(integration.parse_output(process_result))

    assert len(_scan(config=ToolConfig())) >= 1  # unexcluded: the misconfigured bucket is found
    assert _scan(config=ToolConfig(exclude_paths=("vendor/",))) == ()  # excluded: gone


def test_scan_history_raises_unsupported_tool_config_error_against_the_real_binary() -> None:
    """No subprocess involved — `build_command` rejects this before anything runs (ADR §8.5)."""
    integration = CheckovIntegration(version="0.0.0")

    with pytest.raises(UnsupportedToolConfigError, match="no notion of scan history"):
        integration.build_command(workspace_path=".", config=ToolConfig(scan_history=True))
