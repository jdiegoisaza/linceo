"""End-to-end test of the Gitleaks integration against the real binary (ADR §11).

Unlike `tests/unit/test_gitleaks.py` (golden fixtures, no binary required),
this exercises the real `gitleaks` binary through `SubprocessToolExecutor`,
`LocalContextProvider`, and `linceo.core.engine.run` together — the same
composition `linceo scan secrets` wires up — against small, disposable git
repositories created for this test. Requires `gitleaks` on `PATH`; see
`tests/integration/README.md`.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.adapters.gitleaks import GitleaksIntegration
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.core.config import Config
from linceo.core.engine import run
from linceo.core.execution import ExecutionStatus
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.results import RunStatus
from linceo.providers.local import LocalContextProvider

pytestmark = pytest.mark.integration


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


def test_detect_version_reports_the_real_installed_gitleaks_version() -> None:
    executor = SubprocessToolExecutor()

    version = GitleaksIntegration.detect_version(executor)

    assert version
    assert version[0].isdigit()


def test_a_clean_repository_produces_no_findings(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "clean-repo")
    (repo / "app.py").write_text("print('hello world')\n")
    _commit_all(repo, "initial commit")

    executor = SubprocessToolExecutor()
    integration = GitleaksIntegration(version=GitleaksIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo)), env={}, cwd=str(repo)
    )

    findings = integration.parse_output(process_result)

    assert findings == ()


def test_a_committed_secret_is_detected_with_its_hash_not_its_plaintext(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "leaky-repo")
    # Synthetic, gitleaks-rule-shaped value — not a real credential.
    secret_value = "AKIAQPFM3ZXVJ7HKQZ2A"  # noqa: S105
    (repo / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{secret_value}"\n')
    _commit_all(repo, "add aws config (synthetic test fixture, not a real credential)")

    executor = SubprocessToolExecutor()
    integration = GitleaksIntegration(version=GitleaksIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo)), env={}, cwd=str(repo)
    )

    findings = integration.parse_output(process_result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "aws-access-token"
    assert finding.location.path == "config.py"
    assert secret_value not in repr(finding)
    assert finding.secret_hash is not None


def test_scan_secrets_end_to_end_through_the_engine_against_a_real_repository(
    tmp_path: Path,
) -> None:
    """The same composition `linceo scan secrets` wires up (ADR §8, §10), run for real."""
    repo = _init_repo(tmp_path / "widgets")
    secret_value = "AKIAQPFM3ZXVJ7HKQZ2A"  # noqa: S105
    (repo / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{secret_value}"\n')
    _commit_all(repo, "add aws config (synthetic test fixture, not a real credential)")

    executor = SubprocessToolExecutor()
    integration = GitleaksIntegration(version=GitleaksIntegration.detect_version(executor))

    result = run(
        run_id="integration-test-run",
        context_provider=LocalContextProvider(workspace_path=str(repo)),
        integrations={Category.SECRETS: integration},
        executor=executor,
        normalizer=SeverityNormalizer(),
        config=Config(),
        now=datetime.now(UTC),
    )

    assert result.status is RunStatus.COMPLETED
    assert result.executions[0].status is ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "aws-access-token"
    assert result.context.repository == "widgets"
