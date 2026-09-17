"""End-to-end test of the Trivy integration against the real binary (ADR §11).

Unlike `tests/unit/test_trivy.py` (golden fixtures, no binary required), this
exercises the real `trivy` binary through `SubprocessToolExecutor`,
`LocalContextProvider`, and `linceo.core.engine.run` together — the same
composition `linceo scan sca` wires up — against small, disposable
`requirements.txt` files pinning real, long-patched PyPI packages to old,
vulnerable versions. Requires `trivy` on `PATH` with a vulnerability database
already downloaded; see `tests/integration/README.md`.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy import TrivyDatabaseNotReadyError, TrivyIntegration
from linceo.core.config import Config
from linceo.core.engine import run
from linceo.core.execution import ExecutionStatus
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer
from linceo.core.results import RunStatus
from linceo.core.tool_config import ToolConfig
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


def test_detect_version_reports_the_real_installed_trivy_version() -> None:
    executor = SubprocessToolExecutor()

    version = TrivyIntegration.detect_version(executor)

    assert version
    assert version[0].isdigit()


def test_detect_data_sources_reports_the_real_cached_database_metadata() -> None:
    """Requires a database already fetched once (`trivy fs --download-db-only`, ADR §5)."""
    executor = SubprocessToolExecutor()

    [source] = TrivyIntegration.detect_data_sources(executor)

    assert source.name == "trivy-vulnerability-db"
    assert source.built_at is not None


def test_a_clean_manifest_produces_no_findings(tmp_path: Path) -> None:
    repo = tmp_path / "clean-repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("six==1.16.0\n")

    executor = SubprocessToolExecutor()
    integration = TrivyIntegration(version=TrivyIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo), config=ToolConfig()),
        env={},
        cwd=str(repo),
        timeout=None,
    )

    findings = integration.parse_output(process_result)

    assert findings == ()


def test_a_vulnerable_pin_is_detected_with_its_real_package_identity(tmp_path: Path) -> None:
    repo = tmp_path / "vulnerable-repo"
    repo.mkdir()
    # A real, long-patched PyPI package pinned to an old, genuinely
    # vulnerable version — not a synthetic value (unlike gitleaks'
    # synthetic secrets: a vulnerability identifier cannot be synthesized
    # the way a fake credential can).
    (repo / "requirements.txt").write_text("certifi==2015.4.28\n")

    executor = SubprocessToolExecutor()
    integration = TrivyIntegration(version=TrivyIntegration.detect_version(executor))
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo), config=ToolConfig()),
        env={},
        cwd=str(repo),
        timeout=None,
    )

    findings = integration.parse_output(process_result)

    assert len(findings) >= 1
    finding = findings[0]
    assert finding.package is not None
    assert finding.package.name == "certifi"
    assert finding.package.version == "2015.4.28"
    assert finding.location.path == "requirements.txt"
    assert finding.raw_severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}


def test_scan_sca_end_to_end_through_the_engine_against_a_real_workspace(tmp_path: Path) -> None:
    """The same composition `linceo scan sca` wires up (ADR §8, §10), run for real."""
    repo = _init_repo(tmp_path / "widgets")
    (repo / "requirements.txt").write_text("certifi==2015.4.28\n")
    _commit_all(repo, "pin a known-vulnerable certifi version (real CVE, not synthetic)")

    executor = SubprocessToolExecutor()
    integration = TrivyIntegration(
        version=TrivyIntegration.detect_version(executor),
        db_data_sources=TrivyIntegration.detect_data_sources(executor),
    )

    result = run(
        run_id="integration-test-run",
        context_provider=LocalContextProvider(workspace_path=str(repo)),
        integrations={Category.SCA: integration},
        executor=executor,
        normalizer=SeverityNormalizer(),
        config=Config(),
        now=datetime.now(UTC),
    )

    assert result.status is RunStatus.COMPLETED
    assert result.executions[0].status is ExecutionStatus.COMPLETED
    assert len(result.findings) >= 1
    assert result.findings[0].package is not None
    assert result.executions[0].data_sources  # ADR §5: the database's own date always travels


# --- per-integration configuration against the real binary (ADR §8.5) --------


def test_exclude_paths_skips_a_vulnerable_manifest_in_that_directory(tmp_path: Path) -> None:
    """`exclude_paths` -> `--skip-dirs`: unlike gitleaks, trivy has a real flag for this."""
    repo = tmp_path / "skip-dirs-repo"
    (repo / "vendor").mkdir(parents=True)
    (repo / "vendor" / "requirements.txt").write_text("certifi==2015.4.28\n")

    executor = SubprocessToolExecutor()
    integration = TrivyIntegration(version=TrivyIntegration.detect_version(executor))

    def _scan(*, config: ToolConfig) -> tuple[object, ...]:
        process_result = executor.run(
            integration.build_command(workspace_path=str(repo), config=config),
            env={},
            cwd=str(repo),
            timeout=None,
        )
        return tuple(integration.parse_output(process_result))

    assert len(_scan(config=ToolConfig())) >= 1  # unexcluded: the vulnerable pin is found
    assert _scan(config=ToolConfig(exclude_paths=("vendor/",))) == ()  # excluded: gone


def test_database_not_ready_is_reported_with_an_actionable_hint(tmp_path: Path) -> None:
    """ADR R2/§5: pointing at a cache dir with no database reproduces the real first-run error."""
    repo = tmp_path / "widgets"
    repo.mkdir()
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    empty_cache_dir = tmp_path / "empty-trivy-cache"
    empty_cache_dir.mkdir()

    executor = SubprocessToolExecutor()
    integration = TrivyIntegration(version=TrivyIntegration.detect_version(executor))
    config = ToolConfig(passthrough={"cache-dir": str(empty_cache_dir)})
    process_result = executor.run(
        integration.build_command(workspace_path=str(repo), config=config),
        env={},
        cwd=str(repo),
        timeout=None,
    )

    with pytest.raises(TrivyDatabaseNotReadyError, match="download"):
        integration.parse_output(process_result)
