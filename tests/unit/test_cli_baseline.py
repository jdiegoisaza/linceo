"""Tests for `linceo baseline init` (ADR §8.2): the CLI wired end to end.

Mirrors `tests/unit/test_cli_scan.py`/`test_cli_scan_sca.py`: every scenario
runs through `typer.testing.CliRunner`, and none needs a real `gitleaks` or
`trivy` binary — `SubprocessToolExecutor` is replaced with
`linceo.testing.FakeToolExecutor` (ADR §11), fed the same recorded fixtures
those two files already use.
"""

from __future__ import annotations

import subprocess
import tomllib
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from linceo.cli.main import app
from linceo.core.exit_codes import EXIT_CONFIGURATION_ERROR, EXIT_OK, EXIT_TOOL_EXECUTION_FAILED
from linceo.core.policy import (
    DEFAULT_BASELINE_EXPIRY_DAYS,
    DEFAULT_MAX_HORIZON_DAYS,
    baseline_wave_expiry,
    parse_policy_document,
)
from linceo.core.ports import ProcessResult
from linceo.core.severity import Severity
from linceo.testing import FakeToolExecutor

runner = CliRunner()
_NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=UTC)
_GITLEAKS_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
_TRIVY_FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
_CHECKOV_FIXTURES = Path(__file__).parent / "fixtures" / "checkov"

_GITLEAKS_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="8.30.1\n", stderr="", started_at=_NOW, finished_at=_NOW
)
_TRIVY_VERSION_RESULT = ProcessResult(
    exit_code=0,
    stdout='{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
    '"NextUpdate":"2026-09-20T00:00:00Z","UpdatedAt":"2026-09-14T01:15:36Z",'
    '"DownloadedAt":"2026-09-14T04:17:21Z"}}',
    stderr="",
    started_at=_NOW,
    finished_at=_NOW,
)
_CHECKOV_VERSION_RESULT = ProcessResult(
    exit_code=0, stdout="3.3.19\n", stderr="", started_at=_NOW, finished_at=_NOW
)


def _git(*args: str, cwd: Path) -> None:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    (path / "config.py").write_text("AWS_KEY = 'not-really-checked-by-the-fake-executor'\n")
    (path / "requirements.txt").write_text("certifi==2015.4.28\n")
    _git("add", "-A", cwd=path)
    _git("commit", "-q", "-m", "initial commit", cwd=path)
    return path


def _stub_executor_factory(recordings: Mapping[tuple[str, ...], ProcessResult]) -> object:
    def factory() -> FakeToolExecutor:
        return FakeToolExecutor(recordings=dict(recordings))

    return factory


def _findings_recordings(
    *, gitleaks_fixture: str, trivy_fixture: str, checkov_fixture: str = "empty.json"
) -> dict[tuple[str, ...], ProcessResult]:
    """`checkov_fixture` defaults to `empty.json`: every existing scenario here predates the
    `iac` category (ADR §1 amendment, 2026-09-21) and asserts specific gitleaks/trivy finding
    counts — an empty checkov result keeps those counts exactly as each test already expects,
    while still giving `_run_reference_scan`'s third integration real evidence to run against
    (a run with any `SKIPPED`/`FAILED` execution is `RunStatus.PARTIAL`, which `baseline init`
    refuses to write from, ADR §5)."""
    gitleaks_stdout = (_GITLEAKS_FIXTURES / gitleaks_fixture).read_text(encoding="utf-8")
    trivy_stdout = (_TRIVY_FIXTURES / trivy_fixture).read_text(encoding="utf-8")
    checkov_stdout = (_CHECKOV_FIXTURES / checkov_fixture).read_text(encoding="utf-8")
    return {
        ("gitleaks", "version"): _GITLEAKS_VERSION_RESULT,
        ("gitleaks", "detect"): ProcessResult(
            exit_code=1, stdout=gitleaks_stdout, stderr="", started_at=_NOW, finished_at=_NOW
        ),
        ("trivy", "version", "--format", "json"): _TRIVY_VERSION_RESULT,
        ("trivy", "fs"): ProcessResult(
            exit_code=0, stdout=trivy_stdout, stderr="", started_at=_NOW, finished_at=_NOW
        ),
        ("checkov", "--version"): _CHECKOV_VERSION_RESULT,
        ("checkov", "-d"): ProcessResult(
            exit_code=0, stdout=checkov_stdout, stderr="", started_at=_NOW, finished_at=_NOW
        ),
    }


def _patch_executor(
    monkeypatch: pytest.MonkeyPatch, recordings: Mapping[tuple[str, ...], ProcessResult]
) -> None:
    monkeypatch.setattr(
        "linceo.cli.baseline.SubprocessToolExecutor", _stub_executor_factory(recordings)
    )


class _FixedDateTime(datetime):
    """Stands in for `datetime` inside `linceo.cli.baseline` so `datetime.now(UTC)` returns `_NOW`.

    `init()` reads the wall clock exactly once, at the CLI boundary (ADR R3: no
    `core` module ever does) — this is the only way a test can pin that one real
    clock read to a fixed value, without threading a clock port through a whole
    CLI invocation just for this. Without it, `expires_at` values `baseline init`
    writes are computed from whatever the real wall clock happens to be when the
    test runs, not from `_NOW` — the exact non-determinism R3 exists to rule out.
    """

    @classmethod
    def now(cls, tz: object = None) -> datetime:  # type: ignore[override]  # noqa: ARG003
        return _NOW


def _patch_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze `linceo.cli.baseline`'s one real clock read at `_NOW`.

    Required by any test that asserts an exact `expires_at` (via
    `baseline_wave_expiry(today=_NOW.date(), ...)`) rather than just a
    relative bound — otherwise the assertion compares a value the CLI
    computed from the real, unpatched wall clock against one computed from
    `_NOW`, and the two silently drift apart a day at a time.
    """
    monkeypatch.setattr("linceo.cli.baseline.datetime", _FixedDateTime)


def test_owner_is_required(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "widgets")

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo)])

    assert result.exit_code != EXIT_OK
    assert "owner" in result.output.lower()


def test_writes_one_exclusion_per_active_finding_with_identity_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="one_finding.json"),
    )
    _patch_clock(monkeypatch)

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_OK, result.output
    output_path = repo / ".devsecops" / "config.toml"
    assert output_path.is_file()

    with output_path.open("rb") as f:
        document = tomllib.load(f)
    parsed = parse_policy_document(
        document, today=_NOW.date(), max_horizon_days=DEFAULT_MAX_HORIZON_DAYS
    )
    assert len(parsed.exclusions) == 2

    by_category = {
        exclusion.category.value: exclusion
        for exclusion in parsed.exclusions
        if exclusion.category is not None
    }
    secrets_entry = by_category["secrets"]
    assert secrets_entry.rule_id == "aws-access-token"
    assert secrets_entry.path == "config.py"
    assert secrets_entry.package is None
    assert secrets_entry.owner == "team-atlas"
    assert secrets_entry.reason == "Initial adoption baseline — pending real triage"
    # Both fixtures resolve to Severity.HIGH (gitleaks has no native severity
    # and falls to the `secrets` category default; trivy's fixture reports
    # native "HIGH") — same wave, but the exact date is derived per-entry
    # from its own fingerprint (`baseline_wave_expiry`), not asserted as a
    # single flat value.
    assert secrets_entry.expires_at == baseline_wave_expiry(
        severity=Severity.HIGH,
        fingerprint=secrets_entry.fingerprint,
        today=_NOW.date(),
        min_expiry_days=DEFAULT_BASELINE_EXPIRY_DAYS,
        max_expiry_days=DEFAULT_MAX_HORIZON_DAYS,
    )

    sca_entry = by_category["sca"]
    assert sca_entry.rule_id == "CVE-2023-37920"
    assert sca_entry.path == "requirements.txt"
    assert sca_entry.package == "certifi"
    assert sca_entry.package_version == "2015.4.28"
    assert sca_entry.expires_at == baseline_wave_expiry(
        severity=Severity.HIGH,
        fingerprint=sca_entry.fingerprint,
        today=_NOW.date(),
        min_expiry_days=DEFAULT_BASELINE_EXPIRY_DAYS,
        max_expiry_days=DEFAULT_MAX_HORIZON_DAYS,
    )


def test_clean_repository_writes_an_empty_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_OK
    assert "wrote an empty baseline" in result.output.lower()
    document = tomllib.loads((repo / ".devsecops" / "config.toml").read_text(encoding="utf-8"))
    assert document == {"version": 1}


def test_custom_reason_and_expiry_are_applied_to_every_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="one_finding.json"),
    )
    _patch_clock(monkeypatch)

    result = runner.invoke(
        app,
        [
            "baseline",
            "init",
            "--path",
            str(repo),
            "--owner",
            "team-atlas",
            "--reason",
            "Migrating from an older scanner",
            "--expires-in-days",
            "10",
        ],
    )

    assert result.exit_code == EXIT_OK
    document = tomllib.loads((repo / ".devsecops" / "config.toml").read_text(encoding="utf-8"))
    parsed = parse_policy_document(document, today=_NOW.date(), max_horizon_days=90)
    assert {e.reason for e in parsed.exclusions} == {"Migrating from an older scanner"}
    for exclusion in parsed.exclusions:
        # Both fixtures resolve to Severity.HIGH — not the first (most
        # urgent) band, so the custom `--expires-in-days 10` shows up as
        # the *base* of the wave schedule, not a flat value every entry
        # gets: each entry's actual date is later than day 10.
        assert exclusion.expires_at > _NOW.date() + timedelta(days=10)
        assert exclusion.expires_at == baseline_wave_expiry(
            severity=Severity.HIGH,
            fingerprint=exclusion.fingerprint,
            today=_NOW.date(),
            min_expiry_days=10,
            max_expiry_days=90,
        )


def test_custom_output_path_via_config_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    custom_path = tmp_path / "elsewhere" / "policy.toml"
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(
        app,
        [
            "baseline",
            "init",
            "--path",
            str(repo),
            "--owner",
            "team-atlas",
            "--config",
            str(custom_path),
        ],
    )

    assert result.exit_code == EXIT_OK
    assert custom_path.is_file()
    assert not (repo / ".devsecops").exists()


def test_declining_the_confirmation_aborts_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    existing_content = "version = 1\n\n[thresholds]\nhigh = 0\n"
    output_path.write_text(existing_content, encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"], input="n\n"
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Aborted" in result.output
    assert output_path.read_text(encoding="utf-8") == existing_content


def test_confirmation_names_what_already_exists_and_what_will_be_added(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prompt describes an additive merge, never an "overwrite" — nothing existing is at
    risk, so the message must not read as if it were (the bug this behavior replaces)."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("version = 1\n\n[thresholds]\nhigh = 0\n", encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"], input="n\n"
    )

    assert "already exists" in result.output
    assert "gate: configured" in result.output
    assert "ADD 1 new exclusion" in result.output
    assert "Nothing existing is modified or removed" in result.output
    assert "Overwrite" not in result.output


def test_accepting_the_confirmation_appends_and_preserves_everything_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regression this whole rewrite exists to fix: an existing [thresholds] gate and a
    prior exclusion must both survive a baseline init run untouched."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n"
        "\n"
        "[thresholds]\n"
        "critical = 0\n"
        "high = 0\n"
        "\n"
        "[[exclusions]]\n"
        'fingerprint = "v1:preexisting0000000000000000000000000000000000000000000000000000"\n'
        'reason = "Pre-existing, hand-curated exclusion"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n",
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"], input="y\n"
    )

    assert result.exit_code == EXIT_OK, result.output
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    assert document["thresholds"] == {"critical": 0, "high": 0}
    assert len(document["exclusions"]) == 2
    reasons = {e["reason"] for e in document["exclusions"]}
    assert "Pre-existing, hand-curated exclusion" in reasons
    assert "Initial adoption baseline — pending real triage" in reasons


def test_force_skips_the_confirmation_prompt_entirely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("version = 1\n", encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )

    assert result.exit_code == EXIT_OK
    assert "?" not in result.output  # no prompt was ever printed
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    assert len(document["exclusions"]) == 1


def test_missing_gitleaks_binary_refuses_to_write_a_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        {
            ("trivy", "version", "--format", "json"): _TRIVY_VERSION_RESULT,
            ("trivy", "fs"): ProcessResult(
                exit_code=0,
                stdout=(_TRIVY_FIXTURES / "empty.json").read_text(encoding="utf-8"),
                stderr="",
                started_at=_NOW,
                finished_at=_NOW,
            ),
        },
    )

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "incomplete evidence" in result.output
    assert "gitleaks" in result.output
    assert not (repo / ".devsecops").exists()


def test_a_path_that_is_not_a_git_repository_is_a_configuration_error(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(not_a_repo), "--owner", "team-atlas"]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Configuration error" in result.output


def test_rerunning_with_unchanged_findings_adds_nothing_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )
    first = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )
    assert first.exit_code == EXIT_OK, first.output
    output_path = repo / ".devsecops" / "config.toml"
    written_after_first = output_path.read_text(encoding="utf-8")

    second = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )

    assert second.exit_code == EXIT_OK, second.output
    assert "Nothing to add" in second.output
    assert output_path.read_text(encoding="utf-8") == written_after_first


def test_an_expired_existing_exclusion_is_not_silently_renewed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lapsed exclusion is ADR §8.2's own signal that a real decision is overdue — baseline
    init must leave it exactly as it is, not quietly generate a fresh replacement entry."""
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )
    first = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )
    assert first.exit_code == EXIT_OK, first.output
    output_path = repo / ".devsecops" / "config.toml"
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    assert len(document["exclusions"]) == 1

    # Force that one entry into the past, as if it had lapsed long ago.
    expired_text = output_path.read_text(encoding="utf-8").replace(
        f"expires_at = {document['exclusions'][0]['expires_at'].isoformat()}",
        "expires_at = 2020-01-01",
    )
    output_path.write_text(expired_text, encoding="utf-8")

    second = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )

    assert second.exit_code == EXIT_OK, second.output
    assert "Nothing to add" in second.output
    final_document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    assert len(final_document["exclusions"]) == 1
    assert final_document["exclusions"][0]["expires_at"].isoformat() == "2020-01-01"


def test_an_existing_file_that_is_not_valid_toml_is_refused_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("this is not [valid toml", encoding="utf-8")
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "not a valid policy document" in result.output
    assert output_path.read_text(encoding="utf-8") == "this is not [valid toml"


def test_confirmation_mentions_existing_tool_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n"
        "\n"
        "[[skipped_tools]]\n"
        'tool = "trivy"\n'
        'reason = "rollout paused"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n",
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas"], input="n\n"
    )

    assert "1 tool skip(s)" in result.output


def test_a_merged_document_that_would_be_invalid_is_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The safety net around the final write: even if the merge ever produced something
    invalid, nothing reaches `output_path` — proven by forcing exactly that."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("version = 1\n", encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )
    monkeypatch.setattr("linceo.cli.baseline.render_exclusion_fragment", lambda _: "not [valid\n")

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Refusing to write" in result.output
    assert output_path.read_text(encoding="utf-8") == "version = 1\n"
    assert not output_path.with_name("config.toml.tmp").exists()


def test_expired_existing_exclusions_are_noted_when_new_entries_are_also_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A genuinely new (secrets) finding still gets written even while a *different*,
    already-tracked (sca) finding's exclusion has separately expired — the note about the
    latter is informational, never blocking the former."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    # Exact fingerprint the `trivy/one_finding.json` fixture's CVE-2023-37920 (certifi
    # 2015.4.28, requirements.txt) resolves to — already tracked here, but expired.
    trivy_fingerprint = "v1:6fbe3a464caf3164645c917307ea984fcd586ce61b6e1b4da7dbf0b90af8cae4"
    output_path.write_text(
        "version = 1\n"
        "\n"
        "[[exclusions]]\n"
        f'fingerprint = "{trivy_fingerprint}"\n'
        'reason = "old"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2020-01-01\n",
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="one_finding.json"),
    )

    result = runner.invoke(
        app, ["baseline", "init", "--path", str(repo), "--owner", "team-atlas", "--force"]
    )

    assert result.exit_code == EXIT_OK, result.output
    assert "Wrote 1 new exclusion(s)" in result.output
    assert "1 existing exclusion(s)" in result.output
    assert "have expired" in result.output
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    assert len(document["exclusions"]) == 2


def test_expires_in_days_at_or_beyond_the_horizon_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    _patch_executor(
        monkeypatch, _findings_recordings(gitleaks_fixture="empty.json", trivy_fixture="empty.json")
    )

    result = runner.invoke(
        app,
        [
            "baseline",
            "init",
            "--path",
            str(repo),
            "--owner",
            "team-atlas",
            "--expires-in-days",
            "90",
        ],
    )

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "leaves no room to stagger" in result.output
    assert not (repo / ".devsecops").exists()


# --- baseline migrate (ADR §8.2, §5) ------------------------------------------


def test_migrate_with_no_existing_file_is_a_noop(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "widgets")

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo)])

    assert result.exit_code == EXIT_OK
    assert "Nothing to migrate" in result.output
    assert not (repo / ".devsecops").exists()


def test_migrate_with_only_current_version_exclusions_is_a_noop(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    content = (
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v1:preexisting0000000000000000000000000000000000000000000000000000"\n'
        'reason = "Accepted risk"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
    )
    output_path.write_text(content, encoding="utf-8")

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo)])

    assert result.exit_code == EXIT_OK
    assert "already on v1" in result.output
    assert output_path.read_text(encoding="utf-8") == content


def test_migrate_reindexes_an_orphaned_entry_preserving_reason_owner_and_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n',
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_OK, result.output
    assert f"Reindexed 1 exclusion(s) in {output_path}" in result.output
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    entry = document["exclusions"][0]
    assert entry["fingerprint"].startswith("v1:")
    assert entry["fingerprint"] != "v0:deadbeef"
    assert entry["reason"] == "Migrating from an older scanner"
    assert entry["owner"] == "team-atlas"
    assert entry["expires_at"] == date(2026, 12, 1)


def test_migrate_prints_a_future_tense_plan_then_a_past_tense_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan (shown before confirming) and the result (shown after writing) must read as
    two distinct moments, never the same text printed twice."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n',
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo)], input="y\n")

    assert result.exit_code == EXIT_OK, result.output
    assert "1 would be reindexed" in result.output
    assert f"Reindexed 1 exclusion(s) in {output_path}" in result.output
    assert result.output.count("would be reindexed") == 1
    assert result.output.count("Reindexed 1 exclusion(s)") == 1


def test_migrate_with_force_prints_only_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n',
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_OK, result.output
    assert "would be reindexed" not in result.output
    assert f"Reindexed 1 exclusion(s) in {output_path}" in result.output


def test_migrate_recovers_a_renamed_rule_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR §5: the same mechanism recovers a tool renaming its `rule_id` between versions."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-key-legacy"\n'  # the tool's old name for this rule
        'path = "config.py"\n',
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_OK, result.output
    assert "rule_id renamed" in result.output
    document = tomllib.loads(output_path.read_text(encoding="utf-8"))
    entry = document["exclusions"][0]
    assert entry["fingerprint"].startswith("v1:")
    assert entry["rule_id"] == "aws-access-token"


def test_migrate_leaves_an_unresolved_entry_untouched_and_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    original_content = (
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "no-longer-there.py"\n'
    )
    output_path.write_text(original_content, encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_OK, result.output
    assert "Unresolved" in result.output
    assert "v0:deadbeef" in result.output
    assert output_path.read_text(encoding="utf-8") == original_content


def test_migrate_leaves_an_out_of_scope_entry_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    original_content = (
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'repositories = ["some-other-repo"]\n'
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n'
    )
    output_path.write_text(original_content, encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_OK, result.output
    assert "out of scope" in result.output
    assert output_path.read_text(encoding="utf-8") == original_content


def test_migrate_preserves_everything_else_in_the_document_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    output_path.write_text(
        "version = 1\n"
        "\n"
        "# A hand-written comment that must survive untouched.\n"
        "[thresholds]\n"
        "critical = 0\n"
        "high = 0\n"
        "\n"
        "[[exclusions]]\n"
        'fingerprint = "v1:preexisting0000000000000000000000000000000000000000000000000000"\n'
        'reason = "Pre-existing, hand-curated exclusion"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        "\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n',
        encoding="utf-8",
    )
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_OK, result.output
    new_text = output_path.read_text(encoding="utf-8")
    assert "# A hand-written comment that must survive untouched.\n[thresholds]" in new_text
    assert "critical = 0\nhigh = 0" in new_text
    assert (
        'fingerprint = "v1:preexisting0000000000000000000000000000000000000000000000000000"'
        in new_text
    )
    assert 'reason = "Pre-existing, hand-curated exclusion"' in new_text
    assert 'fingerprint = "v0:deadbeef"' not in new_text


def test_migrate_refuses_when_the_scan_has_incomplete_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    original_content = (
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n'
    )
    output_path.write_text(original_content, encoding="utf-8")
    _patch_executor(
        monkeypatch,
        {
            ("trivy", "version", "--format", "json"): _TRIVY_VERSION_RESULT,
            ("trivy", "fs"): ProcessResult(
                exit_code=0,
                stdout=(_TRIVY_FIXTURES / "empty.json").read_text(encoding="utf-8"),
                stderr="",
                started_at=_NOW,
                finished_at=_NOW,
            ),
        },
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_TOOL_EXECUTION_FAILED
    assert "incomplete evidence" in result.output
    assert output_path.read_text(encoding="utf-8") == original_content


def test_migrate_with_no_exclusions_declared_is_a_noop(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    content = "version = 1\n\n[thresholds]\nhigh = 0\n"
    output_path.write_text(content, encoding="utf-8")

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo)])

    assert result.exit_code == EXIT_OK
    assert "declares no exclusions" in result.output
    assert output_path.read_text(encoding="utf-8") == content


def test_migrate_with_an_invalid_existing_document_is_a_configuration_error(
    tmp_path: Path,
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    content = "version = 1\nbogus_top_level_field = true\n"
    output_path.write_text(content, encoding="utf-8")

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo)])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "not a valid policy document" in result.output
    assert output_path.read_text(encoding="utf-8") == content


def test_migrate_refuses_and_leaves_the_file_untouched_when_it_cannot_locate_the_exact_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hand-edited entry using a triple-quoted string is unusual but valid TOML — the
    surgical replace only knows single-line basic/literal strings, so it must refuse rather
    than guess, and the atomic-write discipline must leave the file exactly as it was."""
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    original_content = (
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = """v0:deadbeef"""\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n'
    )
    output_path.write_text(original_content, encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo), "--force"])

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "could not locate the exact text to update" in result.output
    assert output_path.read_text(encoding="utf-8") == original_content
    assert not (repo / ".devsecops" / "config.toml.tmp").exists()


def test_migrate_declining_the_confirmation_aborts_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "widgets")
    output_path = repo / ".devsecops" / "config.toml"
    output_path.parent.mkdir(parents=True)
    original_content = (
        "version = 1\n\n"
        "[[exclusions]]\n"
        'fingerprint = "v0:deadbeef"\n'
        'reason = "Migrating from an older scanner"\n'
        'owner = "team-atlas"\n'
        "expires_at = 2026-12-01\n"
        'category = "secrets"\n'
        'rule_id = "aws-access-token"\n'
        'path = "config.py"\n'
    )
    output_path.write_text(original_content, encoding="utf-8")
    _patch_executor(
        monkeypatch,
        _findings_recordings(gitleaks_fixture="one_finding.json", trivy_fixture="empty.json"),
    )

    result = runner.invoke(app, ["baseline", "migrate", "--path", str(repo)], input="n\n")

    assert result.exit_code == EXIT_CONFIGURATION_ERROR
    assert "Aborted" in result.output
    assert output_path.read_text(encoding="utf-8") == original_content


def test_baseline_init_is_listed_in_help() -> None:
    root_help = runner.invoke(app, ["--help"])
    baseline_help = runner.invoke(app, ["baseline", "--help"])

    assert "baseline" in root_help.output
    assert "init" in baseline_help.output
    assert "migrate" in baseline_help.output
