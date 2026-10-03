"""Tests for `TrivyImageIntegration` (ADR §10) against golden fixtures (ADR §11).

See `tests/unit/fixtures/trivy_image/README.md` for how the fixtures and the
stderr samples below were captured from the real trivy binary.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linceo.adapters.trivy import TrivyDatabaseNotReadyError, TrivyOutputError
from linceo.adapters.trivy_image import (
    DockerDaemonUnavailableError,
    ImageNotInDaemonError,
    InvalidImageReferenceError,
    TrivyImageIntegration,
)
from linceo.core.findings import Category
from linceo.core.normalization import SeverityNormalizer, normalize_finding
from linceo.core.ports import ProcessResult
from linceo.core.severity_map import load_severity_map
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError
from linceo.testing import FakeToolExecutor

_FIXTURES = Path(__file__).parent / "fixtures" / "trivy_image"
_NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
_REF = "registry.example/app:1.2.3"

_STDERR_NO_SUCH_IMAGE = (
    'FATAL\tFatal error\trun error: ... unable to find the specified image "nosuch/image:1.0" '
    'in ["docker"]: 1 error occurred:\n\t* docker error: unable to inspect the image '
    "(nosuch/image:1.0): Error response from daemon: No such image: nosuch/image:1.0\n"
)
_STDERR_NO_SOCKET = (
    "\t* docker error: unable to inspect the image (x:1): failed to connect to the docker API "
    "at unix:///nonexistent.sock; check if the path is correct and if the daemon is running: "
    "dial unix /nonexistent.sock: connect: no such file or directory\n"
)
_STDERR_NO_PERMISSION = (
    "\t* docker error: unable to inspect the image (x:1): permission denied while trying to "
    "connect to the docker API at unix:///var/run/docker.sock\n"
)


def _integration(image: str = _REF) -> TrivyImageIntegration:
    return TrivyImageIntegration(image=image, version="0.74.0")


def _result(stdout: str = "", stderr: str = "", exit_code: int = 0) -> ProcessResult:
    return ProcessResult(
        exit_code=exit_code, stdout=stdout, stderr=stderr, started_at=_NOW, finished_at=_NOW
    )


def _fixture(name: str) -> ProcessResult:
    return _result((_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _report(*results: object) -> ProcessResult:
    return _result(json.dumps({"Results": list(results)}))


def test_build_command_is_offline_daemon_only_and_ends_with_the_image() -> None:
    argv = _integration().build_command(workspace_path="/w", config=ToolConfig())

    assert argv == (
        "trivy", "image", "--image-src", "docker", "--scanners", "vuln", "--format", "json",
        "--skip-db-update", "--disable-telemetry", "--skip-version-check",
        "--cache-backend", "memory", "--no-progress", _REF,
    )  # fmt: skip


def test_build_command_applies_exclude_paths_and_passthrough_after_the_image() -> None:
    config = ToolConfig(exclude_paths=("a", "b"), passthrough={"severity": "HIGH"})

    argv = _integration().build_command(workspace_path="/w", config=config)

    assert argv.count("--skip-dirs") == 2
    assert argv[argv.index(_REF) + 1 :] == ("--severity", "HIGH")


@pytest.mark.parametrize(
    "config", [ToolConfig(scan_history=True), ToolConfig(custom_rules_path="r")]
)
def test_build_command_rejects_fields_trivy_image_has_no_equivalent_for(
    config: ToolConfig,
) -> None:
    with pytest.raises(UnsupportedToolConfigError):
        _integration().build_command(workspace_path="/w", config=config)


@pytest.mark.parametrize("image", ["", "--input=x", "-v", "two words", "tab\tref"])
def test_an_invalid_image_reference_is_rejected(image: str) -> None:
    with pytest.raises(InvalidImageReferenceError):
        TrivyImageIntegration(image=image, version="0.74.0")


@pytest.mark.parametrize("image", ["app:1", "app@sha256:" + "a" * 64, "sha256:" + "b" * 64])
def test_tag_digest_and_id_references_are_accepted(image: str) -> None:
    assert _integration(image).image == image


def test_os_and_language_packages_share_one_shape() -> None:
    findings = _integration().parse_output(_fixture("os_and_gobinary"))

    assert {finding.category for finding in findings} == {Category.IMAGE}
    origins = [finding.location.path for finding in findings]
    assert origins == ["alpine", "alpine", "usr/bin/gitleaks", "usr/bin/gitleaks"]
    assert all((finding.location.layer or "").startswith("sha256:") for finding in findings)
    assert all(_REF not in finding.location.path for finding in findings)
    assert findings[0].package is not None
    assert findings[0].package.fixed_version == "1.36.1-r21"


def test_pkgpath_is_the_origin_when_trivy_reports_one() -> None:
    findings = _integration().parse_output(_fixture("os_and_python"))

    assert findings[0].location.path == "debian"
    assert findings[0].package is not None
    assert findings[0].package.fixed_version is None
    assert findings[1].location.path.endswith("pip-25.0.1.dist-info/METADATA")


def test_a_clean_image_produces_no_findings() -> None:
    assert _integration().parse_output(_fixture("empty")) == ()


def test_the_fingerprint_survives_a_different_image_reference_and_layer() -> None:
    normalizer = SeverityNormalizer.from_severity_map(load_severity_map())
    first = _fixture("os_and_gobinary")
    renamed = _result(
        first.stdout.replace("zricethezav/gitleaks:v8.24.2", "build:999").replace(
            "sha256:0499fc56f5e2", "sha256:ffffffffffff"
        )
    )

    one = [normalize_finding(r, normalizer) for r in _integration("a:1").parse_output(first)]
    two = [normalize_finding(r, normalizer) for r in _integration("b:2").parse_output(renamed)]

    assert [f.fingerprint for f in one] == [f.fingerprint for f in two]
    assert len({f.fingerprint for f in one}) == len(one)


def test_missing_layer_is_none() -> None:
    entry = {"Target": "t", "Class": "lang-pkgs", "Type": "jar", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1"},
        {"VulnerabilityID": "CVE-2", "PkgName": "p", "InstalledVersion": "1",
         "Layer": {"DiffID": 3}},
    ]}  # fmt: skip

    findings = _integration().parse_output(_report(entry))

    assert [f.location.layer for f in findings] == [None, None]
    assert findings[0].location.path == "t"


def test_an_os_result_without_a_type_is_a_parse_error() -> None:
    entry = {"Target": "x (alpine 3)", "Class": "os-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1"},
    ]}  # fmt: skip

    with pytest.raises(TrivyOutputError, match="Type"):
        _integration().parse_output(_report(entry))


def test_database_not_ready_is_reported_actionably() -> None:
    stderr = "--skip-db-update cannot be specified on the first run"

    with pytest.raises(TrivyDatabaseNotReadyError):
        _integration().parse_output(_result(stderr=stderr, exit_code=1))


@pytest.mark.parametrize("stderr", [_STDERR_NO_SOCKET, _STDERR_NO_PERMISSION])
def test_an_unreachable_daemon_names_both_fixes(stderr: str) -> None:
    with pytest.raises(DockerDaemonUnavailableError) as raised:
        _integration().parse_output(_result(stderr=stderr, exit_code=1))

    assert "DOCKER_HOST" in str(raised.value)
    assert "--group-add" in str(raised.value)


def test_a_missing_image_says_it_is_not_in_the_daemon() -> None:
    with pytest.raises(ImageNotInDaemonError) as raised:
        _integration("nosuch/image:1.0").parse_output(
            _result(stderr=_STDERR_NO_SUCH_IMAGE, exit_code=1)
        )

    message = str(raised.value)
    assert "'nosuch/image:1.0' is not in the local Docker daemon" in message
    assert "docker build" in message


def test_any_other_nonzero_exit_is_a_generic_parse_error() -> None:
    with pytest.raises(TrivyOutputError, match="status 2: boom"):
        _integration().parse_output(_result(stderr="boom", exit_code=2))
    with pytest.raises(TrivyOutputError, match="no stderr output"):
        _integration().parse_output(_result(exit_code=2))


@pytest.mark.parametrize(
    "stdout",
    ["{not json", "[]", '{"Results": {"a": 1}}', '{"Results": ["x"]}',
     '{"Results": [{"Vulnerabilities": {"a": 1}}]}', '{"Results": [{"Vulnerabilities": ["x"]}]}'],
)  # fmt: skip
def test_malformed_reports_are_parse_errors(stdout: str) -> None:
    with pytest.raises(TrivyOutputError):
        _integration().parse_output(_result(stdout))


def test_empty_stdout_is_no_findings() -> None:
    assert _integration().parse_output(_result("")) == ()


def test_detect_version_and_data_sources_delegate_to_the_trivy_probe() -> None:
    recorded = _result(
        '{"Version":"0.74.0","VulnerabilityDB":{"Version":2,'
        '"UpdatedAt":"2026-09-14T01:15:36.63677888Z"}}'
    )
    executor = FakeToolExecutor(recordings={("trivy", "version"): recorded})

    assert TrivyImageIntegration.detect_version(executor) == "0.74.0"
    [source] = TrivyImageIntegration.detect_data_sources(executor)
    assert source.name == "trivy-vulnerability-db"


def test_declarative_surface() -> None:
    integration = _integration()

    assert integration.build_env() == {}
    assert "trivy binary not found" in integration.missing_binary_hint()
    assert integration.data_sources() == ()
    assert "CRITICAL" in integration.native_severity_domain()
    schema = integration.report_schema()
    assert [column.header for column in schema.extra] == ["ORIGIN", "LAYER", "FIXED"]
    assert integration.name == "trivy"
    assert integration.category is Category.IMAGE
