"""End-to-end test of the Trivy image integration against the real binary (ADR §11).

Requires `trivy` on `PATH` with a vulnerability database already downloaded
and a reachable Docker daemon that already holds `hello-world:latest` (a
two-line image with no packages, so no network is needed to scan it). The
daemon-dependent tests are skipped, not failed, when no daemon is reachable.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

import pytest

from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.adapters.trivy_image import ImageNotInDaemonError, TrivyImageIntegration
from linceo.core.tool_config import ToolConfig

pytestmark = pytest.mark.integration

_IMAGE = "hello-world:latest"


def _daemon_has(image: str) -> bool:
    try:
        done = subprocess.run(  # noqa: S603
            ["docker", "image", "inspect", image],  # noqa: S607
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def _run(image: str) -> tuple[TrivyImageIntegration, object]:
    executor = SubprocessToolExecutor()
    integration = TrivyImageIntegration(
        image=image, version=TrivyImageIntegration.detect_version(executor)
    )
    argv = integration.build_command(workspace_path=".", config=ToolConfig())
    return integration, executor.run(argv, env={}, cwd=".", timeout=300)


def test_a_missing_image_is_reported_as_not_in_the_daemon() -> None:
    if not _daemon_has("hello-world:latest"):
        pytest.skip("no reachable Docker daemon holding hello-world:latest")
    integration, result = _run("linceo-nonexistent/image:0")

    with pytest.raises(ImageNotInDaemonError):
        integration.parse_output(result)  # type: ignore[arg-type]


def test_a_package_free_image_scans_clean() -> None:
    if not _daemon_has(_IMAGE):
        pytest.skip("no reachable Docker daemon holding hello-world:latest")
    started = datetime.now(UTC)
    integration, result = _run(_IMAGE)

    assert integration.parse_output(result) == ()  # type: ignore[arg-type]
    assert result.started_at >= started  # type: ignore[attr-defined]
