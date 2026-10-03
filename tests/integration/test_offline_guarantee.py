"""R2 as a verified mechanism: no registered `ToolIntegration` touches the network (ADR R2).

Every integration is run for real, under network isolation, against a small
workspace (and, for a category whose target is a container image, an image in
the local daemon), and the test fails if the tool attempts any connection.
The method is `tests/integration/network_probe.py`: a user+network namespace
with no real interface in which every outgoing packet, to any address and
port, is recorded — not a mock, and not a proxy the tool could ignore.

Why this exists: three separate integrations broke R2 while their own
`--skip-db-update`-style flag looked sufficient (checkov calling Prisma Cloud,
trivy calling `check.trivy.dev` from both `fs` and `image`), each found late
and by accident.

The set of integrations is *discovered*, never listed by hand: every class
under `linceo.adapters` that has the whole `ToolIntegration` surface, plus
anything registered under the `linceo.tool_integrations` entry point group. A
new integration is therefore covered the moment it exists. What the test
cannot know is how to construct it — a required constructor field it has no
input for makes it fail loudly rather than skip, which is the safe direction.

This test never skips for a missing prerequisite (no `unshare`, no binary, no
daemon): a guarantee that quietly turns itself off is the intention this test
replaces. Run it on a host where unprivileged user namespaces are allowed.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import os
import pkgutil
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

import linceo.adapters
from linceo.adapters.subprocess_executor import SubprocessToolExecutor
from linceo.core.ports import ProcessResult, ToolIntegration
from linceo.core.registry import TOOL_INTEGRATION_ENTRY_POINT_GROUP, PluginRegistry
from linceo.core.tool_config import ToolConfig

pytestmark = pytest.mark.integration

_PROBE = Path(__file__).with_name("network_probe.py")
_SAMPLE_REPO = Path(__file__).parents[2] / "scripts" / "e2e-verify" / "fixtures" / "sample-repo"
_IMAGE = "alpine:3.19"

#: What the harness can supply for a required constructor field of an
#: integration, by field name. `version` is always detected from the real binary.
_SURFACE = tuple(name for name in vars(ToolIntegration) if not name.startswith("_"))


def _has_integration_surface(candidate: object) -> bool:
    return inspect.isclass(candidate) and all(hasattr(candidate, name) for name in _SURFACE)


def _discover() -> list[type]:
    found: dict[str, type] = {}
    for module_info in pkgutil.iter_modules(linceo.adapters.__path__):
        module = importlib.import_module(f"linceo.adapters.{module_info.name}")
        for _, candidate in inspect.getmembers(module, inspect.isclass):
            if candidate.__module__ == module.__name__ and _has_integration_surface(candidate):
                found[f"{candidate.__module__}.{candidate.__qualname__}"] = candidate
    registry: PluginRegistry[object] = PluginRegistry.discover(
        entry_point_group=TOOL_INTEGRATION_ENTRY_POINT_GROUP
    )
    for name in registry:
        plugin = registry.get(name)
        if _has_integration_surface(plugin):
            assert inspect.isclass(plugin)
            found[f"{plugin.__module__}.{plugin.__qualname__}"] = plugin
    return [found[key] for key in sorted(found)]


_CLASSES = _discover()


def _run_isolated(argv: list[str], env: dict[str, str], cwd: str) -> dict[str, object]:
    spec = json.dumps({"argv": argv, "env": env, "cwd": cwd})
    launched = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            sys.executable,
            str(_PROBE),
            spec,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    try:
        report = json.loads(launched.stdout)
    except json.JSONDecodeError:
        pytest.fail(
            "could not start the network-isolated probe, so R2 cannot be verified here "
            "(needs `unshare` and unprivileged user namespaces): "
            f"{launched.stderr.strip() or launched.stdout.strip()}"
        )
    assert isinstance(report, dict)
    return report


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("offline") / "repo"
    shutil.copytree(_SAMPLE_REPO, path)
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.com"],
        ["config", "user.name", "T"],
        ["add", "-A"],
        ["commit", "-q", "-m", "fixture"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)  # noqa: S603, S607
    return path


@pytest.fixture(scope="module")
def isolated_environment(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """An empty `HOME`, so no tool can skip a network call because a warm cache says it already did.

    Checkov, for one, throttles its PyPI version check through a cache under
    `HOME`: with a developer's warm `HOME` it makes no call and a regression in
    its `CKV_SKIP_PACKAGE_UPDATE_CHECK` guard goes unnoticed; with an empty one
    it does. Without this, the result would depend on the state of whichever
    machine runs the test. The one thing a tool legitimately needs from the
    host is trivy's pre-fetched vulnerability database, handed over explicitly.
    """
    trivy_cache = os.environ.get("TRIVY_CACHE_DIR") or str(Path.home() / ".cache" / "trivy")
    return {
        "HOME": str(tmp_path_factory.mktemp("home")),
        "TRIVY_CACHE_DIR": trivy_cache,
    }


@pytest.fixture(scope="module")
def local_image() -> str:
    """An image in the local daemon — fetched here, outside the isolated namespace, if absent."""
    inspected = ["docker", "image", "inspect", _IMAGE]
    if subprocess.run(inspected, capture_output=True, check=False).returncode != 0:  # noqa: S603
        subprocess.run(["docker", "pull", "-q", _IMAGE], check=False, capture_output=True)  # noqa: S603, S607
    if subprocess.run(inspected, capture_output=True, check=False).returncode != 0:  # noqa: S603
        pytest.fail(f"the image-scan category needs {_IMAGE} in a reachable local Docker daemon")
    return _IMAGE


def _construct(cls: type, *, image: Callable[[], str]) -> ToolIntegration:
    kwargs: dict[str, object] = {}
    if not dataclasses.is_dataclass(cls):
        pytest.fail(f"{cls.__qualname__} is not a dataclass; teach this test how to build it")
    for field in dataclasses.fields(cls):
        required = (
            field.default is dataclasses.MISSING and field.default_factory is dataclasses.MISSING
        )
        if not required:
            continue
        if field.name == "version":
            kwargs["version"] = cls.detect_version(SubprocessToolExecutor())  # type: ignore[attr-defined]
        elif field.name == "image":
            kwargs["image"] = image()
        else:
            pytest.fail(
                f"{cls.__qualname__} requires constructor field {field.name!r}, which this test "
                "has no input for — add one so the integration's offline behavior is verified"
            )
    integration = cls(**kwargs)
    assert isinstance(integration, ToolIntegration)
    return integration


def test_the_probe_observes_a_connection_attempt() -> None:
    """Positive control: a blind probe would make every check below vacuous."""
    code = "import socket; s = socket.socket(); s.settimeout(2); s.connect(('203.0.113.9', 8443))"

    report = _run_isolated([sys.executable, "-c", code], {}, ".")

    assert report["attempts"] == ["tcp 203.0.113.9:8443"]


def test_the_probe_reports_nothing_for_a_process_that_stays_offline() -> None:
    report = _run_isolated([sys.executable, "-c", "pass"], {}, ".")

    assert report["attempts"] == []


def test_at_least_the_reference_integrations_are_discovered() -> None:
    names = {cls.__qualname__ for cls in _CLASSES}

    assert {"GitleaksIntegration", "TrivyIntegration", "CheckovIntegration"} <= names
    assert "TrivyImageIntegration" in names


@pytest.mark.parametrize("cls", _CLASSES, ids=lambda cls: cls.__qualname__)
def test_a_scan_makes_no_network_attempt(
    cls: type,
    workspace: Path,
    isolated_environment: dict[str, str],
    request: pytest.FixtureRequest,
) -> None:
    integration = _construct(cls, image=lambda: request.getfixturevalue("local_image"))
    argv = list(integration.build_command(workspace_path=str(workspace), config=ToolConfig()))

    started = datetime.now(UTC)
    environment = {**isolated_environment, **integration.build_env()}
    report = _run_isolated(argv, environment, str(workspace))

    assert report["attempts"] == [], (
        f"{cls.__qualname__} attempted network connections during a scan: {report['attempts']}"
    )
    # The scan must have really run to a usable result, or "no attempts" proves nothing.
    result = ProcessResult(
        exit_code=int(str(report["exit_code"])),
        stdout=str(report["stdout"]),
        stderr=str(report["stderr"]),
        started_at=started,
        finished_at=datetime.now(UTC),
    )
    integration.parse_output(result)
