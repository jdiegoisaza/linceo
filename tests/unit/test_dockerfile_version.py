"""Anti-drift check for `Dockerfile`'s `ARG LINCEO_VERSION` default (ADR §4/R4, docs/RELEASING.md).

A real release always overrides this default (`.github/workflows/release.yml`
passes `--build-arg LINCEO_VERSION=<version>`, derived from the pushed tag)
— the literal below only ever surfaces for a plain local `docker build`
with no override, exactly mirroring hatch-vcs's own fallback for a plain
local `uv build` with no git tag in scope
(`[tool.hatch.version.raw-options].fallback_version`, pyproject.toml).
Docker has no mechanism for an `ARG` default to read another file at build
time, so the two literals cannot be unified into one — this test is what
keeps them from silently drifting apart instead, the same anti-drift
pattern `tests/unit/test_cli_context.py`'s azure-pipelines-template check
already applies to a different hand-duplicated value.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_ARG_PATTERN = re.compile(r"^ARG LINCEO_VERSION=(?P<default>\S+)$", re.MULTILINE)


def _dockerfile_default() -> str:
    script = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    match = _ARG_PATTERN.search(script)
    assert match is not None, "Dockerfile no longer declares `ARG LINCEO_VERSION=<default>`"
    return match.group("default")


def _pyproject_fallback_version() -> str:
    document = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return document["tool"]["hatch"]["version"]["raw-options"]["fallback_version"]


def test_dockerfile_default_version_matches_hatch_vcs_fallback() -> None:
    """The two literals a plain local build (docker or uv) falls back to must agree.

    A release build never hits either value (both are overridden — the
    Dockerfile's by `release.yml`'s `--build-arg`, hatch-vcs's by the
    pushed tag itself) — this only guards the placeholder a developer
    with no tag in scope actually sees, from either build path.
    """
    dockerfile_default = _dockerfile_default()
    fallback_version = _pyproject_fallback_version()
    assert dockerfile_default == fallback_version, (
        f"Dockerfile's `ARG LINCEO_VERSION` default ({dockerfile_default!r}) no longer matches "
        f"pyproject.toml's `[tool.hatch.version.raw-options].fallback_version` "
        f"({fallback_version!r}) — a local `docker build` and a local `uv build`, both with no "
        "git tag in scope, must fall back to the exact same placeholder version."
    )
