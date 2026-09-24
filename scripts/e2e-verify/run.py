#!/usr/bin/env python3
"""End-to-end verification of linceo's real, published artifacts (ADR §4/R4).

Covers exactly what `uv run pytest` (791 tests) cannot: a real `uv tool
install` from PyPI, a real `docker pull` of the published image, real
container startup cost, the three tool integrations against real binaries
inside both distribution channels, a real (and a simulated) network
failure. Nothing this script exercises duplicates the unit suite or
`pytest -m integration` (`tests/integration/README.md`) — see this
project's own case list below for the map between "what" and "why here,
not there".

Lives in the repository, run by a person, on demand — never wired into
`.github/workflows/release.yml` (that decision is deliberately deferred
until this script's own numbers say whether it is fast enough to belong
there). `uv run scripts/e2e-verify/run.py` — no project dependencies beyond
the standard library, `uv`, `git`, and (for the container-mode cases,
gracefully optional) `docker`.

Two kinds of output, on purpose:

- `cases/<id>.md` — one normalized, ready-to-paste snippet per case,
  **versioned**: it is the evidence that README.md/docs/ADOPTION.md's own
  examples still match what the real binary produces, and its diff between
  two runs against two different releases is itself useful information (a
  changed reporter format shows up as a diff here, not as a surprise the
  next time someone reads the docs).
- `out/manifest.json` — everything raw and unnormalized (absolute paths,
  real timestamps, full stdout/stderr) for debugging a failed run.
  **Gitignored**: it is different on every single invocation by
  construction, so keeping it under version control would just be
  permanent diff noise with no informational content of its own.

See `README.md` in this same directory for what each case needs (network,
Docker, a PAT) and what it degrades to when that is missing — never a hard
failure: this script's own governing rule, stated once here because every
case below follows it, is that a prerequisite it cannot meet becomes a
reported *omission*, with its reason named, not a crashed run. A script
that only works when everything lines up perfectly is a script nobody
runs a second time.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import statistics
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from datetime import UTC, date, datetime
from pathlib import Path

import azure_policy
from capture import CaseResult, docker_available, omitted, run_capture
from normalize import apply_path_substitutions, normalize
from sample_repo import build_sample_repo

IMAGE = "ghcr.io/jdiegoisaza/linceo:latest"
CATEGORIES = ("secrets", "sca", "iac")

SCRIPT_DIR = Path(__file__).parent
CASES_DIR = SCRIPT_DIR / "cases"
OUT_DIR = SCRIPT_DIR / "out"

_HELP_COMMAND_LINE = re.compile(r"^\s{2}(\w[\w-]*)\s", re.MULTILINE)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repo",
        metavar="PATH",
        help=(
            "Scan this real repository instead of the generated one. Exploratory only: "
            "its output is never reproducible run to run, so it is written under out/ad-hoc/ "
            "and never touches the versioned cases/ directory."
        ),
    )
    parser.add_argument(
        "--container-startup-samples",
        type=int,
        default=5,
        metavar="N",
        help="How many `docker run --rm <image> --version` samples to take (default: 5).",
    )
    return parser.parse_args()


# --- uv tool install -----------------------------------------------------------


def _uv_tool_install(
    *, tool_dir: Path, bin_dir: Path, spec: str, case_id: str, description: str
) -> tuple[CaseResult, Path | None]:
    """`uv tool install <spec>` into an isolated location, returning the resulting executable.

    `UV_TOOL_DIR`/`UV_TOOL_BIN_DIR` are both set explicitly, to an
    isolated location per install, rather than left at `uv`'s own default
    (`~/.local/...`): this script installs *two* real variants (bare
    `linceo` and `linceo[remote-config]`) that both export a script
    literally named `linceo` — installing both into the same bin
    directory would make the second overwrite the first's symlink, and
    this script needs both to keep working side by side for the rest of
    the run.
    """
    tool_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "UV_TOOL_DIR": str(tool_dir), "UV_TOOL_BIN_DIR": str(bin_dir)}
    result = run_capture(
        case_id,
        description,
        ["uv", "tool", "install", spec],
        mode="setup",  # a real, documented step — not internal plumbing (see `_write_outputs`)
        env=env,
        timeout=180,
    )
    exe = bin_dir / "linceo"
    if result.status == "ok" and result.exit_code == 0 and exe.exists():
        return result, exe
    return result, None


# --- docker: pull, size, startup ------------------------------------------------


#: Docker's own human-readable size suffixes, as `docker history` prints
#: them (decimal, not binary — confirmed against a real image: `1.43GB` for
#: a layer independently measured at 1.4 GiB via `du`, within decimal
#: rounding).
_SIZE_SUFFIXES = {
    "B": 1,
    "kB": 1_000,
    "MB": 1_000_000,
    "GB": 1_000_000_000,
    "TB": 1_000_000_000_000,
}
_SIZE_PATTERN = re.compile(r"^([\d.]+)\s*(B|kB|MB|GB|TB)$")


def _parse_docker_size(text: str) -> int | None:
    match = _SIZE_PATTERN.match(text.strip())
    if match is None:
        return None
    return int(float(match.group(1)) * _SIZE_SUFFIXES[match.group(2)])


def _docker_pull_and_size() -> tuple[CaseResult, int | None]:
    """Pull the image and total its real size via `docker history` — not `docker image inspect`.

    Confirmed empirically, not assumed: on this same real image,
    `docker image inspect --format '{{.Size}}'` reported 316MB while
    `docker system df -v` and a `du` run *inside* the container both agreed
    on ~2.4GB (matching the ADR §10 amendment's own measurement of the
    locally-built image almost exactly — `/opt/linceo` alone is 1.8GB via
    `du`). Whatever this specific Docker installation's image store does
    differently for `.Size` (plausibly a containerd-snapshotter quirk,
    never fully diagnosed), `docker history`'s own per-layer sizes are what
    a person reading this script's own output would otherwise compute by
    hand — the same method the project maintainer used to produce the
    numbers ADR §10's amendment records, so this reproduces that method
    instead of trusting a single API field that already proved unreliable
    once.
    """
    result = run_capture(
        "docker-pull",
        f"docker pull {IMAGE}",
        ["docker", "pull", IMAGE],
        mode="container",
        timeout=900,
    )
    if result.status != "ok" or result.exit_code != 0:
        return result, None
    history = run_capture(
        "docker-history",
        "docker history (size — not a case of its own, folded into docker-pull's extra)",
        ["docker", "history", "--no-trunc", "--format", "{{.Size}}", IMAGE],
        mode="meta",
        timeout=30,
    )
    size = None
    if history.status == "ok" and history.exit_code == 0:
        parsed = [_parse_docker_size(line) for line in history.stdout.splitlines() if line.strip()]
        if parsed and all(value is not None for value in parsed):
            size = sum(value for value in parsed if value is not None)
    result.extra["image_size_bytes"] = size
    return result, size


def _container_startup(image: str, n: int) -> tuple[CaseResult, list[CaseResult]]:
    """`n` independent `docker run --rm <image> --version` timings, folded into one median case.

    `--version` rather than `--help` or a real scan: the cheapest real
    subcommand, so the measurement isolates container/interpreter/Typer
    startup from any work a scan or `doctor` would additionally do. Each
    individual sample runs for real and lands in `out/manifest.json`
    (`mode="meta"`, since a raw per-sample timing is not itself a CLI
    example anyone would paste into documentation) — this function's own
    return value is the one reader-facing case: the median plus the full
    spread, so a reader sees both "the typical cost" and "how noisy this
    measurement actually was" rather than a single number that looks more
    precise than five samples on a shared machine can honestly support.
    """
    samples = [
        run_capture(
            f"container-startup-sample-{i + 1}",
            f"docker run --rm {image} --version (sample {i + 1}/{n})",
            ["docker", "run", "--rm", image, "--version"],
            mode="meta",
            timeout=60,
        )
        for i in range(n)
    ]
    ok_samples = [s for s in samples if s.status == "ok" and s.duration_seconds is not None]
    durations = [s.duration_seconds for s in ok_samples if s.duration_seconds is not None]
    if not durations:
        aggregate = CaseResult(
            id="container-startup",
            description=f"docker run --rm {image} --version (median of {n} samples)",
            mode="container",
            argv=("docker", "run", "--rm", image, "--version"),
            status="failed_to_invoke",
            reason=f"none of {n} samples completed — see out/manifest.json for each sample's error",
        )
        return aggregate, samples
    # The displayed "output" is one real sample's actual stdout (the plain
    # version string, e.g. "0.9.0") — what a reader running this command
    # themselves would see — never the timing summary: the median, the
    # full spread, and every individual sample are real measurements this
    # script made of *this run*, not something the command itself prints,
    # and belong in `out/manifest.json` alone (`extra`, below), the one
    # place built specifically to hold numbers that are expected to differ
    # every time (this module's own docstring).
    aggregate = CaseResult(
        id="container-startup",
        description=f"docker run --rm {image} --version ({n} samples, fixed per-call cost)",
        mode="container",
        argv=("docker", "run", "--rm", image, "--version"),
        status="ok",
        exit_code=0,
        duration_seconds=statistics.median(durations),
        stdout=ok_samples[0].stdout,
        extra={
            "samples_seconds": durations,
            "median_seconds": statistics.median(durations),
            "min_seconds": min(durations),
            "max_seconds": max(durations),
        },
    )
    return aggregate, samples


# --- category availability probing ----------------------------------------------


def _available_categories(argv_prefix: Sequence[str]) -> tuple[set[str], CaseResult]:
    """Which `scan <category>` subcommands this specific linceo actually has.

    Parsed from `scan --help`'s own `Commands:` block rather than assumed
    from this script's own `CATEGORIES` constant — `iac` did not exist
    before linceo 0.9.0, and this script has no business assuming whatever
    release is installed/pulled already has it (ADR §1 amendment,
    2026-09-21: `iac` was added post-v0.1).
    """
    result = run_capture(
        "probe-scan-help",
        f"{shlex.join(argv_prefix)} scan --help",
        [*argv_prefix, "scan", "--help"],
        mode="meta",
        timeout=30,
    )
    if result.status != "ok" or result.exit_code != 0:
        return set(), result
    names = {match.group(1) for match in _HELP_COMMAND_LINE.finditer(result.stdout)}
    return names & set(CATEGORIES), result


# --- scan matrix argv builders ---------------------------------------------------


def _installed_scan_argv(
    exe: Path, category: str, *, repo_dir: Path, config_path: Path | None
) -> list[str]:
    argv = [str(exe), "scan", category, "--path", str(repo_dir)]
    if config_path is not None:
        argv += ["--config", str(config_path)]
    return argv


def _docker_env_flags(env: Mapping[str, str]) -> list[str]:
    """`-e NAME=value` for each pair — used only for non-secret values.

    A secret (the PAT) is never passed this way: it is forwarded by bare
    `-e NAME` instead, directly in the call sites that need it, so its
    value is read from the calling shell's own environment and never
    appears as a literal in this script's argv at all (ADR §9).
    """
    flags: list[str] = []
    for name, value in env.items():
        flags += ["-e", f"{name}={value}"]
    return flags


# --- output writing ---------------------------------------------------------------


def _render_case_markdown(
    result: CaseResult, *, path_substitutions: Sequence[tuple[str, str]], today: date
) -> str:
    """Render `result` as the versioned snippet — free of anything this script itself measured.

    `cases/*.md` is versioned specifically so a diff between two runs — or,
    more to the point, between two releases — means something
    (`run.py`'s own module docstring). A measured wall-clock number
    (`duration_seconds`, the individual `container-startup` samples, a
    median, a min/max spread) changes on *every* run regardless of
    anything about linceo itself, so it never belongs here: keeping it out
    is what makes a diff on this file mean "the reporter changed", not
    "this run happened to be 40ms slower". Every one of those numbers is
    still real, and still lands in `out/manifest.json` (`asdict(result)`,
    `_write_outputs`) — gitignored, one full copy per run, exactly the
    place built to hold a number that is expected to differ every time.
    `image_size_bytes` is kept here, deliberately not treated the same
    way: an image's size is not a measurement of *this run*, it is a real
    property of *the release being pulled* — stable across runs of the
    same tag, and a genuine, wanted diff signal the day it changes.
    """
    display_argv = [apply_path_substitutions(part, path_substitutions) for part in result.argv]
    lines = [f"# {result.description}", ""]
    lines.append(f"**Status:** {result.status}" + (f" — {result.reason}" if result.reason else ""))
    if result.exit_code is not None:
        lines.append(f"**Exit code:** {result.exit_code}")
    image_size = result.extra.get("image_size_bytes")
    if image_size is not None:
        lines.append(f"**Image size:** {image_size:,} bytes ({image_size / 1_000_000_000:.2f} GB)")
    lines.append("")
    if result.status != "omitted":
        lines.append("```bash")
        lines.append(shlex.join(display_argv))
        lines.append("```")
        lines.append("")
    stdout = apply_path_substitutions(result.stdout, path_substitutions)
    stdout = normalize(stdout, today=today)
    if stdout.strip():
        lines.append("```")
        lines.append(stdout.rstrip("\n"))
        lines.append("```")
        lines.append("")
    stderr = apply_path_substitutions(result.stderr, path_substitutions)
    stderr = normalize(stderr, today=today)
    if stderr.strip():
        lines.append("<details><summary>stderr</summary>")
        lines.append("")
        lines.append("```")
        lines.append(stderr.rstrip("\n"))
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def _write_outputs(
    results: list[CaseResult],
    *,
    path_substitutions: Sequence[tuple[str, str]],
    today: date,
    cases_dir: Path,
    out_dir: Path,
) -> None:
    """Write `out/manifest.json` (raw) and `cases/*.md` (normalized).

    `manifest.json` gets every path raw, on purpose — see this module's
    own docstring for why only `cases/*.md` is normalized at all.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = [asdict(result) for result in results]
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, default=str), encoding="utf-8"
    )

    cases_dir.mkdir(parents=True, exist_ok=True)
    for result in results:
        if result.mode == "meta":
            continue  # internal plumbing (installs, probes) — not a documented CLI example
        markdown = _render_case_markdown(result, path_substitutions=path_substitutions, today=today)
        (cases_dir / f"{result.id}.md").write_text(markdown, encoding="utf-8")


def _print_summary(results: list[CaseResult]) -> None:
    by_status: dict[str, int] = {}
    for result in results:
        by_status[result.status] = by_status.get(result.status, 0) + 1
    print()
    print("=== summary ===")
    for status in ("ok", "omitted", "failed_to_invoke"):
        if status in by_status:
            print(f"  {status}: {by_status[status]}")
    print()
    for result in results:
        if result.status == "omitted":
            print(f"  omitted  {result.id}: {result.reason}")
    print()
    timed = [r for r in results if r.duration_seconds is not None and r.mode != "meta"]
    for result in sorted(timed, key=lambda r: r.id):
        print(f"  {result.duration_seconds:7.2f}s  {result.id}")


# --- main --------------------------------------------------------------------------


def main() -> int:
    """Run every case in the checklist, in order, and write `cases/`/`out/manifest.json`."""
    args = _parse_args()
    today = datetime.now(UTC).date()
    results: list[CaseResult] = []

    workdir = Path(tempfile.mkdtemp(prefix="linceo-e2e-"))
    reproducible = args.repo is None
    if args.repo is not None:
        repo_dir = Path(args.repo).resolve()
        cases_dir = OUT_DIR / "ad-hoc" / "cases"
        print(f"Scanning real repository {repo_dir} — ad-hoc, not reproducible ({cases_dir})")
    else:
        repo_dir = workdir / "sample-repo"
        build_sample_repo(repo_dir)
        cases_dir = CASES_DIR

    (repo_dir / ".devsecops").mkdir(parents=True, exist_ok=True)
    remote_config_path = repo_dir / ".devsecops" / "policy-remote.toml"
    remote_config_path.write_text(azure_policy.REMOTE_POLICY_TOML, encoding="utf-8")
    remote_config_rel = str(remote_config_path.relative_to(repo_dir))

    docker_ok = docker_available()
    pat = azure_policy.pat_from_environment()

    # --- 1. Installation ------------------------------------------------------
    bare_exe: Path | None
    remote_exe: Path | None
    install_result, bare_exe = _uv_tool_install(
        tool_dir=workdir / "uv-tool-bare",
        bin_dir=workdir / "uv-tool-bare-bin",
        spec="linceo",
        case_id="install-pypi",
        description="uv tool install linceo (from PyPI)",
    )
    results.append(install_result)

    install_remote_result, remote_exe = _uv_tool_install(
        tool_dir=workdir / "uv-tool-remote-config",
        bin_dir=workdir / "uv-tool-remote-config-bin",
        spec="linceo[remote-config]",
        case_id="install-pypi-remote-config",
        description="uv tool install 'linceo[remote-config]' (from PyPI)",
    )
    results.append(install_remote_result)

    # --- 2/3. docker pull, container startup -----------------------------------
    if docker_ok:
        pull_result, _size = _docker_pull_and_size()
        results.append(pull_result)
        startup_aggregate, startup_samples = _container_startup(
            IMAGE, args.container_startup_samples
        )
        results.append(startup_aggregate)
        results.extend(startup_samples)
    else:
        results.append(
            omitted(
                "docker-pull",
                f"docker pull {IMAGE}",
                mode="container",
                argv=["docker", "pull", IMAGE],
                reason="docker not available on this machine",
            )
        )
        results.append(
            omitted(
                "container-startup",
                f"docker run --rm {IMAGE} --version",
                mode="container",
                argv=["docker", "run", "--rm", IMAGE, "--version"],
                reason="docker not available on this machine",
            )
        )

    # --- category availability ---------------------------------------------------
    installed_categories: set[str] = set()
    if bare_exe is not None:
        installed_categories, probe_result = _available_categories([str(bare_exe)])
        results.append(probe_result)
    container_categories: set[str] = set()
    if docker_ok:
        container_categories, probe_result = _available_categories(["docker", "run", "--rm", IMAGE])
        results.append(probe_result)

    # --- 4. scan matrix: category x mode x policy --------------------------------
    for category in CATEGORIES:
        for policy in ("local", "remote"):
            case_id = f"scan-{category}-installed-{policy}"
            description = f"linceo scan {category} --path <repo>" + (
                " --config <remote policy>" if policy == "remote" else ""
            )
            if bare_exe is None:
                results.append(
                    omitted(
                        case_id,
                        description,
                        mode="installed",
                        argv=[],
                        reason="uv tool install linceo failed",
                    )
                )
            elif category not in installed_categories:
                results.append(
                    omitted(
                        case_id,
                        description,
                        mode="installed",
                        argv=[],
                        reason=f"not available in this release (no `scan {category}` command)",
                    )
                )
            elif policy == "remote" and pat is None:
                results.append(
                    omitted(
                        case_id,
                        description,
                        mode="installed",
                        argv=[],
                        reason=f"{azure_policy.PAT_ENV_VAR} not set in the environment",
                    )
                )
            else:
                exe = remote_exe if policy == "remote" else bare_exe
                if policy == "remote" and exe is None:
                    results.append(
                        omitted(
                            case_id,
                            description,
                            mode="installed",
                            argv=[],
                            reason="uv tool install 'linceo[remote-config]' failed",
                        )
                    )
                else:
                    # Narrows `exe: Path | None` for the type checker: this branch is
                    # only reached once both `exe is None` cases above have already
                    # returned — never a test assertion (S101 does not apply).
                    assert exe is not None  # noqa: S101
                    config_path = remote_config_path if policy == "remote" else None
                    argv = _installed_scan_argv(
                        exe, category, repo_dir=repo_dir, config_path=config_path
                    )
                    env = dict(os.environ)
                    if policy == "remote":
                        env["SYSTEM_COLLECTIONURI"] = azure_policy.ORG_URL
                        env["LINCEO_POLICY_CACHE_DIR"] = str(workdir / f"policy-cache-{case_id}")
                    results.append(
                        run_capture(case_id, description, argv, mode="installed", env=env)
                    )

            case_id = f"scan-{category}-container-{policy}"
            description = f"docker run ... {IMAGE} scan {category}" + (
                " --config <remote policy>" if policy == "remote" else ""
            )
            if not docker_ok:
                results.append(
                    omitted(
                        case_id,
                        description,
                        mode="container",
                        argv=[],
                        reason="docker not available on this machine",
                    )
                )
            elif category not in container_categories:
                results.append(
                    omitted(
                        case_id,
                        description,
                        mode="container",
                        argv=[],
                        reason=f"not available in this release (no `scan {category}` command)",
                    )
                )
            elif policy == "remote" and pat is None:
                results.append(
                    omitted(
                        case_id,
                        description,
                        mode="container",
                        argv=[],
                        reason=f"{azure_policy.PAT_ENV_VAR} not set in the environment",
                    )
                )
            else:
                argv = ["docker", "run", "--rm", "-v", f"{repo_dir}:/workspace"]
                if policy == "remote":
                    cache_dir = workdir / f"policy-cache-{case_id}"
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    argv += ["-v", f"{cache_dir}:/policy-cache"]
                    argv += _docker_env_flags(
                        {
                            "SYSTEM_COLLECTIONURI": azure_policy.ORG_URL,
                            "LINCEO_POLICY_CACHE_DIR": "/policy-cache",
                        }
                    )
                    argv += ["-e", azure_policy.PAT_ENV_VAR]
                argv += [IMAGE, "scan", category]
                if policy == "remote":
                    argv += ["--config", f"/workspace/{remote_config_rel}"]
                results.append(run_capture(case_id, description, argv, mode="container"))

    # --- 5. doctor / context ------------------------------------------------------
    if bare_exe is not None:
        results.append(
            run_capture(
                "doctor-installed", "linceo doctor", [str(bare_exe), "doctor"], mode="installed"
            )
        )
        results.append(
            run_capture(
                "context-installed",
                "linceo context --path <repo>",
                [str(bare_exe), "context", "--path", str(repo_dir)],
                mode="installed",
            )
        )
    else:
        for cid, desc in (
            ("doctor-installed", "linceo doctor"),
            ("context-installed", "linceo context"),
        ):
            results.append(
                omitted(
                    cid, desc, mode="installed", argv=[], reason="uv tool install linceo failed"
                )
            )

    if docker_ok:
        results.append(
            run_capture(
                "doctor-container",
                f"docker run --rm {IMAGE} doctor",
                ["docker", "run", "--rm", IMAGE, "doctor"],
                mode="container",
            )
        )
        results.append(
            run_capture(
                "context-container",
                f"docker run --rm -v <repo>:/workspace {IMAGE} context",
                ["docker", "run", "--rm", "-v", f"{repo_dir}:/workspace", IMAGE, "context"],
                mode="container",
            )
        )
    else:
        for cid, desc in (
            ("doctor-container", "linceo doctor (container)"),
            ("context-container", "linceo context (container)"),
        ):
            results.append(
                omitted(
                    cid,
                    desc,
                    mode="container",
                    argv=[],
                    reason="docker not available on this machine",
                )
            )

    # --- 6. degradation: remote policy, network down, with/without cache --------
    # Always exercised, never gated on a PAT (the whole point — a script that
    # needs a credential to prove its own failure path is a script nobody
    # trusts the failure path of).
    for cache_state in ("with-cache", "no-cache"):
        cache_label = cache_state.replace("-", " ")
        case_id = f"remote-policy-degraded-{cache_state}-installed"
        description = (
            f"linceo scan secrets --config <remote policy>, network unreachable, {cache_label}"
        )
        if remote_exe is None:
            results.append(
                omitted(
                    case_id,
                    description,
                    mode="installed",
                    argv=[],
                    reason="uv tool install 'linceo[remote-config]' failed",
                )
            )
        else:
            cache_dir = workdir / f"policy-cache-{case_id}"
            if cache_state == "with-cache":
                azure_policy.fabricate_cache(cache_dir, org_url=azure_policy.UNREACHABLE_ORG_URL)
            else:
                cache_dir.mkdir(parents=True, exist_ok=True)
            env = {k: v for k, v in os.environ.items() if k != azure_policy.PAT_ENV_VAR}
            env["SYSTEM_COLLECTIONURI"] = azure_policy.UNREACHABLE_ORG_URL
            env["LINCEO_POLICY_CACHE_DIR"] = str(cache_dir)
            argv = _installed_scan_argv(
                remote_exe, "secrets", repo_dir=repo_dir, config_path=remote_config_path
            )
            results.append(run_capture(case_id, description, argv, mode="installed", env=env))

        case_id = f"remote-policy-degraded-{cache_state}-container"
        description = f"docker run --network none ... scan secrets --config <remote>, {cache_label}"
        if not docker_ok:
            results.append(
                omitted(
                    case_id,
                    description,
                    mode="container",
                    argv=[],
                    reason="docker not available on this machine",
                )
            )
        else:
            cache_dir = workdir / f"policy-cache-{case_id}"
            if cache_state == "with-cache":
                azure_policy.fabricate_cache(cache_dir, org_url=azure_policy.ORG_URL)
            else:
                cache_dir.mkdir(parents=True, exist_ok=True)
            argv = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{repo_dir}:/workspace",
                "-v",
                f"{cache_dir}:/policy-cache",
                "-e",
                f"SYSTEM_COLLECTIONURI={azure_policy.ORG_URL}",
                "-e",
                "LINCEO_POLICY_CACHE_DIR=/policy-cache",
                IMAGE,
                "scan",
                "secrets",
                "--config",
                f"/workspace/{remote_config_rel}",
            ]
            results.append(run_capture(case_id, description, argv, mode="container"))

    # --- write + summarize -------------------------------------------------------
    # Order matters (`apply_path_substitutions`'s own docstring): the
    # installed executables and the generated repository first, `workdir`
    # itself last, since it is a *prefix* of every one of the others (it is
    # this whole run's own top-level temp directory — `uv-tool-bare-bin`,
    # `policy-cache-*`, `sample-repo` all live under it) — replacing it
    # first would leave the more specific ones only partially matched.
    # Without this, every `cases/*.md` command line and every `uv` warning
    # that mentions its own install location would carry a fresh temp path
    # every single run — exactly the diff noise this normalization exists
    # to remove, the same principle as the timing fix above, just for
    # paths instead of durations.
    path_substitutions: list[tuple[str, str]] = []
    if bare_exe is not None:
        path_substitutions.append((str(bare_exe), "linceo"))
    if remote_exe is not None:
        path_substitutions.append((str(remote_exe), "linceo"))
    path_substitutions.append((str(repo_dir), "<WORKSPACE>"))
    path_substitutions.append((str(workdir), "<RUNDIR>"))

    out_dir = OUT_DIR if reproducible else OUT_DIR / "ad-hoc"
    _write_outputs(
        results,
        path_substitutions=path_substitutions,
        today=today,
        cases_dir=cases_dir,
        out_dir=out_dir,
    )
    _print_summary(results)
    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
