"""Trivy image integration: vulnerabilities in a built image via `trivy image` (ADR §10).

The `image` category scans the packages *inside* a container image that is
already present in the local Docker daemon — OS packages and language
packages alike. It is not `iac`: Checkov already covers the files that
describe a container (Dockerfile, Kubernetes manifests); this category
covers what was actually built.

Offline by construction (ADR R2), each point verified against the real
trivy 0.74.0 binary rather than assumed:

- `--image-src docker` is always passed. trivy's default source list ends
  in `remote`, so an image missing from the daemon makes it contact the
  registry (observed: three connections to `index.docker.io`).
- `--disable-telemetry` *and* `--skip-version-check` are both passed. Each
  alone still connects to `check.trivy.dev`; only the pair silences it.
- `--cache-backend memory` is passed because `trivy image` otherwise writes
  its layer-analysis cache under the cache directory, which is read-only
  for the non-root user of the reference container image.

Docker is a hard prerequisite of this category, unlike the other three.
trivy talks to the daemon API directly (no `docker` CLI is needed), so the
prerequisite is exactly "a reachable daemon socket". Failing to reach one,
or not finding the image in it, raises an error naming the fix for both
distribution modes (package install and reference container).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from linceo.adapters.trivy import (
    _DB_NOT_READY_MARKER,
    TRIVY_BINARY,
    TRIVY_DB_NOT_READY_HINT,
    TRIVY_MISSING_BINARY_HINT,
    TRIVY_NATIVE_SEVERITY_DOMAIN,
    TRIVY_OFFLINE_FLAGS,
    TRIVY_TOOL_NAME,
    TrivyDatabaseNotReadyError,
    TrivyIntegration,
    TrivyOutputError,
)
from linceo.core.execution import DataSource, ToolExecutionError
from linceo.core.findings import Category, Location, RawFinding
from linceo.core.ports import ProcessResult, ToolExecutor
from linceo.core.report_schema import Column, ReportSchema, Truncate
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, render_passthrough_flags

#: The `image` report table (ADR §7): `LOCATION` is `package@installed_version`
#: like `sca`; `ORIGIN` is where in the image the package lives (also a
#: fingerprint ingredient), `LAYER` the layer diff ID (display only; 19
#: characters shows `sha256:` plus 12 hex digits), `FIXED` the fixing version.
_REPORT_SCHEMA = ReportSchema(
    location=Column(header="LOCATION", fields=("package.name", "package.version"), separator="@"),
    extra=(
        Column(header="ORIGIN", fields=("location.path",), truncate=Truncate.LEFT),
        Column(header="LAYER", fields=("location.layer",), max_width=19),
        Column(header="FIXED", fields=("package.fixed_version",), missing="(none)"),
    ),
)

#: Substring of trivy's stderr when the daemon socket cannot be used, both
#: for a missing socket ("failed to connect to the docker API") and a
#: permission failure ("permission denied while trying to connect to the
#: docker API") — captured from the real binary.
_DAEMON_UNREACHABLE_MARKER = "connect to the docker API"

#: Substring of trivy's stderr when the daemon answered but has no such image.
_IMAGE_NOT_FOUND_MARKER = "No such image"

DOCKER_DAEMON_UNAVAILABLE_HINT = (
    "linceo's image scan needs a reachable Docker daemon — it reads the image from the "
    "daemon and never pulls it (ADR R2). Fix it with one of:\n"
    "  - installed from PyPI: start Docker, make sure your user may use its socket "
    "(e.g. the `docker` group), or point DOCKER_HOST at the right daemon\n"
    "  - reference container image: run it with the socket mounted and its group added, "
    "e.g. `-v /var/run/docker.sock:/var/run/docker.sock "
    "--group-add $(stat -c %g /var/run/docker.sock)`"
)


class InvalidImageReferenceError(ValueError):
    """The image reference is empty, contains whitespace, or could be read as a flag."""


class DockerDaemonUnavailableError(ToolExecutionError):
    """trivy could not reach the Docker daemon (see `DOCKER_DAEMON_UNAVAILABLE_HINT`)."""


class ImageNotInDaemonError(ToolExecutionError):
    """The requested image is not present in the local Docker daemon."""


@dataclass(slots=True)
class TrivyImageIntegration:
    """Thin `ToolIntegration` adapter around `trivy image` for one local-daemon image.

    `image` is the reference as the daemon knows it (`name:tag`,
    `name@sha256:...`, or an image ID). It is constructor data, not a
    `build_command` argument: the port's `workspace_path` has no meaning for
    this category and is accepted only to satisfy it.
    """

    image: str
    version: str
    db_data_sources: tuple[DataSource, ...] = ()
    cvss_source_preference: tuple[str, ...] = ("nvd",)
    name: str = TRIVY_TOOL_NAME
    category: Category = Category.IMAGE

    @property
    def _sca(self) -> TrivyIntegration:
        """The `sca` integration whose vulnerability-entry parsing this category reuses."""
        return TrivyIntegration(
            version=self.version, cvss_source_preference=self.cvss_source_preference
        )

    def __post_init__(self) -> None:
        """Reject a reference that trivy could parse as a flag or that cannot be one."""
        if not self.image or self.image.startswith("-") or any(c.isspace() for c in self.image):
            msg = (
                f"invalid image reference {self.image!r}: expected a non-empty name:tag, "
                "name@digest or image ID without whitespace, not starting with '-'"
            )
            raise InvalidImageReferenceError(msg)

    @staticmethod
    def detect_version(executor: ToolExecutor) -> str:
        """Detect the installed trivy version — same binary as `TrivyIntegration`."""
        return TrivyIntegration.detect_version(executor)

    @staticmethod
    def detect_data_sources(executor: ToolExecutor) -> tuple[DataSource, ...]:
        """Detect the cached vulnerability database — same database as `TrivyIntegration`."""
        return TrivyIntegration.detect_data_sources(executor)

    def missing_binary_hint(self) -> str:
        """Satisfy `ToolIntegration.missing_binary_hint` with trivy's install hint."""
        return TRIVY_MISSING_BINARY_HINT

    def build_env(self) -> Mapping[str, str]:
        """Satisfy `ToolIntegration.build_env`: every offline guarantee is a real flag."""
        return {}

    def build_command(
        self,
        *,
        workspace_path: str,  # noqa: ARG002 - the port passes it; the target is the image
        config: ToolConfig,
    ) -> Sequence[str]:
        """Build the `trivy image` argv for `self.image`, applying `config` (ADR §8.5).

        `workspace_path` is unused: the scan target is the image. `[tools.trivy]`
        is keyed by tool, so it applies to this category as well as `sca`.

        Raises:
            UnsupportedToolConfigError: for `scan_history` or `custom_rules_path`,
                neither of which `trivy image` has an equivalent for.
        """
        if config.scan_history is not None:
            msg = (
                "trivy image has no notion of scan history — an image is a fixed artifact "
                "(ADR §8.5). Remove scan_history for trivy."
            )
            raise UnsupportedToolConfigError(msg)
        if config.custom_rules_path is not None:
            msg = (
                "trivy's vulnerability scanner has no rule-file equivalent to point at — its "
                "detection rules are its vulnerability database. Remove custom_rules_path "
                "for trivy, or use passthrough (ADR §8.5)."
            )
            raise UnsupportedToolConfigError(msg)

        argv = [
            TRIVY_BINARY,
            "image",
            "--image-src",
            "docker",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--skip-db-update",
            *TRIVY_OFFLINE_FLAGS,
            "--cache-backend",
            "memory",
            "--no-progress",
        ]
        for excluded in config.exclude_paths or ():
            argv.extend(("--skip-dirs", excluded))
        argv.append(self.image)
        argv.extend(render_passthrough_flags(config.passthrough))
        return tuple(argv)

    def parse_output(self, result: ProcessResult) -> Sequence[RawFinding]:
        """Parse trivy's JSON report into `image` `RawFinding`s.

        Raises:
            TrivyDatabaseNotReadyError: no vulnerability database was downloaded.
            DockerDaemonUnavailableError: the daemon socket was unusable.
            ImageNotInDaemonError: the daemon has no such image.
            TrivyOutputError: any other failure or malformed report.
        """
        if result.exit_code != 0:
            if _DB_NOT_READY_MARKER in result.stderr:
                raise TrivyDatabaseNotReadyError(TRIVY_DB_NOT_READY_HINT)
            if _DAEMON_UNREACHABLE_MARKER in result.stderr:
                raise DockerDaemonUnavailableError(DOCKER_DAEMON_UNAVAILABLE_HINT)
            if _IMAGE_NOT_FOUND_MARKER in result.stderr:
                msg = (
                    f"image {self.image!r} is not in the local Docker daemon. linceo scans "
                    "only images already present there and never pulls one (ADR R2) — build "
                    f"it first (`docker build -t {self.image} .`) or `docker load` it; "
                    "`docker images` lists what the daemon has."
                )
                raise ImageNotInDaemonError(msg)
            msg = (
                f"trivy exited with status {result.exit_code}: "
                f"{result.stderr.strip() or '(no stderr output)'}"
            )
            raise TrivyOutputError(msg)

        try:
            document = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            msg = f"trivy report is not valid JSON: {exc}"
            raise TrivyOutputError(msg) from exc
        if not isinstance(document, dict):
            msg = f"trivy report must be a JSON object, got {type(document).__name__}"
            raise TrivyOutputError(msg)
        results = document.get("Results") or []
        if not isinstance(results, list):
            msg = f"trivy report's Results must be a JSON array, got {type(results).__name__}"
            raise TrivyOutputError(msg)

        findings: list[RawFinding] = []
        for entry in results:
            findings.extend(self._parse_result_entry(entry))
        return tuple(findings)

    def _parse_result_entry(self, entry: object) -> Sequence[RawFinding]:
        """Parse one `Results[]` entry, giving each vulnerability its origin and layer."""
        if not isinstance(entry, dict):
            msg = f"trivy report Results entry must be a JSON object, got {type(entry).__name__}"
            raise TrivyOutputError(msg)
        vulnerabilities = entry.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            msg = "trivy report Results entry's Vulnerabilities must be a JSON array"
            raise TrivyOutputError(msg)

        findings: list[RawFinding] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                msg = "trivy vulnerability entry must be a JSON object"
                raise TrivyOutputError(msg)
            origin = self._origin(entry, vulnerability)
            raw = self._sca._parse_vulnerability(vulnerability, manifest_path=origin)
            layer = vulnerability.get("Layer")
            diff_id = layer.get("DiffID") if isinstance(layer, dict) else None
            findings.append(
                replace(
                    raw,
                    category=Category.IMAGE,
                    location=Location(
                        path=origin, layer=diff_id if isinstance(diff_id, str) else None
                    ),
                )
            )
        return tuple(findings)

    @staticmethod
    def _origin(entry: Mapping[str, object], vulnerability: Mapping[str, object]) -> str:
        """Where in the image the package lives, never containing the image reference.

        `PkgPath` when trivy reports one (Python, Node, Java); otherwise a
        language result's `Target` is itself a file path (Go binaries,
        lockfiles); an OS result's `Target` embeds the image reference, so its
        package-database `Type` (`alpine`, `debian`, ...) stands in.
        """
        pkg_path = vulnerability.get("PkgPath")
        if isinstance(pkg_path, str) and pkg_path:
            return pkg_path
        target = entry.get("Target")
        if entry.get("Class") == "lang-pkgs" and isinstance(target, str):
            return target
        kind = entry.get("Type")
        if not isinstance(kind, str):
            msg = "trivy report Results entry is missing a string 'Type'"
            raise TrivyOutputError(msg)
        return kind

    def data_sources(self) -> Sequence[DataSource]:
        """Declare the vulnerability database this scan relied on (ADR §5)."""
        return self.db_data_sources

    def native_severity_domain(self) -> frozenset[str]:
        """Declare trivy's native severity domain (ADR §6) — same tool, same domain."""
        return TRIVY_NATIVE_SEVERITY_DOMAIN

    def report_schema(self) -> ReportSchema:
        """Declare the `image` category's console table columns (ADR §7)."""
        return _REPORT_SCHEMA


__all__ = [
    "DOCKER_DAEMON_UNAVAILABLE_HINT",
    "DockerDaemonUnavailableError",
    "ImageNotInDaemonError",
    "InvalidImageReferenceError",
    "TrivyImageIntegration",
]
