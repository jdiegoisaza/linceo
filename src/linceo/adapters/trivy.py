"""Trivy integration: SCA scanning via `trivy fs --scanners vuln` (ADR §10, §13.1).

Deliberately thin (ADR §13.1), the same way `linceo.adapters.gitleaks` is:
builds the `trivy fs` command line and parses its JSON report into
`RawFinding`s, nothing more — no severity normalization of its own
(`SeverityNormalizer`'s job, ADR §6): the native-value-to-`Severity` map
itself lives in the versioned `linceo/data/severity_map.toml` (ADR §6),
not here. This module only declares `TRIVY_NATIVE_SEVERITY_DOMAIN` — the
complete set of native values trivy can produce, a fact about the tool's
own CLI, confirmed against its `--help` output, independent of how any of
those values gets mapped — and reads `cvss_source_preference` (also from
that same file, threaded in by the caller that constructs this
integration) to pick one CVSS v3.1 base score deterministically when
trivy reports more than one source for the same finding.

`--scanners vuln` is always passed, never left to trivy's own default
(`vuln,secret`): this integration's category is `sca`, and this project
already has a dedicated `secrets` integration (Gitleaks) — mixing in
trivy's own secret scanner would blur that category boundary without
anyone asking for it. `--exit-code` is deliberately never passed either:
trivy's own exit code stays a pure signal of whether the tool itself ran
successfully, never of whether it found anything, so `parse_output` can
treat any non-zero exit as a genuine tool failure (ADR §5) — the same
freedom `GitleaksIntegration.parse_output` does not have, since gitleaks
exits non-zero by design whenever it finds a leak.

`--skip-db-update` is always passed (ADR R2/§5: offline by default, no
network call as a side effect of a scan) — see `TrivyDatabaseNotReadyError`
below for the one documented, actionable exception this creates on a
database that was never downloaded at all.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from linceo.core.execution import DataSource, ToolExecutionError
from linceo.core.findings import Category, Location, Package, RawFinding
from linceo.core.ports import ProcessResult, ToolExecutor
from linceo.core.report_schema import Column, ReportSchema
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, render_passthrough_flags

#: The `sca` category's report table contract (ADR §7): `LOCATION` is
#: `package@installed_version`, with `MANIFEST` (the manifest path — also a
#: fingerprint ingredient, ADR §5, that would otherwise disappear from the
#: table) and `FIXED` (the version that resolves the vulnerability, or
#: `(none)` when trivy reports none) as this category's two extra columns.
_REPORT_SCHEMA = ReportSchema(
    location=Column(header="LOCATION", fields=("package.name", "package.version"), separator="@"),
    extra=(
        Column(header="MANIFEST", fields=("location.path",)),
        Column(header="FIXED", fields=("package.fixed_version",), missing="(none)"),
    ),
)

#: Binary name looked up on `PATH` (ADR R4) — never a path baked in at
#: install time, exactly like `linceo.adapters.gitleaks.GITLEAKS_BINARY`.
TRIVY_BINARY = "trivy"

#: `RawFinding.tool` / `ToolIntegration.name` for this integration — pulled
#: into its own constant because it is also the key `[native.trivy]` in
#: `severity_map.toml` is keyed by; duplicating the literal in both places
#: would risk them drifting apart silently.
TRIVY_TOOL_NAME = "trivy"

#: The version range this integration's JSON parsing was built and golden-
#: fixture-tested against (ADR §11) — surfaced in the missing-binary hint
#: below. Trivy's report `SchemaVersion` (embedded in its JSON, currently
#: `2`) has been stable across this whole range; this integration reads
#: nothing that depends on a narrower guarantee than that.
SUPPORTED_VERSION_RANGE = ">=0.50,<1"

#: ADR R4: a missing binary fails with an actionable error naming what is
#: missing, which version is expected, and how to install it — never an
#: attempt to install it automatically (also ADR R2).
TRIVY_MISSING_BINARY_HINT = (
    "trivy binary not found on PATH.\n"
    f"linceo's sca scan needs trivy {SUPPORTED_VERSION_RANGE} "
    "(built and golden-fixture-tested against 0.74.0).\n"
    "linceo never downloads or installs tool binaries itself (ADR R2/R4) — install trivy "
    "yourself first, with one of:\n"
    "  - https://trivy.dev/latest/getting-started/installation/ "
    "(official releases and package manager instructions)\n"
    "  - the linceo reference container image, which bundles a pinned trivy build with a "
    "pre-fetched vulnerability database (ADR §4/R4, §5)"
)

#: The exact, literal substring trivy's own stderr carries when
#: `--skip-db-update` is given but no database has ever been downloaded —
#: reproduced verbatim by running `trivy fs --skip-db-update` by hand
#: against an empty `--cache-dir` (see `tests/unit/fixtures/trivy/README.md`)
#: rather than guessed from documentation, the same standard
#: `GITLEAKS_MISSING_BINARY_HINT` was held to.
_DB_NOT_READY_MARKER = "--skip-db-update cannot be specified on the first run"

#: ADR R2/§5: the offline default creates exactly one anticipated, nameable
#: failure — a database that was never downloaded at all. `--skip-db-update`
#: is never dropped to work around this (that would silently reintroduce a
#: network call, ADR R2); instead this is the one case
#: `TrivyIntegration.parse_output` raises `TrivyDatabaseNotReadyError` for,
#: naming exactly how to fetch the database once, explicitly.
TRIVY_DB_NOT_READY_HINT = (
    "trivy's vulnerability database has never been downloaded, and linceo runs trivy "
    "offline by default (--skip-db-update, ADR R2/§5) — it never fetches one automatically. "
    "Fetch it once, explicitly, with one of:\n"
    "  - `trivy fs --download-db-only` run by hand on this machine — the one command in "
    "this whole workflow allowed to touch the network, and only because you ran it yourself\n"
    "  - rebuild or re-pull the linceo reference container image, which bakes the database "
    "in at build time (ADR §4/R4, §5)\n"
    "  - point the TRIVY_DB_REPOSITORY environment variable at an internal OCI mirror, for "
    "an environment with no direct access to the public database (ADR §5)"
)

#: Name recorded on the `DataSource` `data_sources()` declares (ADR §5).
TRIVY_VULNERABILITY_DB_NAME = "trivy-vulnerability-db"

#: Trivy's complete native `Severity` domain (ADR §6) — the allowed values
#: of its own `-s/--severity` flag, confirmed against the installed 0.74.0
#: binary's `--help` output, not guessed from documentation.
TRIVY_NATIVE_SEVERITY_DOMAIN: frozenset[str] = frozenset(
    {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
)

#: `TrivyIntegration.cvss_source_preference`'s own default, for a caller
#: that constructs one without threading in `severity_map.toml`'s own
#: `cvss_source_preference` (ADR §6) — matches that file's shipped value,
#: so a bare `TrivyIntegration(version=...)` (every existing test, and any
#: future caller that does not care to override it) behaves identically to
#: one built the real way, through the loaded map. ADR §6: "cuando hay
#: varias fuentes de CVSS disponibles... el orden de preferencia entre
#: fuentes se declara explícitamente" — NVD before a distro/vendor
#: advisory is the ADR's own worked example, not a new one invented here.
DEFAULT_CVSS_SOURCE_PREFERENCE: tuple[str, ...] = ("nvd",)


class TrivyOutputError(Exception):
    """trivy produced output that is not the JSON report shape this parser expects.

    Raised for genuinely malformed output (not valid JSON, not the expected
    object/array shape, or an entry missing a field this parser relies on)
    — treated by `linceo.core.engine` the same as any other parse failure:
    absence of evidence, not zero findings (ADR §5). Also raised for a
    non-zero trivy exit this parser cannot attribute to the one specific,
    nameable cause `TrivyDatabaseNotReadyError` covers.
    """


class TrivyDatabaseNotReadyError(ToolExecutionError):
    """trivy exited because `--skip-db-update` was given but no database exists yet.

    The one anticipated, nameable failure mode ADR R2/§5's offline-by-
    default design creates (see `TRIVY_DB_NOT_READY_HINT`) — raised instead
    of the generic `TrivyOutputError` specifically so
    `linceo.core.engine._execute_one` surfaces its message on the resulting
    `FAILED` execution, the same actionable treatment a missing binary gets.
    """


def _extract_cvss_score(
    cvss: Mapping[str, object], *, preferred_sources: Sequence[str]
) -> float | None:
    """Pick one CVSS v3.1 base score from trivy's per-source `CVSS` map, deterministically.

    Tries each of `preferred_sources` in order, then every other source
    trivy reported that isn't already in it, in alphabetically sorted
    order — never dict iteration order (ADR R3) — returning the first
    `V3Score` found. `preferred_sources` is `severity_map.toml`'s own
    `cvss_source_preference` (ADR §6: "el orden de preferencia entre
    fuentes se declara explícitamente en el propio fichero de mapa"),
    threaded in via `TrivyIntegration.cvss_source_preference` — this
    function itself declares no preference of its own. A source with only
    a `V2Score`, or a `V40Score` (CVSS v4) but no `V3Score`, is skipped:
    `Severity.from_cvss` buckets CVSS v3.1 specifically (ADR §6), and mixing
    scales in would make the bucketing meaningless.
    """
    ordered_sources = (
        *preferred_sources,
        *sorted(source for source in cvss if source not in preferred_sources),
    )
    for source in ordered_sources:
        block = cvss.get(source)
        if not isinstance(block, Mapping):
            continue
        score = block.get("V3Score")
        if isinstance(score, int | float) and not isinstance(score, bool):
            return float(score)
    return None


@dataclass(slots=True)
class TrivyIntegration:
    """Thin `ToolIntegration` adapter around `trivy fs --scanners vuln --format json` (ADR §10).

    `version` and `db_data_sources` are both supplied by the caller —
    resolved via `detect_version` and `detect_data_sources` respectively,
    both called on the class itself before this integration is
    constructed (ADR R4) — rather than hardcoded or looked up lazily, the
    same pattern `GitleaksIntegration.version` establishes.
    `cvss_source_preference` is `severity_map.toml`'s own
    `cvss_source_preference` (ADR §6), likewise supplied by the caller —
    this integration has no CVSS-source opinion of its own beyond
    `DEFAULT_CVSS_SOURCE_PREFERENCE`, its neutral default.
    """

    version: str
    db_data_sources: tuple[DataSource, ...] = ()
    cvss_source_preference: tuple[str, ...] = DEFAULT_CVSS_SOURCE_PREFERENCE
    name: str = TRIVY_TOOL_NAME
    category: Category = Category.SCA

    @staticmethod
    def detect_version(executor: ToolExecutor) -> str:
        """Detect the installed trivy binary's version via `trivy version --format json`.

        Satisfies the `ToolIntegration.detect_version` contract (ADR §1
        checkpoint): called on the class itself, before any
        `TrivyIntegration` instance exists. JSON, not `trivy version`'s
        plain-text form, on purpose: the plain form's first line is the
        version, but only when no database is cached yet — once one is,
        trivy appends a multi-line "Vulnerability DB:" block to the same
        plain output, which `str.strip()` alone (the `GitleaksIntegration`
        approach) could not tell apart from the version reliably.

        Raises:
            FileNotFoundError: if the trivy binary is not on `PATH` — the
                actionable signal a caller (typically the CLI) turns into
                `missing_binary_hint` (ADR R4).
            TrivyOutputError: if trivy's own version output cannot be
                parsed as the JSON object this method expects.
        """
        result = executor.run(
            (TRIVY_BINARY, "version", "--format", "json"), env={}, cwd=".", timeout=None
        )
        try:
            payload = json.loads(result.stdout)
            version = payload["Version"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            msg = f"trivy version --format json produced unexpected output: {exc}"
            raise TrivyOutputError(msg) from exc
        if not isinstance(version, str):
            msg = "trivy version --format json's 'Version' field must be a string"
            raise TrivyOutputError(msg)
        return version

    @staticmethod
    def detect_data_sources(executor: ToolExecutor) -> tuple[DataSource, ...]:
        """Detect the cached vulnerability database's own version and build date, if any.

        Calls `trivy version --format json` — read-only and offline, never
        touching the network and never requiring a scan to have run first
        (ADR R2) — the same calling convention `detect_version` uses,
        before any `TrivyIntegration` instance exists.

        Returns `()`, not an error, both when no database has ever been
        downloaded (its `VulnerabilityDB` key is simply absent from
        trivy's own output in that case — confirmed against the installed
        binary with an empty `--cache-dir`) and when the output cannot be
        parsed as expected: this is best-effort metadata gathered up
        front, not a precondition check. A database that is genuinely
        absent is discovered, and reported with an actionable hint, at the
        one point that actually matters — the real scan, via
        `parse_output` raising `TrivyDatabaseNotReadyError` — never here.

        Raises:
            FileNotFoundError: if the trivy binary is not on `PATH` — same
                as `detect_version`.
        """
        result = executor.run(
            (TRIVY_BINARY, "version", "--format", "json"), env={}, cwd=".", timeout=None
        )
        try:
            payload = json.loads(result.stdout)
            db = payload["VulnerabilityDB"]
            schema_version = db["Version"]
            updated_at = datetime.fromisoformat(db["UpdatedAt"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return ()
        return (
            DataSource(
                name=TRIVY_VULNERABILITY_DB_NAME,
                version=str(schema_version),
                built_at=updated_at.date(),
            ),
        )

    def missing_binary_hint(self) -> str:
        """Satisfy `ToolIntegration.missing_binary_hint` with trivy's own actionable text."""
        return TRIVY_MISSING_BINARY_HINT

    def build_command(self, *, workspace_path: str, config: ToolConfig) -> Sequence[str]:
        """Build the `trivy fs` argv against `workspace_path`, applying `config` (ADR §8.5).

        Translates `exclude_paths` to trivy's own `--skip-dirs` (repeated
        once per entry, confirmed against the installed 0.74.0 binary to
        union rather than intersect, unlike a single comma-joined value
        some other flags on the same binary expect) — unlike gitleaks,
        trivy does have a real flag for this (ADR §8.5's motivating
        contrast). `config.timeout` is never read here, for the same
        reason `GitleaksIntegration.build_command` never reads it (see
        `ToolConfig.timeout`). `config.passthrough` is appended last via
        `render_passthrough_flags`, after the positional `workspace_path`
        — confirmed against the installed binary that a flag placed after
        a positional argument still parses correctly.

        Raises:
            UnsupportedToolConfigError: if `config.scan_history` is not
                `None` — a dependency-manifest scan has no notion of
                history to switch between (ADR §8.5) — or if
                `config.custom_rules_path` is set — trivy's vulnerability
                scanner has no rule-file equivalent to point at; its
                detection rules are its vulnerability database, not a file
                on disk, unlike gitleaks.
        """
        if config.scan_history is not None:
            msg = (
                "trivy fs has no notion of scan history — a dependency-manifest scan only "
                "ever reflects the workspace as currently checked out, the same way any "
                "such scan must (ADR §8.5). Remove scan_history for trivy."
            )
            raise UnsupportedToolConfigError(msg)
        if config.custom_rules_path is not None:
            msg = (
                "trivy's vulnerability scanner has no rule-file equivalent to point at — its "
                "detection rules are its vulnerability database, not a file on disk (unlike "
                "gitleaks). Remove custom_rules_path for trivy, or use passthrough for a "
                "trivy flag not covered by level 1 (ADR §8.5)."
            )
            raise UnsupportedToolConfigError(msg)

        argv = [
            TRIVY_BINARY,
            "fs",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--skip-db-update",
        ]
        if config.exclude_paths:
            for excluded in config.exclude_paths:
                argv.extend(("--skip-dirs", excluded))
        argv.append(workspace_path)
        argv.extend(render_passthrough_flags(config.passthrough))
        return tuple(argv)

    def parse_output(self, result: ProcessResult) -> Sequence[RawFinding]:
        """Parse trivy's JSON report (on stdout) into `RawFinding`s.

        Raises:
            TrivyDatabaseNotReadyError: if `result.exit_code` is non-zero
                because `--skip-db-update` was given but no database has
                ever been downloaded (ADR R2/§5) — see
                `TRIVY_DB_NOT_READY_HINT`.
            TrivyOutputError: for any other non-zero exit, or if
                `result.stdout` is not the JSON object shape this parser
                expects.
        """
        if result.exit_code != 0:
            if _DB_NOT_READY_MARKER in result.stderr:
                raise TrivyDatabaseNotReadyError(TRIVY_DB_NOT_READY_HINT)
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
        """Parse one `Results[]` entry — one scanned manifest — into its `RawFinding`s.

        Raises:
            TrivyOutputError: if `entry` is not an object, its `Target` is
                missing or not a string, or `Vulnerabilities` is present
                but is not a JSON array.
        """
        if not isinstance(entry, dict):
            msg = f"trivy report Results entry must be a JSON object, got {type(entry).__name__}"
            raise TrivyOutputError(msg)

        target = entry.get("Target")
        if not isinstance(target, str):
            msg = "trivy report Results entry is missing a string 'Target'"
            raise TrivyOutputError(msg)

        vulnerabilities = entry.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            msg = (
                "trivy report Results entry's Vulnerabilities must be a JSON array, got "
                f"{type(vulnerabilities).__name__}"
            )
            raise TrivyOutputError(msg)

        return tuple(
            self._parse_vulnerability(vulnerability, manifest_path=target)
            for vulnerability in vulnerabilities
        )

    def _parse_vulnerability(self, entry: object, *, manifest_path: str) -> RawFinding:
        """Parse one `Vulnerabilities[]` entry into a `RawFinding`.

        Raises:
            TrivyOutputError: if `entry` is not an object, is missing a
                required field, or has one of the wrong type.
        """
        if not isinstance(entry, dict):
            msg = f"trivy vulnerability entry must be a JSON object, got {type(entry).__name__}"
            raise TrivyOutputError(msg)

        try:
            vulnerability_id = entry["VulnerabilityID"]
            package_name = entry["PkgName"]
            installed_version = entry["InstalledVersion"]
        except KeyError as exc:
            msg = f"trivy vulnerability entry is missing required field {exc}"
            raise TrivyOutputError(msg) from exc

        if not all(isinstance(value, str) for value in (vulnerability_id, package_name)):
            msg = "trivy vulnerability entry's VulnerabilityID and PkgName must both be strings"
            raise TrivyOutputError(msg)
        if not isinstance(installed_version, str):
            msg = "trivy vulnerability entry's InstalledVersion must be a string"
            raise TrivyOutputError(msg)

        fixed_version = entry.get("FixedVersion")
        if fixed_version is not None and not isinstance(fixed_version, str):
            msg = "trivy vulnerability entry's FixedVersion must be a string when present"
            raise TrivyOutputError(msg)

        raw_severity = entry.get("Severity")
        if raw_severity is not None and not isinstance(raw_severity, str):
            msg = "trivy vulnerability entry's Severity must be a string when present"
            raise TrivyOutputError(msg)

        cvss = entry.get("CVSS")
        cvss_score = (
            _extract_cvss_score(cvss, preferred_sources=self.cvss_source_preference)
            if isinstance(cvss, Mapping)
            else None
        )

        message = str(entry.get("Title") or entry.get("Description") or vulnerability_id)

        return RawFinding(
            tool=self.name,
            category=Category.SCA,
            rule_id=vulnerability_id,
            message=message,
            location=Location(path=manifest_path),
            raw_severity=raw_severity,
            cvss_score=cvss_score,
            package=Package(
                name=package_name, version=installed_version, fixed_version=fixed_version
            ),
        )

    def data_sources(self) -> Sequence[DataSource]:
        """Declare this integration's data sources (ADR §5): the vulnerability database.

        Returns whatever `detect_data_sources` resolved before this
        integration was constructed — `()` when no database was present
        (ADR §5's freshness/frescura policy has nothing to declare for a
        database that does not exist, distinct from declaring one that is
        merely stale).
        """
        return self.db_data_sources

    def native_severity_domain(self) -> frozenset[str]:
        """Declare trivy's native severity domain (ADR §6): `TRIVY_NATIVE_SEVERITY_DOMAIN`."""
        return TRIVY_NATIVE_SEVERITY_DOMAIN

    def report_schema(self) -> ReportSchema:
        """Declare the `sca` category's console table columns (ADR §7)."""
        return _REPORT_SCHEMA


__all__ = [
    "DEFAULT_CVSS_SOURCE_PREFERENCE",
    "SUPPORTED_VERSION_RANGE",
    "TRIVY_BINARY",
    "TRIVY_DB_NOT_READY_HINT",
    "TRIVY_MISSING_BINARY_HINT",
    "TRIVY_NATIVE_SEVERITY_DOMAIN",
    "TRIVY_TOOL_NAME",
    "TRIVY_VULNERABILITY_DB_NAME",
    "TrivyDatabaseNotReadyError",
    "TrivyIntegration",
    "TrivyOutputError",
]
