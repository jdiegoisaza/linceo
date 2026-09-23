"""Gitleaks integration: secrets scanning via `gitleaks detect` (ADR §10, §13.1).

Deliberately thin (ADR §13.1): builds the `gitleaks detect` command line
and parses its JSON report into `RawFinding`s, nothing more — no severity
normalization (gitleaks emits none natively at all, ADR §6) and no
provenance bookkeeping beyond what `RawFinding.tool` already carries.
`build_command` also translates the level 1 configuration contract (ADR
§8.5) into gitleaks' own flags — see `GitleaksIntegration.build_command`.

`RawFinding.secret_hash` is a SHA-256 hex digest of gitleaks' own `Secret`
field: read from the parsed JSON just long enough to hash, and never
otherwise stored, logged, or returned (ADR §5, §9) — only the hash crosses
into the rest of the pipeline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from linceo.core.execution import DataSource
from linceo.core.findings import Category, Location, RawFinding
from linceo.core.ports import ProcessResult, ToolExecutor
from linceo.core.report_schema import Column, ReportSchema, Truncate
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, render_passthrough_flags

#: The `secrets` category's report table contract (ADR §7): `LOCATION` is
#: `path:line`, truncated from the left so a long path still ends in its
#: file name and line number — the two things that matter once a table row
#: is too narrow to show the whole path.
_REPORT_SCHEMA = ReportSchema(
    location=Column(
        header="LOCATION",
        fields=("location.path", "location.line"),
        separator=":",
        max_width=50,
        truncate=Truncate.LEFT,
    )
)

#: Binary name looked up on `PATH` — never a path baked in at install time,
#: so the reference container image (ADR §4/R4) and a bring-your-own-tool
#: PyPI install both resolve it the same way.
GITLEAKS_BINARY = "gitleaks"

#: The version range this integration's JSON parsing was built and golden-
#: fixture-tested against (ADR §11) — surfaced in the missing-binary hint
#: below, and the range a future `doctor` command (ADR §8) would check a
#: detected version against.
SUPPORTED_VERSION_RANGE = ">=8.18,<9"

#: ADR R4: "si un binario requerido no está en PATH, el CLI falla con un
#: error accionable que nombra qué falta, qué versión se espera, y cómo
#: instalarla — y nunca intenta instalarla por su cuenta."
GITLEAKS_MISSING_BINARY_HINT = (
    "gitleaks binary not found on PATH.\n"
    f"linceo's secrets scan needs gitleaks {SUPPORTED_VERSION_RANGE} "
    "(built and golden-fixture-tested against 8.30.1).\n"
    "linceo never downloads or installs tool binaries itself (ADR R2/R4) — install gitleaks "
    "yourself first, with one of:\n"
    "  - https://github.com/gitleaks/gitleaks#installing "
    "(official releases and package manager instructions)\n"
    "  - the linceo reference container image, which bundles a pinned gitleaks build "
    "(ADR §4/R4)"
)


class GitleaksOutputError(Exception):
    """gitleaks produced output that is not the JSON report shape this parser expects.

    Raised for genuinely malformed output (not valid JSON, not a JSON
    array, or an entry missing a field this parser relies on) — treated by
    `linceo.core.engine` the same as any other parse failure: absence of
    evidence, not zero findings (ADR §5).
    """


@dataclass(slots=True)
class GitleaksIntegration:
    """Thin `ToolIntegration` adapter around `gitleaks detect --report-format json` (ADR §10).

    Scans the workspace's full git history by default (gitleaks' own
    default mode, not `--no-git`) rather than only the current working
    tree: a secret committed and later removed is exactly the case a
    secrets scanner earns its keep on, and `workspace_path` is already
    guaranteed to be a git checkout by every `ContextProvider` in scope
    for v0.1 (ADR §10). `build_command`'s `config` (ADR §8.5) can override
    this per run via `scan_history=False`.

    `version` is supplied by the caller — typically the real installed
    version detected via `detect_version` before this integration is even
    constructed (ADR R4) — rather than hardcoded, so `ToolExecution.
    tool_version` always reflects what actually ran.
    """

    version: str
    name: str = "gitleaks"
    category: Category = Category.SECRETS

    @staticmethod
    def detect_version(executor: ToolExecutor) -> str:
        """Detect the installed gitleaks binary's version via `gitleaks version`.

        Satisfies the `ToolIntegration.detect_version` contract (ADR §1
        checkpoint): called on the class itself, before any
        `GitleaksIntegration` instance exists.

        Raises:
            FileNotFoundError: if the gitleaks binary is not on `PATH` —
                the actionable signal a caller (typically the CLI) turns
                into `missing_binary_hint` (ADR R4).
        """
        result = executor.run((GITLEAKS_BINARY, "version"), env={}, cwd=".", timeout=None)
        return result.stdout.strip()

    def missing_binary_hint(self) -> str:
        """Satisfy `ToolIntegration.missing_binary_hint` with gitleaks' own actionable text."""
        return GITLEAKS_MISSING_BINARY_HINT

    def build_env(self) -> Mapping[str, str]:
        """Satisfy `ToolIntegration.build_env` (ADR §1 amendment): none needed.

        gitleaks makes no network call at all by default, so there is
        nothing for an environment variable to suppress (unlike
        `linceo.adapters.checkov.CheckovIntegration.build_env`).
        """
        return {}

    def build_command(self, *, workspace_path: str, config: ToolConfig) -> Sequence[str]:
        """Build the `gitleaks detect` argv against `workspace_path`, applying `config` (ADR §8.5).

        Translates the two level 1 fields gitleaks has a real flag for:
        `scan_history=False` appends `--no-git`, and `custom_rules_path`
        appends `--config <path>` (gitleaks' own rule/allowlist file,
        real flag confirmed against the installed 8.30.1 binary this
        integration is golden-fixture-tested against). `config.timeout`
        is never read here — see `ToolConfig.timeout` for why, even
        though gitleaks happens to have its own `--timeout` flag.
        `config.passthrough` is appended last, via
        `render_passthrough_flags`, so it can override either of the two
        translated flags above if a document's author explicitly wants
        that (the accepted cost of opting into the level 2 escape hatch,
        ADR §8.5).

        Raises:
            UnsupportedToolConfigError: if `config.exclude_paths` is
                non-empty — gitleaks has no command-line flag to exclude
                paths from a scan, only a `[allowlist]` table inside its
                own `--config` file, which this integration does not
                generate.
        """
        if config.exclude_paths:
            msg = (
                "gitleaks has no command-line flag to exclude paths from a scan — only a "
                "[allowlist] table inside its own --config file, which this integration does "
                "not generate. Remove exclude_paths for gitleaks, or set custom_rules_path to "
                "a gitleaks config file that declares [allowlist] paths yourself."
            )
            raise UnsupportedToolConfigError(msg)

        argv = [
            GITLEAKS_BINARY,
            "detect",
            "--source",
            workspace_path,
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
        ]
        if config.scan_history is False:
            argv.append("--no-git")
        if config.custom_rules_path is not None:
            argv.extend(("--config", config.custom_rules_path))
        argv.extend(render_passthrough_flags(config.passthrough))
        return tuple(argv)

    def parse_output(self, result: ProcessResult) -> Sequence[RawFinding]:
        """Parse gitleaks' JSON report (on stdout) into `RawFinding`s.

        Raises:
            GitleaksOutputError: if `result.stdout` is not a JSON array of
                objects, each carrying every field this parser relies on.
        """
        try:
            entries = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            msg = f"gitleaks report is not valid JSON: {exc}"
            raise GitleaksOutputError(msg) from exc

        if not isinstance(entries, list):
            msg = f"gitleaks report must be a JSON array, got {type(entries).__name__}"
            raise GitleaksOutputError(msg)

        return tuple(self._parse_entry(entry) for entry in entries)

    def _parse_entry(self, entry: object) -> RawFinding:
        """Parse one gitleaks report entry into a `RawFinding`.

        Raises:
            GitleaksOutputError: if `entry` is not an object, is missing a
                required field, or has one of the wrong type.
        """
        if not isinstance(entry, dict):
            msg = f"gitleaks finding entry must be a JSON object, got {type(entry).__name__}"
            raise GitleaksOutputError(msg)

        try:
            rule_id = entry["RuleID"]
            description = entry["Description"]
            file_path = entry["File"]
            start_line = entry["StartLine"]
            secret = entry["Secret"]
        except KeyError as exc:
            msg = f"gitleaks finding entry is missing required field {exc}"
            raise GitleaksOutputError(msg) from exc

        if not isinstance(rule_id, str) or not isinstance(file_path, str):
            msg = "gitleaks finding entry's RuleID and File must both be strings"
            raise GitleaksOutputError(msg)
        if not isinstance(secret, str):
            msg = "gitleaks finding entry's Secret must be a string"
            raise GitleaksOutputError(msg)

        secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return RawFinding(
            tool=self.name,
            category=Category.SECRETS,
            rule_id=rule_id,
            message=str(description),
            location=Location(
                path=file_path, line=start_line if isinstance(start_line, int) else None
            ),
            raw_severity=None,
            secret_hash=secret_hash,
        )

    def data_sources(self) -> Sequence[DataSource]:
        """Declare this integration's data sources (ADR §5): none.

        gitleaks' detection rules ship baked into its own binary — there
        is no separately versioned, separately dated artifact to track
        staleness against, unlike Trivy's vulnerability database.
        """
        return ()

    def native_severity_domain(self) -> frozenset[str]:
        """Declare gitleaks' native severity domain (ADR §6): empty.

        gitleaks never emits a native severity value at all — every
        `RawFinding` this integration produces has `raw_severity=None`.
        """
        return frozenset()

    def report_schema(self) -> ReportSchema:
        """Declare the `secrets` category's console table columns (ADR §7)."""
        return _REPORT_SCHEMA
