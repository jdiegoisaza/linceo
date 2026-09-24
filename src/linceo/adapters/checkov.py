"""Checkov integration: IaC scanning via `checkov -d <path> -o json` (ADR §10, §13.1).

The third tool integration and the first of a third category (`iac`, ADR §1
amendment, 2026-09-21) — added specifically to test whether the contract
this project already validated with two tools of two categories (Gitleaks/
`secrets`, Trivy/`sca`) survives a tool that was not designed with in mind.
Three places it did not fit cleanly without a real decision, each recorded
here rather than silently forced:

1. **Severity.** Checkov's open-source edition never emits a native
   severity value at all — the same case as gitleaks (`[native.checkov]` in
   `severity_map.toml` is empty, on purpose) — but unlike gitleaks'
   uniformly-serious findings, checkov's default ruleset spans a public S3
   bucket (CRITICAL) to a missing resource description (LOW hygiene) with
   no native signal to tell them apart. `[defaults.iac]`'s own comment in
   `severity_map.toml` carries the full argument for landing on `medium`,
   not `high`. `native_severity_domain()` below still declares the empty
   set — matching what this integration's own default configuration can
   ever produce — even though `parse_output` reads `severity` from the JSON
   generically (like `TrivyIntegration`, not like `GitleaksIntegration`,
   whose JSON has no such field at all): a `[native.checkov]` entry added
   later for an operator connecting through the Bridgecrew/Prisma Cloud
   platform (`--bc-api-key`, reachable only via `ToolConfig.passthrough`,
   never set by this integration itself) would then resolve through the
   normal precedence chain (ADR §6) with no code change here.

2. **Location vs. resource identity.** A checkov finding has a file and a
   line, like a `secrets` finding, but also a cloud/IaC resource address
   (`aws_s3_bucket.logs`) with no equivalent in either existing category.
   `linceo.core.findings.Location` documents explicitly why that address
   does *not* live there: `Location` is defined as "never a fingerprint
   ingredient," but a resource address *must* be one — two distinct
   resources of the same type, flagged by the same rule, in the same file
   (an ordinary Terraform file with several similar blocks; see
   `tests/unit/fixtures/checkov/README.md`'s `many_findings.json`) would
   otherwise collide onto one fingerprint and one would silently vanish
   during intra-run dedup. It travels as `Finding.resource` instead — a
   sibling field, the same shape `Finding.package` already establishes for
   `sca`'s own extra fingerprint ingredients beyond `Location.path` — never
   as an extension of `Location` itself (ADR §5 amendment, 2026-09-21).
   `LOCATION` in the console table stays `path:line`, matching `secrets`;
   `RESOURCE` is this category's own extra column, the same role `MANIFEST`
   plays for `sca`. A renamed resource is treated as a genuine identity
   change, not code movement, and is expected to leave a baseline entry
   unresolved rather than silently reindexed — the same precedent `sca`'s
   own package-version bump already sets.

3. **Offline default (ADR R2) — two separate network paths, not one.** Checkov's
   CLI entry point unconditionally imports `checkov.common.util.banner`,
   which calls PyPI's JSON API to check for a newer release unless the
   `CKV_SKIP_PACKAGE_UPDATE_CHECK` environment variable is truthy —
   confirmed against the real 3.3.19 source, not assumed from documentation
   (there is no CLI flag equivalent). Neither gitleaks nor trivy ever
   needed a `ToolIntegration` to set an environment variable for its own
   subprocess: gitleaks makes no network call at all, and trivy's offline
   default (`--skip-db-update`) is a real flag. `build_env` below is what a
   real, general mechanism for this case looks like — added to the
   `ToolIntegration` contract itself (`linceo.core.ports`, ADR §1
   amendment) rather than solved as a one-off inside this module, since a
   fourth tool with the same shape of requirement should not have to
   reinvent it either.

   A second, entirely separate path was found only by actually running the
   real integration test against the real binary (`tests/integration/
   test_checkov_integration.py`) under a network-denying sandbox — reading
   the `--help` text alone, as the rest of this list was built from, missed
   it: `checkov/main.py` calls `bc_integration.get_platform_run_config()`
   and `bc_integration.get_prisma_build_policies(...)` **unconditionally**,
   entirely outside the `if self.config.bc_api_key:` branch that gates
   every other Bridgecrew/Prisma Cloud call — so these two run, and attempt
   to reach `api0.prismacloud.io`, on *every* invocation, with or without
   `--bc-api-key`. The only thing that stops them (confirmed by reading
   `checkov/common/bridgecrew/platform_integration.py`: both methods
   `return` immediately when `self.skip_download` is `True`) is
   `--skip-download` — despite its own `--help` text reading as if it only
   mattered "when using an API key" ("Do not download any data from Prisma
   Cloud... Note: it will prevent BC platform IDs from being available"),
   which is what led this integration to omit it at first. `build_command`
   below now passes it unconditionally, the same way `--skip-framework`
   already is — the lesson generalizes past this one flag: a tool's
   `--help` text describing a flag's *effect* is not proof of when that
   effect is *needed*, and the real source (or a real, sandboxed run) is
   what actually settles it.

   `--download-external-modules` is, separately, never passed either —
   confirmed empirically that omitting it already leaves external Terraform
   module resolution off by default (a warning is logged, no network call
   is attempted) — and `--bc-api-key`/`--docker-image` are never passed,
   the same way `TrivyIntegration` never scans an authenticated container
   registry (ADR §10).

`--skip-framework` always excludes `secrets`, `sca_package`, `sca_image`,
and every `sast*` framework checkov's own `--help` lists — deliberately,
the same category-boundary reasoning that motivates
`TrivyIntegration` always passing `--scanners vuln` (never trivy's own
default `vuln,secret`, ADR §10): this project already has a dedicated
`secrets` integration (Gitleaks) and a dedicated `sca` integration (Trivy),
and checkov's own secrets/SCA/SAST scanners would blur those category
boundaries the moment `scan iac` ran alongside them, with nobody having
asked for that. Every other framework checkov ships (terraform,
cloudformation, kubernetes, dockerfile, helm, arm, bicep, ...) stays on —
`iac` names the whole class of infrastructure/configuration-as-code
misconfiguration, not Terraform specifically.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from linceo.core.execution import DataSource
from linceo.core.findings import Category, Location, RawFinding
from linceo.core.ports import ProcessResult, ToolExecutor
from linceo.core.report_schema import Column, ReportSchema, Truncate
from linceo.core.tool_config import ToolConfig, UnsupportedToolConfigError, render_passthrough_flags

#: The `iac` category's report table contract (ADR §7): `LOCATION` is
#: `path:line`, exactly like `secrets` (both are source-file-anchored
#: categories) — truncated from the left so a long path still ends in its
#: file name and line number. `RESOURCE` is this category's own extra
#: column, the same role `sca`'s `MANIFEST` plays: a fingerprint ingredient
#: (ADR §5 amendment, 2026-09-21) that would otherwise disappear from the
#: table entirely.
_REPORT_SCHEMA = ReportSchema(
    location=Column(
        header="LOCATION",
        fields=("location.path", "location.line"),
        separator=":",
        max_width=50,
        truncate=Truncate.LEFT,
    ),
    extra=(Column(header="RESOURCE", fields=("resource",)),),
)

#: Binary name looked up on `PATH` — never a path baked in at install time,
#: exactly like `linceo.adapters.gitleaks.GITLEAKS_BINARY` and
#: `linceo.adapters.trivy.TRIVY_BINARY`.
CHECKOV_BINARY = "checkov"

#: `RawFinding.tool` / `ToolIntegration.name` for this integration — pulled
#: into its own constant for the same reason `TRIVY_TOOL_NAME` is: it is
#: also the key `[native.checkov]` in `severity_map.toml` is keyed by.
CHECKOV_TOOL_NAME = "checkov"

#: The version range this integration's JSON parsing was built and golden-
#: fixture-tested against (ADR §11), surfaced in the missing-binary hint
#: below.
SUPPORTED_VERSION_RANGE = ">=3.2,<4"

#: ADR R4: a missing binary fails with an actionable error naming what is
#: missing, which version is expected, and how to install it — never an
#: attempt to install it automatically (also ADR R2).
CHECKOV_MISSING_BINARY_HINT = (
    "checkov binary not found on PATH.\n"
    f"linceo's iac scan needs checkov {SUPPORTED_VERSION_RANGE} "
    "(built and golden-fixture-tested against 3.3.19).\n"
    "linceo never downloads or installs tool binaries itself (ADR R2/R4) — install checkov "
    "yourself first, with one of:\n"
    "  - https://www.checkov.io/2.Basics/Installing%20Checkov.html "
    "(official installation instructions)\n"
    "  - the linceo reference container image, which bundles a pinned checkov build in its "
    "own isolated environment (ADR §4/R4, §8.3)"
)

#: The environment variable checkov's own CLI entry point reads, at import
#: time, before it ever parses argv — confirmed against the real 3.3.19
#: source (`checkov.common.util.banner`, `checkov.common.util.env_vars_config`),
#: not assumed from documentation. There is no CLI flag equivalent.
_SKIP_PACKAGE_UPDATE_CHECK_ENV = "CKV_SKIP_PACKAGE_UPDATE_CHECK"

#: checkov frameworks this integration always excludes via `--skip-framework`
#: (ADR §10's category-boundary reasoning, this module's own docstring) —
#: confirmed against the real 3.3.19 `--help` output's `--framework`/
#: `--skip-framework` value list, not guessed. `secrets` and the two `sca_*`
#: frameworks duplicate this project's own Gitleaks/Trivy categories; every
#: `sast*` framework is source-code static analysis, a category of its own
#: this project does not have yet.
_EXCLUDED_FRAMEWORKS: tuple[str, ...] = (
    "secrets",
    "sca_package",
    "sca_image",
    "sast",
    "sast_python",
    "sast_java",
    "sast_javascript",
    "sast_typescript",
    "sast_golang",
)


class CheckovOutputError(Exception):
    """checkov produced output that is not the JSON report shape this parser expects.

    Raised for genuinely malformed output (not valid JSON, or an unexpected
    top-level or entry shape) — treated by `linceo.core.engine` the same as
    any other parse failure: absence of evidence, not zero findings (ADR
    §5).
    """


def _framework_documents(document: object) -> Sequence[Mapping[str, object]]:
    """Normalize checkov's three real top-level JSON shapes into a list of per-framework documents.

    Checkov's `-o json` report shape depends on how many frameworks
    produced results (confirmed against the real 3.3.19 binary, not
    assumed — see `tests/unit/fixtures/checkov/README.md`):

    - Zero findings anywhere (including a directory with no matching IaC
      files at all): a bare summary object with no `results` key —
      normalizes to `()`.
    - Exactly one framework produced results: a single
      `{"check_type": ..., "results": {...}}` object — normalizes to a
      one-element list.
    - More than one framework produced results: a JSON array of that same
      per-framework object shape — passed through as-is.

    Raises:
        CheckovOutputError: if `document` is a list containing a non-object
            entry, or is neither an object nor a list at all.
    """
    if isinstance(document, list):
        if not all(isinstance(entry, Mapping) for entry in document):
            msg = "checkov report array must contain only JSON objects"
            raise CheckovOutputError(msg)
        return document
    if isinstance(document, Mapping):
        return (document,) if "results" in document else ()
    msg = f"checkov report must be a JSON object or array, got {type(document).__name__}"
    raise CheckovOutputError(msg)


@dataclass(slots=True)
class CheckovIntegration:
    """Thin `ToolIntegration` adapter around `checkov -d <path> -o json` (ADR §10).

    `version` is supplied by the caller — typically the real installed
    version detected via `detect_version` before this integration is even
    constructed (ADR R4) — the same pattern
    `GitleaksIntegration.version`/`TrivyIntegration.version` establish.
    """

    version: str
    name: str = CHECKOV_TOOL_NAME
    category: Category = Category.IAC

    @staticmethod
    def detect_version(executor: ToolExecutor) -> str:
        """Detect the installed checkov binary's version via `checkov --version`.

        Satisfies the `ToolIntegration.detect_version` contract (ADR §1
        checkpoint): called on the class itself, before any
        `CheckovIntegration` instance exists. Plain text, like
        `GitleaksIntegration.detect_version` — confirmed against the real
        3.3.19 binary that `--version` prints nothing but the bare version
        number.

        Raises:
            FileNotFoundError: if the checkov binary is not on `PATH` —
                the actionable signal a caller (typically the CLI) turns
                into `missing_binary_hint` (ADR R4).
        """
        result = executor.run((CHECKOV_BINARY, "--version"), env={}, cwd=".", timeout=None)
        return result.stdout.strip()

    def missing_binary_hint(self) -> str:
        """Satisfy `ToolIntegration.missing_binary_hint` with checkov's own actionable text."""
        return CHECKOV_MISSING_BINARY_HINT

    def build_env(self) -> Mapping[str, str]:
        """Satisfy `ToolIntegration.build_env` (ADR §1 amendment): suppress checkov's PyPI check.

        Unconditional, on every invocation, regardless of what the
        operator's own shell happens to have set — the same "the
        integration itself guarantees the offline default" standard
        `TrivyIntegration.build_command` already meets via
        `--skip-db-update` (this module's own docstring, point 3).
        """
        return {_SKIP_PACKAGE_UPDATE_CHECK_ENV: "True"}

    def build_command(self, *, workspace_path: str, config: ToolConfig) -> Sequence[str]:
        """Build the `checkov -d` argv against `workspace_path`, applying `config` (ADR §8.5).

        Translates `exclude_paths` to checkov's own `--skip-path` (repeated
        once per entry, the same repeatable-flag shape
        `TrivyIntegration.build_command` already uses for `--skip-dirs`)
        and `custom_rules_path` to `--external-checks-dir` (a directory of
        custom Python checks — the closest checkov equivalent to gitleaks'
        own `--config`). `config.timeout` is never read here, for the same
        reason neither `GitleaksIntegration.build_command` nor
        `TrivyIntegration.build_command` reads it (see `ToolConfig.timeout`).
        `--skip-framework` and `--skip-download` are always included,
        unconditionally, the same way `--skip-db-update` always is for
        `TrivyIntegration` — the latter is this module's own offline
        default (this module's own docstring, point 3): without it,
        checkov attempts to reach `api0.prismacloud.io` on every
        invocation, with or without an API key. `config.passthrough` is
        appended last via `render_passthrough_flags`.

        Raises:
            UnsupportedToolConfigError: if `config.scan_history` is not
                `None` — an IaC directory scan has no notion of history to
                switch between, the same reasoning
                `TrivyIntegration.build_command` already gives for its own
                dependency-manifest scan (ADR §8.5).
        """
        if config.scan_history is not None:
            msg = (
                "checkov has no notion of scan history — an IaC directory scan only ever "
                "reflects the workspace as currently checked out, the same way trivy's "
                "dependency-manifest scan must (ADR §8.5). Remove scan_history for checkov."
            )
            raise UnsupportedToolConfigError(msg)

        argv = [
            CHECKOV_BINARY,
            "-d",
            workspace_path,
            "-o",
            "json",
            "--skip-framework",
            ",".join(_EXCLUDED_FRAMEWORKS),
            "--skip-download",
        ]
        if config.exclude_paths:
            for excluded in config.exclude_paths:
                argv.extend(("--skip-path", excluded))
        if config.custom_rules_path is not None:
            argv.extend(("--external-checks-dir", config.custom_rules_path))
        argv.extend(render_passthrough_flags(config.passthrough))
        return tuple(argv)

    def parse_output(self, result: ProcessResult) -> Sequence[RawFinding]:
        """Parse checkov's JSON report (on stdout) into `RawFinding`s.

        Never gates on `result.exit_code` — like `GitleaksIntegration.
        parse_output` and unlike `TrivyIntegration.parse_output`: checkov,
        like gitleaks, exits non-zero by design whenever it finds anything
        (confirmed against the real binary), so a non-zero exit is not on
        its own evidence of a crash. A genuine crash still surfaces as a
        parse failure below, since it would not produce this parser's
        expected JSON shape on stdout either.

        Raises:
            CheckovOutputError: if `result.stdout` is not valid JSON, or is
                not one of the three real top-level shapes
                `_framework_documents` normalizes (ADR §11's golden
                fixtures document all three), or a `failed_checks` entry is
                missing a field this parser relies on.
        """
        try:
            document = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            msg = f"checkov report is not valid JSON: {exc}"
            raise CheckovOutputError(msg) from exc

        findings: list[RawFinding] = []
        for framework_document in _framework_documents(document):
            findings.extend(self._parse_framework_document(framework_document))
        return tuple(findings)

    def _parse_framework_document(
        self, framework_document: Mapping[str, object]
    ) -> Sequence[RawFinding]:
        """Parse one per-framework document's `results.failed_checks` into `RawFinding`s.

        Raises:
            CheckovOutputError: if `results` is present but not an object,
                or `failed_checks` is present but not an array.
        """
        results = framework_document.get("results")
        if results is None:
            return ()
        if not isinstance(results, Mapping):
            msg = f"checkov report's results must be a JSON object, got {type(results).__name__}"
            raise CheckovOutputError(msg)

        failed_checks = results.get("failed_checks") or []
        if not isinstance(failed_checks, list):
            msg = (
                "checkov report's results.failed_checks must be a JSON array, got "
                f"{type(failed_checks).__name__}"
            )
            raise CheckovOutputError(msg)

        return tuple(self._parse_entry(entry) for entry in failed_checks)

    def _parse_entry(self, entry: object) -> RawFinding:
        """Parse one `results.failed_checks[]` entry into a `RawFinding`.

        Raises:
            CheckovOutputError: if `entry` is not an object, is missing a
                required field, or has one of the wrong type.
        """
        if not isinstance(entry, Mapping):
            msg = f"checkov failed_checks entry must be a JSON object, got {type(entry).__name__}"
            raise CheckovOutputError(msg)

        try:
            check_id = entry["check_id"]
            check_name = entry["check_name"]
            file_path = entry["file_path"]
            resource = entry["resource"]
        except KeyError as exc:
            msg = f"checkov failed_checks entry is missing required field {exc}"
            raise CheckovOutputError(msg) from exc

        if not all(isinstance(value, str) for value in (check_id, file_path, resource)):
            msg = "checkov failed_checks entry's check_id, file_path, and resource must be strings"
            raise CheckovOutputError(msg)

        # checkov's own `file_path` is relative to `-d workspace_path`, but
        # prefixed with a single leading "/" (confirmed against the real
        # binary — "/main.tf", "/subdir/main.tf") — stripped here to match
        # every other category's repository-relative, no-leading-slash
        # `Location.path` convention.
        relative_path = file_path.removeprefix("/")

        line_range = entry.get("file_line_range")
        line = (
            line_range[0]
            if isinstance(line_range, list) and line_range and isinstance(line_range[0], int)
            else None
        )

        raw_severity = entry.get("severity")
        if raw_severity is not None and not isinstance(raw_severity, str):
            msg = "checkov failed_checks entry's severity must be a string when present"
            raise CheckovOutputError(msg)

        return RawFinding(
            tool=self.name,
            category=Category.IAC,
            rule_id=check_id,
            message=str(check_name),
            location=Location(path=relative_path, line=line),
            raw_severity=raw_severity,
            resource=resource,
        )

    def data_sources(self) -> Sequence[DataSource]:
        """Declare this integration's data sources (ADR §5): none.

        checkov's detection rules ship baked into the installed package —
        there is no separately versioned, separately dated artifact to
        track staleness against, the same reasoning
        `GitleaksIntegration.data_sources` already gives.
        """
        return ()

    def native_severity_domain(self) -> frozenset[str]:
        """Declare checkov's native severity domain (ADR §6): empty.

        checkov's open-source edition never emits a native severity value
        at all — every `RawFinding` this integration's default
        configuration produces has `raw_severity=None` (this module's own
        docstring, point 1).
        """
        return frozenset()

    def report_schema(self) -> ReportSchema:
        """Declare the `iac` category's console table columns (ADR §7)."""
        return _REPORT_SCHEMA


__all__ = [
    "CHECKOV_BINARY",
    "CHECKOV_MISSING_BINARY_HINT",
    "CHECKOV_TOOL_NAME",
    "SUPPORTED_VERSION_RANGE",
    "CheckovIntegration",
    "CheckovOutputError",
]
