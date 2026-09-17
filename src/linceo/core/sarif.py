"""SARIF 2.1.0 exporter (ADR §7): the interchange format, not the canonical one.

`render_sarif` is deliberately lossy for `sca` findings — SARIF has no
first-class field for a package's name, installed version, or the version
that fixes a vulnerability — while `linceo.core.reporters.render_json`
never loses anything at all. That asymmetry is not a defect to fix here:
it is exactly why this project keeps its own JSON report as the canonical,
lossless format and treats SARIF as what it is by design — an interchange
format with controlled, documented loss for the `sca` case (ADR §7). The
loss is absorbed, not silently dropped: an `sca` result carries a
`properties` extension block with the package's name, installed version,
and fixed version, and `locations` still points at the manifest that
declares the dependency.

One SARIF `run` per `ToolExecution`, never one `run` for the whole
`RunResult`: a SARIF `run.tool.driver` names exactly one tool, and
`RunResult` is explicitly built to carry N tool executions producing one
verdict (ADR §1's "N ejecuciones, un veredicto" invariant). Collapsing
every execution's findings into a single `tool.driver` would misattribute
one tool's findings to another the day a run legitimately spans more than
one category — today's CLI never does that (ADR §8, "una categoría por
invocación"), but the object model already allows it, and this reporter
must not assume otherwise just because nothing exercises it yet.

Each run's own `tool.driver.rules` is built from the `rule_id`s that run's
own findings use, and every one of that run's `results` references its
rule both by `ruleId` (the stable id ADR §7 asks for) and `ruleIndex` (the
by-position reference the same requirement asks for) — never through the
SARIF `result.rule` reference object, which exists to point at a rule
defined by a *different* tool component than the one reporting the
result; every rule any integration in this project reports is defined in
that same tool's own `driver`.

Validated in `tests/unit/test_sarif_reporter.py` against the official
SARIF 2.1.0 schema, vendored at `linceo/data/sarif-schema-2.1.0.json`
(ADR §7) — never against a remote copy of the schema, which would make
the project's own test suite reach the network (ADR R2).
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from linceo.core.execution import ToolExecution
from linceo.core.findings import Finding
from linceo.core.results import RunResult
from linceo.core.severity import Severity

#: Descriptive metadata only — the exact `id` of the vendored schema file,
#: identifying which published version of SARIF 2.1.0 this reporter
#: targets. Never fetched: no module in this project makes a network call
#: to resolve it (ADR R2).
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

#: The SARIF log's own `version` field — the one and only version this
#: reporter produces.
SARIF_VERSION = "2.1.0"

#: The key `result.partialFingerprints` carries this project's fingerprint
#: under (ADR §5, §7). Namespaced so a consumer correlating results from
#: several tools' own SARIF output — exactly what `partialFingerprints` is
#: for — never confuses this project's fingerprint with a differently
#: shaped one another tool happens to publish under the same bare key.
_FINGERPRINT_KEY = "linceo/fingerprint"

#: Normalized `Severity` (ADR §6) -> SARIF `result.level`. SARIF's scale
#: tops out at `error`, with no equivalent of this project's CRITICAL/HIGH
#: split — both map there, since the two consumers ADR §7 names (GitHub
#: Code Scanning, the Azure DevOps panel) both drive their own "does this
#: need attention" presentation off `level`, not off a `properties`
#: extension, so collapsing the two top levels into `error` is what keeps
#: this project's most severe findings visible where those consumers
#: actually look.
_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_catalog(
    findings: Sequence[Finding],
) -> tuple[tuple[dict[str, object], ...], dict[str, int]]:
    """Build one run's `tool.driver.rules` plus a `rule_id -> index` lookup, both deterministic.

    One entry per distinct `rule_id` among `findings`, sorted by id so the
    same set of findings always produces the same array regardless of the
    order `findings` happens to arrive in (ADR R3). Each rule's
    `shortDescription` borrows the `message` of whichever of its findings
    sorts first by fingerprint — the closest thing to a stable, standalone
    rule description available: `ToolIntegration` declares no separate
    rule catalog of its own (the ADR §1 checkpoint already found
    `Finding.rule_id` plus `message` "sufficient rule metadata" for SARIF,
    so this reporter does not go looking for more than that).
    """
    by_rule_id: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule_id.setdefault(finding.rule_id, []).append(finding)

    rule_ids = sorted(by_rule_id)
    rules: tuple[dict[str, object], ...] = tuple(
        {
            "id": rule_id,
            "shortDescription": {
                "text": min(by_rule_id[rule_id], key=lambda f: f.fingerprint).message
            },
        }
        for rule_id in rule_ids
    )
    index_by_rule_id = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    return rules, index_by_rule_id


def _location(finding: Finding) -> dict[str, object]:
    """One `result.locations[0]` entry: a `secrets` finding's source file, or `sca`'s manifest.

    `Finding.location.path` is already the right value for both
    categories with no category branch needed here — a source file for
    `secrets`, the manifest path for `sca` (ADR §5; the same field backs
    the console table's `MANIFEST` column, ADR §7). `region` is added only
    when a line number exists at all — `sca` findings never carry one, a
    manifest scan having no notion of a line to point at.
    """
    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": finding.location.path},
    }
    if finding.location.line is not None:
        region: dict[str, object] = {"startLine": finding.location.line}
        if finding.location.column is not None:
            region["startColumn"] = finding.location.column
        physical_location["region"] = region
    return {"physicalLocation": physical_location}


def _properties(finding: Finding) -> dict[str, object] | None:
    """The `sca` extension `properties` block ADR §7 requires — `None` for `secrets`.

    SARIF has no first-class field for a package's name, its installed
    version, or the version that fixes a vulnerability — this is the
    controlled, documented loss this module's own docstring describes:
    `linceo.core.reporters.render_json` is the lossless report; this is
    the interchange format recovering as much of the same fact as its
    `properties` extension mechanism allows.
    """
    if finding.package is None:
        return None
    return {
        "package_name": finding.package.name,
        "package_version": finding.package.version,
        "fixed_version": finding.package.fixed_version,
    }


def _result(finding: Finding, *, rule_index: int, suppressed: bool) -> dict[str, object]:
    """One `run.results[]` entry for `finding` — the secret itself never among its fields.

    Nothing here redacts a secret value: `Finding` (ADR §5, §9) carries no
    field for it in the first place, only `secret_hash`, which `secrets`
    findings don't even surface here — the leak this function could
    otherwise cause is structurally impossible, not merely avoided by
    care.
    """
    entry: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": finding.message},
        "locations": [_location(finding)],
        "partialFingerprints": {_FINGERPRINT_KEY: finding.fingerprint},
    }
    properties = _properties(finding)
    if properties is not None:
        entry["properties"] = properties
    if suppressed:
        # `kind: "external"`: suppressed by this project's own policy
        # engine, external to the tool that reported it (ADR §8.2) — no
        # `justification` text: `RunResult` retains *which* findings are
        # currently suppressed (`suppressed_findings`) but not which
        # `Exclusion` suppressed each one (contrast `expired_exclusions`,
        # which does keep the full `Exclusion`, reason included) — see
        # `linceo.core.policy.apply_exclusions` — so there is nothing
        # honest to put in `justification` yet.
        entry["suppressions"] = [{"kind": "external"}]
    return entry


def _run(execution: ToolExecution, *, suppressed_fingerprints: frozenset[str]) -> dict[str, object]:
    """One `runs[]` entry: `execution`'s own tool, its own rules, its own results.

    Built from `execution.findings` — not the run-level,
    cross-tool-deduplicated `RunResult.findings` — because a SARIF `run`
    describes one tool's own complete output; a consumer correlates the
    same finding reported by two different tools' `run`s through
    `partialFingerprints` itself, exactly the mechanism SARIF defines that
    field for (ADR §5, §7).
    """
    rules, index_by_rule_id = _rule_catalog(execution.findings)
    results = [
        _result(
            finding,
            rule_index=index_by_rule_id[finding.rule_id],
            suppressed=finding.fingerprint in suppressed_fingerprints,
        )
        for finding in execution.findings
    ]
    return {
        "tool": {
            "driver": {
                "name": execution.tool,
                "version": execution.tool_version,
                "rules": list(rules),
            }
        },
        "results": results,
    }


def render_sarif(result: RunResult) -> str:
    """Render `result` as a SARIF 2.1.0 log (ADR §7): always every finding, never `max_rows`-cut.

    One `run` per `result.executions` entry (see `_run`). `max_rows` (ADR
    §7) is a console-only presentation setting — exactly like
    `linceo.core.reporters.render_json`, this function has no equivalent
    parameter at all, so there is nothing here that could turn a legibility
    option into a silent loss of evidence.
    """
    suppressed_fingerprints = frozenset(
        finding.fingerprint for finding in result.suppressed_findings
    )
    runs = [
        _run(execution, suppressed_fingerprints=suppressed_fingerprints)
        for execution in result.executions
    ]
    document = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": runs,
    }
    return json.dumps(document, indent=2)
