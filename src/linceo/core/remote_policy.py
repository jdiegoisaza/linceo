"""Remote policy resolution: fetch, governance boundary, merge, and degradation (ADR R2, §8.4).

Realizes the "future remote source" §8.4 already designed `parse_policy_document`
around without building: this module never touches TOML *schema* parsing
itself (`linceo.core.policy.parse_policy_document`,
`linceo.core.tool_config.parse_tool_defaults`/`parse_tool_configs` do that,
unchanged) — its own job is entirely upstream of that, and entirely about
*where* a document's mapping came from, not what is inside it:

- **Governance boundary** (ADR §8.4's design note, made concrete). A remote
  document may declare only what security centrally owns and changes a few
  times a year — `fail_on`/`[thresholds]`/`[thresholds.<category>]` and
  `[tool_defaults]`/`[tools.<name>]` — never `[[exclusions]]` or
  `[[skipped_tools]]`, which a team owns locally and changes every week.
  Declaring either in a remote document is a configuration error
  (`validate_remote_document`), not a warning: it is a mistake in a document
  security itself authored, and failing loudly at the point that document is
  actually consumed is far cheaper than letting every downstream pipeline
  silently apply a suppression nobody local to that repository ever agreed
  to. The same reasoning already governs every other misplaced field in this
  project (`linceo.core.config._validate_top_level_keys`'s
  `[tool_defaults]`/`[tools.<name>]` hint is the closest precedent) — this is
  that same idiom, not a new one.
- **Merge.** `merge_remote_into_local` overlays exactly the governed keys the
  remote document actually declares onto the local document, leaving
  everything else — `[[exclusions]]`, `[[skipped_tools]]`, every scalar,
  `[remote_policy]` itself — untouched. A governed key the remote document
  does not mention falls back to the local file's own declaration, the same
  "a layer that doesn't mention a field never hides a lower layer's value"
  rule ADR §5/R5 already applies to CLI/env/file scalars and to
  `[tool_defaults]`/`[tools.<name>]` (`resolve_tool_config`).
- **Degradation.** `resolve_remote_policy_document` is the one place a fetch
  is attempted, a local cache (the "última buena conocida") is read or
  written, and both are turned into one `PolicySourceStatus` a report can
  render (ADR §5's `stale_data` principle, generalized: "un reporte no puede
  declararse limpio sin declarar la edad de su evidencia" applies exactly as
  much to which policy governed a run as it does to a vulnerability
  database's own age). A failed fetch — network, auth, a malformed or
  invalid remote document — is never a fatal error on its own: it degrades
  to the cached copy, or to the local document alone, always loudly declared
  (ADR §5, §8.4). There is deliberately no automatic refresh cadence to
  configure: a run with `[remote_policy]` declared always attempts a fresh
  fetch, precisely so a policy change security pushes reaches every pipeline
  on its very next run without anyone needing to force anything — the whole
  point of "todos los pipelines la heredan" (ADR §8.4). "Forcing a refresh"
  of a *stale cached fallback* is therefore not a flag this module exposes:
  fixing whatever made the live fetch fail is what does it, automatically,
  on the next run.
- **Cache identity and permissions (ADR §9).** The cache is keyed by
  `linceo.core.ports.PolicySource.cache_key()` — the concrete source's own
  resolved real-world location (organization, project, repository, path for
  `AzureDevOpsPolicySource`) — never by `RemotePolicyDeclaration` alone: a
  key derived only from what the *scanned repository* declares (a name, an
  optional project override) cannot tell apart two different organizations,
  or two different projects of the same organization, that happen to
  declare the same repository name — exactly the case on a self-hosted
  agent pool shared across teams. `write_cached_policy` also creates the
  cache directory and file owner-only (`0700`/`0600`, set at creation time,
  never loosened by a later `chmod`): a policy document is not itself a
  credential, but it is still one tenant's data that another local user or
  process on a shared runner has no business reading.

Every function here is pure with respect to the real process environment and
the network — `env: Mapping[str, str]` is always an already-resolved mapping
the caller supplies (ADR §5/R5's own `load_config` pattern), and the actual
fetch happens behind the `PolicySource` protocol (`linceo.core.ports`), never
inside this module — so this stays importable, and fully testable, with zero
third-party dependencies and zero network or `os.environ` access, exactly
like the rest of `linceo.core` (AGENTS.md, "Layer boundaries").
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from linceo.core.policy import DEFAULT_MAX_POLICY_CACHE_AGE_DAYS, PolicyConfigurationError
from linceo.core.ports import PolicySource

#: `remote_policy.path`'s value when a declaration does not set one.
DEFAULT_REMOTE_POLICY_PATH = "policy.toml"

_DECLARATION_KNOWN_FIELDS = frozenset({"repository", "path", "project", "token_env"})

#: The only top-level keys a remote policy document may declare at all
#: (ADR §8.4's governance boundary) — thresholds and tool configuration,
#: nothing else. `version` is accepted but never required or inspected here;
#: a remote document reuses the same `version = 1` header a local one does,
#: for the same future-compatibility reason (ADR §8.4).
_REMOTE_GOVERNED_KEYS = frozenset({"fail_on", "thresholds", "tool_defaults", "tools"})
_REMOTE_ALLOWED_TOP_LEVEL_KEYS = frozenset({"version"}) | _REMOTE_GOVERNED_KEYS

#: Local-only sections a remote document must never declare (ADR §8.4's
#: governance boundary) — checked, and named specifically in the resulting
#: error, before the generic "outside its governance surface" check below,
#: so the message a security engineer sees for this specific mistake
#: explains *why*, not just *that* it is rejected.
_REMOTE_LOCAL_ONLY_KEYS = frozenset({"exclusions", "skipped_tools"})


@dataclass(frozen=True, slots=True)
class RemotePolicyDeclaration:
    """One scanned repository's own pointer to the remote policy document that governs it.

    Lives in the *local* `.devsecops/config.toml`'s own `[remote_policy]`
    table (ADR §5/R5, §8.4) — a pointer is not itself client-specific
    *policy*, the same way `--config`'s own path is not, so it is exactly
    the kind of thing R5 already lets this file declare. `repository` is a
    name, never a URL (ADR §8.4, "referencia por nombre, no por URL"): a
    concrete `PolicySource` (`linceo.providers.azure_devops.AzureDevOpsPolicySource`)
    resolves it against the current build's own platform context.
    `project` defaults to the build's own project when unset — the common
    case, a security team's baseline repository living in the same Azure
    DevOps project as everything else — but is overridable for the very
    real case where it lives in a dedicated security/platform project of
    its own instead. `token_env` names the environment variable carrying
    the auth token (ADR §9: never the token's value itself); `None` when
    the source needs no authentication at all (a public or anonymously
    readable repository).
    """

    repository: str
    path: str = DEFAULT_REMOTE_POLICY_PATH
    project: str | None = None
    token_env: str | None = None


def parse_remote_policy_declaration(
    document: Mapping[str, object],
) -> RemotePolicyDeclaration | None:
    """Parse the local document's own `[remote_policy]` table, if it declares one (ADR §8.4).

    `None` when the document declares no `remote_policy` table at all — the
    common case today, and the same "absent means not configured, never an
    error" treatment every other optional section of this document already
    gets.

    Raises:
        PolicyConfigurationError: if `remote_policy` is present but is not a
            table, declares an unknown field, omits `repository`, or gives
            any field the wrong type.
    """
    raw = document.get("remote_policy")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        msg = f"remote_policy must be a table, got {type(raw).__name__}"
        raise PolicyConfigurationError(msg)

    unknown = set(raw) - _DECLARATION_KNOWN_FIELDS
    if unknown:
        msg = f"remote_policy declares unknown field(s): {sorted(unknown)}"
        raise PolicyConfigurationError(msg)

    repository = raw.get("repository")
    if not isinstance(repository, str) or not repository:
        msg = "remote_policy.repository is required and must be a non-empty string"
        raise PolicyConfigurationError(msg)

    path = raw.get("path", DEFAULT_REMOTE_POLICY_PATH)
    if not isinstance(path, str) or not path:
        msg = "remote_policy.path must be a non-empty string"
        raise PolicyConfigurationError(msg)

    project = raw.get("project")
    if project is not None and not isinstance(project, str):
        msg = "remote_policy.project must be a string"
        raise PolicyConfigurationError(msg)

    token_env = raw.get("token_env")
    if token_env is not None and not isinstance(token_env, str):
        msg = "remote_policy.token_env must be a string"
        raise PolicyConfigurationError(msg)

    return RemotePolicyDeclaration(
        repository=repository, path=path, project=project, token_env=token_env
    )


def validate_remote_document(document: Mapping[str, object]) -> None:
    """Reject a remote document that oversteps its governance boundary (ADR §8.4).

    Raises:
        PolicyConfigurationError: if `document` declares `exclusions` or
            `skipped_tools` (local-only, named specifically — see the
            module docstring for why this is an error rather than a
            silently-ignored warning), or any other key outside
            `_REMOTE_ALLOWED_TOP_LEVEL_KEYS`.
    """
    local_only = set(document) & _REMOTE_LOCAL_ONLY_KEYS
    if local_only:
        msg = (
            f"remote policy document declares {sorted(local_only)} — exclusions and tool skips "
            "are local-only by governance design (ADR R2, §8.4): security owns thresholds and "
            "tool configuration and changes them a few times a year; each scanned repository "
            "owns its own exclusions and tool skips in its own .devsecops/config.toml and "
            "changes them every week — a team should never need a pull request to the security "
            "repository to suppress its own false positive. Remove these from the remote "
            "document."
        )
        raise PolicyConfigurationError(msg)

    unknown = set(document) - _REMOTE_ALLOWED_TOP_LEVEL_KEYS
    if unknown:
        msg = (
            f"remote policy document declares field(s) outside its governance surface: "
            f"{sorted(unknown)} — a remote policy document may declare only "
            f"{sorted(_REMOTE_ALLOWED_TOP_LEVEL_KEYS)} (ADR R2, §8.4): thresholds and tool "
            "configuration, nothing else."
        )
        raise PolicyConfigurationError(msg)


def merge_remote_into_local(
    *, local_document: Mapping[str, object], remote_document: Mapping[str, object]
) -> Mapping[str, object]:
    """Overlay `remote_document`'s governed keys onto `local_document`, entirely (ADR §8.4).

    Only `_REMOTE_GOVERNED_KEYS` can move from `remote_document` to the
    result, and only the ones `remote_document` actually declares — a
    governed key it is silent on leaves `local_document`'s own value (if
    any) untouched, never cleared. Every other key — `exclusions`,
    `skipped_tools`, `remote_policy` itself, every scalar — always comes
    from `local_document` alone: `validate_remote_document` already
    guarantees `remote_document` never carries the first two, and this
    function does not even look at the rest.

    Callers pass the merged mapping to `linceo.core.policy.parse_policy_document`,
    `linceo.core.tool_config.parse_tool_defaults`, and `parse_tool_configs`
    exactly as they would the local document alone (ADR §8.4's "the schema
    difficult to get right is this one" design note, realized without
    changing any of those three functions).
    """
    merged: dict[str, object] = dict(local_document)
    for key in _REMOTE_GOVERNED_KEYS:
        if key in remote_document:
            merged[key] = remote_document[key]
    return merged


class RemotePolicyFetchError(Exception):
    """A `PolicySource.fetch` could not produce a usable remote policy document (ADR R2, §8.4).

    The one exception type every concrete `PolicySource` translates *every*
    failure into (see `linceo.core.ports.PolicySource.fetch`) — a network
    error, a missing or rejected auth token, a non-200 response, the
    `linceo[remote-config]` extra not being installed. `resolve_remote_policy_document`
    also raises this internally, wrapping a fetched-but-invalid document
    (unparseable TOML, or one `validate_remote_document` rejects) so both
    failure classes — "could not fetch" and "fetched something unusable" —
    degrade through the exact same path: a real-world mistake in the remote
    document (a typo security pushed) must never turn into a hard failure
    for every pipeline that inherits it, any more than a network blip
    should (ADR §5's "degradación, nunca error fatal").
    """


class PolicySourceState(StrEnum):
    """Where this run's remote-governed policy (thresholds, tool config) actually came from."""

    #: Fetched successfully this run.
    FRESH = "fresh"
    #: The fetch attempt failed; a previously cached copy was used instead.
    CACHED = "cached"
    #: The fetch attempt failed and no usable cached copy existed either —
    #: this run's policy is the local document alone.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class PolicySourceStatus:
    """A report-facing declaration of this run's remote policy provenance (ADR §5, §8.4).

    Attached to `linceo.core.results.RunResult.policy_source` (via
    `linceo.core.config.Config`) only when a run actually declares
    `[remote_policy]` — `None` on every other run, so this never shows up
    for the common case that does not use the feature at all.

    `age_days` and `fetched_at` are `None` only for `PolicySourceState.UNAVAILABLE`
    (there is no successful fetch, cached or otherwise, to date); `0` and
    `now` for `FRESH`. `stale` is `True` for `UNAVAILABLE` unconditionally
    (there is no policy freshness to speak of at all) and for `CACHED` once
    `age_days` exceeds `DEFAULT_MAX_POLICY_CACHE_AGE_DAYS` — mirroring
    `linceo.cli.doctor.DataSourceStatus.stale` exactly, including that
    exceeding it is a `WARN`, never by itself a hard failure (ADR §5).
    `detail` carries the fetch failure's own message for `CACHED`/`UNAVAILABLE`,
    so a report can say not just *that* the remote source degraded but
    *why*; always `None` for `FRESH`.
    """

    repository: str
    path: str
    state: PolicySourceState
    fetched_at: datetime | None
    age_days: int | None
    stale: bool
    detail: str | None = None


#: Directory segments under the resolved cache base (ADR §8.4, "CACHÉ LOCAL").
_CACHE_SUBDIR = ("linceo", "remote-policy")


def default_cache_dir(env: Mapping[str, str]) -> str:
    """Resolve the local cache directory a remote policy document's fallback copy lives under.

    `env` is the caller's already-resolved process environment — this
    function never reads the real `os.environ` itself (ADR §5/R5's own
    `load_config` pattern; AGENTS.md, "Layer boundaries"). `LINCEO_POLICY_CACHE_DIR`
    overrides the default outright, for a runner with an unusual filesystem
    layout; otherwise `XDG_CACHE_HOME` if set (the standard convention on
    Linux, the reference container image's own platform — ADR §4/R4), else
    `~/.cache` resolved against `HOME` (or, on Windows, `USERPROFILE`) from
    the same mapping.
    """
    override = env.get("LINCEO_POLICY_CACHE_DIR")
    if override:
        return override
    xdg_cache_home = env.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        base = xdg_cache_home
    else:
        home = env.get("HOME") or env.get("USERPROFILE") or "."
        base = str(Path(home) / ".cache")
    return str(Path(base, *_CACHE_SUBDIR))


def cache_path_for(cache_key: str, *, cache_dir: str) -> Path:
    """The full path a `PolicySource.cache_key()` value's cached copy lives at, under `cache_dir`.

    `cache_key` must already be the *source's own* resolved identity
    (`linceo.core.ports.PolicySource.cache_key`) — organization, project,
    repository, and path hashed together for `AzureDevOpsPolicySource` —
    never derived from `RemotePolicyDeclaration` alone here: the
    declaration only ever carries what the *scanned repository* wrote
    (a name, optionally a project override), not the organization a
    concrete source resolves from the runner's own environment, so a
    `core`-only key would collide across two different real-world
    locations that happen to share a declared name (ADR §8.4, ADR §9's
    "no inventar valores" extended to cache identity: guessing a key from
    less information than the source actually has is exactly how two
    tenants of one shared runner would end up reading each other's
    policy).
    """
    return Path(cache_dir) / f"{cache_key}.toml"


def read_cached_policy(cache_path: Path) -> tuple[str, datetime] | None:
    """Read `cache_path`'s last known good content and its own fetch time.

    The file's own mtime doubles as `fetched_at` — no separate sidecar file
    for one timestamp (AGENTS.md, "No placeholder code"). `None` if
    `cache_path` does not exist, or exists but cannot be read as UTF-8 text
    — the caller (`_degraded_status`) treats either exactly like "no cache
    exists", never as a distinct error of its own.
    """
    if not cache_path.is_file():
        return None
    try:
        content = cache_path.read_text(encoding="utf-8")
    except OSError:
        return None
    fetched_at = datetime.fromtimestamp(cache_path.stat().st_mtime, tz=UTC)
    return content, fetched_at


#: Owner-only (ADR §9): a policy document fetched on behalf of one
#: tenant of a shared runner must not be world- or group-readable to any
#: other local user or process on that same host, even though its content
#: is not itself a credential — the same least-privilege default this
#: project already applies to the credential that fetched it.
_CACHE_DIR_MODE = 0o700
_CACHE_FILE_MODE = 0o600


def write_cached_policy(cache_path: Path, content: str) -> None:
    """Persist `content` as `cache_path`'s new last-known-good copy, owner-only (ADR §8.4, §9).

    Called only once a freshly fetched document has already parsed and
    validated successfully (`resolve_remote_policy_document`) — the cache
    never holds content that failed either check. The containing directory
    is (re)set to `_CACHE_DIR_MODE` on every write — self-healing a
    directory a previous version of this function, or anything else, left
    world-readable — and the file itself is created (or truncated) with
    `_CACHE_FILE_MODE` from the very first `os.open` call, never `chmod`ed
    afterward: setting the mode at creation time closes the window during
    which a default-permission file would otherwise be briefly readable by
    any other local user before a following `chmod` call could tighten it.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.parent.chmod(_CACHE_DIR_MODE)
    file_descriptor = os.open(cache_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _CACHE_FILE_MODE)
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    cache_path.chmod(_CACHE_FILE_MODE)


def _decode_and_validate(content: str) -> Mapping[str, object]:
    """Parse `content` as TOML and check it against the governance boundary.

    Raises:
        RemotePolicyFetchError: if `content` is not valid TOML, or
            `validate_remote_document` rejects its shape — both folded into
            this one exception type so `resolve_remote_policy_document`
            treats "fetched, but unusable" identically to "could not fetch
            at all" (see `RemotePolicyFetchError`'s own docstring).
    """
    try:
        document = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        msg = f"remote policy document is not valid TOML: {exc}"
        raise RemotePolicyFetchError(msg) from exc
    try:
        validate_remote_document(document)
    except PolicyConfigurationError as exc:
        raise RemotePolicyFetchError(str(exc)) from exc
    return document


def _resolved_cache_path(source: PolicySource, *, cache_dir: str) -> Path | None:
    """`cache_path_for(source.cache_key(), cache_dir=cache_dir)`, or `None` if unresolvable.

    A source unable to resolve its own `cache_key` — the same condition
    that would make `fetch` itself unable to resolve a location, e.g. a
    required environment variable absent — has no cache to read from or
    write to at all: there is no safe key to read an old entry under, or to
    write a new one under, without risking either reading a stale value
    that belongs to nothing this run can identify, or writing one under a
    key some *other* location might later collide with. Treated as "no
    cache", never as a second error on top of whatever already made `fetch`
    fail.
    """
    try:
        return cache_path_for(source.cache_key(), cache_dir=cache_dir)
    except RemotePolicyFetchError:
        return None


def _degraded_status(
    *,
    source: PolicySource,
    declaration: RemotePolicyDeclaration,
    cache_dir: str,
    now: datetime,
    detail: str,
) -> tuple[Mapping[str, object] | None, PolicySourceStatus]:
    """Fall back to a cached copy, or to local-only, after a failed fetch attempt (ADR §5, §8.4)."""
    cache_path = _resolved_cache_path(source, cache_dir=cache_dir)
    cached = read_cached_policy(cache_path) if cache_path is not None else None
    if cached is not None:
        content, fetched_at = cached
        try:
            document = _decode_and_validate(content)
        except RemotePolicyFetchError:
            document = None
        if document is not None:
            age_days = (now.date() - fetched_at.date()).days
            status = PolicySourceStatus(
                repository=declaration.repository,
                path=declaration.path,
                state=PolicySourceState.CACHED,
                fetched_at=fetched_at,
                age_days=age_days,
                stale=age_days > DEFAULT_MAX_POLICY_CACHE_AGE_DAYS,
                detail=detail,
            )
            return document, status

    status = PolicySourceStatus(
        repository=declaration.repository,
        path=declaration.path,
        state=PolicySourceState.UNAVAILABLE,
        fetched_at=None,
        age_days=None,
        stale=True,
        detail=detail,
    )
    return None, status


def resolve_remote_policy_document(
    *, source: PolicySource, declaration: RemotePolicyDeclaration, cache_dir: str, now: datetime
) -> tuple[Mapping[str, object] | None, PolicySourceStatus]:
    """Fetch this run's remote-governed policy, degrading to a cache or local-only (ADR R2, §8.4).

    Always attempts a fresh fetch through `source` first — there is no TTL
    gating this attempt (see the module docstring): a run that declares
    `[remote_policy]` inherits whatever security most recently published,
    every time, with no operator action required to pick up a change. Only
    once that attempt fails — for any reason `RemotePolicyFetchError`
    covers, network or otherwise, including a fetched-but-invalid document —
    does this fall back to the last known good copy cached under
    `source.cache_key()` (never a key derived from `declaration` alone —
    see `cache_path_for`), or, failing that too, to `None` (local-only). On
    success, the fetched content is also written to that same cache entry,
    becoming the fallback a future failed fetch degrades to.

    Returns a `(document, status)` pair. `document` is the decoded and
    validated mapping `linceo.core.config.load_config` merges into the
    local one via `merge_remote_into_local` — `None` exactly when `status.state`
    is `PolicySourceState.UNAVAILABLE`, meaning this run's policy is the
    local document alone (ADR §8.4, "qué pasa cuando no hay ni remota ni
    local": never a configuration error — the same permissive default an
    entirely absent local file already resolves to, ADR §5/R5). `status` is
    never `None`: every call that reaches this function has a
    `[remote_policy]` declaration to report on, one way or another.
    """
    try:
        fetched = source.fetch()
        document = _decode_and_validate(fetched.content)
    except RemotePolicyFetchError as exc:
        return _degraded_status(
            source=source, declaration=declaration, cache_dir=cache_dir, now=now, detail=str(exc)
        )

    cache_path = _resolved_cache_path(source, cache_dir=cache_dir)
    if cache_path is not None:
        write_cached_policy(cache_path, fetched.content)
    status = PolicySourceStatus(
        repository=declaration.repository,
        path=declaration.path,
        state=PolicySourceState.FRESH,
        fetched_at=now,
        age_days=0,
        stale=False,
        detail=None,
    )
    return document, status


__all__ = [
    "DEFAULT_REMOTE_POLICY_PATH",
    "PolicySourceState",
    "PolicySourceStatus",
    "RemotePolicyDeclaration",
    "RemotePolicyFetchError",
    "cache_path_for",
    "default_cache_dir",
    "merge_remote_into_local",
    "parse_remote_policy_declaration",
    "read_cached_policy",
    "resolve_remote_policy_document",
    "validate_remote_document",
    "write_cached_policy",
]
