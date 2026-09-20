"""Tests for `linceo.core.remote_policy` (ADR R2, §8.4): governance boundary and degradation."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from linceo.core.policy import DEFAULT_MAX_POLICY_CACHE_AGE_DAYS, PolicyConfigurationError
from linceo.core.ports import FetchedPolicy
from linceo.core.remote_policy import (
    DEFAULT_TOKEN_ENV_VAR,
    PolicySourceState,
    RemotePolicyDeclaration,
    RemotePolicyFetchError,
    cache_path_for,
    default_cache_dir,
    merge_remote_into_local,
    parse_remote_policy_declaration,
    read_cached_policy,
    resolve_remote_policy_document,
    validate_remote_document,
    write_cached_policy,
)
from linceo.testing.fakes import FakePolicySource

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)

# --- parse_remote_policy_declaration ------------------------------------------


def test_no_remote_policy_table_is_none() -> None:
    assert parse_remote_policy_declaration({}) is None


def test_a_minimal_declaration_defaults_path_project_and_token_env() -> None:
    """The common case (ADR §8.4): a same-organization repository needs no `token_env` line."""
    declaration = parse_remote_policy_declaration(
        {"remote_policy": {"repository": "security-baseline"}}
    )

    assert declaration == RemotePolicyDeclaration(repository="security-baseline")
    assert declaration is not None
    assert declaration.path == "policy.toml"
    assert declaration.project is None
    assert declaration.token_env == DEFAULT_TOKEN_ENV_VAR


def test_an_explicit_empty_token_env_opts_out_of_the_default() -> None:
    """An explicit `token_env = ""` never resolves to any real environment variable."""
    declaration = parse_remote_policy_declaration(
        {"remote_policy": {"repository": "security-baseline", "token_env": ""}}
    )

    assert declaration is not None
    assert declaration.token_env == ""


def test_a_full_declaration_parses_every_field() -> None:
    declaration = parse_remote_policy_declaration(
        {
            "remote_policy": {
                "repository": "security-baseline",
                "path": "policies/linceo.toml",
                "project": "platform-security",
                "token_env": "SYSTEM_ACCESSTOKEN",
            }
        }
    )

    assert declaration == RemotePolicyDeclaration(
        repository="security-baseline",
        path="policies/linceo.toml",
        project="platform-security",
        token_env="SYSTEM_ACCESSTOKEN",  # noqa: S106 -- an env var *name*, not a credential (ADR §9)
    )


def test_remote_policy_not_a_table_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="must be a table"):
        parse_remote_policy_declaration({"remote_policy": "oops"})


def test_remote_policy_missing_repository_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="repository"):
        parse_remote_policy_declaration({"remote_policy": {"path": "policy.toml"}})


def test_remote_policy_unknown_field_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="unknown field"):
        parse_remote_policy_declaration(
            {"remote_policy": {"repository": "security-baseline", "bogus": 1}}
        )


@pytest.mark.parametrize("field", ["path", "project", "token_env"])
def test_remote_policy_wrong_type_field_is_a_configuration_error(field: str) -> None:
    with pytest.raises(PolicyConfigurationError, match=field):
        parse_remote_policy_declaration(
            {"remote_policy": {"repository": "security-baseline", field: 5}}
        )


# --- validate_remote_document (governance boundary) ---------------------------


def test_a_document_with_only_governed_keys_is_valid() -> None:
    validate_remote_document({"version": 1, "fail_on": "high", "thresholds": {"high": 0}})


def test_exclusions_in_a_remote_document_is_a_configuration_error_naming_governance() -> None:
    with pytest.raises(PolicyConfigurationError, match="local-only by governance design"):
        validate_remote_document({"exclusions": []})


def test_skipped_tools_in_a_remote_document_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="local-only by governance design"):
        validate_remote_document({"skipped_tools": []})


def test_severity_overrides_in_a_remote_document_is_a_configuration_error() -> None:
    """A severity override, like an exclusion, carries a mandatory audit trail — local-only."""
    with pytest.raises(PolicyConfigurationError, match="local-only by governance design"):
        validate_remote_document({"severity_overrides": []})


def test_an_unrelated_key_in_a_remote_document_is_a_configuration_error() -> None:
    with pytest.raises(PolicyConfigurationError, match="governance surface"):
        validate_remote_document({"remote_policy": {"repository": "other"}})


def test_banner_is_accepted_as_a_governed_key() -> None:
    """`validate_remote_document` checks only the governance boundary — see
    `test_a_fetched_document_with_an_invalid_banner_degrades_like_a_failed_fetch`
    for where the banner's own *content* gets checked instead."""
    validate_remote_document({"banner": "ACME Corp Security Gate"})


# --- merge_remote_into_local ---------------------------------------------------


def test_merge_overlays_only_the_governed_keys_the_remote_document_declares() -> None:
    local = {
        "fail_on": "critical",
        "exclusions": [{"fingerprint": "v1:abc"}],
        "tool_defaults": {"timeout": 60},
    }
    remote = {"fail_on": "high", "thresholds": {"high": 0}}

    merged = merge_remote_into_local(local_document=local, remote_document=remote)

    assert merged["fail_on"] == "high"
    assert merged["thresholds"] == {"high": 0}
    assert merged["exclusions"] == local["exclusions"]
    assert merged["tool_defaults"] == {"timeout": 60}


def test_merge_leaves_a_governed_key_the_remote_document_is_silent_on_untouched() -> None:
    local = {"tool_defaults": {"timeout": 60}}
    remote = {"thresholds": {"high": 0}}

    merged = merge_remote_into_local(local_document=local, remote_document=remote)

    assert merged["tool_defaults"] == {"timeout": 60}
    assert merged["thresholds"] == {"high": 0}


def test_merge_of_an_empty_remote_document_changes_nothing() -> None:
    local = {"fail_on": "critical"}

    merged = merge_remote_into_local(local_document=local, remote_document={})

    assert merged == local


def test_merge_overlays_banner_when_the_remote_document_declares_it() -> None:
    local = {"banner": "local team banner"}
    remote = {"banner": "ACME Corp Security Gate"}

    merged = merge_remote_into_local(local_document=local, remote_document=remote)

    assert merged["banner"] == "ACME Corp Security Gate"


# --- cache directory resolution -------------------------------------------------


def test_default_cache_dir_prefers_the_explicit_override() -> None:
    assert default_cache_dir({"LINCEO_POLICY_CACHE_DIR": "/custom/cache"}) == "/custom/cache"


def test_default_cache_dir_prefers_xdg_cache_home() -> None:
    result = default_cache_dir({"XDG_CACHE_HOME": "/xdg-cache"})

    assert result == str(Path("/xdg-cache", "linceo", "remote-policy"))


def test_default_cache_dir_falls_back_to_home_dot_cache() -> None:
    result = default_cache_dir({"HOME": "/home/dev"})

    assert result == str(Path("/home/dev", ".cache", "linceo", "remote-policy"))


def test_cache_path_for_is_deterministic_given_the_same_cache_key() -> None:
    path_1 = cache_path_for("abc123", cache_dir="/cache")
    path_2 = cache_path_for("abc123", cache_dir="/cache")

    assert path_1 == path_2
    assert path_1.parent == Path("/cache")


def test_cache_path_for_distinguishes_different_cache_keys() -> None:
    """The regression this guards: two real-world locations must never share a cache entry."""
    path_a = cache_path_for("org-a-project-x-security-baseline", cache_dir="/cache")
    path_b = cache_path_for("org-b-project-y-security-baseline", cache_dir="/cache")

    assert path_a != path_b


# --- cache read/write, and its permissions (ADR §9) -----------------------------


def test_read_cached_policy_returns_none_when_the_file_does_not_exist(tmp_path: Path) -> None:
    assert read_cached_policy(tmp_path / "missing.toml") is None


def test_write_then_read_cached_policy_round_trips(tmp_path: Path) -> None:
    cache_path = tmp_path / "sub" / "cached.toml"

    write_cached_policy(cache_path, "version = 1\n")
    result = read_cached_policy(cache_path)

    assert result is not None
    content, fetched_at = result
    assert content == "version = 1\n"
    assert fetched_at.tzinfo is not None


def test_write_cached_policy_creates_an_owner_only_file_and_directory(tmp_path: Path) -> None:
    """ADR §9: a shared runner's other local users/processes must not be able to read this."""
    cache_path = tmp_path / "sub" / "cached.toml"

    write_cached_policy(cache_path, "version = 1\n")

    file_mode = stat.S_IMODE(cache_path.stat().st_mode)
    dir_mode = stat.S_IMODE(cache_path.parent.stat().st_mode)
    assert file_mode == 0o600
    assert dir_mode == 0o700


def test_write_cached_policy_tightens_a_previously_loose_directory(tmp_path: Path) -> None:
    """Self-healing: a directory a prior version left world-readable is corrected on next write."""
    cache_dir = tmp_path / "sub"
    cache_dir.mkdir(mode=0o755)
    cache_path = cache_dir / "cached.toml"

    write_cached_policy(cache_path, "version = 1\n")

    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700


# --- resolve_remote_policy_document: the full degradation flow ----------------

_DECLARATION = RemotePolicyDeclaration(repository="security-baseline", path="policy.toml")


def test_a_successful_fetch_is_fresh_and_writes_the_cache(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=FetchedPolicy(content='fail_on = "high"\n'))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document == {"fail_on": "high"}
    assert status.state is PolicySourceState.FRESH
    assert status.fetched_at == NOW
    assert status.age_days == 0
    assert status.stale is False
    assert status.detail is None
    cache_path = cache_path_for(source.cache_key(), cache_dir=str(tmp_path))
    assert cache_path.read_text(encoding="utf-8") == 'fail_on = "high"\n'


def test_a_failed_fetch_falls_back_to_a_fresh_cached_copy(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=RemotePolicyFetchError("network unreachable"))
    cache_path = cache_path_for(source.cache_key(), cache_dir=str(tmp_path))
    write_cached_policy(cache_path, 'fail_on = "critical"\n')
    os.utime(cache_path, (NOW.timestamp(), NOW.timestamp()))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document == {"fail_on": "critical"}
    assert status.state is PolicySourceState.CACHED
    assert status.age_days == 0
    assert status.stale is False
    assert status.detail == "network unreachable"


def test_a_failed_fetch_with_an_old_cache_is_flagged_stale(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=RemotePolicyFetchError("network unreachable"))
    cache_path = cache_path_for(source.cache_key(), cache_dir=str(tmp_path))
    write_cached_policy(cache_path, 'fail_on = "critical"\n')
    old_moment = NOW - timedelta(days=DEFAULT_MAX_POLICY_CACHE_AGE_DAYS + 1)
    old_timestamp = old_moment.timestamp()
    os.utime(cache_path, (old_timestamp, old_timestamp))

    _, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert status.state is PolicySourceState.CACHED
    assert status.age_days == DEFAULT_MAX_POLICY_CACHE_AGE_DAYS + 1
    assert status.stale is True


def test_a_failed_fetch_with_no_cache_at_all_is_unavailable_never_an_error(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=RemotePolicyFetchError("401 unauthorized"))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE
    assert status.fetched_at is None
    assert status.age_days is None
    assert status.stale is True
    assert status.detail == "401 unauthorized"


def test_a_fetched_document_declaring_exclusions_degrades_like_a_failed_fetch(
    tmp_path: Path,
) -> None:
    """A remote document that oversteps its governance boundary never reaches the merge step."""
    source = FakePolicySource(outcome=FetchedPolicy(content="[[exclusions]]\n"))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE
    assert status.detail is not None
    assert "governance" in status.detail


def test_a_fetched_document_with_a_valid_banner_resolves_normally(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=FetchedPolicy(content='banner = "ACME Corp Security Gate"\n'))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document == {"banner": "ACME Corp Security Gate"}
    assert status.state is PolicySourceState.FRESH


def test_a_fetched_document_with_an_invalid_banner_degrades_like_a_failed_fetch(
    tmp_path: Path,
) -> None:
    """Unlike an invalid `fail_on`/`[thresholds]` value (left to `linceo.core.config.load_config`
    to reject as a hard failure for the fetching pipeline), an invalid `banner` is checked here,
    at fetch time, and degrades instead — see `linceo.core.banner`'s own module docstring for
    why this one governed key gets the more forgiving treatment.

    A non-ASCII character, not a raw control character, is what demonstrates this: TOML itself
    already refuses an unescaped control character (e.g. a literal `ESC`) as a syntax error
    before this project's own `banner` check ever runs — `café`-style text is valid TOML and
    exactly the shape `linceo.core.banner.validate_banner` rejects on its own content.
    """
    source = FakePolicySource(outcome=FetchedPolicy(content='banner = "ACME Sécurité"\n'))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE
    assert status.detail is not None
    assert "printable ASCII" in status.detail


def test_a_fetched_document_that_is_not_valid_toml_degrades_like_a_failed_fetch(
    tmp_path: Path,
) -> None:
    source = FakePolicySource(outcome=FetchedPolicy(content="this is not [ valid toml"))

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE


def test_a_corrupted_cache_is_treated_as_no_cache_at_all(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=RemotePolicyFetchError("network unreachable"))
    cache_path = cache_path_for(source.cache_key(), cache_dir=str(tmp_path))
    write_cached_policy(cache_path, "this is not [ valid toml")

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE


def test_a_successful_fetch_overwrites_a_previously_cached_copy(tmp_path: Path) -> None:
    source = FakePolicySource(outcome=FetchedPolicy(content='fail_on = "high"\n'))
    cache_path = cache_path_for(source.cache_key(), cache_dir=str(tmp_path))
    write_cached_policy(cache_path, 'fail_on = "critical"\n')

    resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert cache_path.read_text(encoding="utf-8") == 'fail_on = "high"\n'


def test_every_successful_fetch_is_attempted_even_with_a_fresh_cache_present(
    tmp_path: Path,
) -> None:
    """No TTL gates the fetch attempt itself — every run inherits the latest policy (ADR §8.4)."""
    source = FakePolicySource(outcome=FetchedPolicy(content='fail_on = "critical"\n'))
    cache_path = cache_path_for(source.cache_key(), cache_dir=str(tmp_path))
    write_cached_policy(cache_path, 'fail_on = "high"\n')

    resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert source.calls == 1


# --- cache isolation across real-world locations (ADR §9) -----------------------


def test_two_sources_with_different_cache_keys_never_share_a_cache_entry(tmp_path: Path) -> None:
    """The regression this guards against: two tenants of one shared runner must never collide.

    Even though both declarations below name the exact same repository and
    path — the realistic case of two teams copy-pasting the same example
    `[remote_policy]` block in two different Azure DevOps organizations (or
    two projects of the same organization) — their `PolicySource`s resolve
    different `cache_key()`s, so team A's successful fetch can never be
    read back as team B's fallback.
    """
    declaration = RemotePolicyDeclaration(repository="security-baseline", path="policy.toml")
    source_org_a = FakePolicySource(
        outcome=FetchedPolicy(content='fail_on = "high"\n'), cache_key_outcome="org-a-key"
    )
    source_org_b = FakePolicySource(
        outcome=RemotePolicyFetchError("network unreachable"), cache_key_outcome="org-b-key"
    )

    resolve_remote_policy_document(
        source=source_org_a, declaration=declaration, cache_dir=str(tmp_path), now=NOW
    )
    document, status = resolve_remote_policy_document(
        source=source_org_b, declaration=declaration, cache_dir=str(tmp_path), now=NOW
    )

    # Org B has no cache of its own yet — it must never read org A's, even though
    # both declarations are identical and share the same cache directory.
    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE


def test_a_source_unable_to_resolve_its_cache_key_has_no_fallback(tmp_path: Path) -> None:
    """A source that cannot identify its own location has nothing safe to read or write."""
    source = FakePolicySource(
        outcome=RemotePolicyFetchError("network unreachable"),
        cache_key_outcome=RemotePolicyFetchError("SYSTEM_COLLECTIONURI is not set"),
    )

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document is None
    assert status.state is PolicySourceState.UNAVAILABLE
    assert not any(tmp_path.iterdir())


def test_a_successful_fetch_that_cannot_resolve_its_cache_key_still_returns_fresh(
    tmp_path: Path,
) -> None:
    """Losing the ability to *cache* a fetch must never lose the fetch's own result."""
    source = FakePolicySource(
        outcome=FetchedPolicy(content='fail_on = "high"\n'),
        cache_key_outcome=RemotePolicyFetchError("SYSTEM_COLLECTIONURI is not set"),
    )

    document, status = resolve_remote_policy_document(
        source=source, declaration=_DECLARATION, cache_dir=str(tmp_path), now=NOW
    )

    assert document == {"fail_on": "high"}
    assert status.state is PolicySourceState.FRESH
    assert not any(tmp_path.iterdir())
