"""Tests for `AzureDevOpsPolicySource` (ADR R2, §8.4): the reference `PolicySource`.

`httpx.get` is monkeypatched directly rather than run against a real
service — this module never needs network access to verify the request
this class builds, the header it authenticates with, and how it translates
every failure into `RemotePolicyFetchError` (ADR §5's "one exception type"
contract, see `linceo.core.ports.PolicySource.fetch`).
"""

from __future__ import annotations

import builtins
import logging
from collections.abc import Generator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from linceo.core.remote_policy import DEFAULT_TOKEN_ENV_VAR, RemotePolicyFetchError
from linceo.providers.azure_devops import REMOTE_POLICY_ENV_VARS, AzureDevOpsPolicySource

_ENV_VARS = (*REMOTE_POLICY_ENV_VARS, "MY_TOKEN")


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _clean_http_client_log_filters() -> Generator[None]:
    """Undo `fetch`'s own `logging.getLogger("httpx"/"httpcore").addFilter(...)` (ADR §9).

    Those two loggers are process-wide singletons — a filter `fetch` installs
    in one test would otherwise persist into every test that runs after it
    in the same session.
    """
    yield
    logging.getLogger("httpx").filters.clear()
    logging.getLogger("httpcore").filters.clear()


@dataclass(slots=True)
class _FakeResponse:
    text: str

    def raise_for_status(self) -> None:
        return None


@dataclass(slots=True)
class _CapturingGet:
    """Records every call it receives and returns a fixed `_FakeResponse`."""

    response_text: str = "version = 1\n"
    calls: list[tuple[str, Mapping[str, str], Mapping[str, str]]] = field(default_factory=list)

    def __call__(
        self,
        url: str,
        *,
        params: Mapping[str, str],
        headers: Mapping[str, str],
        timeout: float,  # noqa: ARG002 -- part of httpx.get's call shape, unused by this fake
    ) -> _FakeResponse:
        self.calls.append((url, params, headers))
        return _FakeResponse(self.response_text)


def test_fetch_requires_the_organization_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="SYSTEM_COLLECTIONURI"):
        source.fetch()


def test_fetch_requires_a_project_from_declaration_or_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="project"):
        source.fetch()


def test_fetch_defaults_the_project_to_the_builds_own(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "widgets")
    capturing_get = _CapturingGet()
    monkeypatch.setattr(httpx, "get", capturing_get)

    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")
    fetched = source.fetch()

    assert fetched.content == "version = 1\n"
    [(url, params, _headers)] = capturing_get.calls
    assert (
        url == "https://dev.azure.com/acme/widgets/_apis/git/repositories/security-baseline/items"
    )
    assert params == {"path": "policy.toml", "download": "true", "api-version": "7.1"}


def test_fetch_prefers_the_declared_project_over_the_builds_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "widgets")
    capturing_get = _CapturingGet()
    monkeypatch.setattr(httpx, "get", capturing_get)

    source = AzureDevOpsPolicySource(
        repository="security-baseline", path="policy.toml", project="platform-security"
    )
    source.fetch()

    [(url, _params, _headers)] = capturing_get.calls
    assert "/platform-security/" in url


def test_fetch_with_the_default_token_env_unset_sends_no_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`DEFAULT_TOKEN_ENV_VAR` is harmless when the variable is genuinely absent (ADR §9)."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    capturing_get = _CapturingGet()
    monkeypatch.setattr(httpx, "get", capturing_get)

    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")
    assert source.token_env == DEFAULT_TOKEN_ENV_VAR
    source.fetch()

    [(_url, _params, headers)] = capturing_get.calls
    assert headers == {}


def test_fetch_uses_the_default_token_env_automatically_when_the_build_sets_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The common case task 2 exists for: a same-org repository needs no `token_env` declared.

    `azure-pipelines/templates/linceo-scan.yml` maps `System.AccessToken`
    into this exact variable by default (docs/ADOPTION.md) — once that
    mapping exists, `AzureDevOpsPolicySource` picks it up with zero
    declaration in the scanned repository's own `.devsecops/config.toml`.
    """
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "build-identity-token")
    capturing_get = _CapturingGet()
    monkeypatch.setattr(httpx, "get", capturing_get)

    AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml").fetch()

    [(_url, _params, headers)] = capturing_get.calls
    assert headers == {"Authorization": "Bearer build-identity-token"}


def test_an_explicit_empty_token_env_opts_out_of_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "build-identity-token")
    capturing_get = _CapturingGet()
    monkeypatch.setattr(httpx, "get", capturing_get)

    source = AzureDevOpsPolicySource(
        repository="security-baseline", path="policy.toml", token_env=""
    )
    source.fetch()

    [(_url, _params, headers)] = capturing_get.calls
    assert headers == {}


def test_fetch_sends_the_token_as_a_bearer_header_never_in_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv("MY_TOKEN", "super-secret-value")
    capturing_get = _CapturingGet()
    monkeypatch.setattr(httpx, "get", capturing_get)

    source = AzureDevOpsPolicySource(
        repository="security-baseline",
        path="policy.toml",
        token_env="MY_TOKEN",  # noqa: S106 -- an env var *name*, not a credential value (ADR §9)
    )
    source.fetch()

    [(url, params, headers)] = capturing_get.calls
    assert headers == {"Authorization": "Bearer super-secret-value"}
    assert "super-secret-value" not in url
    assert "super-secret-value" not in str(params)


def test_fetch_wraps_any_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise httpx.HTTPError("connection refused")

    monkeypatch.setattr(httpx, "get", _raising_get)

    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="security-baseline/policy"):
        source.fetch()


# --- HTTP failure hints: 401/403 (identidad del build) and 404 (ambiguo) -------


def _status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request(
        "GET", "https://dev.azure.com/acme/platform/_apis/git/repositories/security-baseline/items"
    )
    response = httpx.Response(status_code, request=request, text="")
    return httpx.HTTPStatusError(f"{status_code} error", request=request, response=response)


def test_status_error_message_is_built_from_status_and_url_never_httpxs_own_str(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact regression this guards: `str(httpx.HTTPStatusError)` includes its own generic
    "For more information check" link to MDN's HTTP status documentation — noise once this
    project's own, more specific causes already apply (`_error_hint`), and unhelpful even when
    none of them do; interpolating it was never buying anything the status code and URL alone
    do not already say more plainly.
    """
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise _status_error(404)

    monkeypatch.setattr(httpx, "get", _raising_get)
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError) as exc_info:
        source.fetch()

    message = str(exc_info.value)
    assert "developer.mozilla.org" not in message
    assert "For more information" not in message
    assert "404 Not Found for" in message
    assert "security-baseline/items" in message


@pytest.mark.parametrize("status_code", [401, 403])
def test_fetch_names_the_permission_hint_for_the_default_token_env(
    monkeypatch: pytest.MonkeyPatch, status_code: int
) -> None:
    """A 401/403 through the build's own identity has one overwhelmingly likely cause."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "build-identity-token")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise _status_error(status_code)

    monkeypatch.setattr(httpx, "get", _raising_get)
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="Read permission") as exc_info:
        source.fetch()

    assert "Project Settings" in str(exc_info.value)
    assert "Limit job authorization scope" in str(exc_info.value)


def test_fetch_omits_the_permission_hint_for_a_custom_token_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A custom `token_env` means the operator already chose a credential (typically a PAT) —
    naming a "build identity" cause there would be actively misleading."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv("MY_TOKEN", "pat-value")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise _status_error(401)

    monkeypatch.setattr(httpx, "get", _raising_get)
    source = AzureDevOpsPolicySource(
        repository="security-baseline",
        path="policy.toml",
        token_env="MY_TOKEN",  # noqa: S106 -- an env var *name*, not a credential value (ADR §9)
    )

    with pytest.raises(RemotePolicyFetchError) as exc_info:
        source.fetch()

    assert "build identity" not in str(exc_info.value)


def test_fetch_omits_every_hint_for_an_unrelated_status_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise _status_error(500)

    monkeypatch.setattr(httpx, "get", _raising_get)
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError) as exc_info:
        source.fetch()

    assert "build identity" not in str(exc_info.value)
    assert "four different causes" not in str(exc_info.value)


def test_fetch_names_all_four_causes_for_a_404_with_the_default_token_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact bug report this guards: Azure DevOps' 404 collapses four distinct causes into
    one status code, and used to just repeat httpx's own bare error instead of naming them."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "build-identity-token")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise _status_error(404)

    monkeypatch.setattr(httpx, "get", _raising_get)
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="four different causes") as exc_info:
        source.fetch()

    message = str(exc_info.value)
    assert "'security-baseline' does not exist" in message
    assert "'policy.toml' does not exist in that repository" in message
    assert "not on the repository's default branch" in message
    assert f"identity behind {DEFAULT_TOKEN_ENV_VAR} lacks Read permission" in message
    # Never the 401/403 hint's own single-cause framing — a 404 is never
    # attributable to just one of the four with any confidence.
    assert "the most likely cause" not in message


def test_fetch_names_all_four_causes_for_a_404_with_a_custom_token_env_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unlike the 401/403 hint, the 404 hint is not narrowed to the default `token_env` — Azure
    DevOps hides a permission denial behind 404 for a PAT exactly as it does for the build's own
    identity, so leaving this hint out for a custom token would silently drop a real cause."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv("MY_TOKEN", "pat-value")

    def _raising_get(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise _status_error(404)

    monkeypatch.setattr(httpx, "get", _raising_get)
    source = AzureDevOpsPolicySource(
        repository="security-baseline",
        path="policy.toml",
        token_env="MY_TOKEN",  # noqa: S106 -- an env var *name*, not a credential value (ADR §9)
    )

    with pytest.raises(RemotePolicyFetchError, match="four different causes") as exc_info:
        source.fetch()

    assert "identity behind MY_TOKEN lacks Read permission" in str(exc_info.value)


def test_fetch_without_the_remote_config_extra_installed_is_an_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    real_import = builtins.__import__

    def _import_without_httpx(name: str, *args: object, **kwargs: object) -> object:
        if name == "httpx":
            raise ImportError("no module named httpx")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _import_without_httpx)

    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="remote-config") as exc_info:
        source.fetch()

    # Neither an operator who `pip install`ed linceo nor one running the
    # reference container should be left with no actionable next step —
    # this message names both, since the exception alone cannot tell which
    # one applies (the review finding this guards: the message used to name
    # only `pip install`, impossible advice from inside a container with no
    # writable venv and no expectation anyone shells into it at all).
    message = str(exc_info.value)
    assert "pip install 'linceo[remote-config]'" in message
    assert "container image" in message


# --- cache_key: the cross-tenant collision fix (ADR §9) -------------------------


def test_cache_key_requires_the_organization_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="SYSTEM_COLLECTIONURI"):
        source.cache_key()


def test_cache_key_requires_a_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    with pytest.raises(RemotePolicyFetchError, match="project"):
        source.cache_key()


def test_cache_key_is_deterministic_for_the_same_location(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    assert source.cache_key() == source.cache_key()


def test_cache_key_differs_across_organizations(monkeypatch: pytest.MonkeyPatch) -> None:
    """The regression this guards: the same declared name in two orgs must never collide."""
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/org-a/")
    key_a = source.cache_key()
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/org-b/")
    key_b = source.cache_key()

    assert key_a != key_b


def test_cache_key_differs_across_projects_of_the_same_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    source = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")

    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "team-a")
    key_a = source.cache_key()
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "team-b")
    key_b = source.cache_key()

    assert key_a != key_b


def test_cache_key_agrees_with_fetch_about_which_project_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit `project` override changes the key exactly as it changes the URL `fetch` uses."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "widgets")
    default_project = AzureDevOpsPolicySource(repository="security-baseline", path="policy.toml")
    overridden_project = AzureDevOpsPolicySource(
        repository="security-baseline", path="policy.toml", project="platform-security"
    )

    assert default_project.cache_key() != overridden_project.cache_key()


# --- defense in depth against a third-party library's own logging (ADR §9) -----


def test_fetch_installs_a_redaction_filter_that_catches_a_hypothetical_header_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """httpcore does not currently log request headers (verified by reading its source, see the
    ADR amendment) — this proves the second, independent layer actually works regardless, by
    simulating the one hypothetical it exists to guard against."""
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "platform")
    monkeypatch.setenv("MY_TOKEN", "super-secret-value")

    httpcore_logger = logging.getLogger("httpcore")
    httpcore_logger.setLevel(logging.DEBUG)
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[assignment]
    httpcore_logger.addHandler(handler)

    def _get_that_logs_its_own_headers(
        url: str,
        *,
        params: Mapping[str, str],  # noqa: ARG001 -- part of httpx.get's call shape, unused here
        headers: Mapping[str, str],
        timeout: float,  # noqa: ARG001 -- part of httpx.get's call shape, unused here
    ) -> _FakeResponse:
        httpcore_logger.debug("send_request_headers request=%r headers=%r", url, headers)
        return _FakeResponse("version = 1\n")

    monkeypatch.setattr(httpx, "get", _get_that_logs_its_own_headers)

    try:
        source = AzureDevOpsPolicySource(
            repository="security-baseline",
            path="policy.toml",
            token_env="MY_TOKEN",  # noqa: S106 -- an env var *name*, not a credential (ADR §9)
        )
        source.fetch()
    finally:
        httpcore_logger.handlers.remove(handler)

    [record] = records
    assert "super-secret-value" not in record.getMessage()
    assert "***" in record.getMessage()


# --- the reference pipeline template forwards everything this port reads -------


def test_azure_pipelines_template_forwards_every_remote_policy_variable() -> None:
    """The anti-drift check for `REMOTE_POLICY_ENV_VARS`, mirroring
    `tests/unit/test_cli_context.py::test_azure_pipelines_template_forwards_every_variable_this_project_reads`
    for `linceo.providers.azure_devops.ENV_VARS`: a container invocation using the reference
    template must pass `-e VARNAME` for every variable `AzureDevOpsPolicySource` reads, not a
    partial or stale copy of the list hand-maintained separately in the YAML/bash template.
    """
    template_path = (
        Path(__file__).resolve().parents[2] / "azure-pipelines" / "templates" / "linceo-scan.yml"
    )
    script = template_path.read_text(encoding="utf-8")

    missing = [var for var in REMOTE_POLICY_ENV_VARS if f"-e {var}" not in script]
    assert not missing, (
        f"{missing} not forwarded with `-e` in azure-pipelines/templates/linceo-scan.yml — a "
        "container invocation using this template would silently lose them."
    )


def test_azure_pipelines_template_maps_system_access_token_via_its_own_env_block() -> None:
    """`System.AccessToken`, unlike every other predefined variable this project reads, is not
    forwarded into a step's own process environment automatically — Azure Pipelines requires an
    explicit `env:` mapping (`$(System.AccessToken)`) before `-e SYSTEM_ACCESSTOKEN` on the
    `docker run` line has anything real to forward at all.
    """
    template_path = (
        Path(__file__).resolve().parents[2] / "azure-pipelines" / "templates" / "linceo-scan.yml"
    )
    script = template_path.read_text(encoding="utf-8")

    assert f"{DEFAULT_TOKEN_ENV_VAR}: $(System.AccessToken)" in script


def test_azure_pipelines_template_mounts_a_persistent_policy_cache_directory() -> None:
    """docs/ADOPTION.md, "La caché local no sobrevive un `docker run` efímero": without a host
    mount surviving between jobs, `PolicySourceStatus.state == cached` is unreachable under
    `docker run --rm` — every failed fetch degrades straight to `unavailable`, regardless of how
    many earlier runs succeeded.
    """
    template_path = (
        Path(__file__).resolve().parents[2] / "azure-pipelines" / "templates" / "linceo-scan.yml"
    )
    script = template_path.read_text(encoding="utf-8")

    # `$(Agent.TempDirectory)` is documented as cleared between jobs; only
    # `$(Agent.ToolsDirectory)` persists across runs on the same agent.
    assert "$(Agent.ToolsDirectory)" in script
    assert "mkdir -p" in script
    assert "chmod 0777" in script
    # The mount target and the value `LINCEO_POLICY_CACHE_DIR` is set to
    # must be the exact same container-side path, or the container would
    # write its cache somewhere the host mount never actually covers.
    assert "LINCEO_POLICY_CACHE_DIR=${LINCEO_POLICY_CACHE_CONTAINER_DIR}" in script
    assert '-v "${LINCEO_POLICY_CACHE_HOST_DIR}:${LINCEO_POLICY_CACHE_CONTAINER_DIR}"' in script
