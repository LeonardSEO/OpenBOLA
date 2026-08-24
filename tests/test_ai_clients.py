from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from openbola.ai import AIProviderConfig, PlanningCandidate, build_sanitized_context
from openbola.ai_clients import (
    AzureOpenAIClient,
    OpenAICompatibleClient,
    ProviderCredentialError,
    ProviderRedirectError,
    ProviderRequestError,
    ProviderResponseError,
    client_for_config,
)
from openbola.handles import InMemorySessionValueRegistry, SecretHandle
from openbola.scope import ScopeGuard

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
API_KEY = "api-key-secret-sentinel"
RAW_ID = "raw-record-id-sentinel"
FULL_VALUE = "full-response-value-sentinel"


def _scope(
    path: Path,
    *,
    host: str = "llm.example.test",
    allowed_path: str,
    allowed_cidrs: list[str] | None = None,
) -> ScopeGuard:
    path.write_text(
        yaml.safe_dump(
            {
                "client_name": "AI provider",
                "authorization_reference": "PT-2026-AI",
                "confirmed": True,
                "starts_at": "2026-08-24T10:00:00Z",
                "expires_at": "2026-08-24T14:00:00Z",
                "allowed_hosts": [host],
                "allowed_cidrs": allowed_cidrs or [],
                "allowed_paths": [f"glob:{allowed_path}"],
                "mutation_grants": [
                    {
                        "methods": ["POST"],
                        "path_patterns": [f"glob:{allowed_path}"],
                        "allowed_fields": ["none"],
                        "record_scope": "explicit",
                        "max_records": 1,
                        "max_requests": 1,
                        "allow_canary_create_delete": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    resolver = (lambda _host: ["192.0.2.10"]) if allowed_cidrs else None
    return ScopeGuard.from_file(path, resolver=resolver, now=NOW)


def _candidate() -> PlanningCandidate:
    return PlanningCandidate(
        endpoint_handle="endpoint-handle",
        owner_identity_handle="owner-handle",
        attacker_identity_handle="attacker-handle",
        record_handle="record-handle",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        field_handles=("field-handle",),
    )


def _config(
    *,
    kind: str = "openai_compatible",
    base_url: str = "https://llm.example.test",
    api_key: SecretHandle | None = None,
) -> AIProviderConfig:
    values: dict[str, Any] = {
        "kind": kind,
        "base_url": base_url,
        "model": "test-model",
        "api_key": api_key or SecretHandle(id="provider-secret", purpose="provider_api_key"),
    }
    if kind == "azure_openai":
        values.update(azure_deployment="deployment", api_version="2026-01-01")
    return AIProviderConfig(**values)


def test_openai_compatible_client_checks_provider_scope_and_never_sends_raw_values(
    tmp_path: Path,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"tests": []}'}}]})

    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    config = AIProviderConfig(
        kind="openai_compatible",
        base_url="https://llm.example.test",
        model="test-model",
        api_key=secret,
        safe_headers={"X-Client": "openbola-test"},
    )
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        config,
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )

    result = client.propose_tests(build_sanitized_context((_candidate(),)))

    assert result.tests == ()
    assert len(seen) == 1
    payload = json.loads(seen[0].content)
    rendered = json.dumps(payload)
    assert RAW_ID not in rendered
    assert FULL_VALUE not in rendered
    assert API_KEY not in rendered
    assert seen[0].headers["authorization"] == f"Bearer {API_KEY}"
    assert seen[0].headers["x-client"] == "openbola-test"


def test_denied_provider_scope_never_invokes_transport(tmp_path: Path) -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"choices": []})

    registry = InMemorySessionValueRegistry()
    config = _config()
    registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/other")
    client = OpenAICompatibleClient(
        config,
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ProviderRequestError):
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert not called


def test_missing_secret_fails_before_transport(tmp_path: Path) -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    registry = InMemorySessionValueRegistry()
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderCredentialError):
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert not called


def test_unsafe_safe_headers_are_rejected() -> None:
    with pytest.raises(ValueError, match="unsafe header"):
        _config_with_headers({"Authorization": "attempted-override"})
    with pytest.raises(ValueError, match="unsafe header"):
        _config_with_headers({"X-Extra": "line\nfeed"})


@pytest.mark.parametrize(
    "name",
    ["Host", ":authority", "Connection", "Content-Length", "Transfer-Encoding", "Forwarded"],
)
def test_forbidden_static_headers_are_rejected_by_client(tmp_path: Path, name: str) -> None:
    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
    )
    object.__setattr__(client._config, "safe_headers", {name: "value"})
    with pytest.raises(ProviderRequestError):
        client.propose_tests(build_sanitized_context((_candidate(),)))


def _config_with_headers(headers: dict[str, str]) -> AIProviderConfig:
    return AIProviderConfig(
        kind="openai_compatible",
        base_url="https://llm.example.test",
        model="test-model",
        api_key=SecretHandle(id="provider-secret", purpose="provider_api_key"),
        safe_headers=headers,
    )


def test_azure_deployment_and_api_version_are_encoded_and_scoped(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"tests": []}'}}]})

    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    config = AIProviderConfig(
        kind="azure_openai",
        base_url="https://llm.example.test",
        model="ignored-model",
        api_key=secret,
        azure_deployment="deployment-name",
        api_version="2026-01-01-preview",
    )
    guard = _scope(
        tmp_path / "provider.yaml",
        allowed_path="/openai/deployments/deployment-name/chat/completions",
    )
    client = AzureOpenAIClient(
        config,
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )

    client.propose_tests(build_sanitized_context((_candidate(),)))

    assert len(seen) == 1
    assert str(seen[0].url) == (
        "https://llm.example.test/openai/deployments/deployment-name/chat/completions"
        "?api-version=2026-01-01-preview"
    )


@pytest.mark.parametrize("timeout", [0, -1, 121, float("inf"), True])
def test_provider_timeout_is_bounded(tmp_path: Path, timeout: float) -> None:
    registry = InMemorySessionValueRegistry()
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    with pytest.raises(ValueError, match="provider timeout"):
        OpenAICompatibleClient(
            _config(),
            secrets=registry,
            provider_scope_guard=guard,
            timeout=timeout,
        )


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [{"message": {"content": "{}}"}}]}),
        httpx.Response(200, content=b"x" * (32 * 1024 + 1)),
        httpx.Response(500, content=b"secret provider body"),
    ],
)
def test_invalid_or_oversize_provider_responses_are_generic(
    tmp_path: Path, response: httpx.Response
) -> None:
    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(lambda _request: response),
    )
    with pytest.raises(ProviderResponseError) as error:
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert API_KEY not in str(error.value)
    assert "secret provider body" not in str(error.value)


@pytest.mark.parametrize(
    "body",
    [
        b'{"choices": [], "choices": []}',
        b'{"choices": NaN}',
    ],
)
def test_outer_provider_envelope_rejects_duplicate_or_nonfinite_json(
    tmp_path: Path, body: bytes
) -> None:
    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=body)),
    )
    with pytest.raises(ProviderResponseError):
        client.propose_tests(build_sanitized_context((_candidate(),)))


def test_non_ascii_provider_secret_is_rejected_before_transport(tmp_path: Path) -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value="clé")
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderCredentialError):
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert not called


def test_provider_scope_peer_set_requires_pinned_transport(tmp_path: Path) -> None:
    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(
        tmp_path / "provider.yaml",
        allowed_path="/v1/chat/completions",
        allowed_cidrs=["192.0.2.0/24"],
    )
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
    )
    with pytest.raises(ProviderRequestError, match="pinned transport"):
        client.propose_tests(build_sanitized_context((_candidate(),)))


def test_redirect_target_is_checked_once_and_never_followed(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": "/v1/chat/completions/final"})

    class GuardSpy(ScopeGuard):
        def __init__(self, delegate: ScopeGuard) -> None:
            super().__init__(delegate.config, now=NOW)
            self.delegate = delegate
            self.urls: list[str] = []

        def require_allowed(self, url: str, method: str) -> object:
            self.urls.append(url)
            return self.delegate.require_allowed(url, method)

    delegate = _scope(
        tmp_path / "provider.yaml",
        allowed_path="/v1/chat/completions",
    )
    spy = GuardSpy(delegate)
    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=spy,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ProviderRedirectError):
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert len(seen) == 1
    assert spy.urls == [
        "https://llm.example.test/v1/chat/completions",
        "https://llm.example.test/v1/chat/completions/final",
    ]


def test_redirect_denial_is_typed_and_does_not_follow(tmp_path: Path) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"Location": "https://evil.example.test/steal"})

    registry = InMemorySessionValueRegistry()
    secret = registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(api_key=secret),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderRedirectError):
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert calls == 1


def test_factory_selects_exact_provider_class(tmp_path: Path) -> None:
    registry = InMemorySessionValueRegistry()
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    openai = client_for_config(_config(), secrets=registry, provider_scope_guard=guard)
    assert type(openai) is OpenAICompatibleClient

    azure_guard = _scope(
        tmp_path / "azure.yaml",
        allowed_path="/openai/deployments/deployment/chat/completions",
    )
    azure = client_for_config(
        _config(kind="azure_openai", base_url="https://llm.example.test"),
        secrets=registry,
        provider_scope_guard=azure_guard,
    )
    assert type(azure) is AzureOpenAIClient


def test_client_rejects_mismatched_provider_config(tmp_path: Path) -> None:
    registry = InMemorySessionValueRegistry()
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    with pytest.raises(ValueError):
        OpenAICompatibleClient(
            _config(kind="azure_openai", base_url="https://llm.example.test"),
            secrets=registry,
            provider_scope_guard=guard,
        )
    with pytest.raises(ValueError):
        AzureOpenAIClient(
            _config(),
            secrets=registry,
            provider_scope_guard=guard,
        )


def test_unsafe_context_is_rejected_before_scope_or_transport(tmp_path: Path) -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    registry = InMemorySessionValueRegistry()
    registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/chat/completions")
    client = OpenAICompatibleClient(
        _config(),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderRequestError):
        client.propose_tests({"schema": "openbola-ai-context-v1", "candidates": [{"raw": RAW_ID}]})
    assert not called


def test_provider_scope_errors_do_not_echo_url_or_secret(tmp_path: Path) -> None:
    registry = InMemorySessionValueRegistry()
    registry.store_secret(purpose="provider_api_key", value=API_KEY)
    guard = _scope(tmp_path / "provider.yaml", allowed_path="/v1/other")
    client = OpenAICompatibleClient(
        _config(),
        secrets=registry,
        provider_scope_guard=guard,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
    )
    with pytest.raises(ProviderRequestError) as error:
        client.propose_tests(build_sanitized_context((_candidate(),)))
    assert API_KEY not in str(error.value)
    assert "llm.example.test" not in str(error.value)
