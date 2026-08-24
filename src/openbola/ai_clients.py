"""Scope-guarded HTTP clients for typed AI planning proposals.

The clients in this module are deliberately small.  They send only the
allowlisted planning context and a strict proposal schema; they never resolve
target values or issue requests to a tested API.  The provider scope is a
separate authority from the target scope and is checked for every provider
request (including redirect targets).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Protocol
from urllib.parse import quote, urljoin

import httpx

from openbola.ai import (
    MAX_AI_OUTPUT_BYTES,
    MAX_CONTEXT_BYTES,
    AIProviderConfig,
    ProposedPlan,
    _validate_timeout,
    parse_proposed_plan,
)
from openbola.handles import SessionValueRegistry
from openbola.scope import ScopeGuard

MAX_PROVIDER_REQUEST_BYTES = 64 * 1024
_MAX_CONTEXT_CANDIDATES = 100
_MAX_CONTEXT_FIELDS = 100
_MAX_CONTEXT_TEXT = 256


class ProviderClientError(RuntimeError):
    """Base error for provider calls without provider response material."""


class ProviderCredentialError(ProviderClientError):
    """Raised when the configured provider secret cannot be resolved."""


class ProviderRequestError(ProviderClientError):
    """Raised when a proposal request cannot be constructed safely."""


class ProviderTransportError(ProviderClientError):
    """Raised when the provider transport fails."""


class ProviderResponseError(ProviderClientError):
    """Raised when the provider response is not a valid proposal response."""


class ProviderRedirectError(ProviderClientError):
    """Raised for every redirect; redirects are never followed implicitly."""


class AIProviderClient(Protocol):
    """Provider boundary that can produce typed, non-executable proposals."""

    def propose_tests(self, context: Mapping[str, object]) -> ProposedPlan:
        """Return proposals for a sanitized structural context."""


_PROPOSAL_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "tests": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "endpoint_handle": {"type": "string"},
                    "owner_identity_handle": {"type": "string"},
                    "attacker_identity_handle": {"type": "string"},
                    "record_handle": {"type": "string"},
                    "method": {"type": "string"},
                    "field_handles": {"type": "array", "items": {"type": "string"}},
                    "rationale": {"type": "string"},
                },
                "required": [
                    "endpoint_handle",
                    "owner_identity_handle",
                    "attacker_identity_handle",
                    "record_handle",
                    "method",
                    "field_handles",
                    "rationale",
                ],
            },
        }
    },
    "required": ["tests"],
}

_SYSTEM_PROMPT = (
    "You are a constrained planning component for OpenBOLA. Return only one strict JSON "
    "object matching the supplied schema. Use only handles and structural fields in the "
    "sanitized context. Never include resolved values, credentials, URLs, or executable "
    "requests. Propose tests only; a deterministic local policy layer validates them."
)
_CONTEXT_KEYS = frozenset({"schema", "candidates"})
_CANDIDATE_KEYS = frozenset(
    {
        "endpoint_handle",
        "owner_identity_handle",
        "attacker_identity_handle",
        "record_handle",
        "endpoint_template",
        "method",
        "field_handles",
    }
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})


def _safe_context(context: Mapping[str, object]) -> dict[str, object]:
    """Copy and validate the exact output shape of ``build_sanitized_context``."""

    if not isinstance(context, Mapping) or set(context) != _CONTEXT_KEYS:
        raise ProviderRequestError("provider context is not an approved planning context")
    if context.get("schema") != "openbola-ai-context-v1":
        raise ProviderRequestError("provider context is not an approved planning context")
    raw_candidates = context.get("candidates")
    if (
        isinstance(raw_candidates, (str, bytes))
        or not isinstance(raw_candidates, Sequence)
        or len(raw_candidates) > _MAX_CONTEXT_CANDIDATES
    ):
        raise ProviderRequestError("provider context is not an approved planning context")

    candidates: list[dict[str, object]] = []
    for candidate in raw_candidates:
        if not isinstance(candidate, Mapping) or set(candidate) != _CANDIDATE_KEYS:
            raise ProviderRequestError("provider context is not an approved planning context")
        copied: dict[str, object] = {}
        for key in (
            "endpoint_handle",
            "owner_identity_handle",
            "attacker_identity_handle",
            "record_handle",
            "endpoint_template",
            "method",
        ):
            value = candidate.get(key)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > _MAX_CONTEXT_TEXT
                or any(ord(character) < 32 or character.isspace() for character in value)
            ):
                raise ProviderRequestError("provider context is not an approved planning context")
            if key == "endpoint_template" and (
                not value.startswith("/")
                or value.startswith("//")
                or any(character in value for character in ("?", "#", "\\", "%"))
                or any(segment in {".", ".."} for segment in value.split("/"))
            ):
                raise ProviderRequestError("provider context is not an approved planning context")
            if key == "method" and value not in _SAFE_METHODS:
                raise ProviderRequestError("provider context is not an approved planning context")
            copied[key] = value
        raw_fields = candidate.get("field_handles")
        if (
            isinstance(raw_fields, (str, bytes))
            or not isinstance(raw_fields, Sequence)
            or len(raw_fields) > _MAX_CONTEXT_FIELDS
        ):
            raise ProviderRequestError("provider context is not an approved planning context")
        fields: list[str] = []
        for field_handle in raw_fields:
            if (
                not isinstance(field_handle, str)
                or not field_handle
                or len(field_handle) > _MAX_CONTEXT_TEXT
                or any(ord(character) < 32 or character.isspace() for character in field_handle)
            ):
                raise ProviderRequestError("provider context is not an approved planning context")
            fields.append(field_handle)
        copied["field_handles"] = fields
        candidates.append(copied)

    safe: dict[str, object] = {"schema": "openbola-ai-context-v1", "candidates": candidates}
    try:
        encoded = json.dumps(safe, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ProviderRequestError("provider context is not serializable") from None
    if len(encoded.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ProviderRequestError("provider context exceeds the maximum safe size")
    return safe


def _provider_url(config: AIProviderConfig) -> str:
    if config.kind == "openai_compatible":
        return f"{config.base_url}/chat/completions"
    if config.azure_deployment is None or config.api_version is None:
        raise ProviderRequestError("Azure provider configuration is incomplete")
    deployment = quote(config.azure_deployment, safe="")
    version = quote(config.api_version, safe="")
    return (
        f"{config.base_url}/openai/deployments/{deployment}/chat/completions"
        f"?api-version={version}"
    )


def _request_payload(config: AIProviderConfig, context: Mapping[str, object]) -> dict[str, object]:
    safe_context = _safe_context(context)
    user_prompt = (
        "Sanitized structural context (handles only):\n"
        f"{json.dumps(safe_context, ensure_ascii=True, separators=(',', ':'))}\n\n"
        "Return a ProposedPlan JSON object matching this strict schema."
    )
    payload: dict[str, object] = {
        "model": config.model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "openbola_proposed_plan",
                "strict": True,
                "schema": _PROPOSAL_SCHEMA,
            },
        },
    }
    try:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ProviderRequestError("provider request is not serializable") from None
    if len(encoded.encode("utf-8")) > MAX_PROVIDER_REQUEST_BYTES:
        raise ProviderRequestError("provider request exceeds the maximum safe size")
    return payload


class OpenAICompatibleClient:
    """Call an OpenAI-compatible chat endpoint through a provider ScopeGuard."""

    def __init__(
        self,
        config: AIProviderConfig,
        *,
        secrets: SessionValueRegistry,
        provider_scope_guard: ScopeGuard,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not isinstance(config, AIProviderConfig) or config.kind != "openai_compatible":
            raise ValueError("OpenAI-compatible client requires an OpenAI-compatible config")
        if not hasattr(secrets, "resolve_secret"):
            raise TypeError("secrets must provide the SessionValueRegistry protocol")
        if not hasattr(provider_scope_guard, "require_allowed"):
            raise TypeError("provider_scope_guard must provide require_allowed")
        self._config = config
        self._secrets = secrets
        self._provider_scope_guard = provider_scope_guard
        self._transport = transport
        self._timeout = _validate_timeout(timeout)

    def propose_tests(self, context: Mapping[str, object]) -> ProposedPlan:
        payload = _request_payload(self._config, context)
        url = _provider_url(self._config)
        try:
            decision = self._provider_scope_guard.require_allowed(url, "POST")
        except Exception:
            raise ProviderRequestError("provider request is not authorized") from None
        request_url = getattr(decision, "canonical_url", url)
        try:
            api_key = self._secrets.resolve_secret(self._config.api_key)
        except Exception:
            raise ProviderCredentialError("provider credential cannot be resolved") from None
        if not isinstance(api_key, str) or not api_key or any(
            ord(character) < 32 or ord(character) == 127 for character in api_key
        ):
            raise ProviderCredentialError("provider credential cannot be resolved")

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        headers.update(dict(self._config.safe_headers))
        try:
            with httpx.Client(
                follow_redirects=False,
                transport=self._transport,
                timeout=self._timeout,
                trust_env=False,
            ) as client:
                response = client.post(request_url, headers=headers, json=payload)
        except httpx.HTTPError:
            raise ProviderTransportError("provider transport failed") from None

        if 300 <= response.status_code < 400:
            location = response.headers.get("location")
            if location is not None:
                redirect_url = urljoin(request_url, location)
                try:
                    self._provider_scope_guard.require_allowed(redirect_url, "POST")
                except Exception:
                    raise ProviderRedirectError("provider redirect is not authorized") from None
            raise ProviderRedirectError("provider redirects are not followed")
        if not 200 <= response.status_code < 300:
            raise ProviderResponseError("provider returned an unsuccessful response")
        try:
            raw = response.content
        except httpx.HTTPError:
            raise ProviderTransportError("provider response could not be read") from None
        if len(raw) > MAX_AI_OUTPUT_BYTES:
            raise ProviderResponseError("provider response exceeds the maximum safe size")
        try:
            document = json.loads(raw)
            choices = document.get("choices") if isinstance(document, Mapping) else None
            first = choices[0] if isinstance(choices, Sequence) and choices else None
            message = first.get("message") if isinstance(first, Mapping) else None
            content = message.get("content") if isinstance(message, Mapping) else None
            if not isinstance(content, str):
                raise ValueError
            return parse_proposed_plan(content)
        except (ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError):
            raise ProviderResponseError("provider response is not a valid proposal") from None


class AzureOpenAIClient(OpenAICompatibleClient):
    """Call an Azure OpenAI deployment through the same scoped boundary."""

    def __init__(
        self,
        config: AIProviderConfig,
        *,
        secrets: SessionValueRegistry,
        provider_scope_guard: ScopeGuard,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not isinstance(config, AIProviderConfig) or config.kind != "azure_openai":
            raise ValueError("Azure client requires an Azure OpenAI config")
        # The parent performs shared capability and timeout validation.  It
        # intentionally accepts the Azure kind only for this subclass.
        self._config = config
        if not hasattr(secrets, "resolve_secret"):
            raise TypeError("secrets must provide the SessionValueRegistry protocol")
        if not hasattr(provider_scope_guard, "require_allowed"):
            raise TypeError("provider_scope_guard must provide require_allowed")
        self._secrets = secrets
        self._provider_scope_guard = provider_scope_guard
        self._transport = transport
        self._timeout = _validate_timeout(timeout)


def client_for_config(
    config: AIProviderConfig,
    *,
    secrets: SessionValueRegistry,
    provider_scope_guard: ScopeGuard,
    transport: httpx.BaseTransport | None = None,
) -> AIProviderClient:
    """Construct the exact provider client for a validated configuration."""

    if not isinstance(config, AIProviderConfig):
        raise ValueError("provider configuration is invalid")
    if config.kind == "openai_compatible":
        return OpenAICompatibleClient(
            config,
            secrets=secrets,
            provider_scope_guard=provider_scope_guard,
            transport=transport,
        )
    if config.kind == "azure_openai":
        return AzureOpenAIClient(
            config,
            secrets=secrets,
            provider_scope_guard=provider_scope_guard,
            transport=transport,
        )
    raise ValueError("provider kind is unsupported")
