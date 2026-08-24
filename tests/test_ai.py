from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from openbola.ai import (
    MAX_AI_OUTPUT_BYTES,
    MAX_PROVIDER_TIMEOUT_SECONDS,
    CodexCLIAdapter,
    CodexCLIAdapterDisabledError,
    HTTPMethod,
    LiteLLMAdapter,
    ObjectIDLocation,
    TestPlan,
    _parse_test_plan,
    sanitize_context,
    validate_plan_for_context,
)


def _context() -> dict[str, Any]:
    return {
        "allowed_methods": ["GET"],
        "endpoint_patterns": [
            {"endpoint_template": "/documents", "methods": ["GET", "POST"]}
        ],
        "candidates": [
            {
                "endpoint_template": "/documents",
                "method": "GET",
                "location": "query",
                "id_field": "document_id",
                "locator": "query:document_id",
                "object_id": "42",
            }
        ],
    }


def _raw_plan(endpoint: str = "/documents") -> str:
    return json.dumps(
        {
            "suggestions": [
                {
                    "endpoint_template": endpoint,
                    "method": "GET",
                    "object_id_location": "query_param",
                    "object_id_field_hint": "document_id",
                    "id_field_for_diff": "document_id",
                    "reasoning": "The captured query identifier can select another document.",
                }
            ]
        }
    )


def test_schema_is_typed_bounded_and_non_executable() -> None:
    schema = TestPlan.model_json_schema()

    assert schema["properties"]["suggestions"]["maxItems"] == 10
    suggestion = _parse_test_plan(_raw_plan()).suggestions[0]
    assert suggestion.method is HTTPMethod.GET
    assert suggestion.object_id_location is ObjectIDLocation.QUERY_PARAM
    assert not hasattr(suggestion, "url")
    assert not hasattr(suggestion, "headers")


@pytest.mark.parametrize(
    "raw",
    [
        '{"suggestions": []} trailing',
        '{"suggestions": [], "suggestions": []}',
        '{"suggestions": [], "unknown": true}',
        "~~~json\n{\"suggestions\": []}\n~~~",
    ],
)
def test_strict_parser_rejects_trailing_duplicate_unknown_and_inexact_fences(raw: str) -> None:
    with pytest.raises(ValueError):
        _parse_test_plan(raw)


def test_strict_parser_accepts_one_exact_json_fence_and_rejects_oversize() -> None:
    fence = chr(96) * 3

    assert _parse_test_plan(f"{fence}json\n{_raw_plan()}\n{fence}").suggestions
    with pytest.raises(ValueError, match="maximum size"):
        _parse_test_plan(" " * (MAX_AI_OUTPUT_BYTES + 1))


def test_sanitize_context_uses_allowlist_and_drops_secrets_and_raw_urls() -> None:
    secret = "not-for-ai-or-logs"  # noqa: S105 - test sentinel, never a real credential
    context = _context() | {
        "url": f"https://api.example.test/documents?access_token={secret}",
        "headers": {"Authorization": f"Bearer {secret}"},
        "body": {"password": secret},
        "credentials": {"token": secret},
    }

    sanitized = sanitize_context(context)
    rendered = json.dumps(sanitized)

    assert secret not in rendered
    assert "https://" not in rendered
    assert "object_id" not in rendered
    assert sanitized["endpoint_patterns"] == [
        {"endpoint_template": "/documents", "allowed_methods": ["GET"]}
    ]
    assert sanitized["candidates"] == [
        {
            "endpoint_template": "/documents",
            "method": "GET",
            "location": "query_param",
            "id_field": "document_id",
            "locator": "query:document_id",
        }
    ]


def test_plan_validation_rejects_hallucinated_endpoint() -> None:
    plan = _parse_test_plan(_raw_plan("/admin/users/{id}"))

    with pytest.raises(ValueError, match="endpoint or method"):
        validate_plan_for_context(plan, sanitize_context(_context()))


@pytest.mark.parametrize(
    "unsafe_template",
    [
        "//api.example.test/documents",
        "/documents/%2fadmin",
        "/documents/../admin",
        "/documents//admin",
        "/documents\\admin",
        "/documents/\x00",
    ],
)
def test_sanitize_context_rejects_ambiguous_endpoint_paths(unsafe_template: str) -> None:
    context = _context()
    context["endpoint_patterns"][0]["endpoint_template"] = unsafe_template

    with pytest.raises(ValueError, match="unsafe endpoint template"):
        sanitize_context(context)


def test_sanitize_context_derives_locator_and_rejects_object_like_field_value() -> None:
    context = _context()
    context["candidates"][0]["locator"] = "query:untrusted-value"

    assert sanitize_context(context)["candidates"][0]["locator"] == "query:document_id"

    context["candidates"][0]["id_field"] = "aB3dE5fG7hI9jK2m"
    with pytest.raises(ValueError, match="unsafe endpoint candidate"):
        sanitize_context(context)


def test_plan_validation_binds_response_diff_field_to_the_known_candidate() -> None:
    plan_data = json.loads(_raw_plan())
    plan_data["suggestions"][0]["id_field_for_diff"] = "other_id"
    plan = TestPlan.model_validate(plan_data)

    with pytest.raises(ValueError, match="candidate outside"):
        validate_plan_for_context(plan, sanitize_context(_context()))


def test_litellm_is_imported_lazily_and_receives_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}

    def completion(**kwargs: Any) -> dict[str, Any]:
        calls.update(kwargs)
        return {"choices": [{"message": {"content": _raw_plan()}}]}

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    plan = LiteLLMAdapter("test/provider", api_key="provider-secret", timeout=12).propose_tests(
        _context()
    )

    assert plan.suggestions[0].endpoint_template == "/documents"
    assert calls["temperature"] == 0
    assert calls["timeout"] == 12
    assert calls["response_format"]["type"] == "json_schema"
    assert calls["response_format"]["json_schema"]["strict"] is True


def test_codex_adapter_is_fail_closed_without_starting_a_general_agent() -> None:
    with pytest.raises(CodexCLIAdapterDisabledError, match="disabled"):
        CodexCLIAdapter(codex_bin="not-run").propose_tests(_context())


@pytest.mark.parametrize(
    "timeout",
    [0.0, -1.0, float("inf"), float("nan"), MAX_PROVIDER_TIMEOUT_SECONDS + 1, True],
)
def test_provider_timeouts_must_be_finite_positive_and_bounded(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout"):
        LiteLLMAdapter("test/provider", timeout=timeout)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="timeout"):
        CodexCLIAdapter(timeout=timeout)  # type: ignore[arg-type]
