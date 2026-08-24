from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, fields, is_dataclass
from typing import Any

import pytest

from openbola.ai import (
    MAX_AI_OUTPUT_BYTES,
    MAX_CONTEXT_BYTES,
    MAX_PROPOSED_TESTS,
    MAX_PROVIDER_TIMEOUT_SECONDS,
    AIProviderConfig,
    CodexCLIAdapter,
    CodexCLIAdapterDisabledError,
    HTTPMethod,
    LegacyAIAdapterError,
    LiteLLMAdapter,
    ObjectIDLocation,
    PlanningCandidate,
    ProposedPlan,
    ProposedTest,
    TestPlan,
    _parse_test_plan,
    build_sanitized_context,
    migrate_legacy_plan,
    parse_proposed_plan,
    sanitize_context,
    validate_plan_for_context,
    validate_proposed_plan,
)
from openbola.capture import InSessionCapture
from openbola.discovery import GenericAdapter
from openbola.handles import InMemorySessionValueRegistry, SecretHandle
from openbola.scope import ScopeGuard


def _planning_candidate(**overrides: Any) -> PlanningCandidate:
    values: dict[str, Any] = {
        "endpoint_handle": "ep-opaque",
        "owner_identity_handle": "owner-opaque",
        "attacker_identity_handle": "attacker-opaque",
        "record_handle": "record-opaque",
        "endpoint_template": "/v1/documents/{id}",
        "method": "GET",
        "field_handles": ("field-opaque",),
    }
    values.update(overrides)
    return PlanningCandidate(**values)


def test_typed_contracts_are_frozen_dataclasses_and_context_is_private() -> None:
    raw_id = "raw-record-id-sentinel"
    full_value = "full-response-value-sentinel"
    cookie = "cookie-sentinel"
    api_key = "api-key-sentinel"
    candidate = _planning_candidate()
    context = build_sanitized_context((candidate, candidate))
    rendered = json.dumps(context, sort_keys=True, separators=(",", ":"))

    assert context.keys() == {"schema", "candidates"}
    assert rendered.count("ep-opaque") == 1
    for sentinel in (raw_id, full_value, cookie, api_key):
        assert sentinel not in rendered
    assert "cookie" not in rendered.casefold()
    assert len(rendered.encode()) <= MAX_CONTEXT_BYTES

    proposal = ProposedTest(
        endpoint_handle="ep-opaque",
        owner_identity_handle="owner-opaque",
        attacker_identity_handle="attacker-opaque",
        record_handle="record-opaque",
        method="get",
        field_handles=("field-opaque",),
        rationale="Check the observed ownership boundary.",
    )
    contracts = (
        AIProviderConfig(
            kind="openai_compatible",
            base_url="https://llm.example.test",
            model="test-model",
            api_key=SecretHandle(id="secret-handle", purpose="provider_api_key"),
        ),
        candidate,
        proposal,
        ProposedPlan((proposal,)),
    )
    for contract in contracts:
        assert is_dataclass(contract)
        assert all(
            parameter.name not in {"url", "body", "headers"}
            for parameter in fields(contract)
        )
        with pytest.raises(FrozenInstanceError):
            setattr(contract, fields(contract)[0].name, None)


def test_planning_context_sorts_and_deduplicates_candidates() -> None:
    first = _planning_candidate(endpoint_handle="ep-b")
    second = _planning_candidate(endpoint_handle="ep-a", method="POST")

    context = build_sanitized_context((first, second, first))

    assert context["candidates"] == [
        {
            "endpoint_handle": "ep-a",
            "owner_identity_handle": "owner-opaque",
            "attacker_identity_handle": "attacker-opaque",
            "record_handle": "record-opaque",
            "endpoint_template": "/v1/documents/{id}",
            "method": "POST",
            "field_handles": ["field-opaque"],
        },
        {
            "endpoint_handle": "ep-b",
            "owner_identity_handle": "owner-opaque",
            "attacker_identity_handle": "attacker-opaque",
            "record_handle": "record-opaque",
            "endpoint_template": "/v1/documents/{id}",
            "method": "GET",
            "field_handles": ["field-opaque"],
        },
    ]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: _planning_candidate(endpoint_template="https://example.test/documents"),
        lambda: _planning_candidate(endpoint_template="/documents?token=secret"),
        lambda: _planning_candidate(endpoint_template="/documents#fragment"),
        lambda: _planning_candidate(field_handles=("field-opaque", "field-opaque")),
        lambda: _planning_candidate(record_handle=""),
        lambda: _planning_candidate(method="CONNECT"),
    ],
)
def test_planning_candidate_rejects_unsafe_values(factory: Any) -> None:
    with pytest.raises(ValueError):
        factory()


def test_proposed_contract_bounds_and_provider_url_validation() -> None:
    with pytest.raises(ValueError):
        ProposedTest(
            endpoint_handle="ep",
            owner_identity_handle="owner",
            attacker_identity_handle="attacker",
            record_handle="record",
            method="GET",
            field_handles=(),
            rationale="x" * 241,
        )
    assert MAX_PROPOSED_TESTS == 10
    with pytest.raises(ValueError):
        AIProviderConfig(
            kind="openai_compatible",
            base_url="http://llm.example.test",
            model="model",
            api_key=SecretHandle(id="secret", purpose="api_key"),
        )
    with pytest.raises(ValueError):
        AIProviderConfig(
            kind="openai_compatible",
            base_url="https://llm.example.test/v1",
            model="model",
            api_key=SecretHandle(id="secret", purpose="api_key"),
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


def test_ai_context_from_session_adapter_has_no_full_value_sentinel(
    captured_session_with_sentinels: InSessionCapture,
) -> None:
    registry = InMemorySessionValueRegistry()
    inventories = captured_session_with_sentinels.with_adapter_records(
        GenericAdapter(registry).inventory
    )
    context = {
        "endpoint_patterns": [
            {
                "endpoint_template": item.endpoint_template,
                "allowed_methods": sorted(item.observed_methods),
            }
            for item in inventories
        ],
        "candidates": [],
    }
    assert b"FULL_VALUE_SENTINEL" not in json.dumps(sanitize_context(context)).encode()


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


def _legacy_plan(
    *,
    endpoint_template: str = "/v1/documents/{id}",
    method: str = "GET",
    location: str = "query_param",
    object_id_field_hint: str = "document_id",
    id_field_for_diff: str = "document_id",
) -> TestPlan:
    return TestPlan.model_validate(
        {
            "suggestions": [
                {
                    "endpoint_template": endpoint_template,
                    "method": method,
                    "object_id_location": location,
                    "object_id_field_hint": object_id_field_hint,
                    "id_field_for_diff": id_field_for_diff,
                    "reasoning": "Use the observed identifier boundary.",
                }
            ]
        }
    )


def test_legacy_plan_migrates_only_with_one_explicit_candidate_mapping() -> None:
    candidate = _planning_candidate(field_handles=("query:document_id",))
    migrated = migrate_legacy_plan(_legacy_plan(), (candidate,))

    assert migrated.tests[0] == ProposedTest(
        endpoint_handle=candidate.endpoint_handle,
        owner_identity_handle=candidate.owner_identity_handle,
        attacker_identity_handle=candidate.attacker_identity_handle,
        record_handle=candidate.record_handle,
        method="GET",
        field_handles=candidate.field_handles,
        rationale="Use the observed identifier boundary.",
    )


@pytest.mark.parametrize(
    "candidate_factory",
    [
        lambda: (
            _planning_candidate(field_handles=("query:document_id",)),
            _planning_candidate(endpoint_handle="other", field_handles=("query:document_id",)),
        ),
        lambda: (_planning_candidate(field_handles=("field-opaque",)),),
        lambda: (_planning_candidate(method="POST", field_handles=("query:document_id",)),),
    ],
)
def test_legacy_plan_migration_rejects_ambiguous_or_absent_mapping(
    candidate_factory: Any,
) -> None:
    with pytest.raises(ValueError, match="one observed candidate"):
        migrate_legacy_plan(_legacy_plan(), candidate_factory())


def test_legacy_adapter_is_deprecated_and_has_no_network_or_subprocess_path() -> None:
    with pytest.deprecated_call(match="LiteLLMAdapter is deprecated"):
        adapter = LiteLLMAdapter("test/provider", timeout=12)
    with pytest.raises(LegacyAIAdapterError, match="AIProviderConfig"):
        adapter.propose_tests(_context())


def test_legacy_adapter_rejects_api_key_argument() -> None:
    with pytest.raises(TypeError, match="api_key"):
        LiteLLMAdapter("test/provider", api_key="provider-secret")  # type: ignore[call-arg]


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


def _proposed_json(candidate: PlanningCandidate | None = None) -> str:
    item = candidate or _planning_candidate()
    return json.dumps(
        {
            "tests": [
                {
                    "endpoint_handle": item.endpoint_handle,
                    "owner_identity_handle": item.owner_identity_handle,
                    "attacker_identity_handle": item.attacker_identity_handle,
                    "record_handle": item.record_handle,
                    "method": "get",
                    "field_handles": list(item.field_handles),
                    "rationale": "Prioritize the observed record boundary.",
                }
            ]
        }
    )


def test_parse_proposed_plan_accepts_object_and_exact_json_fence() -> None:
    parsed = parse_proposed_plan(_proposed_json())
    assert parsed.tests[0].method == "GET"
    fence = chr(96) * 3
    fenced = f"{fence}json\n{_proposed_json()}\n{fence}"
    assert parse_proposed_plan(fenced) == parsed


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '{"tests": [], "unknown": true}',
        '{"tests": [], "tests": []}',
        '{"tests": []} trailing',
        '{"tests": [1]}',
        '{"tests": [{"endpoint_handle": "secret", "unknown": true}]}',
        '{"tests": [], "value": NaN}',
    ],
)
def test_parse_proposed_plan_rejects_non_strict_shapes_without_echoing_input(raw: str) -> None:
    with pytest.raises(ValueError) as error:
        parse_proposed_plan(raw)
    assert "secret" not in str(error.value)


def test_parse_proposed_plan_rejects_oversize_count_and_rationale() -> None:
    candidate = _planning_candidate()
    item = json.loads(_proposed_json(candidate))["tests"][0]
    with pytest.raises(ValueError):
        parse_proposed_plan(json.dumps({"tests": [item] * (MAX_PROPOSED_TESTS + 1)}))
    item["rationale"] = " "
    with pytest.raises(ValueError):
        parse_proposed_plan(json.dumps({"tests": [item]}))
    item["rationale"] = "x" * 241
    with pytest.raises(ValueError):
        parse_proposed_plan(json.dumps({"tests": [item]}))
    with pytest.raises(ValueError, match="maximum size"):
        parse_proposed_plan("x" * (MAX_AI_OUTPUT_BYTES + 1))


class _RecordingScopeGuard(ScopeGuard):
    def __init__(self, *, denied: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.denied = denied

    def require_allowed(self, url: str, method: str, *, now: Any = None) -> Any:
        self.calls.append((url, method))
        if self.denied:
            raise ValueError("scope denied")
        return None


def test_validate_proposed_plan_binds_exact_candidate_and_checks_scope() -> None:
    candidate = _planning_candidate()
    plan = parse_proposed_plan(_proposed_json(candidate))
    guard = _RecordingScopeGuard()
    assert validate_proposed_plan(plan, (candidate,), guard, "https://api.example.test") == plan
    assert guard.calls == [("https://api.example.test/v1/documents/{id}", "GET")]


@pytest.mark.parametrize(
    "origin",
    [
        "http://api.example.test",
        "https://api.example.test/v1",
        "https://api.example.test?scope=wrong",
        "https://api.example.test#fragment",
        "https://user:password@api.example.test",
        "https://api.example.test:bad",
        "https://api.example.test:99999",
        "https://api.example.test:0",
        "https://:443",
        "https://api.example.test:",
    ],
)
def test_validate_proposed_plan_rejects_malformed_target_origins(origin: str) -> None:
    candidate = _planning_candidate()
    plan = parse_proposed_plan(_proposed_json(candidate))
    guard = _RecordingScopeGuard()
    with pytest.raises(ValueError, match="target origin"):
        validate_proposed_plan(plan, (candidate,), guard, origin)
    assert guard.calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint_handle": "unknown-endpoint"},
        {"owner_identity_handle": "wrong-owner"},
        {"attacker_identity_handle": "wrong-attacker"},
        {"record_handle": "wrong-record"},
        {"method": "POST"},
        {"field_handles": ["unknown-field"]},
    ],
)
def test_validate_proposed_plan_rejects_unobserved_binding(changes: dict[str, Any]) -> None:
    candidate = _planning_candidate()
    payload = json.loads(_proposed_json(candidate))
    payload["tests"][0].update(changes)
    plan = parse_proposed_plan(json.dumps(payload))
    with pytest.raises(ValueError, match="observed candidate"):
        validate_proposed_plan(plan, (candidate,), _RecordingScopeGuard(), "https://api.example.test")


def test_validate_proposed_plan_checks_every_proposal_and_denial_is_fail_closed() -> None:
    first = _planning_candidate(endpoint_handle="ep-a", record_handle="record-a")
    second = _planning_candidate(endpoint_handle="ep-b", record_handle="record-b")
    payload = json.loads(_proposed_json(first))
    payload["tests"].append(json.loads(_proposed_json(second))["tests"][0])
    plan = parse_proposed_plan(json.dumps(payload))
    allowed_guard = _RecordingScopeGuard()
    validate_proposed_plan(plan, (first, second), allowed_guard, "https://api.example.test")
    assert len(allowed_guard.calls) == 2
    guard = _RecordingScopeGuard(denied=True)
    with pytest.raises(ValueError, match="scope denied"):
        validate_proposed_plan(plan, (first, second), guard, "https://api.example.test")
    assert len(guard.calls) == 1
