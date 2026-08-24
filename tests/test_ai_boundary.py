from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from openbola.ai import (
    AIProviderConfig,
    PlanningCandidate,
    ProposedPlan,
    ProposedTest,
    build_sanitized_context,
    validate_proposed_plan,
)
from openbola.ai_clients import (
    OpenAICompatibleClient,
    ProviderCredentialError,
)
from openbola.capture import AdapterRecordView, SessionRequestMaterial, SessionResponseMaterial
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.scope import ScopeGuard

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
API_KEY = "p5-api-key-sentinel"
RAW_OBJECT_ID = "p5-raw-object-id-sentinel"
FULL_RESPONSE = "p5-full-response-sentinel"
COOKIE = "p5-cookie-sentinel"
TARGET_SCOPE_CONTENT = "p5-target-scope-content-sentinel"


def _scope(path: Path, *, allowed_path: str, client_name: str) -> ScopeGuard:
    path.write_text(
        yaml.safe_dump(
            {
                "client_name": client_name,
                "authorization_reference": "PT-2026-P5-BOUNDARY",
                "confirmed": True,
                "starts_at": "2026-08-24T10:00:00Z",
                "expires_at": "2026-08-24T14:00:00Z",
                "allowed_hosts": [
                    "llm.example.test" if client_name == "AI provider" else "api.example.test"
                ],
                "allowed_cidrs": [],
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
        )
        + f"# {TARGET_SCOPE_CONTENT}\n",
        encoding="utf-8",
    )
    return ScopeGuard.from_file(path, now=NOW)


def _candidate() -> PlanningCandidate:
    # This is the sanitized discovery output. None of the values below are
    # resolved record IDs, bodies, credentials, or browser material.
    return PlanningCandidate(
        endpoint_handle="endpoint-handle",
        owner_identity_handle="owner-handle",
        attacker_identity_handle="attacker-handle",
        record_handle="record-handle",
        endpoint_template="/v1/documents/{id}",
        method="GET",
        field_handles=("field-handle",),
    )


def _proposal(candidate: PlanningCandidate) -> ProposedPlan:
    return ProposedPlan(
        (
            ProposedTest(
                endpoint_handle=candidate.endpoint_handle,
                owner_identity_handle=candidate.owner_identity_handle,
                attacker_identity_handle=candidate.attacker_identity_handle,
                record_handle=candidate.record_handle,
                method=candidate.method,
                field_handles=candidate.field_handles,
                rationale="Compare the observed ownership boundary.",
            ),
        )
    )


@pytest.fixture
def p5_boundary(tmp_path: Path) -> dict[str, Any]:
    registry = InMemorySessionValueRegistry()
    api_key = registry.store_secret(purpose="provider_api_key", value=API_KEY)

    # Raw session material exists only behind process-local handles. It is
    # intentionally never passed to discovery context construction or the AI.
    registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial(
            f"https://api.example.test/v1/documents/{RAW_OBJECT_ID}",
            {"Cookie": COOKIE},
            RAW_OBJECT_ID.encode(),
        ),
    )
    registry.store_value(
        kind="session_state",
        value=SessionResponseMaterial(200, {"Set-Cookie": COOKIE}, FULL_RESPONSE.encode()),
    )

    provider_guard = _scope(
        tmp_path / "provider-scope.yaml",
        allowed_path="/v1/chat/completions",
        client_name="AI provider",
    )
    target_guard = _scope(
        tmp_path / "target-scope.yaml",
        allowed_path="/v1/documents/*",
        client_name="Target API",
    )
    candidate = _candidate()
    return {
        "registry": registry,
        "api_key": api_key,
        "provider_guard": provider_guard,
        "target_guard": target_guard,
        "candidate": candidate,
        "context": build_sanitized_context((candidate,)),
    }


def test_end_to_end_provider_payload_and_plan_boundary(p5_boundary: dict[str, Any]) -> None:
    captured: list[httpx.Request] = []
    candidate = p5_boundary["candidate"]
    expected_plan = _proposal(candidate)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        body = json.loads(request.content)
        assert set(body) == {"model", "temperature", "messages", "response_format"}
        assert body["response_format"]["type"] == "json_schema"
        assert body["response_format"]["json_schema"]["strict"] is True
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "tests": [
                                        {
                                            "endpoint_handle": candidate.endpoint_handle,
                                            "owner_identity_handle": (
                                                candidate.owner_identity_handle
                                            ),
                                            "attacker_identity_handle": (
                                                candidate.attacker_identity_handle
                                            ),
                                            "record_handle": candidate.record_handle,
                                            "method": candidate.method,
                                            "field_handles": list(candidate.field_handles),
                                            "rationale": "Compare the observed ownership boundary.",
                                        }
                                    ]
                                }
                            )
                        }
                    }
                ]
            },
        )

    config = AIProviderConfig(
        kind="openai_compatible",
        base_url="https://llm.example.test",
        model="p5-test-model",
        api_key=p5_boundary["api_key"],
    )
    client = OpenAICompatibleClient(
        config,
        secrets=p5_boundary["registry"],
        provider_scope_guard=p5_boundary["provider_guard"],
        transport=httpx.MockTransport(handler),
    )

    plan = client.propose_tests(p5_boundary["context"])
    assert plan == expected_plan
    assert len(captured) == 1
    rendered = captured[0].content.decode("utf-8")
    for sentinel in (
        API_KEY,
        RAW_OBJECT_ID,
        FULL_RESPONSE,
        COOKIE,
        TARGET_SCOPE_CONTENT,
        "AdapterRecordView",
    ):
        assert sentinel not in rendered
    assert "openbola-ai-context-v1" in rendered
    assert candidate.endpoint_handle in rendered
    assert candidate.endpoint_template in rendered
    assert captured[0].headers["authorization"] == f"Bearer {API_KEY}"

    target_guard = p5_boundary["target_guard"]
    assert validate_proposed_plan(
        plan, (candidate,), target_guard, "https://api.example.test"
    ) == plan

    with pytest.raises(ValueError, match="observed candidate"):
        validate_proposed_plan(
            ProposedPlan((replace(plan.tests[0], record_handle="other"),)),
            (candidate,),
            target_guard,
            "https://api.example.test",
        )
    with pytest.raises(ValueError, match="observed candidate"):
        validate_proposed_plan(
            ProposedPlan((replace(plan.tests[0], method="POST"),)),
            (candidate,),
            target_guard,
            "https://api.example.test",
        )
    with pytest.raises(ValueError, match="observed candidate"):
        validate_proposed_plan(
            ProposedPlan((replace(plan.tests[0], field_handles=("other",)),)),
            (candidate,),
            target_guard,
            "https://api.example.test",
        )

    changed_path = PlanningCandidate(
        endpoint_handle=candidate.endpoint_handle,
        owner_identity_handle=candidate.owner_identity_handle,
        attacker_identity_handle=candidate.attacker_identity_handle,
        record_handle=candidate.record_handle,
        endpoint_template="/v1/admin/{id}",
        method=candidate.method,
        field_handles=candidate.field_handles,
    )
    with pytest.raises(ValueError):
        validate_proposed_plan(
            plan, (changed_path,), target_guard, "https://api.example.test"
        )

    denied_target = _scope(
        Path(p5_boundary["provider_guard"].config._source_path).with_name("denied-target.yaml"),
        allowed_path="/v1/other/*",
        client_name="Target API",
    )
    with pytest.raises(ValueError):
        validate_proposed_plan(plan, (candidate,), denied_target, "https://api.example.test")


def test_session_close_prevents_provider_secret_resolution(p5_boundary: dict[str, Any]) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"choices": []})

    client = OpenAICompatibleClient(
        AIProviderConfig(
            kind="openai_compatible",
            base_url="https://llm.example.test",
            model="p5-test-model",
            api_key=p5_boundary["api_key"],
        ),
        secrets=p5_boundary["registry"],
        provider_scope_guard=p5_boundary["provider_guard"],
        transport=httpx.MockTransport(handler),
    )
    p5_boundary["registry"].close()
    with pytest.raises(RuntimeError, match="closed"):
        p5_boundary["registry"].resolve_secret(p5_boundary["api_key"])
    with pytest.raises(ProviderCredentialError):
        client.propose_tests(p5_boundary["context"])
    assert calls == 0


def test_adapter_record_view_material_is_not_accepted_as_ai_context() -> None:
    view = AdapterRecordView(
        RequestRecord("alice", "GET", "https://api.example.test/v1/documents/[REDACTED]"),
        RAW_OBJECT_ID.encode(),
        FULL_RESPONSE.encode(),
    )
    with pytest.raises(ValueError):
        build_sanitized_context((view,))  # type: ignore[arg-type]
