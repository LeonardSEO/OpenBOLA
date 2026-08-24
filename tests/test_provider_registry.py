from __future__ import annotations

import json

import pytest

from openbola.capture import AdapterRecordView
from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.providers import (
    ProviderDiscoveryError,
    ProviderRegistration,
    ProviderRegistry,
    provider_adapters,
)


def _view(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    request_body: object | None = None,
    response_body: object | None = None,
) -> AdapterRecordView:
    request_bytes = (
        json.dumps(request_body, separators=(",", ":")).encode()
        if request_body is not None
        else None
    )
    response_bytes = (
        json.dumps(response_body, separators=(",", ":")).encode()
        if response_body is not None
        else None
    )
    record = RequestRecord(
        "alice",
        method,
        url,
        headers or {},
        b"{\"query\":\"[REDACTED]\"}" if request_body is not None else None,
        200,
        {},
        b"[REDACTED]" if response_body is not None else None,
    )
    return AdapterRecordView(record, request_bytes, response_bytes)


def test_default_provider_registry_is_ordered_and_uses_one_adapter_per_protocol() -> None:
    registry = InMemorySessionValueRegistry()
    adapters = provider_adapters(registry)

    assert tuple(adapter.name for adapter in adapters) == (
        "generic",
        "supabase",
        "firebase-rtdb",
        "hasura",
    )


def test_discover_runs_all_adapters_and_keeps_provider_confidence_local() -> None:
    value_registry = InMemorySessionValueRegistry()
    orchestrator = ProviderRegistry(value_registry)
    records = (
        _view(
            "GET",
            "https://api.example.test/users/42",
            response_body={"id": 42, "name": "Alice"},
        ),
        _view(
            "GET",
            "https://xyz.supabase.co/rest/v1/orders?id=eq.550e8400-e29b-41d4-a716-446655440000",
            headers={"apikey": "[REDACTED]"},
            response_body={"id": "550e8400-e29b-41d4-a716-446655440000"},
        ),
        _view(
            "GET",
            "https://sample.firebaseio.com/messages/42.json",
            response_body={"text": "hello"},
        ),
        _view(
            "POST",
            "https://graphql.example.test/v1/graphql",
            headers={"x-hasura-role": "[REDACTED]"},
            request_body={
                "query": "query Get($id: uuid!) { orders_by_pk(id: $id) { id total } }",
                "variables": {"id": "550e8400-e29b-41d4-a716-446655440000"},
            },
        ),
    )

    result = orchestrator.discover(records)

    assert tuple(item.provider for item in result.detections) == (
        "generic",
        "supabase",
        "firebase-rtdb",
        "hasura",
    )
    assert result.detections[1].confidence is ProviderConfidence.CONFIRMED
    assert result.detections[2].confidence is ProviderConfidence.CONFIRMED
    assert result.detections[3].confidence is ProviderConfidence.CONFIRMED
    assert {item.provider for item in result.inventories} == {
        "generic",
        "supabase",
        "firebase-rtdb",
        "hasura",
    }
    assert all(
        "550e8400-e29b-41d4-a716-446655440000" not in repr(item)
        for item in result.inventories
    )
    handles = [handle for item in result.inventories for handle in item.record_handles]
    assert handles
    assert "550e8400-e29b-41d4-a716-446655440000" in {
        value_registry.resolve_value(handle) for handle in handles
    }


def test_registry_is_safe_callback_for_ephemeral_views() -> None:
    orchestrator = ProviderRegistry(InMemorySessionValueRegistry())
    view = _view("GET", "https://api.example.test/users/42")

    assert orchestrator.inventory((view,))
    with pytest.raises(TypeError, match="ephemeral adapter views"):
        orchestrator.inventory((view.record,))  # type: ignore[arg-type]


def test_registry_rejects_duplicate_names_and_nonconforming_factories() -> None:
    duplicate = ProviderRegistration("generic", lambda _registry: object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="names must be unique"):
        ProviderRegistry(
            InMemorySessionValueRegistry(),
            registrations=(duplicate, duplicate),
        )

    broken = ProviderRegistration("broken", lambda _registry: object())  # type: ignore[arg-type]
    with pytest.raises(ProviderDiscoveryError, match="registration contract"):
        ProviderRegistry(InMemorySessionValueRegistry(), registrations=(broken,))
