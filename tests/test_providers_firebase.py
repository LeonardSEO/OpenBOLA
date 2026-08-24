from __future__ import annotations

from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.providers.firebase import FirebaseRealtimeDatabaseAdapter


def _record(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    response_body: bytes | None = None,
    response_status: int | None = 200,
) -> RequestRecord:
    return RequestRecord(
        "alice",
        method,
        url,
        {},
        body,
        response_status,
        {},
        response_body,
    )


def test_detect_confirmed_with_firebaseio_host_and_json_suffix() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://myproj.firebaseio.com/users/42.json")]
    detection = adapter.detect(records)
    assert detection.provider == "firebase-rtdb"
    assert detection.confidence == ProviderConfidence.CONFIRMED


def test_detect_confirmed_with_regional_firebasedatabase_app_host() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://myproj-default-rtdb.europe-west1.firebasedatabase.app/users.json",
        ),
    ]
    assert adapter.detect(records).confidence == ProviderConfidence.CONFIRMED


def test_detect_inferred_from_firebase_host_without_json_suffix() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://myproj.firebaseio.com/users/42")]
    assert adapter.detect(records).confidence == ProviderConfidence.INFERRED


def test_detect_inferred_from_json_suffix_without_firebase_host() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://random.example.com/users/42.json")]
    assert adapter.detect(records).confidence == ProviderConfidence.INFERRED


def test_detect_unknown_with_no_signals() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.test/v1/orders")]
    assert adapter.detect(records).confidence == ProviderConfidence.UNKNOWN


def test_detect_unknown_on_empty_records() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    assert adapter.detect(()).confidence == ProviderConfidence.UNKNOWN


def test_inventory_ignores_records_without_json_suffix() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://myproj.firebaseio.com/users/42")]
    assert adapter.inventory(records) == ()


def test_inventory_extracts_path_embedded_push_id_and_fields() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://myproj.firebaseio.com/users/42/profile.json",
            response_body=b'{"email": "alice@example.test", "name": "Alice"}',
        ),
        _record(
            "PUT",
            "https://myproj.firebaseio.com/users/42/profile.json",
            body=b'{"name": "Alice Updated"}',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.provider == "firebase-rtdb"
    assert inv.provider_confidence == ProviderConfidence.CONFIRMED
    assert inv.resource_name == "profile"
    assert inv.endpoint_template == "/users/{id}/profile"
    assert inv.observed_methods == frozenset({"GET", "PUT"})
    assert {f.name for f in inv.fields} == {"email", "name"}
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"42"}


def test_inventory_routes_push_id_shaped_list_keys_to_handles_not_fields() -> None:
    # A "list" node's response is a JSON object keyed by each child's push ID
    # -- structurally the same case P4a's classify_key/top_level_json_keys
    # were built for (Firebase-shaped keys), reused here unchanged.
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://myproj.firebaseio.com/messages.json",
            response_body=(
                b'{"-NqA1bC2dEfGhIjKlMn": {"text": "hi"}, '
                b'"-NqB2cD3eFgHiJkLmN": {"text": "yo"}}'
            ),
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.resource_name == "messages"
    assert inv.endpoint_template == "/messages"
    assert inv.fields == ()
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"-NqA1bC2dEfGhIjKlMn", "-NqB2cD3eFgHiJkLmN"}


def test_inventory_does_not_merge_across_origins() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://tenant-a.firebaseio.com/users/42/profile.json"),
        _record("GET", "https://tenant-b.firebaseio.com/users/99/profile.json"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    for inv in inventories:
        assert inv.endpoint_template == "/users/{id}/profile"
        assert len(inv.record_handles) == 1


def test_inventory_confidence_is_scoped_per_group() -> None:
    # Mirrors the P4b final-review fix: confidence must never bleed across
    # groups that happen to share a path shape.
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://tenant-a.firebaseio.com/users/1.json"),
        _record("GET", "https://random.example.com/users/2.json"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    confidences = {inv.provider_confidence for inv in inventories}
    assert confidences == {ProviderConfidence.CONFIRMED, ProviderConfidence.INFERRED}
