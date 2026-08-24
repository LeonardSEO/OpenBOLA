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


def test_inventory_ignores_json_suffixed_non_firebase_traffic() -> None:
    # Regression for a false-positive: any *.json URL on an unrelated host
    # (e.g. a web app's manifest.json) must never be claimed as firebase-rtdb.
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record("GET", "https://app.example.com/manifest.json"),
        _record("GET", "https://app.example.com/asset-manifest.json"),
    ]
    assert adapter.inventory(records) == ()


def test_inventory_only_includes_firebase_host_records_and_stays_confirmed() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://myproj.firebaseio.com/users/1.json"),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].provider_confidence == ProviderConfidence.CONFIRMED


def test_inventory_excludes_sensitive_parent_keyed_ids() -> None:
    # RTDB has no query-by-value, so keying a node directly by a secret
    # (e.g. a password-reset token) is an idiomatic pattern -- that secret
    # must never become a probeable record_id handle.
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://myproj.firebaseio.com/passwordResetTokens/8Kj2mQ7xR4pL9nV3wZ5t.json",
        ),
    ]
    inv = adapter.inventory(records)[0]
    assert inv.record_handles == ()


def test_inventory_captures_push_id_from_create_response() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record(
            "POST",
            "https://myproj.firebaseio.com/messages.json",
            body=b'{"text": "hi"}',
            response_body=b'{"name": "-NqA1bC2dEfGhIjKlMn"}',
        ),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert {f.name for f in inv.fields} == {"text"}
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"-NqA1bC2dEfGhIjKlMn"}


def test_inventory_trailing_slash_groups_with_non_trailing_slash() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://myproj.firebaseio.com/users/42.json"),
        _record("GET", "https://myproj.firebaseio.com/users/42/.json"),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1


def test_inventory_case_insensitive_host_merges_origins() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://Myproj.FirebaseIO.com/users/1.json"),
        _record("GET", "https://myproj.firebaseio.com/users/2.json"),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    resolved = {registry.resolve_value(h) for h in inventories[0].record_handles}
    assert resolved == {"1", "2"}


def test_inventory_different_ports_stay_separate() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record("GET", "https://myproj.firebaseio.com:8080/users/1.json"),
        _record("GET", "https://myproj.firebaseio.com:9090/users/2.json"),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 2


def test_inventory_never_inspects_or_leaks_the_auth_query_parameter() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    secret_token = "AIzaSyD-secret-database-token-value-should-never-leak"  # noqa: S105
    records = [
        _record("GET", f"https://myproj.firebaseio.com/users/42.json?auth={secret_token}"),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert secret_token not in inv.endpoint_template
    assert secret_token not in inv.resource_name
    assert all(secret_token not in f.name for f in inv.fields)
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert secret_token not in resolved
