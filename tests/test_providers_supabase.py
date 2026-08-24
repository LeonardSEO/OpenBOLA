from __future__ import annotations

from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.providers.supabase import SupabaseAdapter


def _record(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    response_body: bytes | None = None,
    response_status: int | None = 200,
) -> RequestRecord:
    return RequestRecord(
        "alice",
        method,
        url,
        headers or {},
        body,
        response_status,
        {},
        response_body,
    )


def test_detect_confirmed_with_apikey_header_and_rest_path() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.42",
            headers={"apikey": "abc123", "Authorization": "Bearer jwt"},
        ),
    ]
    detection = adapter.detect(records)
    assert detection.provider == "supabase"
    assert detection.confidence == ProviderConfidence.CONFIRMED


def test_detect_confirmed_apikey_header_lookup_is_case_insensitive() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders",
            headers={"ApiKey": "abc123"},
        ),
    ]
    assert adapter.detect(records).confidence == ProviderConfidence.CONFIRMED


def test_detect_inferred_from_rest_path_without_apikey() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://self-hosted.example.com/rest/v1/orders?id=eq.42")]
    detection = adapter.detect(records)
    assert detection.confidence == ProviderConfidence.INFERRED


def test_detect_inferred_from_postgrest_operator_without_rest_prefix() -> None:
    # Plain self-hosted PostgREST is commonly mounted at root, with no
    # "/rest/v1/" prefix at all -- the operator-shaped query value is the
    # only signal available in that deployment shape.
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.com/orders?id=eq.42")]
    detection = adapter.detect(records)
    assert detection.confidence == ProviderConfidence.INFERRED


def test_detect_unknown_with_no_signals() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.test/v1/orders")]
    detection = adapter.detect(records)
    assert detection.confidence == ProviderConfidence.UNKNOWN


def test_detect_unknown_on_empty_records() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    assert adapter.detect(()).confidence == ProviderConfidence.UNKNOWN


def test_inventory_ignores_non_rest_records() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.test/v1/orders")]
    assert adapter.inventory(records) == ()


def test_inventory_extracts_table_fields_and_eq_filter_handle() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders"
            "?id=eq.550e8400-e29b-41d4-a716-446655440000",
            headers={"apikey": "k"},
            response_body=b'{"id": "550e8400-e29b-41d4-a716-446655440000", "total": 9.5}',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.provider == "supabase"
    assert inv.provider_confidence == ProviderConfidence.CONFIRMED
    assert inv.resource_name == "orders"
    assert inv.endpoint_template == "/rest/v1/orders"
    assert inv.observed_methods == frozenset({"GET"})
    assert {f.name for f in inv.fields} == {"id", "total"}
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"550e8400-e29b-41d4-a716-446655440000"}


def test_inventory_ignores_non_object_id_eq_filter_values() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?status=eq.active",
            headers={"apikey": "k"},
        ),
    ]
    inv = adapter.inventory(records)[0]
    assert inv.record_handles == ()


def test_inventory_deduplicates_record_handles_within_a_table() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "PATCH",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.2",
            headers={"apikey": "k"},
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.observed_methods == frozenset({"GET", "PATCH"})
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"1", "2"}
    assert len(inv.record_handles) == 2


def test_inventory_does_not_merge_tables_across_origins() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://tenant-a.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "GET",
            "https://tenant-b.supabase.co/rest/v1/orders?id=eq.2",
            headers={"apikey": "k"},
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    for inv in inventories:
        assert inv.endpoint_template == "/rest/v1/orders"
        assert len(inv.record_handles) == 1


def test_inventory_separates_multiple_tables() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET", "https://xyzcompany.supabase.co/rest/v1/orders", headers={"apikey": "k"}
        ),
        _record(
            "GET", "https://xyzcompany.supabase.co/rest/v1/customers", headers={"apikey": "k"}
        ),
    ]

    inventories = adapter.inventory(records)
    assert {inv.resource_name for inv in inventories} == {"orders", "customers"}


def test_inventory_rpc_calls_to_the_same_function_group_together() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "POST",
            "https://xyzcompany.supabase.co/rest/v1/rpc/calculate_total",
            headers={"apikey": "k"},
            body=b'{"order_id": "550e8400-e29b-41d4-a716-446655440000"}',
        ),
        _record(
            "POST",
            "https://xyzcompany.supabase.co/rest/v1/rpc/calculate_total",
            headers={"apikey": "k"},
            body=b'{"currency": "USD"}',
        ),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.resource_name == "rpc/calculate_total"
    assert inv.endpoint_template == "/rest/v1/rpc/calculate_total"
    assert {f.name for f in inv.fields} == {"order_id", "currency"}


def test_inventory_confidence_does_not_bleed_across_origins() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://confirmed-tenant.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "GET",
            "https://unconfirmed-tenant.supabase.co/rest/v1/orders?id=eq.2",
        ),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    by_confidence = {inv.provider_confidence for inv in inventories}
    assert by_confidence == {ProviderConfidence.CONFIRMED, ProviderConfidence.INFERRED}


def test_inventory_ignores_sensitive_named_eq_filters() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/api_keys"
            "?secret_token=eq.opaque_secret_record_4eC39HqLyjWDarjtT1zdp7dc",
            headers={"apikey": "k"},
        ),
    ]
    inv = adapter.inventory(records)[0]
    assert inv.record_handles == ()


def test_inventory_rpc_calls_to_different_functions_do_not_merge() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "POST",
            "https://xyzcompany.supabase.co/rest/v1/rpc/get_my_orders",
            headers={"apikey": "k"},
            body=b'{"limit": 10}',
        ),
        _record(
            "POST",
            "https://xyzcompany.supabase.co/rest/v1/rpc/admin_delete_user",
            headers={"apikey": "k"},
            body=b'{"target_user": "u1"}',
        ),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    by_resource = {inv.resource_name: inv for inv in inventories}
    assert set(by_resource) == {"rpc/get_my_orders", "rpc/admin_delete_user"}
    assert {f.name for f in by_resource["rpc/get_my_orders"].fields} == {"limit"}
    assert {f.name for f in by_resource["rpc/admin_delete_user"].fields} == {"target_user"}
