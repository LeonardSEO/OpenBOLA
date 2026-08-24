from __future__ import annotations

from openbola.discovery import (
    FieldInventory,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
)
from openbola.handles import InMemorySessionValueRegistry, ValueHandle
from openbola.models import RequestRecord


def test_provider_confidence_has_three_members() -> None:
    assert {member.value for member in ProviderConfidence} == {
        "confirmed",
        "inferred",
        "unknown",
    }


def test_field_inventory_is_frozen_and_name_only() -> None:
    field = FieldInventory(name="email")
    assert field.name == "email"
    assert not hasattr(field, "type")
    assert not hasattr(field, "observed_types")


def test_provider_detection_pairs_provider_and_confidence() -> None:
    detection = ProviderDetection(provider="generic", confidence=ProviderConfidence.UNKNOWN)
    assert detection.provider == "generic"
    assert detection.confidence is ProviderConfidence.UNKNOWN


def test_resource_inventory_holds_value_handles_not_raw_ids() -> None:
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_value(kind="record_id", value="42")
    inventory = ResourceInventory(
        provider="generic",
        provider_confidence=ProviderConfidence.UNKNOWN,
        resource_name="users",
        endpoint_template="/v1/users/{id}",
        fields=(FieldInventory(name="email"),),
        record_handles=(handle,),
        observed_methods=frozenset({"GET", "PATCH"}),
    )
    assert inventory.record_handles == (handle,)
    assert isinstance(inventory.record_handles[0], ValueHandle)
    assert inventory.observed_methods == frozenset({"GET", "PATCH"})


def test_provider_adapter_is_a_protocol_with_expected_members() -> None:
    # A structural check that a minimal conforming class satisfies the Protocol
    # at the attribute/method level - Protocol membership is duck-typed, so
    # this test exercises that shape rather than calling isinstance().
    class MinimalAdapter:
        name = "minimal"

        def detect(self, records: object) -> ProviderDetection:
            return ProviderDetection(provider="minimal", confidence=ProviderConfidence.UNKNOWN)

        def inventory(self, records: object) -> tuple[ResourceInventory, ...]:
            return ()

    adapter: ProviderAdapter = MinimalAdapter()
    assert adapter.name == "minimal"
    assert adapter.detect(()).provider == "minimal"
    assert adapter.inventory(()) == ()


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


def test_generic_adapter_detect_is_always_unknown_confidence() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    detection = adapter.detect(())
    assert detection.provider == "generic"
    assert detection.confidence == ProviderConfidence.UNKNOWN


def test_generic_adapter_groups_records_by_templatized_endpoint() -> None:
    from openbola.discovery import GenericAdapter

    registry = InMemorySessionValueRegistry()
    adapter = GenericAdapter(registry)
    records = [
        _record("GET", "https://api.example.test/v1/users"),
        _record("GET", "https://api.example.test/v1/users/42"),
        _record(
            "PATCH",
            "https://api.example.test/v1/users/42",
            body=b'{"email": "alice@example.test"}',
            response_body=b'{"id": 42, "email": "alice@example.test", "name": "Alice"}',
        ),
        _record(
            "POST",
            "https://api.example.test/v1/users",
            body=b'{"email": "bob@example.test", "name": "Bob"}',
            response_body=b'{"id": 43}',
        ),
    ]

    inventories = adapter.inventory(records)
    by_template = {item.endpoint_template: item for item in inventories}

    assert set(by_template) == {"/v1/users", "/v1/users/{id}"}

    collection = by_template["/v1/users"]
    assert collection.provider == "generic"
    assert collection.provider_confidence == ProviderConfidence.UNKNOWN
    assert collection.resource_name == "users"
    assert collection.observed_methods == frozenset({"GET", "POST"})
    assert {f.name for f in collection.fields} == {"email", "name", "id"}
    assert collection.record_handles == ()  # no path-embedded ID at this template

    item = by_template["/v1/users/{id}"]
    assert item.observed_methods == frozenset({"GET", "PATCH"})
    assert {f.name for f in item.fields} == {"email", "id", "name"}
    assert len(item.record_handles) == 1
    assert registry.resolve_value(item.record_handles[0]) == "42"


def test_generic_adapter_ignores_non_json_and_malformed_bodies() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record("POST", "https://api.example.test/v1/reports", body=b"not json"),
        _record(
            "POST",
            "https://api.example.test/v1/reports",
            body=b'"just a json string, not an object"',
        ),
        _record("GET", "https://api.example.test/v1/reports", response_body=b"[]"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].fields == ()


def test_generic_adapter_extracts_fields_from_list_of_objects_response() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://api.example.test/v1/orders",
            response_body=b'[{"id": 1, "total": 9.5}, {"id": 2, "status": "paid"}]',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert {f.name for f in inventories[0].fields} == {"id", "total", "status"}


def test_generic_adapter_deduplicates_record_handles_per_template() -> None:
    from openbola.discovery import GenericAdapter

    registry = InMemorySessionValueRegistry()
    adapter = GenericAdapter(registry)
    records = [
        _record("GET", "https://api.example.test/v1/users/42"),
        _record("PATCH", "https://api.example.test/v1/users/42"),
        _record("GET", "https://api.example.test/v1/users/43"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    handles = inventories[0].record_handles
    resolved = {registry.resolve_value(handle) for handle in handles}
    assert resolved == {"42", "43"}
    assert len(handles) == 2  # one handle per unique ID, not per record


def test_generic_adapter_resource_name_skips_every_numbered_placeholder() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record("GET", "https://api.example.test/v1/orgs/7/users/42"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].endpoint_template == "/v1/orgs/{id}/users/{id2}"
    assert inventories[0].resource_name == "users"


def test_generic_adapter_routes_id_shaped_keys_to_handles_not_fields() -> None:
    from openbola.discovery import GenericAdapter

    registry = InMemorySessionValueRegistry()
    adapter = GenericAdapter(registry)
    records = [
        _record(
            "GET",
            "https://proj.firebaseio.com/users.json",
            response_body=(
                b'{"-NqA1bC2dEfGhIjKlMn": {"name": "Alice"}, '
                b'"opaque_secret_record_4eC39HqLyjWDarjtT1zdp7dc": {"name": "Bob"}}'
            ),
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    # Both top-level keys are ID-shaped, so no field names survive at this
    # level; the nested "name" fields are one level deeper than this
    # provider-agnostic scan inspects (top_level_json_keys only, per Fix 1's
    # scope), and only the ID-shaped keys themselves are the concern here.
    assert {f.name for f in inv.fields} == set()
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {
        "-NqA1bC2dEfGhIjKlMn",
        "opaque_secret_record_4eC39HqLyjWDarjtT1zdp7dc",
    }


def test_generic_adapter_routes_email_shaped_keys_to_handles() -> None:
    from openbola.discovery import GenericAdapter

    registry = InMemorySessionValueRegistry()
    adapter = GenericAdapter(registry)
    records = [
        _record(
            "GET",
            "https://api.example.test/v1/accounts",
            response_body=b'{"alice@example.test": {"role": "admin"}}',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    # The only top-level key is the email address; the nested "role" field
    # is one level deeper than this provider-agnostic scan inspects
    # (top_level_json_keys only, per Fix 1's scope).
    assert {f.name for f in inv.fields} == set()
    assert {registry.resolve_value(h) for h in inv.record_handles} == {"alice@example.test"}


def test_generic_adapter_does_not_merge_records_across_origins() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record("GET", "https://tenant-a.example.com/v1/users/42"),
        _record("DELETE", "https://tenant-b.example.com/v1/users/99"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    for inv in inventories:
        assert inv.endpoint_template == "/v1/users/{id}"
        assert len(inv.record_handles) == 1
    observed = {inv.observed_methods for inv in inventories}
    assert observed == {frozenset({"GET"}), frozenset({"DELETE"})}


def test_generic_adapter_normalizes_method_case() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record("get", "https://api.example.test/v1/widgets"),
        _record("GET", "https://api.example.test/v1/widgets"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].observed_methods == frozenset({"GET"})
