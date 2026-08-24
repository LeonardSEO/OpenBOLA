from __future__ import annotations

import json

from openbola.capture import AdapterRecordView
from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.providers.hasura import (
    HasuraAdapter,
    _parse_operation,
    _ParsedOperation,
    _resource_name,
    _RootSelection,
)


def _view(
    body: dict[str, object],
    *,
    url: str = "https://api.example.test/v1/graphql",
    headers: dict[str, str] | None = None,
    method: str = "POST",
    response: dict[str, object] | None = None,
) -> AdapterRecordView:
    record = RequestRecord("alice", method, url, headers or {}, b'{"query":"[REDACTED]"}', 200)
    return AdapterRecordView(
        record=record,
        request_body=json.dumps(body).encode(),
        response_body=json.dumps(response).encode() if response is not None else None,
    )


def test_parse_query_root_alias_variables_and_selected_fields() -> None:
    parsed = _parse_operation(
        "query Get($orderId: uuid!) { order: orders_by_pk(id: $orderId) { id total } }"
    )
    assert parsed is not None
    assert isinstance(parsed, _ParsedOperation)
    assert parsed.operation_kind == "query"
    assert parsed.roots == (
        _RootSelection(
            field_name="orders_by_pk",
            variable_names=frozenset({"orderId"}),
            selected_fields=frozenset({"id", "total"}),
            mutation_returning_fields=frozenset(),
        ),
    )
    assert _resource_name("orders_by_pk") == "orders"


def test_parse_mutation_uses_returning_fields_not_wrapper_fields() -> None:
    parsed = _parse_operation(
        "mutation Update($id: uuid!, $name: String!) { "
        "update_orders(where: {id: {_eq: $id}}, _set: {name: $name}) "
        "{ affected_rows returning { id name } } }"
    )
    assert parsed is not None
    root = parsed.roots[0]
    assert parsed.operation_kind == "mutation"
    assert root.field_name == "update_orders"
    assert root.variable_names == frozenset({"id", "name"})
    assert root.selected_fields == frozenset({"affected_rows", "returning"})
    assert root.mutation_returning_fields == frozenset({"id", "name"})
    assert _resource_name(root.field_name) == "orders"


def test_mutation_inventory_uses_returning_fields_and_post_method() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {
            "query": (
                "mutation($id: uuid!, $name: String!) { "
                "update_orders(where: {id: {_eq: $id}}, _set: {name: $name}) "
                "{ affected_rows returning { id name } } }"
            ),
            "variables": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "changed",
            },
        },
        headers={"x-hasura-role": "user"},
    )
    inventory = adapter.inventory([record])[0]
    assert inventory.resource_name == "orders"
    assert {field.name for field in inventory.fields} == {"id", "name"}
    assert inventory.observed_methods == frozenset({"POST"})


def test_mutation_without_returning_selection_reports_no_envelope_fields() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {
            "query": (
                "mutation($id: uuid!) { "
                "delete_orders(where: {id: {_eq: $id}}) { affected_rows } }"
            ),
            "variables": {"id": "550e8400-e29b-41d4-a716-446655440000"},
        },
        headers={"x-hasura-role": "user"},
    )
    assert adapter.inventory([record])[0].fields == ()


def test_redacted_or_malformed_payload_is_skipped_without_exception() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    redacted = AdapterRecordView(
        record=RequestRecord(
            "alice",
            "POST",
            "https://api.example.test/v1/graphql",
            {"x-hasura-role": "[REDACTED]"},
            b'{"query":"[REDACTED]"}',
            200,
        ),
        request_body=b'{"query":"[REDACTED]"}',
    )
    malformed = AdapterRecordView(
        record=RequestRecord(
            "alice",
            "POST",
            "https://api.example.test/v1/graphql",
            {"x-hasura-role": "[REDACTED]"},
            b"[REDACTED]",
            200,
        ),
        request_body=b"not-json",
    )
    assert adapter.inventory([redacted, malformed]) == ()


def test_parse_ignores_variable_lookalikes_in_comments_and_strings() -> None:
    assert _parse_operation("# $fake\nquery { orders { note } }") is not None
    assert _parse_operation('query { orders { note(format: "$fake") } }') is not None
    assert _parse_operation("fragment OrderFields on orders { id }") is None
    assert _parse_operation("query { __schema { types { name } } }") is None


def test_parse_rejects_mismatched_or_empty_argument_delimiters() -> None:
    assert _parse_operation("query { orders(where: [id: 1)) { id } }") is None
    assert _parse_operation("query { orders(where: {id: 1]) { id } }") is None
    assert _parse_operation("query { orders(where: ) { id } }") is None


def test_parse_rejects_numeric_tokens_with_identifier_suffixes() -> None:
    assert _parse_operation("query { orders(limit: 123abc) { id } }") is None


def test_parse_rejects_malformed_argument_and_directive_grammar() -> None:
    malformed = (
        "where = 1",
        "where",
        "where:: 1",
        "where: foo bar",
        "where: 1,,",
    )
    for argument in malformed:
        assert _parse_operation(f"query {{ orders({argument}) {{ id }} }}") is None
    assert _parse_operation("query { orders @skip(if: ) { id } }") is None


def test_parse_accepts_variable_definition_types_defaults_and_trailing_commas() -> None:
    parsed = _parse_operation(
        'query Q($ids: [uuid!]!, $id: uuid = "fallback",) '
        "{ orders(ids: $ids, id: $id,) { id } }"
    )
    assert parsed is not None


def test_parse_fails_closed_before_python_recursion_limit() -> None:
    nested = "query { orders " + "{ child " * 140 + "id" + " }" * 140 + " }"
    assert _parse_operation(nested) is None


def test_detect_confirmed_from_graphql_payload_and_case_insensitive_hasura_header() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {"query": "query { orders { id total } }"},
        headers={"X-Hasura-Role": "user"},
    )
    assert adapter.detect([record]).confidence is ProviderConfidence.CONFIRMED


def test_detect_inferred_without_a_hasura_marker_and_unknown_without_graphql() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    inferred = _view({"query": "query { orders { id } }"})
    unknown = _view({"queryText": "not graphql"}, url="https://api.example.test/health")
    assert adapter.detect([inferred]).confidence is ProviderConfidence.INFERRED
    assert adapter.detect([unknown]).confidence is ProviderConfidence.UNKNOWN


def test_inventory_requires_confirmed_hasura_evidence_per_origin() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    confirmed = _view(
        {"query": "query { orders { id total } }"},
        headers={"x-hasura-role": "user"},
        url="https://tenant-a.example.test/v1/graphql",
    )
    generic = _view(
        {"query": "query { orders { id leaked } }"},
        url="https://tenant-b.example.test/v1/graphql",
    )
    inventories = adapter.inventory([confirmed, generic])
    assert len(inventories) == 1
    assert inventories[0].resource_name == "orders"
    assert {field.name for field in inventories[0].fields} == {"id", "total"}
    assert inventories[0].endpoint_template == "/v1/graphql"
    assert inventories[0].observed_methods == frozenset({"POST"})


def test_inventory_does_not_merge_same_resource_across_origins_or_ports() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    body = {"query": "query { orders { id } }"}
    records = [
        _view(body, headers={"x-hasura-role": "user"}, url="https://API.example.test:8443/v1/graphql"),
        _view(body, headers={"x-hasura-role": "user"}, url="https://api.example.test:9443/v1/graphql"),
    ]
    assert len(adapter.inventory(records)) == 2


def test_detection_never_exposes_header_values() -> None:
    sentinel = "this-admin-secret-must-never-appear"  # noqa: S105
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    detection = adapter.detect([
        _view({"query": "query { orders { id } }"}, headers={"x-hasura-admin-secret": sentinel})
    ])
    assert sentinel not in repr(detection)


def test_inventory_maps_each_variable_to_its_own_root_resource() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = HasuraAdapter(registry)
    record = _view(
        {
            "query": (
                "query($orderId: uuid!, $userId: uuid!) { "
                "orders_by_pk(id: $orderId) { id } users_by_pk(id: $userId) { id } }"
            ),
            "variables": {
                "orderId": "550e8400-e29b-41d4-a716-446655440000",
                "userId": "507f1f77bcf86cd799439011",
            },
        },
        headers={"x-hasura-role": "user"},
    )
    inventories = {item.resource_name: item for item in adapter.inventory([record])}
    assert {registry.resolve_value(h) for h in inventories["orders"].record_handles} == {
        "550e8400-e29b-41d4-a716-446655440000"
    }
    assert {registry.resolve_value(h) for h in inventories["users"].record_handles} == {
        "507f1f77bcf86cd799439011"
    }


def test_inventory_extracts_only_id_and_id_eq_variables() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = HasuraAdapter(registry)
    record = _view(
        {
            "query": (
                "query($id: uuid!, $where: orders_bool_exp!) { "
                "orders_by_pk(id: $id) { id } orders(where: $where) { id } }"
            ),
            "variables": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "where": {
                    "id": {"_eq": "507f1f77bcf86cd799439011"},
                    "status": {"_in": ["paid", "new"]},
                },
            },
        },
        headers={"x-hasura-role": "user"},
    )
    values = {
        registry.resolve_value(handle)
        for inventory in adapter.inventory([record])
        for handle in inventory.record_handles
    }
    assert values == {
        "550e8400-e29b-41d4-a716-446655440000",
        "507f1f77bcf86cd799439011",
    }


def test_sensitive_variable_or_sensitive_parent_never_becomes_a_handle() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = HasuraAdapter(registry)
    sentinel = "opaque_secret_record_4eC39HqLyjWDarjtT1zdp7dc"  # noqa: S105
    record = _view(
        {
            "query": (
                "query($apiTokenId: uuid!, $where: api_keys_bool_exp!) { "
                "api_keys_by_pk(id: $apiTokenId) { id } "
                "api_keys(where: $where) { id } }"
            ),
            "variables": {
                "apiTokenId": sentinel,
                "where": {"secret_token": {"_eq": sentinel}},
            },
        },
        headers={"x-hasura-role": "user"},
    )
    inventory = adapter.inventory([record])[0]
    assert inventory.record_handles == ()
    assert sentinel not in repr(inventory)


def test_inline_literals_and_in_filters_never_mint_handles() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {
            "query": "query { orders(where: {id: {_in: [1, 2]}}) { id } }",
            "variables": {},
        },
        headers={"x-hasura-role": "user"},
    )
    assert adapter.inventory([record])[0].record_handles == ()
