from __future__ import annotations

from openbola.providers.hasura import (
    _parse_operation,
    _ParsedOperation,
    _resource_name,
    _RootSelection,
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
