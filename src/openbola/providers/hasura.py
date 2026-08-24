"""Bounded GraphQL parsing contracts for the Hasura provider adapter.

The parser in this module is deliberately smaller than a GraphQL implementation.  It
only keeps names and punctuation needed to identify top-level resources and selected
fields; string and numeric literal contents are discarded while lexing.  This keeps
captured documents out of provider-owned state and makes malformed input fail closed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlsplit

from openbola.discovery import (
    FieldInventory,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
    adapter_record,
)
from openbola.endpoints import _id_field, _is_sensitive_field, is_object_id
from openbola.handles import InMemorySessionValueRegistry

if TYPE_CHECKING:
    from openbola.capture import AdapterRecordView


@dataclass(frozen=True)
class _RootSelection:
    field_name: str
    variable_names: frozenset[str]
    selected_fields: frozenset[str]
    mutation_returning_fields: frozenset[str]


@dataclass(frozen=True)
class _ParsedOperation:
    operation_kind: Literal["query", "mutation"]
    roots: tuple[_RootSelection, ...]


@dataclass(frozen=True)
class _Token:
    kind: Literal["name", "variable", "punctuation", "string", "literal"]
    value: str = ""


_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_NUMBER_RE = re.compile(
    r"(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)"
)
_PUNCTUATION = frozenset("!$():=@[]{|}&")
_OPEN_DELIMITERS = {"(": ")", "[": "]", "{": "}"}
_CLOSE_DELIMITERS = frozenset(_OPEN_DELIMITERS.values())
_MAX_PARSE_DEPTH = 128


def _lex(document: str) -> tuple[_Token, ...] | None:
    """Tokenise the safe subset needed by the provider parser.

    Names and variable names are retained, while quoted and numeric values are
    represented only by placeholders.  No token stores a document substring that
    could contain a credential or object value.
    """

    tokens: list[_Token] = []
    index = 0
    length = len(document)
    while index < length:
        character = document[index]
        if character.isspace():
            index += 1
            continue
        if character == "#":
            newline = document.find("\n", index + 1)
            index = length if newline == -1 else newline + 1
            continue
        if document.startswith("\"\"\"", index):
            end = document.find("\"\"\"", index + 3)
            if end == -1:
                return None
            index = end + 3
            tokens.append(_Token("string"))
            continue
        if character == '"':
            index += 1
            while index < length:
                current = document[index]
                if current == "\\":
                    index += 2
                    continue
                if current == '"':
                    break
                if current in "\r\n":
                    return None
                index += 1
            if index >= length or document[index] != '"':
                return None
            index += 1
            tokens.append(_Token("string"))
            continue
        if character == "$":
            match = _NAME_RE.match(document, index + 1)
            if match is None:
                return None
            tokens.append(_Token("variable", match.group(0)))
            index = match.end()
            continue
        if document.startswith("...", index):
            tokens.append(_Token("punctuation", "..."))
            index += 3
            continue
        match = _NAME_RE.match(document, index)
        if match is not None:
            tokens.append(_Token("name", match.group(0)))
            index = match.end()
            continue
        number = _NUMBER_RE.match(document, index)
        if number is not None:
            if number.end() < length and (
                document[number.end()].isalnum() or document[number.end()] in "_."
            ):
                return None
            tokens.append(_Token("literal"))
            index = number.end()
            continue
        if character == "," or character in _PUNCTUATION:
            tokens.append(_Token("punctuation", character))
            index += 1
            continue
        # GraphQL permits no other source characters in the subset we parse.
        return None
    return tuple(tokens)


def _is(tokens: tuple[_Token, ...], index: int, kind: str, value: str = "") -> bool:
    if index >= len(tokens) or tokens[index].kind != kind:
        return False
    return not value or tokens[index].value == value


def _consume_balanced(
    tokens: tuple[_Token, ...], index: int, opening: str, closing: str
) -> tuple[tuple[_Token, ...], int] | None:
    if not _is(tokens, index, "punctuation", opening):
        return None
    delimiters = [closing]
    cursor = index + 1
    start = cursor
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.kind == "punctuation" and token.value in _OPEN_DELIMITERS:
            delimiters.append(_OPEN_DELIMITERS[token.value])
        elif token.kind == "punctuation" and token.value in _CLOSE_DELIMITERS:
            if not delimiters or token.value != delimiters[-1]:
                return None
            delimiters.pop()
            if not delimiters:
                inner = tokens[start:cursor]
                if not inner or inner[-1].value == ":":
                    return None
                if not _validate_argument_tokens(inner):
                    return None
                return inner, cursor + 1
        cursor += 1
    return None


def _parse_value(tokens: tuple[_Token, ...], index: int, depth: int = 0) -> int | None:
    """Consume one GraphQL value/type without retaining its contents."""

    if depth > _MAX_PARSE_DEPTH or index >= len(tokens):
        return None
    token = tokens[index]
    if token.kind in {"name", "variable", "string", "literal"}:
        cursor = index + 1
        if token.kind == "name" and _is(tokens, cursor, "punctuation", "!"):
            cursor += 1
        return cursor
    if token.kind != "punctuation" or token.value not in {"[", "{"}:
        return None
    closing = "]" if token.value == "[" else "}"
    cursor = index + 1
    if _is(tokens, cursor, "punctuation", closing):
        return cursor + 1
    while cursor < len(tokens):
        if token.value == "{":
            if not _is(tokens, cursor, "name"):
                return None
            cursor += 1
            if not _is(tokens, cursor, "punctuation", ":"):
                return None
            cursor += 1
        value_end = _parse_value(tokens, cursor, depth + 1)
        if value_end is None:
            return None
        cursor = value_end
        if _is(tokens, cursor, "punctuation", ","):
            cursor += 1
            if _is(tokens, cursor, "punctuation", closing):
                return None
        if _is(tokens, cursor, "punctuation", closing):
            cursor += 1
            if token.value == "[" and _is(tokens, cursor, "punctuation", "!"):
                cursor += 1
            return cursor
        # Commas are optional in GraphQL, so adjacent values/object fields are
        # accepted when the next token starts another value or object field.
    return None


def _validate_argument_tokens(tokens: tuple[_Token, ...]) -> bool:
    if not tokens:
        return False
    cursor = 0
    while cursor < len(tokens):
        if not _is(tokens, cursor, "name") and not _is(tokens, cursor, "variable"):
            return False
        key_kind = tokens[cursor].kind
        cursor += 1
        if not _is(tokens, cursor, "punctuation", ":"):
            return False
        cursor += 1
        value_end = _parse_value(tokens, cursor)
        if value_end is None:
            return False
        cursor = value_end
        if key_kind == "variable" and _is(tokens, cursor, "punctuation", "="):
            cursor += 1
            default_end = _parse_value(tokens, cursor)
            if default_end is None:
                return False
            cursor = default_end
        if cursor == len(tokens):
            return True
        if _is(tokens, cursor, "punctuation", ","):
            cursor += 1
            if cursor == len(tokens):
                return True
    return cursor == len(tokens)


def _variables(tokens: tuple[_Token, ...]) -> frozenset[str]:
    return frozenset(token.value for token in tokens if token.kind == "variable")


def _skip_directives(tokens: tuple[_Token, ...], index: int) -> int | None:
    cursor = index
    while _is(tokens, cursor, "punctuation", "@"):
        cursor += 1
        if not _is(tokens, cursor, "name"):
            return None
        cursor += 1
        if _is(tokens, cursor, "punctuation", "("):
            consumed = _consume_balanced(tokens, cursor, "(", ")")
            if consumed is None:
                return None
            _, cursor = consumed
    return cursor


def _skip_spread(tokens: tuple[_Token, ...], index: int, depth: int = 0) -> int | None:
    """Consume a fragment spread or inline fragment without retaining its names."""

    cursor = index + 1
    if _is(tokens, cursor, "name", "on"):
        cursor += 1
        if not _is(tokens, cursor, "name"):
            return None
        cursor += 1
    elif _is(tokens, cursor, "name"):
        cursor += 1
    next_cursor = _skip_directives(tokens, cursor)
    if next_cursor is None:
        return None
    cursor = next_cursor
    if _is(tokens, cursor, "punctuation", "{"):
        parsed = _parse_selection_set(tokens, cursor, depth + 1)
        if parsed is None:
            return None
        _, _, cursor = parsed
    return cursor


def _parse_selection_set(
    tokens: tuple[_Token, ...], index: int, depth: int = 0
) -> tuple[frozenset[str], frozenset[str], int] | None:
    if depth > _MAX_PARSE_DEPTH or not _is(tokens, index, "punctuation", "{"):
        return None
    cursor = index + 1
    selected: set[str] = set()
    returning: set[str] = set()
    while cursor < len(tokens) and not _is(tokens, cursor, "punctuation", "}"):
        if _is(tokens, cursor, "punctuation", ","):
            cursor += 1
            continue
        if _is(tokens, cursor, "punctuation", "..."):
            next_cursor = _skip_spread(tokens, cursor, depth)
            if next_cursor is None:
                return None
            cursor = next_cursor
            continue
        if not _is(tokens, cursor, "name"):
            return None
        field_name = tokens[cursor].value
        cursor += 1
        if _is(tokens, cursor, "punctuation", ":"):
            cursor += 1
            if not _is(tokens, cursor, "name"):
                return None
            field_name = tokens[cursor].value
            cursor += 1
        if _is(tokens, cursor, "punctuation", "("):
            consumed = _consume_balanced(tokens, cursor, "(", ")")
            if consumed is None:
                return None
            _, cursor = consumed
        next_cursor = _skip_directives(tokens, cursor)
        if next_cursor is None:
            return None
        cursor = next_cursor
        child_fields: frozenset[str] = frozenset()
        if _is(tokens, cursor, "punctuation", "{"):
            parsed = _parse_selection_set(tokens, cursor, depth + 1)
            if parsed is None:
                return None
            child_fields, _, cursor = parsed
        selected.add(field_name)
        if field_name == "returning":
            returning.update(child_fields)
    if not _is(tokens, cursor, "punctuation", "}"):
        return None
    return frozenset(selected), frozenset(returning), cursor + 1


def _parse_root_selection_set(
    tokens: tuple[_Token, ...], index: int
) -> tuple[tuple[_RootSelection, ...], int] | None:
    if not _is(tokens, index, "punctuation", "{"):
        return None
    cursor = index + 1
    roots: list[_RootSelection] = []
    while cursor < len(tokens) and not _is(tokens, cursor, "punctuation", "}"):
        if _is(tokens, cursor, "punctuation", ","):
            cursor += 1
            continue
        if _is(tokens, cursor, "punctuation", "..."):
            next_cursor = _skip_spread(tokens, cursor)
            if next_cursor is None:
                return None
            cursor = next_cursor
            continue
        if not _is(tokens, cursor, "name"):
            return None
        field_name = tokens[cursor].value
        cursor += 1
        if _is(tokens, cursor, "punctuation", ":"):
            cursor += 1
            if not _is(tokens, cursor, "name"):
                return None
            field_name = tokens[cursor].value
            cursor += 1
        variables: frozenset[str] = frozenset()
        if _is(tokens, cursor, "punctuation", "("):
            consumed = _consume_balanced(tokens, cursor, "(", ")")
            if consumed is None:
                return None
            argument_tokens, cursor = consumed
            variables = _variables(argument_tokens)
        next_cursor = _skip_directives(tokens, cursor)
        if next_cursor is None:
            return None
        cursor = next_cursor
        selected_fields: frozenset[str] = frozenset()
        returning_fields: frozenset[str] = frozenset()
        if _is(tokens, cursor, "punctuation", "{"):
            parsed_selection = _parse_selection_set(tokens, cursor)
            if parsed_selection is None:
                return None
            selected_fields, returning_fields, cursor = parsed_selection
        roots.append(
            _RootSelection(
                field_name=field_name,
                variable_names=variables,
                selected_fields=selected_fields,
                mutation_returning_fields=returning_fields,
            )
        )
    if not _is(tokens, cursor, "punctuation", "}") or not roots:
        return None
    return tuple(roots), cursor + 1


def _parse_operation(document: str) -> _ParsedOperation | None:
    tokens = _lex(document)
    if not tokens or not _is(tokens, 0, "name"):
        return None
    operation_name = tokens[0].value
    if operation_name not in {"query", "mutation"}:
        return None
    operation_kind = cast(Literal["query", "mutation"], operation_name)
    cursor = 1
    if _is(tokens, cursor, "name"):
        cursor += 1
    if _is(tokens, cursor, "punctuation", "("):
        consumed = _consume_balanced(tokens, cursor, "(", ")")
        if consumed is None:
            return None
        _, cursor = consumed
    next_cursor = _skip_directives(tokens, cursor)
    if next_cursor is None:
        return None
    cursor = next_cursor
    parsed = _parse_root_selection_set(tokens, cursor)
    if parsed is None:
        return None
    roots, cursor = parsed

    # Fragment definitions may follow an operation.  They are intentionally not
    # expanded: only direct fields in the captured operation are safe to report.
    while cursor < len(tokens):
        if not _is(tokens, cursor, "name", "fragment"):
            return None
        cursor += 1
        if not _is(tokens, cursor, "name"):
            return None
        cursor += 1
        if not _is(tokens, cursor, "name", "on"):
            return None
        cursor += 1
        if not _is(tokens, cursor, "name"):
            return None
        cursor += 1
        next_cursor = _skip_directives(tokens, cursor)
        if next_cursor is None:
            return None
        cursor = next_cursor
        fragment_selection = _parse_selection_set(tokens, cursor)
        if fragment_selection is None:
            return None
        _, _, cursor = fragment_selection
    if all(root.field_name.startswith("__") for root in roots):
        return None
    return _ParsedOperation(operation_kind=operation_kind, roots=roots)


_ROOT_SUFFIXES = ("_by_pk", "_aggregate", "_stream")
_MUTATION_PREFIXES = ("insert_", "update_", "delete_")


def _resource_name(root_field: str) -> str | None:
    if root_field.startswith("__"):
        return None
    for prefix in _MUTATION_PREFIXES:
        if root_field.startswith(prefix):
            root_field = root_field[len(prefix) :]
            break
    for suffix in _ROOT_SUFFIXES:
        if root_field.endswith(suffix):
            root_field = root_field[: -len(suffix)]
            break
    return root_field if re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", root_field) else None


_HASURA_HEADER_NAMES = frozenset({"x-hasura-role", "x-hasura-admin-secret"})
_GRAPHQL_PATHS = frozenset({"/graphql", "/v1/graphql"})
_REDACTED = "[REDACTED]"
_NON_SINGLE_RECORD_OPERATORS = frozenset(
    {
        "_in",
        "_nin",
        "in",
        "nin",
        "gt",
        "gte",
        "lt",
        "lte",
        "like",
        "ilike",
        "regex",
        "_gt",
        "_gte",
        "_lt",
        "_lte",
        "_like",
        "_ilike",
        "_regex",
    }
)


def _origin(url: str) -> str | None:
    """Return a normalized origin, omitting userinfo and preserving explicit ports."""

    try:
        split = urlsplit(url)
        hostname = split.hostname
        if not split.scheme or hostname is None:
            return None
        port = split.port
    except ValueError:
        return None
    port_suffix = f":{port}" if port is not None else ""
    return f"{split.scheme.casefold()}://{hostname.casefold()}{port_suffix}"


def _request_json(view: AdapterRecordView) -> Mapping[str, object] | None:
    body = view.request_body
    if body is None:
        return None
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(decoded, Mapping):
        return None
    if not all(isinstance(key, str) for key in decoded):
        return None
    return decoded


def _graphql_document(view: AdapterRecordView) -> str | None:
    payload = _request_json(view)
    if payload is None:
        return None
    query = payload.get("query")
    if not isinstance(query, str) or query == _REDACTED:
        return None
    return query


def _has_hasura_header(headers: Mapping[str, str]) -> bool:
    return any(name.casefold() in _HASURA_HEADER_NAMES for name in headers)


def _is_graphql_payload(view: AdapterRecordView) -> bool:
    document = _graphql_document(view)
    return document is not None and _parse_operation(document) is not None


def _record_ids_for_variable(name: str, value: object) -> set[str]:
    """Return safe, single-record IDs referenced by one GraphQL variable.

    Hasura boolean-expression variables may contain many values that look like
    identifiers but do not identify one observed record (membership, ranges,
    pattern filters, and nested arbitrary input).  Only ID-named scalar fields
    and equality values directly below an ID-named field are eligible.
    """

    if _is_sensitive_field(name):
        return set()

    record_ids: set[str] = set()

    def walk(current: object, parent_key: str | None = None) -> None:
        if isinstance(current, Mapping):
            for raw_key, child in current.items():
                if not isinstance(raw_key, str):
                    continue
                key = raw_key
                if _is_sensitive_field(key):
                    continue
                if key.casefold() in _NON_SINGLE_RECORD_OPERATORS:
                    continue
                if isinstance(child, (str, int)) and not isinstance(child, bool):
                    candidate = str(child)
                    is_id_value = _id_field(key) and is_object_id(candidate)
                    is_id_equality = (
                        key == "_eq"
                        and parent_key is not None
                        and _id_field(parent_key)
                        and is_object_id(candidate)
                    )
                    if is_id_value or is_id_equality:
                        record_ids.add(candidate)
                    continue
                walk(child, key)
            return
        if isinstance(current, list):
            for child in current:
                walk(child, parent_key)

    if isinstance(value, (str, int)) and not isinstance(value, bool):
        candidate = str(value)
        if _id_field(name) and is_object_id(candidate):
            record_ids.add(candidate)
    else:
        walk(value)
    return record_ids


class HasuraAdapter:
    """Read-only Hasura GraphQL discovery adapter."""

    name = "hasura"

    def __init__(self, registry: InMemorySessionValueRegistry) -> None:
        self._registry = registry

    def detect(self, records: Sequence[AdapterRecordView]) -> ProviderDetection:
        inferred = False
        for view in records:
            record = adapter_record(view)
            try:
                path = urlsplit(record.url).path
            except ValueError:
                path = ""
            graphql_payload = _is_graphql_payload(view)
            if graphql_payload and _has_hasura_header(record.headers):
                return ProviderDetection(
                    provider=self.name,
                    confidence=ProviderConfidence.CONFIRMED,
                )
            if graphql_payload or path in _GRAPHQL_PATHS:
                inferred = True
        confidence = ProviderConfidence.INFERRED if inferred else ProviderConfidence.UNKNOWN
        return ProviderDetection(provider=self.name, confidence=confidence)

    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]:
        by_origin: dict[str, list[AdapterRecordView]] = {}
        for view in records:
            origin = _origin(adapter_record(view).url)
            if origin is not None:
                by_origin.setdefault(origin, []).append(view)

        groups: dict[tuple[str, str, str], list[AdapterRecordView]] = {}
        for origin, origin_records in sorted(by_origin.items()):
            if self.detect(origin_records).confidence is not ProviderConfidence.CONFIRMED:
                continue
            for view in origin_records:
                document = _graphql_document(view)
                if document is None:
                    continue
                parsed = _parse_operation(document)
                if parsed is None:
                    continue
                try:
                    path = urlsplit(adapter_record(view).url).path
                except ValueError:
                    continue
                for root in parsed.roots:
                    resource_name = _resource_name(root.field_name)
                    if resource_name is None:
                        continue
                    groups.setdefault((origin, path, resource_name), []).append(view)

        inventories: list[ResourceInventory] = []
        for origin, path, resource_name in sorted(groups):
            group = groups[(origin, path, resource_name)]
            confidence = self.detect(group).confidence
            field_names: set[str] = set()
            object_ids: set[str] = set()
            for view in group:
                document = _graphql_document(view)
                if document is None:
                    continue
                parsed = _parse_operation(document)
                if parsed is None:
                    continue
                payload = _request_json(view)
                variables = payload.get("variables") if payload is not None else None
                for root in parsed.roots:
                    if _resource_name(root.field_name) != resource_name:
                        continue
                    selected = (
                        root.mutation_returning_fields
                        if parsed.operation_kind == "mutation"
                        else root.selected_fields
                    )
                    field_names.update(
                        field
                        for field in selected
                        if re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", field)
                    )
                    if isinstance(variables, Mapping):
                        for variable_name in root.variable_names:
                            if variable_name not in variables:
                                continue
                            object_ids.update(
                                _record_ids_for_variable(
                                    variable_name, variables[variable_name]
                                )
                            )
            methods = frozenset(adapter_record(view).method.upper() for view in group)
            record_handles = tuple(
                self._registry.store_value(kind="record_id", value=object_id)
                for object_id in sorted(object_ids)
            )
            inventories.append(
                ResourceInventory(
                    provider=self.name,
                    provider_confidence=confidence,
                    resource_name=resource_name,
                    endpoint_template=path or "/",
                    fields=tuple(FieldInventory(name=name) for name in sorted(field_names)),
                    record_handles=record_handles,
                    observed_methods=methods,
                )
            )
        return tuple(inventories)


if TYPE_CHECKING:

    def _hasura_adapter_satisfies_provider_adapter(
        registry: InMemorySessionValueRegistry,
    ) -> ProviderAdapter:
        return HasuraAdapter(registry)
