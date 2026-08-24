"""Bounded GraphQL parsing contracts for the Hasura provider adapter.

The parser in this module is deliberately smaller than a GraphQL implementation.  It
only keeps names and punctuation needed to identify top-level resources and selected
fields; string and numeric literal contents are discarded while lexing.  This keeps
captured documents out of provider-owned state and makes malformed input fail closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, cast


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
        if character.isspace() or character == ",":
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
            tokens.append(_Token("literal"))
            index = number.end()
            continue
        if character in _PUNCTUATION:
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
    depth = 1
    cursor = index + 1
    start = cursor
    while cursor < len(tokens):
        if _is(tokens, cursor, "punctuation", opening):
            depth += 1
        elif _is(tokens, cursor, "punctuation", closing):
            depth -= 1
            if depth == 0:
                return tokens[start:cursor], cursor + 1
        cursor += 1
    return None


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


def _skip_spread(tokens: tuple[_Token, ...], index: int) -> int | None:
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
        parsed = _parse_selection_set(tokens, cursor)
        if parsed is None:
            return None
        _, _, cursor = parsed
    return cursor


def _parse_selection_set(
    tokens: tuple[_Token, ...], index: int
) -> tuple[frozenset[str], frozenset[str], int] | None:
    if not _is(tokens, index, "punctuation", "{"):
        return None
    cursor = index + 1
    selected: set[str] = set()
    returning: set[str] = set()
    while cursor < len(tokens) and not _is(tokens, cursor, "punctuation", "}"):
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
            parsed = _parse_selection_set(tokens, cursor)
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
