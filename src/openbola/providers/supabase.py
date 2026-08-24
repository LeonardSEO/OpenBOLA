"""Supabase/PostgREST provider adapter.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Unlike generic REST APIs, PostgREST (the engine Supabase's REST API wraps)
never embeds a record ID in the URL path -- filtering happens entirely
through query-string operators, e.g. ``?id=eq.<uuid>``. Record-ID
extraction here reads the query string's ``eq.`` (equality) filters
instead of ``openbola.endpoints.extract_object_ids`` (path-only, and
inapplicable here since PostgREST paths never carry one). Only ``eq.`` is
used for extraction in v1 -- range/membership operators (``gt.``, ``in.``,
``like.``, ...) don't identify a single record and are out of scope.
Sensitive-named filter parameters (``token``, ``secret``, ``apikey``, ...)
are never treated as record IDs even when their value is opaque-ID-shaped,
matching ``endpoints.py``'s own guard for the structurally identical
query-ID case. RPC calls (``POST /rest/v1/rpc/<function>``) are grouped
per function name, not collapsed together -- each function gets its own
``ResourceInventory`` with a real, callable ``endpoint_template``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlsplit

from openbola.discovery import (
    FieldInventory,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
    adapter_record,
    adapter_request_body,
    adapter_response_body,
    classify_key,
    top_level_json_keys,
)
from openbola.endpoints import _is_sensitive_field, is_object_id
from openbola.handles import InMemorySessionValueRegistry

if TYPE_CHECKING:
    from openbola.capture import AdapterRecordView

_REST_PREFIX = "/rest/v1/"
_EQ_OPERATOR = "eq."
_RPC_SEGMENT = "rpc"
# Detection-only: a broader operator vocabulary raises INFERRED confidence
# for plain self-hosted PostgREST deployments. Record-ID *extraction*
# (below, in inventory()) uses only _EQ_OPERATOR, never this tuple.
_POSTGREST_OPERATORS = (
    "eq.",
    "neq.",
    "gt.",
    "gte.",
    "lt.",
    "lte.",
    "like.",
    "ilike.",
    "in.",
    "is.",
    "not.",
)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _is_rest_path(path: str) -> bool:
    return _REST_PREFIX in path


def _table_name(path: str) -> str | None:
    idx = path.find(_REST_PREFIX)
    if idx == -1:
        return None
    remainder = path[idx + len(_REST_PREFIX) :].strip("/")
    if not remainder:
        return None
    segments = remainder.split("/")
    if segments[0] == _RPC_SEGMENT and len(segments) > 1 and segments[1]:
        return f"{_RPC_SEGMENT}/{segments[1]}"
    return segments[0]


def _has_postgrest_operator(query: str) -> bool:
    for _, value in parse_qsl(query, keep_blank_values=True):
        if value.startswith(_POSTGREST_OPERATORS):
            return True
    return False


class SupabaseAdapter:
    """Supabase/PostgREST REST API discovery adapter."""

    name = "supabase"

    def __init__(self, registry: InMemorySessionValueRegistry) -> None:
        self._registry = registry

    def detect(self, records: Sequence[AdapterRecordView]) -> ProviderDetection:
        confirmed = False
        inferred = False
        for view in records:
            record = adapter_record(view)
            split = urlsplit(record.url)
            if not _is_rest_path(split.path):
                if _has_postgrest_operator(split.query):
                    inferred = True
                continue
            if _header(record.headers, "apikey") is not None:
                confirmed = True
                break
            inferred = True
        if confirmed:
            return ProviderDetection(provider="supabase", confidence=ProviderConfidence.CONFIRMED)
        if inferred:
            return ProviderDetection(provider="supabase", confidence=ProviderConfidence.INFERRED)
        return ProviderDetection(provider="supabase", confidence=ProviderConfidence.UNKNOWN)

    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]:
        groups: dict[tuple[str, str], list[AdapterRecordView]] = {}
        for view in records:
            record = adapter_record(view)
            split = urlsplit(record.url)
            if not _is_rest_path(split.path):
                continue
            table = _table_name(split.path)
            if table is None:
                continue
            origin = f"{split.scheme}://{split.netloc}"
            groups.setdefault((origin, table), []).append(view)

        inventories: list[ResourceInventory] = []
        for origin, table in sorted(groups):
            group = groups[(origin, table)]
            confidence = self.detect(group).confidence
            methods = frozenset(adapter_record(view).method.upper() for view in group)

            field_names: set[str] = set()
            object_ids: set[str] = set()
            for member in group:
                record = adapter_record(member)
                for key in top_level_json_keys(adapter_request_body(member)):
                    classify_key(key, field_names, object_ids)
                for key in top_level_json_keys(adapter_response_body(member)):
                    classify_key(key, field_names, object_ids)
                query = urlsplit(record.url).query
                for param_name, value in parse_qsl(query, keep_blank_values=True):
                    if value.startswith(_EQ_OPERATOR):
                        candidate = value[len(_EQ_OPERATOR) :]
                        if not _is_sensitive_field(param_name) and is_object_id(candidate):
                            object_ids.add(candidate)

            fields = tuple(FieldInventory(name=name) for name in sorted(field_names))
            record_handles = tuple(
                self._registry.store_value(kind="record_id", value=object_id)
                for object_id in sorted(object_ids)
            )
            inventories.append(
                ResourceInventory(
                    provider="supabase",
                    provider_confidence=confidence,
                    resource_name=table,
                    endpoint_template=f"{_REST_PREFIX}{table}",
                    fields=fields,
                    record_handles=record_handles,
                    observed_methods=methods,
                )
            )
        return tuple(inventories)


if TYPE_CHECKING:

    def _supabase_adapter_satisfies_provider_adapter(
        registry: InMemorySessionValueRegistry,
    ) -> ProviderAdapter:
        """Static-only check: mypy fails here if SupabaseAdapter drifts from the Protocol."""
        return SupabaseAdapter(registry)
