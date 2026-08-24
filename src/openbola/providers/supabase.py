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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from openbola.discovery import (
    FieldInventory,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
    classify_key,
    top_level_json_keys,
)
from openbola.endpoints import is_object_id
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord

_REST_PREFIX = "/rest/v1/"
_EQ_OPERATOR = "eq."
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
    return remainder.split("/")[0]


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

    def detect(self, records: Sequence[RequestRecord]) -> ProviderDetection:
        confirmed = False
        inferred = False
        for record in records:
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

    def inventory(self, records: Sequence[RequestRecord]) -> tuple[ResourceInventory, ...]:
        groups: dict[tuple[str, str], list[RequestRecord]] = {}
        for record in records:
            split = urlsplit(record.url)
            if not _is_rest_path(split.path):
                continue
            table = _table_name(split.path)
            if table is None:
                continue
            origin = f"{split.scheme}://{split.netloc}"
            groups.setdefault((origin, table), []).append(record)

        confidence = self.detect(records).confidence

        inventories: list[ResourceInventory] = []
        for origin, table in sorted(groups):
            group = groups[(origin, table)]
            methods = frozenset(record.method.upper() for record in group)

            field_names: set[str] = set()
            object_ids: set[str] = set()
            for record in group:
                for key in top_level_json_keys(record.body):
                    classify_key(key, field_names, object_ids)
                for key in top_level_json_keys(record.response_body):
                    classify_key(key, field_names, object_ids)
                query = urlsplit(record.url).query
                for _, value in parse_qsl(query, keep_blank_values=True):
                    if value.startswith(_EQ_OPERATOR):
                        candidate = value[len(_EQ_OPERATOR) :]
                        if is_object_id(candidate):
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
