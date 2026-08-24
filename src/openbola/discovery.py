"""Provider-agnostic and provider-specific resource inventory contracts.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Adapters consume already-captured ``RequestRecord`` evidence and never send
a request themselves. Every field this module reports comes from data
``RequestRecord`` already carries; it never assumes richer fidelity than
that (see the roadmap's P4 entry for why field *value types* are
deliberately not part of ``FieldInventory``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from openbola.endpoints import extract_object_ids, templatize
from openbola.handles import InMemorySessionValueRegistry, ValueHandle
from openbola.models import RequestRecord


class ProviderConfidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FieldInventory:
    name: str


@dataclass(frozen=True)
class ResourceInventory:
    provider: str
    provider_confidence: ProviderConfidence
    resource_name: str
    endpoint_template: str
    fields: tuple[FieldInventory, ...]
    record_handles: tuple[ValueHandle, ...]
    observed_methods: frozenset[str]


@dataclass(frozen=True)
class ProviderDetection:
    provider: str
    confidence: ProviderConfidence


class ProviderAdapter(Protocol):
    name: str

    def detect(self, records: Sequence[RequestRecord]) -> ProviderDetection: ...
    def inventory(self, records: Sequence[RequestRecord]) -> tuple[ResourceInventory, ...]: ...


class GenericAdapter:
    """Always-present fallback: groups traffic by templatized endpoint."""

    name = "generic"

    def __init__(self, registry: InMemorySessionValueRegistry) -> None:
        self._registry = registry

    def detect(self, records: Sequence[RequestRecord]) -> ProviderDetection:
        del records
        return ProviderDetection(provider="generic", confidence=ProviderConfidence.UNKNOWN)

    def inventory(self, records: Sequence[RequestRecord]) -> tuple[ResourceInventory, ...]:
        groups: dict[str, list[RequestRecord]] = {}
        for record in records:
            template = templatize(record.url)
            groups.setdefault(template, []).append(record)

        inventories: list[ResourceInventory] = []
        for template in sorted(groups):
            group = groups[template]
            methods = frozenset(record.method for record in group)

            field_names: set[str] = set()
            object_ids: set[str] = set()
            for record in group:
                field_names.update(_top_level_json_keys(record.body))
                field_names.update(_top_level_json_keys(record.response_body))
                object_ids.update(extract_object_ids(record.url))

            fields = tuple(FieldInventory(name=name) for name in sorted(field_names))
            record_handles = tuple(
                self._registry.store_value(kind="record_id", value=object_id)
                for object_id in sorted(object_ids)
            )
            inventories.append(
                ResourceInventory(
                    provider="generic",
                    provider_confidence=ProviderConfidence.UNKNOWN,
                    resource_name=_resource_name_from_template(template),
                    endpoint_template=template,
                    fields=fields,
                    record_handles=record_handles,
                    observed_methods=methods,
                )
            )
        return tuple(inventories)


def _top_level_json_keys(body: bytes | None) -> set[str]:
    if body is None:
        return set()
    try:
        decoded: Any = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return set()
    if isinstance(decoded, Mapping):
        return {key for key in decoded if isinstance(key, str)}
    if isinstance(decoded, list):
        keys: set[str] = set()
        for item in decoded:
            if isinstance(item, Mapping):
                keys.update(key for key in item if isinstance(key, str))
        return keys
    return set()


def _resource_name_from_template(template: str) -> str:
    segments = [
        segment for segment in template.split("/") if segment and not segment.startswith("{id")
    ]
    return segments[-1] if segments else "root"
