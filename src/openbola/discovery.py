"""Provider-agnostic and provider-specific resource inventory contracts.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Adapters consume already-captured ``RequestRecord`` evidence and never send
a request themselves. Every field this module reports comes from data
``RequestRecord`` already carries; it never assumes richer fidelity than
that (see the roadmap's P4 entry for why field *value types* are
deliberately not part of ``FieldInventory``). Object-ID-shaped JSON keys
(e.g. Firebase-style ``{"uid_...": {...}}`` maps) are routed to
``record_handles`` rather than ``fields`` for the same reason path-embedded
IDs are: raw IDs never appear in persisted state, reports, or AI context —
only opaque handles do.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from openbola.endpoints import _walk_json_ids, extract_object_ids, is_object_id, templatize
from openbola.handles import InMemorySessionValueRegistry, ValueHandle
from openbola.models import RequestRecord

if TYPE_CHECKING:
    from openbola.capture import AdapterRecordView


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
    @property
    def name(self) -> str: ...

    def detect(self, records: Sequence[AdapterRecordView]) -> ProviderDetection: ...
    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]: ...


def adapter_record(view: AdapterRecordView | RequestRecord) -> RequestRecord:
    """Return the sanitized record carried by an ephemeral adapter view.

    RequestRecord input remains accepted at runtime for compatibility with the
    pre-session discovery callers. New capture-to-provider paths pass only
    ``AdapterRecordView`` values, whose raw bodies are deliberately handled by
    the owning adapter rather than copied into the persistent record.
    """
    if isinstance(view, RequestRecord):
        return view
    return view.record


def adapter_request_body(view: AdapterRecordView | RequestRecord) -> bytes | None:
    if isinstance(view, RequestRecord):
        return view.body
    return view.request_body


def adapter_response_body(view: AdapterRecordView | RequestRecord) -> bytes | None:
    if isinstance(view, RequestRecord):
        return view.response_body
    return view.response_body


class GenericAdapter:
    """Always-present fallback: groups traffic by templatized endpoint."""

    name = "generic"

    def __init__(self, registry: InMemorySessionValueRegistry) -> None:
        self._registry = registry

    def detect(self, records: Sequence[AdapterRecordView]) -> ProviderDetection:
        del records
        return ProviderDetection(provider="generic", confidence=ProviderConfidence.UNKNOWN)

    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]:
        groups: dict[tuple[str, str], list[AdapterRecordView | RequestRecord]] = {}
        for candidate in records:
            record = adapter_record(candidate)
            split = urlsplit(record.url)
            origin = f"{split.scheme}://{split.netloc}"
            template = templatize(record.url)
            groups.setdefault((origin, template), []).append(candidate)

        inventories: list[ResourceInventory] = []
        for origin, template in sorted(groups):
            group = groups[(origin, template)]
            methods = frozenset(adapter_record(view).method.upper() for view in group)

            field_names: set[str] = set()
            object_ids: set[str] = set()
            for member in group:
                record = adapter_record(member)
                request_body = adapter_request_body(member)
                response_body = adapter_response_body(member)
                for key in top_level_json_keys(request_body):
                    classify_key(key, field_names, object_ids)
                for key in top_level_json_keys(response_body):
                    classify_key(key, field_names, object_ids)
                if not isinstance(member, RequestRecord):
                    object_ids.update(_body_object_ids(request_body))
                    object_ids.update(_body_object_ids(response_body))
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


if TYPE_CHECKING:

    def _generic_adapter_satisfies_provider_adapter(
        registry: InMemorySessionValueRegistry,
    ) -> ProviderAdapter:
        """Static-only check: mypy fails here if GenericAdapter drifts from the Protocol."""
        return GenericAdapter(registry)


def classify_key(key: str, field_names: set[str], object_ids: set[str]) -> None:
    """Route object-ID-shaped or email-shaped JSON keys to handles, not field names."""
    if "@" in key or is_object_id(key):
        object_ids.add(key)
    else:
        field_names.add(key)


def top_level_json_keys(body: bytes | None) -> set[str]:
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


def _body_object_ids(body: bytes | None) -> set[str]:
    if body is None:
        return set()
    try:
        decoded: Any = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return set()
    return {value for value, _field, _pointer in _walk_json_ids(decoded)}


def _resource_name_from_template(template: str) -> str:
    segments = [
        segment for segment in template.split("/") if segment and not segment.startswith("{id")
    ]
    return segments[-1] if segments else "root"
