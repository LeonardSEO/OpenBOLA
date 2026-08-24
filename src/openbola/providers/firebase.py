"""Firebase Realtime Database provider adapter.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Firebase Realtime Database (RTDB) REST calls always end their path in
``.json`` and embed record IDs directly in the path (unlike PostgREST's
query-string ``eq.`` filters, see ``providers/supabase.py``) -- e.g.
``/messages/-NqA1bC2dEfGhIjKlMn.json``. This adapter strips the mandatory
``.json`` suffix, then reuses ``endpoints.templatize``/``extract_object_ids``
unchanged, since Firebase's push-ID format is already recognised by
``endpoints.is_object_id``. RTDB "list" nodes return a JSON object keyed by
each child's push ID (e.g. ``{"-NqA...": {...}, "-NqB...": {...}}``) --
the same "JSON keys can themselves be record IDs" case
``discovery.classify_key``/``top_level_json_keys`` already handle, reused
here unchanged. v1 scope covers Realtime Database only; Firestore's REST
API is a structurally different typed-document envelope and is tracked
separately.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

from openbola.discovery import (
    FieldInventory,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
    _resource_name_from_template,
    classify_key,
    top_level_json_keys,
)
from openbola.endpoints import extract_object_ids, templatize
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord

_JSON_SUFFIX = ".json"
_RTDB_HOST_SUFFIXES = (".firebaseio.com", ".firebasedatabase.app")


def _is_rtdb_host(netloc: str) -> bool:
    host = netloc.split(":", 1)[0].lower()
    return host.endswith(_RTDB_HOST_SUFFIXES)


def _strip_json_suffix(path: str) -> str | None:
    if not path.endswith(_JSON_SUFFIX):
        return None
    return path[: -len(_JSON_SUFFIX)]


class FirebaseRealtimeDatabaseAdapter:
    """Firebase Realtime Database REST API discovery adapter."""

    name = "firebase-rtdb"

    def __init__(self, registry: InMemorySessionValueRegistry) -> None:
        self._registry = registry

    def detect(self, records: Sequence[RequestRecord]) -> ProviderDetection:
        confirmed = False
        inferred = False
        for record in records:
            split = urlsplit(record.url)
            host_match = _is_rtdb_host(split.netloc)
            json_match = split.path.endswith(_JSON_SUFFIX)
            if host_match and json_match:
                confirmed = True
                break
            if host_match or json_match:
                inferred = True
        if confirmed:
            return ProviderDetection(
                provider="firebase-rtdb", confidence=ProviderConfidence.CONFIRMED
            )
        if inferred:
            return ProviderDetection(
                provider="firebase-rtdb", confidence=ProviderConfidence.INFERRED
            )
        return ProviderDetection(provider="firebase-rtdb", confidence=ProviderConfidence.UNKNOWN)

    def inventory(self, records: Sequence[RequestRecord]) -> tuple[ResourceInventory, ...]:
        groups: dict[tuple[str, str], list[RequestRecord]] = {}
        for record in records:
            split = urlsplit(record.url)
            stripped = _strip_json_suffix(split.path)
            if stripped is None:
                continue
            template = templatize(stripped)
            origin = f"{split.scheme}://{split.netloc}"
            groups.setdefault((origin, template), []).append(record)

        inventories: list[ResourceInventory] = []
        for origin, template in sorted(groups):
            group = groups[(origin, template)]
            confidence = self.detect(group).confidence
            methods = frozenset(record.method.upper() for record in group)

            field_names: set[str] = set()
            object_ids: set[str] = set()
            for record in group:
                for key in top_level_json_keys(record.body):
                    classify_key(key, field_names, object_ids)
                for key in top_level_json_keys(record.response_body):
                    classify_key(key, field_names, object_ids)
                record_split = urlsplit(record.url)
                record_stripped = _strip_json_suffix(record_split.path)
                if record_stripped is not None:
                    object_ids.update(extract_object_ids(record_stripped))

            fields = tuple(FieldInventory(name=name) for name in sorted(field_names))
            record_handles = tuple(
                self._registry.store_value(kind="record_id", value=object_id)
                for object_id in sorted(object_ids)
            )
            inventories.append(
                ResourceInventory(
                    provider="firebase-rtdb",
                    provider_confidence=confidence,
                    resource_name=_resource_name_from_template(template),
                    endpoint_template=template,
                    fields=fields,
                    record_handles=record_handles,
                    observed_methods=methods,
                )
            )
        return tuple(inventories)
