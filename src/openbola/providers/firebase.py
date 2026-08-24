"""Firebase Realtime Database provider adapter.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Firebase Realtime Database (RTDB) REST calls always end their path in
``.json`` and embed record IDs directly in the path (unlike PostgREST's
query-string ``eq.`` filters, see ``providers/supabase.py``) -- e.g.
``/messages/-NqA1bC2dEfGhIjKlMn.json``. This adapter strips the mandatory
``.json`` suffix, then reuses ``endpoints.templatize``/``endpoints._path_ids``
(the latter gated through ``endpoints._is_sensitive_field`` on each ID's
parent path segment, so a token/secret used as a lookup key -- e.g.
``/passwordResetTokens/<token>.json``, an idiomatic RTDB pattern since RTDB
has no query-by-value -- is never minted as a probeable ``record_id``
handle). Firebase's push-ID format is already recognised by
``endpoints.is_object_id``. RTDB "list" nodes return a JSON object keyed by
each child's push ID (e.g. ``{"-NqA...": {...}, "-NqB...": {...}}``) --
the same "JSON keys can themselves be record IDs" case
``discovery.classify_key``/``top_level_json_keys`` already handle, reused
here unchanged. A successful RTDB push (``POST .../<collection>.json``)
responds with ``{"name": "<new-push-id>"}`` -- that envelope key is
recognised and routed to a handle instead of being reported as a data
field. ``inventory()`` only considers records whose host matches a known
RTDB host suffix (unlike ``detect()``, which also treats either signal
alone as weaker INFERRED evidence) -- without this gate, any unrelated
``*.json`` URL (e.g. a web app's ``manifest.json``) would be misreported
as Firebase RTDB traffic. v1 scope covers Realtime Database only;
Firestore's REST API is a structurally different typed-document envelope
and is tracked separately.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from openbola.discovery import (
    FieldInventory,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
    _resource_name_from_template,
    adapter_record,
    adapter_request_body,
    adapter_response_body,
    classify_key,
    top_level_json_keys,
)
from openbola.endpoints import _is_sensitive_field, _path_ids, is_object_id, templatize
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord

if TYPE_CHECKING:
    from openbola.capture import AdapterRecordView

_JSON_SUFFIX = ".json"
_RTDB_HOST_SUFFIXES = (".firebaseio.com", ".firebasedatabase.app")
_PUSH_ID_ENVELOPE_KEY = "name"


def _is_rtdb_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    return hostname.lower().endswith(_RTDB_HOST_SUFFIXES)


def _strip_json_suffix(path: str) -> str | None:
    if not path.endswith(_JSON_SUFFIX):
        return None
    return path[: -len(_JSON_SUFFIX)].rstrip("/") or "/"


def _non_sensitive_object_ids(path: str) -> list[str]:
    """Path-embedded object IDs, excluding those keyed under a sensitive parent segment."""
    decoded_parts = urlsplit(path).path.split("/")
    ids: list[str] = []
    for index, value in _path_ids(path):
        parent = decoded_parts[index - 1] if index > 0 else ""
        if not _is_sensitive_field(parent):
            ids.append(value)
    return ids


def _push_id_from_create_response(
    record: RequestRecord, response_body: bytes | None
) -> str | None:
    """RTDB's push-create envelope (``{"name": "<new-id>"}``) is not a data field."""
    if record.method.upper() != "POST" or response_body is None:
        return None
    try:
        decoded = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(decoded, Mapping):
        return None
    name_value = decoded.get(_PUSH_ID_ENVELOPE_KEY)
    if isinstance(name_value, str) and is_object_id(name_value):
        return name_value
    return None


class FirebaseRealtimeDatabaseAdapter:
    """Firebase Realtime Database REST API discovery adapter."""

    name = "firebase-rtdb"

    def __init__(self, registry: InMemorySessionValueRegistry) -> None:
        self._registry = registry

    def detect(self, records: Sequence[AdapterRecordView]) -> ProviderDetection:
        confirmed = False
        inferred = False
        for view in records:
            record = adapter_record(view)
            split = urlsplit(record.url)
            host_match = _is_rtdb_host(split.hostname)
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

    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]:
        groups: dict[tuple[str, str], list[AdapterRecordView]] = {}
        for view in records:
            record = adapter_record(view)
            split = urlsplit(record.url)
            if not _is_rtdb_host(split.hostname):
                continue
            stripped = _strip_json_suffix(split.path)
            if stripped is None:
                continue
            template = templatize(stripped)
            port_suffix = f":{split.port}" if split.port else ""
            origin = f"{split.scheme}://{split.hostname}{port_suffix}"
            groups.setdefault((origin, template), []).append(view)

        inventories: list[ResourceInventory] = []
        for origin, template in sorted(groups):
            group = groups[(origin, template)]
            confidence = self.detect(group).confidence
            methods = frozenset(adapter_record(view).method.upper() for view in group)

            field_names: set[str] = set()
            object_ids: set[str] = set()
            for member in group:
                record = adapter_record(member)
                for key in top_level_json_keys(adapter_request_body(member)):
                    classify_key(key, field_names, object_ids)

                response_body = adapter_response_body(member)
                push_id = _push_id_from_create_response(record, response_body)
                if push_id is not None:
                    object_ids.add(push_id)
                for key in top_level_json_keys(response_body):
                    if push_id is not None and key == _PUSH_ID_ENVELOPE_KEY:
                        continue
                    classify_key(key, field_names, object_ids)

                record_split = urlsplit(record.url)
                record_stripped = _strip_json_suffix(record_split.path)
                if record_stripped is not None:
                    object_ids.update(_non_sensitive_object_ids(record_stripped))

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


if TYPE_CHECKING:

    def _firebase_rtdb_adapter_satisfies_provider_adapter(
        registry: InMemorySessionValueRegistry,
    ) -> ProviderAdapter:
        """Static-only check: mypy fails here if FirebaseRealtimeDatabaseAdapter drifts from
        the Protocol.
        """
        return FirebaseRealtimeDatabaseAdapter(registry)
