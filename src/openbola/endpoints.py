"""Deterministic endpoint discovery and evidence-based ownership correlation.

This module only derives typed candidates and ownership evidence from captured
traffic. It deliberately has no HTTP client and never turns requester-only
observations into executable probe targets.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import parse_qsl, unquote, urlsplit

from openbola.models import (
    OwnershipConfidence,
    OwnershipConflictError,
    OwnershipEvidence,
    RequestRecord,
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_MONGO_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
_INTEGER_RE = re.compile(r"^\d+$")
_ID_FIELD_RE = re.compile(r"^(?:id|.*(?:[_-]id|Id|ID))$")
_OWNER_FIELD_RE = re.compile(r"^(?:owner|user|account|created_by)(?:[_-]?id)?$", re.IGNORECASE)
_CREATE_METHOD = "POST"
_SENSITIVE_FIELD_PARTS = (
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "cookie",
    "session",
    "credential",
    "bearer",
    "privatekey",
)


class CandidateLocation(StrEnum):
    """Where an object identifier was observed in a request."""

    PATH = "path"
    QUERY = "query"
    JSON_BODY = "json_body"
    GRAPHQL_VARIABLE = "graphql_variable"


@dataclass(frozen=True)
class EndpointCandidate:
    """A discovered object identifier; discovery alone does not authorize a probe."""

    endpoint_template: str
    method: str
    object_id: str
    location: CandidateLocation
    id_field: str
    locator: str


@dataclass(frozen=True)
class OwnershipConflict:
    """Strong persisted evidence that contradicts a candidate ownership relation."""

    candidate: OwnershipEvidence
    existing: tuple[OwnershipEvidence, ...]


@dataclass(frozen=True)
class OwnershipPersistenceResult:
    """Auditable outcome of persisting ownership evidence for later phases."""

    persisted: tuple[OwnershipEvidence, ...]
    conflicts: tuple[OwnershipConflict, ...]


def _decoded_segment(part: str) -> str:
    """Decode one path segment without making an encoded slash structural."""

    return unquote(part)


def _is_calendar_date(value: str) -> bool:
    """Recognise common date-only route values so they are not mistaken for IDs."""

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            date.fromisoformat(value)
        except ValueError:
            return False
        return True
    if re.fullmatch(r"\d{8}", value):
        try:
            date.fromisoformat(value)
        except ValueError:
            return False
        return True
    return False


def _is_standalone_year(value: str) -> bool:
    return value.isdecimal() and 1900 <= int(value) <= 2100


def _entropy(value: str) -> float:
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in map(value.count, set(value))
    )


def _is_opaque_id(value: str) -> bool:
    """Return whether *value* looks like a generated, URL-safe opaque identifier.

    Requiring both entropy and three character classes avoids turning ordinary
    route slugs into IDs while still accepting typical base64url-style values.
    """

    if not re.fullmatch(r"[A-Za-z0-9_-]{16,}", value):
        return False
    character_classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(character in "_-" for character in value),
        )
    )
    return character_classes >= 3 and _entropy(value) >= 3.5


def is_object_id(value: str) -> bool:
    """Recognise supported identifier shapes, while excluding versions and dates."""

    return (
        not _is_calendar_date(value)
        and not _is_standalone_year(value)
        and (
            _UUID_RE.fullmatch(value) is not None
            or _MONGO_OBJECT_ID_RE.fullmatch(value) is not None
            or _INTEGER_RE.fullmatch(value) is not None
            or _is_opaque_id(value)
        )
    )


def _is_version_marker(value: str) -> bool:
    return value.lower() in {"v", "version"}


def _path_ids(path: str) -> list[tuple[int, str]]:
    """Return supported path IDs, excluding numeric values under version markers."""

    decoded_parts = [_decoded_segment(part) for part in urlsplit(path).path.split("/")]
    return [
        (index, value)
        for index, value in enumerate(decoded_parts)
        if is_object_id(value)
        and not (index > 0 and _is_version_marker(decoded_parts[index - 1]) and value.isdecimal())
    ]


def templatize(path: str) -> str:
    """Replace supported ID-like path segments with stable ``{id}`` names.

    The function accepts either a path or an absolute URL. Query parameters are
    intentionally omitted: they are discovered as separate candidates.
    """

    raw_path = urlsplit(path).path
    ids_by_index = dict(_path_ids(raw_path))
    placeholders = 0
    parts: list[str] = []
    for index, raw_part in enumerate(raw_path.split("/")):
        if index in ids_by_index:
            placeholders += 1
            suffix = "" if placeholders == 1 else str(placeholders)
            parts.append(f"{{id{suffix}}}")
        else:
            # Preserve escaped delimiters and other non-ID path semantics.
            parts.append(raw_part)
    templated = "/".join(parts)
    return templated or "/"


def extract_object_ids(path: str) -> list[str]:
    """Return decoded object-ID path segments in appearance order."""

    return [value for _, value in _path_ids(path)]


def _entry_value(entry: RequestRecord | Mapping[str, Any], name: str, default: Any = None) -> Any:
    if isinstance(entry, RequestRecord):
        return getattr(entry, name, default)
    return entry.get(name, default)


def _request_body(
    entry: RequestRecord | Mapping[str, Any],
) -> bytes | str | Mapping[Any, Any] | None:
    body = _entry_value(entry, "body")
    if isinstance(body, (bytes, str, Mapping)):
        return body
    body = _entry_value(entry, "request_body")
    if isinstance(body, (bytes, str, Mapping)):
        return body
    request = _entry_value(entry, "request")
    if isinstance(request, Mapping):
        post_data = request.get("postData")
        if isinstance(post_data, Mapping):
            text = post_data.get("text")
            if isinstance(text, (bytes, str, Mapping)):
                return text
    return None


def _response_body(
    entry: RequestRecord | Mapping[str, Any],
) -> bytes | str | Mapping[Any, Any] | None:
    body = _entry_value(entry, "response_body")
    if isinstance(body, (bytes, str, Mapping)):
        return body
    response = _entry_value(entry, "response")
    if isinstance(response, Mapping):
        content = response.get("content")
        if isinstance(content, Mapping):
            text = content.get("text")
            if isinstance(text, (bytes, str, Mapping)):
                return text
    return None


def _json_value(value: bytes | str | Mapping[Any, Any] | None) -> Any | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _id_field(name: str) -> bool:
    return _ID_FIELD_RE.fullmatch(name) is not None


def _is_sensitive_field(name: str) -> bool:
    normalised = "".join(character for character in name.lower() if character.isalnum())
    return any(part in normalised for part in _SENSITIVE_FIELD_PARTS)


def _walk_json_ids(value: Any, pointer: str = "$") -> Iterable[tuple[str, str, str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if _is_sensitive_field(key_text):
                continue
            child_pointer = f"{pointer}.{key_text}"
            if _id_field(key_text) and isinstance(child, (str, int)) and is_object_id(str(child)):
                yield str(child), key_text, child_pointer
            yield from _walk_json_ids(child, child_pointer)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json_ids(child, f"{pointer}[{index}]")


def extract_endpoint_candidates(
    entry: RequestRecord | Mapping[str, Any],
) -> list[EndpointCandidate]:
    """Discover typed ID locations in one captured request without executing it."""

    url = _entry_value(entry, "url")
    if not isinstance(url, str):
        return []
    method_value = _entry_value(entry, "method", "GET")
    method = str(method_value).upper()
    parsed = urlsplit(url)
    template = templatize(parsed.path)
    candidates: list[EndpointCandidate] = []

    for index, object_id in enumerate(extract_object_ids(parsed.path), start=1):
        id_field = "id" if index == 1 else f"id{index}"
        candidates.append(
            EndpointCandidate(
                template, method, object_id, CandidateLocation.PATH, id_field, f"path:{id_field}"
            )
        )

    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not _is_sensitive_field(name) and _id_field(name) and is_object_id(value):
            candidates.append(
                EndpointCandidate(
                    template, method, value, CandidateLocation.QUERY, name, f"query:{name}"
                )
            )

    body = _json_value(_request_body(entry))
    if not isinstance(body, (Mapping, list)):
        return candidates
    variables = body.get("variables") if isinstance(body, Mapping) else None
    is_graphql = (
        isinstance(body, Mapping)
        and isinstance(body.get("query"), str)
        and isinstance(variables, Mapping)
    )
    for object_id, field, pointer in _walk_json_ids(body):
        if is_graphql and pointer.startswith("$.variables"):
            continue
        candidates.append(
            EndpointCandidate(
                template, method, object_id, CandidateLocation.JSON_BODY, field, pointer
            )
        )
    if is_graphql and isinstance(variables, Mapping):
        for object_id, field, pointer in _walk_json_ids(variables, "$.variables"):
            candidates.append(
                EndpointCandidate(
                    template,
                    method,
                    object_id,
                    CandidateLocation.GRAPHQL_VARIABLE,
                    field,
                    pointer,
                )
            )
    return candidates


def discover_endpoint_candidates(
    entries: Iterable[RequestRecord | Mapping[str, Any]],
) -> list[EndpointCandidate]:
    """Discover candidates across captures, preserving capture order."""

    return [candidate for entry in entries for candidate in extract_endpoint_candidates(entry)]


def _identity_from_hint(hint: Any, identity_by_hint: Mapping[str, str]) -> str | None:
    if not isinstance(hint, (str, int)):
        return None
    return identity_by_hint.get(str(hint))


def _identity(entry: RequestRecord | Mapping[str, Any]) -> str | None:
    identity = _entry_value(entry, "requester_identity")
    if identity is None:
        identity = _entry_value(entry, "identity")
    return identity if isinstance(identity, str) and identity else None


def _response_status(entry: RequestRecord | Mapping[str, Any]) -> int | None:
    status = _entry_value(entry, "response_status")
    if status is None:
        response = _entry_value(entry, "response")
        status = response.get("status") if isinstance(response, Mapping) else None
    return status if isinstance(status, int) else None


def _response_headers(entry: RequestRecord | Mapping[str, Any]) -> Mapping[str, str]:
    headers = _entry_value(entry, "response_headers")
    if isinstance(headers, Mapping):
        return {str(key): str(value) for key, value in headers.items()}
    response = _entry_value(entry, "response")
    headers = response.get("headers") if isinstance(response, Mapping) else None
    if isinstance(headers, Mapping):
        return {str(key): str(value) for key, value in headers.items()}
    if isinstance(headers, list):
        return {
            str(header["name"]): str(header["value"])
            for header in headers
            if isinstance(header, Mapping) and "name" in header and "value" in header
        }
    return {}


def _response_objects(value: Any) -> Iterable[tuple[str, Any, str, str]]:
    """Yield ``(object_id, owner_hint, owner_field, pointer)`` response matches."""

    def walk(current: Any, pointer: str) -> Iterable[tuple[str, Any, str, str]]:
        if isinstance(current, Mapping):
            object_id = next(
                (
                    str(child)
                    for key, child in current.items()
                    if not _is_sensitive_field(str(key))
                    and _id_field(str(key))
                    and isinstance(child, (str, int))
                    and is_object_id(str(child))
                ),
                None,
            )
            owner_item = next(
                (
                    (str(key), child)
                    for key, child in current.items()
                    if _OWNER_FIELD_RE.fullmatch(str(key))
                ),
                None,
            )
            if object_id is not None and owner_item is not None:
                owner_key, owner_value = owner_item
                if isinstance(owner_value, Mapping):
                    owner_value = owner_value.get("id")
                yield object_id, owner_value, owner_key, pointer
            for key, child in current.items():
                if _is_sensitive_field(str(key)):
                    continue
                yield from walk(child, f"{pointer}.{key}")
        elif isinstance(current, list):
            for index, child in enumerate(current):
                yield from walk(child, f"{pointer}[{index}]")

    yield from walk(value, "$")


def _explicit_evidence(
    entry: RequestRecord | Mapping[str, Any],
    endpoint_template: str,
    method: str,
    identity_by_hint: Mapping[str, str],
) -> Iterable[OwnershipEvidence]:
    if isinstance(entry, RequestRecord):
        return ()
    mappings = entry.get("explicit_ownership")
    if not isinstance(mappings, Mapping):
        return ()
    result: list[OwnershipEvidence] = []
    for object_id, owner in mappings.items():
        if not is_object_id(str(object_id)):
            continue
        if isinstance(owner, Mapping):
            owner = owner.get("identity", owner.get("hint"))
        identity = _identity_from_hint(owner, identity_by_hint)
        if identity is None and isinstance(owner, str):
            identity = owner
        if identity is not None:
            result.append(
                OwnershipEvidence(
                    identity,
                    endpoint_template,
                    method,
                    str(object_id),
                    OwnershipConfidence.EXPLICIT,
                    "explicit_mapping",
                )
            )
    return result


def _observed_create_evidence(
    entry: RequestRecord | Mapping[str, Any],
    requester: str | None,
    endpoint_template: str,
    method: str,
) -> Iterable[OwnershipEvidence]:
    if requester is None or method != _CREATE_METHOD or _response_status(entry) != 201:
        return ()
    result: list[OwnershipEvidence] = []
    headers = _response_headers(entry)
    location = next((value for key, value in headers.items() if key.lower() == "location"), None)
    location_ids: set[str] = set()
    if location is not None:
        location_path = urlsplit(location).path
        location_template = templatize(location_path)
        for object_id in extract_object_ids(location_path):
            location_ids.add(object_id)
            result.append(
                OwnershipEvidence(
                    requester,
                    location_template,
                    method,
                    object_id,
                    OwnershipConfidence.OBSERVED_CREATE,
                    "observed_create_location",
                )
            )
    response = _json_value(_response_body(entry))
    for object_id, field, pointer in _observed_create_body_ids(response, location_ids):
        result.append(
            OwnershipEvidence(
                requester,
                endpoint_template,
                method,
                object_id,
                OwnershipConfidence.OBSERVED_CREATE,
                f"observed_create_body:{pointer}:{field}",
            )
        )
    return result


def _observed_create_body_ids(
    response: Any, location_ids: set[str]
) -> Iterable[tuple[str, str, str]]:
    """Yield only a create result's canonical or Location-confirmed IDs.

    Nested related objects commonly have their own ``id`` fields. They are not
    ownership evidence for the newly created object unless the ID is confirmed
    by the response Location header.
    """

    if isinstance(response, Mapping):
        for field in ("id", "object_id"):
            value = response.get(field)
            if isinstance(value, (str, int)) and is_object_id(str(value)):
                yield str(value), field, f"$.{field}"
    for object_id, field, pointer in _walk_json_ids(response):
        if pointer not in {"$.id", "$.object_id"} and object_id in location_ids:
            yield object_id, field, pointer


def correlate_ownership(
    entries: Iterable[RequestRecord | Mapping[str, Any]], identity_by_hint: Mapping[str, str]
) -> list[OwnershipEvidence]:
    """Derive ownership evidence from captures without assuming requester ownership.

    ``identity_by_hint`` is only used for an owner hint found in the response or
    an explicit mapping. A requester on its own produces heuristic evidence,
    never a probe-authorizing ownership claim.
    """

    evidence: list[OwnershipEvidence] = []
    for entry in entries:
        url = _entry_value(entry, "url")
        if not isinstance(url, str):
            continue
        method = str(_entry_value(entry, "method", "GET")).upper()
        template = templatize(urlsplit(url).path)
        requester = _identity(entry)
        evidence.extend(_explicit_evidence(entry, template, method, identity_by_hint))
        evidence.extend(_observed_create_evidence(entry, requester, template, method))

        response = _json_value(_response_body(entry))
        if response is not None:
            for object_id, owner_hint, owner_field, pointer in _response_objects(response):
                owner = _identity_from_hint(owner_hint, identity_by_hint)
                if owner is not None:
                    evidence.append(
                        OwnershipEvidence(
                            owner,
                            template,
                            method,
                            object_id,
                            OwnershipConfidence.RESPONSE_MATCH,
                            f"response_owner_field:{pointer}.{owner_field}",
                        )
                    )

        if requester is not None:
            for object_id in extract_object_ids(urlsplit(url).path):
                evidence.append(
                    OwnershipEvidence(
                        requester,
                        template,
                        method,
                        object_id,
                        OwnershipConfidence.HEURISTIC,
                        "requester_identity",
                    )
                )

    # Preserve insertion order while making duplicate capture rows harmless.
    return list(dict.fromkeys(evidence))


_EXECUTABLE_CONFIDENCES = frozenset(
    {
        OwnershipConfidence.EXPLICIT,
        OwnershipConfidence.OBSERVED_CREATE,
        OwnershipConfidence.RESPONSE_MATCH,
    }
)
_CONFIDENCE_ORDER = {
    OwnershipConfidence.EXPLICIT: 0,
    OwnershipConfidence.OBSERVED_CREATE: 1,
    OwnershipConfidence.RESPONSE_MATCH: 2,
}


def executable_ownership(evidence: Iterable[OwnershipEvidence]) -> list[OwnershipEvidence]:
    """Return unambiguous, executable ownership evidence only.

    A disagreement between strong sources is intentionally omitted. Selecting
    whichever capture happened to be processed last would be unsafe.
    """

    grouped: dict[tuple[str, str, str], list[OwnershipEvidence]] = defaultdict(list)
    for item in evidence:
        if item.confidence in _EXECUTABLE_CONFIDENCES:
            grouped[(item.endpoint_template, item.method, item.object_id)].append(item)

    selected: list[OwnershipEvidence] = []
    for items in grouped.values():
        identities = {item.identity for item in items}
        if len(identities) != 1:
            continue
        selected.append(
            min(
                items,
                key=lambda item: (
                    _CONFIDENCE_ORDER[item.confidence],
                    item.source,
                    item.identity,
                ),
            )
        )
    return selected


class _StateStore(Protocol):
    def ownership_evidence_for(
        self, endpoint_template: str, method: str, object_id: str
    ) -> Iterable[OwnershipEvidence]: ...

    def persist_ownership_evidence(self, evidence: OwnershipEvidence) -> int: ...


def build_test_targets(
    state_store: _StateStore, correlations: Iterable[OwnershipEvidence]
) -> OwnershipPersistenceResult:
    """Persist unambiguous ownership and return every persisted-state conflict.

    The StateStore lookup closes the gap between independent imports: evidence
    that is safe within one capture batch may still contradict earlier stored
    strong evidence. Conflicting candidates are deliberately not persisted.
    """

    persisted: list[OwnershipEvidence] = []
    conflicts: list[OwnershipConflict] = []
    for evidence in executable_ownership(correlations):
        existing = tuple(
            item
            for item in state_store.ownership_evidence_for(
                evidence.endpoint_template, evidence.method, evidence.object_id
            )
            if item.confidence in _EXECUTABLE_CONFIDENCES and item.identity != evidence.identity
        )
        if existing:
            conflicts.append(OwnershipConflict(evidence, existing))
            continue
        try:
            state_store.persist_ownership_evidence(evidence)
        except OwnershipConflictError as error:
            # The precheck can lose a race to a different capture import. The
            # StateStore transaction is authoritative, so expose its evidence
            # through the same result channel rather than failing the import.
            conflicts.append(OwnershipConflict(error.candidate, error.existing))
            continue
        persisted.append(evidence)
    return OwnershipPersistenceResult(tuple(persisted), tuple(conflicts))
