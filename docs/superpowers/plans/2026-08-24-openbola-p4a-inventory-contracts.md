# OpenBOLA P4a: Resource Inventory Contracts & Generic Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `ResourceInventory`/`ProviderAdapter` contracts (spec §5) in a new `src/openbola/discovery.py` module, plus the generic HTTP adapter every discovery run always has available — grouping already-captured `RequestRecord`s by templatized endpoint, extracting observed HTTP methods and JSON field names, and minting `ValueHandle`s (P1) for observed record IDs.

**Architecture:** `src/openbola/endpoints.py` already has a mature, tested `templatize(url) -> str` (path templating with `{id}` placeholders) and `extract_object_ids(url) -> list[str]` — this plan reuses both rather than reimplementing path-ID logic a second time. `discovery.py` is new and adapter-shaped: it never makes an HTTP request itself (adapters "consume already captured evidence," spec §5), and its adapters take a concrete `InMemorySessionValueRegistry` (P1) via constructor injection to mint record-id handles, matching the `ProviderAdapter` Protocol's method signatures exactly (`detect`/`inventory` take only `records`, per spec — the registry is a constructor dependency, not a per-call argument, since Python `Protocol`s only constrain the listed methods, not `__init__`).

**Tech Stack:** Python 3.11+, stdlib only (`json`, `dataclasses`, `enum`, `typing`), reuses `openbola.endpoints.templatize`/`extract_object_ids` and `openbola.handles.InMemorySessionValueRegistry`/`ValueHandle`.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 Resource and provider inventory)

## Global Constraints

- Adapters consume already captured evidence and produce normalized resource and capability contracts without sending requests themselves (spec §5) — `discovery.py` must not import `httpx` or open any socket.
- `FieldInventory` tracks field **names only**, never inferred value types. Every `RequestRecord` this codebase produces has its JSON body leaf values already redacted to the literal string `"[REDACTED]"` by `capture.py`'s `_sanitize_body`/`_redact_json` (only key names and path segments survive redaction) — inferring a "type" from a redacted body would silently fabricate false schema information. This is a deliberate, ledgered scope decision (see the roadmap's P4 entry), not an oversight to fix here.
- Provider name `"generic"` and confidence `ProviderConfidence.UNKNOWN` are the correct values for the generic adapter — it is always structurally applicable (spec §5: "generic HTTP/OpenAPI/GraphQL discovery is always present") and never claims provider-specific knowledge.
- `record_handles` on a `ResourceInventory` must be `ValueHandle`s (P1's `openbola.handles.ValueHandle`, `kind="record_id"`), never raw ID strings — persisted state, reports, and AI context see handles only (spec §5's overarching handle rule).

---

### Task 1: `ResourceInventory`/`ProviderAdapter` contracts

**Files:**
- Create: `src/openbola/discovery.py`
- Test: `tests/test_discovery.py`

**Interfaces:**
- Consumes: `RequestRecord` (`openbola.models`), `ValueHandle`/`SessionValueRegistry` (`openbola.handles`, P1).
- Produces: `ProviderConfidence` (`StrEnum`: `CONFIRMED`, `INFERRED`, `UNKNOWN`), `FieldInventory(name: str)`, `ResourceInventory(provider, provider_confidence, resource_name, endpoint_template, fields, record_handles, observed_methods)`, `ProviderDetection(provider: str, confidence: ProviderConfidence)`, `ProviderAdapter` (`Protocol` with `name: str`, `detect(records) -> ProviderDetection`, `inventory(records) -> tuple[ResourceInventory, ...]`). Task 2 implements `GenericAdapter` against this Protocol; P4b/c/d implement the provider-specific adapters against the same Protocol.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_discovery.py
from __future__ import annotations

from openbola.discovery import (
    FieldInventory,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
)
from openbola.handles import ValueHandle


def test_provider_confidence_has_three_members() -> None:
    assert {member.value for member in ProviderConfidence} == {
        "confirmed",
        "inferred",
        "unknown",
    }


def test_field_inventory_is_frozen_and_name_only() -> None:
    field = FieldInventory(name="email")
    assert field.name == "email"
    assert not hasattr(field, "type")
    assert not hasattr(field, "observed_types")


def test_provider_detection_pairs_provider_and_confidence() -> None:
    detection = ProviderDetection(provider="generic", confidence=ProviderConfidence.UNKNOWN)
    assert detection.provider == "generic"
    assert detection.confidence is ProviderConfidence.UNKNOWN


def test_resource_inventory_holds_value_handles_not_raw_ids() -> None:
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_value(kind="record_id", value="42")
    inventory = ResourceInventory(
        provider="generic",
        provider_confidence=ProviderConfidence.UNKNOWN,
        resource_name="users",
        endpoint_template="/v1/users/{id}",
        fields=(FieldInventory(name="email"),),
        record_handles=(handle,),
        observed_methods=frozenset({"GET", "PATCH"}),
    )
    assert inventory.record_handles == (handle,)
    assert isinstance(inventory.record_handles[0], ValueHandle)
    assert inventory.observed_methods == frozenset({"GET", "PATCH"})


def test_provider_adapter_is_a_protocol_with_expected_members() -> None:
    # A structural check that a minimal conforming class satisfies the Protocol
    # at the attribute/method level - Protocol membership is duck-typed, so
    # this test exercises that shape rather than calling isinstance().
    class MinimalAdapter:
        name = "minimal"

        def detect(self, records: object) -> ProviderDetection:
            return ProviderDetection(provider="minimal", confidence=ProviderConfidence.UNKNOWN)

        def inventory(self, records: object) -> tuple[ResourceInventory, ...]:
            return ()

    adapter: ProviderAdapter = MinimalAdapter()
    assert adapter.name == "minimal"
    assert adapter.detect(()).provider == "minimal"
    assert adapter.inventory(()) == ()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_discovery.py -v`
Expected: `ModuleNotFoundError: No module named 'openbola.discovery'`

- [ ] **Step 3: Write the implementation**

```python
# src/openbola/discovery.py
"""Provider-agnostic and provider-specific resource inventory contracts.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Adapters consume already-captured ``RequestRecord`` evidence and never send
a request themselves. Every field this module reports comes from data
``RequestRecord`` already carries; it never assumes richer fidelity than
that (see the roadmap's P4 entry for why field *value types* are
deliberately not part of ``FieldInventory``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from openbola.handles import ValueHandle
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_discovery.py -v`
Expected: `5 passed`

- [ ] **Step 5: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/discovery.py tests/test_discovery.py
.venv/bin/mypy src/openbola/discovery.py
```

Expected: full suite passes (301 pre-existing + 5 new), ruff and mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/openbola/discovery.py tests/test_discovery.py
git commit -m "feat: add ResourceInventory/ProviderAdapter contracts"
```

---

### Task 2: `GenericAdapter`

**Files:**
- Modify: `src/openbola/discovery.py`
- Test: `tests/test_discovery.py`

**Interfaces:**
- Consumes: `templatize`, `extract_object_ids` (`openbola.endpoints`, both already public, unmodified); `InMemorySessionValueRegistry` (`openbola.handles`, P1) via constructor injection — the concrete class, not the `SessionValueRegistry` Protocol, because `SessionValueRegistry` only declares the read side (`resolve_secret`/`resolve_value`); minting a handle via `store_value` is only exposed on the concrete registry, matching P1's own design (write access is deliberately narrower than read access).
- Produces: `GenericAdapter(registry: InMemorySessionValueRegistry)` implementing `ProviderAdapter` with `name = "generic"`. This is the adapter that is always present in a discovery run (spec §5); P4b/c/d's provider-specific adapters run alongside it, not instead of it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_discovery.py`:

```python
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord


def _record(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    response_body: bytes | None = None,
    response_status: int | None = 200,
) -> RequestRecord:
    return RequestRecord(
        "alice",
        method,
        url,
        {},
        body,
        response_status,
        {},
        response_body,
    )


def test_generic_adapter_detect_is_always_unknown_confidence() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    detection = adapter.detect(())
    assert detection.provider == "generic"
    assert detection.confidence == ProviderConfidence.UNKNOWN


def test_generic_adapter_groups_records_by_templatized_endpoint() -> None:
    from openbola.discovery import GenericAdapter

    registry = InMemorySessionValueRegistry()
    adapter = GenericAdapter(registry)
    records = [
        _record("GET", "https://api.example.test/v1/users"),
        _record("GET", "https://api.example.test/v1/users/42"),
        _record(
            "PATCH",
            "https://api.example.test/v1/users/42",
            body=b'{"email": "alice@example.test"}',
            response_body=b'{"id": 42, "email": "alice@example.test", "name": "Alice"}',
        ),
        _record(
            "POST",
            "https://api.example.test/v1/users",
            body=b'{"email": "bob@example.test", "name": "Bob"}',
            response_body=b'{"id": 43}',
        ),
    ]

    inventories = adapter.inventory(records)
    by_template = {item.endpoint_template: item for item in inventories}

    assert set(by_template) == {"/v1/users", "/v1/users/{id}"}

    collection = by_template["/v1/users"]
    assert collection.provider == "generic"
    assert collection.provider_confidence == ProviderConfidence.UNKNOWN
    assert collection.resource_name == "users"
    assert collection.observed_methods == frozenset({"GET", "POST"})
    assert {f.name for f in collection.fields} == {"email", "name", "id"}
    assert collection.record_handles == ()  # no path-embedded ID at this template

    item = by_template["/v1/users/{id}"]
    assert item.observed_methods == frozenset({"GET", "PATCH"})
    assert {f.name for f in item.fields} == {"email", "id", "name"}
    assert len(item.record_handles) == 1
    assert registry.resolve_value(item.record_handles[0]) == "42"


def test_generic_adapter_ignores_non_json_and_malformed_bodies() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record("POST", "https://api.example.test/v1/reports", body=b"not json"),
        _record(
            "POST",
            "https://api.example.test/v1/reports",
            body=b'"just a json string, not an object"',
        ),
        _record("GET", "https://api.example.test/v1/reports", response_body=b"[]"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].fields == ()


def test_generic_adapter_extracts_fields_from_list_of_objects_response() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://api.example.test/v1/orders",
            response_body=b'[{"id": 1, "total": 9.5}, {"id": 2, "status": "paid"}]',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert {f.name for f in inventories[0].fields} == {"id", "total", "status"}


def test_generic_adapter_deduplicates_record_handles_per_template() -> None:
    from openbola.discovery import GenericAdapter

    registry = InMemorySessionValueRegistry()
    adapter = GenericAdapter(registry)
    records = [
        _record("GET", "https://api.example.test/v1/users/42"),
        _record("PATCH", "https://api.example.test/v1/users/42"),
        _record("GET", "https://api.example.test/v1/users/43"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    handles = inventories[0].record_handles
    resolved = {registry.resolve_value(handle) for handle in handles}
    assert resolved == {"42", "43"}
    assert len(handles) == 2  # one handle per unique ID, not per record


def test_generic_adapter_resource_name_skips_every_numbered_placeholder() -> None:
    from openbola.discovery import GenericAdapter

    adapter = GenericAdapter(InMemorySessionValueRegistry())
    records = [
        _record("GET", "https://api.example.test/v1/orgs/7/users/42"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].endpoint_template == "/v1/orgs/{id}/users/{id2}"
    assert inventories[0].resource_name == "users"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_discovery.py -k generic -v`
Expected: `AttributeError`/`ImportError` — `GenericAdapter` does not exist yet.

- [ ] **Step 3: Write the implementation**

Add these imports to the top of `src/openbola/discovery.py` (replacing the existing import block):

```python
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from openbola.endpoints import extract_object_ids, templatize
from openbola.handles import InMemorySessionValueRegistry, ValueHandle
from openbola.models import RequestRecord
```

Then, at the end of `src/openbola/discovery.py`, append:

```python
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
```

Note: `templatize()` emits numbered placeholders (`{id2}`, `{id3}`, ...) when a single path has more than one ID segment, e.g. `/v1/orgs/{id}/users/{id2}` — the filter above uses `not segment.startswith("{id")` (not an exact `!= "{id}"` match) specifically so every numbered variant is excluded too, not just the first one.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_discovery.py -v`
Expected: all pass (5 from Task 1 + 6 from this task = 11 total in this file).

- [ ] **Step 5: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/discovery.py tests/test_discovery.py
.venv/bin/mypy src/openbola/discovery.py
```

Expected: full suite passes (301 pre-existing + 11 new), ruff and mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/openbola/discovery.py tests/test_discovery.py
git commit -m "feat: add GenericAdapter for provider-agnostic resource inventory"
```

---

## Self-Review Notes

- **Spec coverage:** §5's `ResourceInventory`/`ProviderAdapter` contracts → Task 1. §5's "generic HTTP/OpenAPI/GraphQL discovery is always present" → Task 2 (`GraphQL`-shaped generic discovery specifically — GraphQL requests are POSTs to a single endpoint with a `query` field in the body, which `GenericAdapter` already groups correctly by URL template and would report `query`/`variables`/`operationName` as observed field names; no GraphQL-specific parsing is added in this plan, matching "generic" scope). Provider-specific adapters (Supabase/Firebase/Hasura) are P4b/c/d, written just-in-time against this task's contract.
- **Placeholder scan:** every step has literal code; the `_resource_name_from_template` numbered-placeholder bug was caught and fixed inline in Step 3 rather than left as a known issue.
- **Type consistency:** `ResourceInventory`/`ProviderAdapter`/`ProviderConfidence` field names and types match spec §5's own dataclass sketch verbatim, so P4b/c/d can implement against this file without renaming anything.
