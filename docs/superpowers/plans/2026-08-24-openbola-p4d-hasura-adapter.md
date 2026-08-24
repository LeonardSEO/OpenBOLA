# OpenBOLA P4d: Hasura Provider Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only `HasuraAdapter` that recognizes confirmed Hasura GraphQL traffic and returns origin-isolated, handle-safe `ResourceInventory` entries for supported Hasura query and mutation payloads.

**Architecture:** Hasura shares GraphQL's single HTTP endpoint with many non-Hasura servers, so inventory is gated on Hasura-specific captured evidence per normalized origin, not merely `/graphql` or a JSON body with a `query` key. A small stdlib lexer/parser reads only the operation's top-level selections and argument variable references; it never stores query text or GraphQL values. The adapter consumes P3b's ephemeral adapter view: persistent `RequestRecord` data remains structurally redacted while a process-local view makes the GraphQL document and variables available just long enough to derive field names and opaque record handles.

**Tech Stack:** Python 3.11+, stdlib only (`dataclasses`, `json`, `re`, `urllib.parse`); existing `ProviderAdapter`, `ProviderConfidence`, `ResourceInventory`, `FieldInventory`, `InMemorySessionValueRegistry`, `is_object_id`, `_id_field`, and `_is_sensitive_field`.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 resource/provider inventory; §7 read-only discovery; acceptance criterion 4) and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P4/P3b rulings).

## Global Constraints

- Adapters only consume captured evidence; `src/openbola/providers/hasura.py` must not import `httpx`, Playwright, `ScopeGuard`, `ProbeExecutor`, or open a socket.
- Preserve P4a's public contract exactly: `ProviderAdapter.name`, `detect(records) -> ProviderDetection`, and `inventory(records) -> tuple[ResourceInventory, ...]`. `ResourceInventory.endpoint_template` is the real queryless HTTP path, never a synthetic `#resource` URI.
- The P3b prerequisite below changes the *input view* consistently for every adapter before P4d begins. P4d must not introduce a Hasura-only overload or accept raw `RequestRecord` bodies.
- `FieldInventory` contains field names only. It never contains GraphQL source, aliases, operation names, values, inferred types, headers, or response values.
- `record_handles` contain only `ValueHandle(kind="record_id")`. IDs are deduplicated inside one `(origin, endpoint_path, resource_name)` group and are never placed in an inventory string, report, or exception.
- Detection and inventory are origin-isolated. A confirmation, method, field, resource, or handle from one origin must never influence another origin. Normalize scheme and hostname to lowercase; preserve an explicit port; derive the host from `urlsplit(...).hostname`, not `netloc`.
- Header checks inspect case-insensitive header *names* only. They must never branch on, log, compare, or retain header values, including `x-hasura-admin-secret`, `authorization`, and `cookie`.
- ID discovery rejects sensitive field families before inspecting values, including a sensitive top-level variable name or any sensitive ancestor. Reuse `openbola.endpoints._is_sensitive_field` rather than copying its vocabulary.
- Only direct ID variables and `_eq` values below an ID-shaped field can mint a handle. `_in`, `_nin`, range, pattern, inline literals, and response values are out of scope because they do not safely identify one observed record.
- Supported operation payloads are JSON objects with `query: str`, optional `operationName: str`, and optional `variables: Mapping[str, object]`. A malformed, redacted, multipart, batched, subscription, fragment-only, introspection, or unrecognized root operation is skipped without raising or inventing a resource.
- Do not change `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` in this task. Do not commit unless a later, separately authorized implementation task asks for it.

---

## Prerequisite Gate: P3b ephemeral adapter view

P4d cannot start before P3b provides an adapter-only ephemeral view. Current `capture._redact_json()` redacts GraphQL's `query` string and every variable value, so a provider adapter supplied with today's `RequestRecord` cannot recover the root resource, field names, variable references, or IDs. The prerequisite is deliberately a gate, not an implementation task inside P4d.

P3b must define this transport contract and migrate P4a/P4b/P4c to it before this plan is executed:

```python
# src/openbola/capture.py (P3b-owned; exact name required by P4d)
@dataclass(frozen=True)
class AdapterRecordView:
    record: RequestRecord
    request_body: bytes | None = field(default=None, repr=False)
    response_body: bytes | None = field(default=None, repr=False)

    def __getstate__(self) -> NoReturn: ...
    def __reduce__(self) -> NoReturn: ...
    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn: ...
```

`record` is the existing persistent-safe, structurally redacted `RequestRecord`; `request_body` and `response_body` are process-local originals captured only after scope approval and destroyed with the session registry. They must not be written to HAR, SQLite, reports, audit events, logging, exceptions, or AI context. `ProviderAdapter`, `GenericAdapter`, `SupabaseAdapter`, and `FirebaseRealtimeDatabaseAdapter` must consistently change from `Sequence[RequestRecord]` to `Sequence[AdapterRecordView]`, reading only `view.record` unless a future adapter explicitly needs ephemeral bytes. `detect()` continues to operate from safe URL/header metadata. This avoids a Hasura-specific escape hatch and keeps the persisted surface unchanged.

P3b acceptance command before P4d begins:

```bash
uv run pytest tests/test_capture.py tests/test_discovery.py tests/test_providers_supabase.py tests/test_providers_firebase.py
```

Required P3b evidence: a captured Hasura request has a redacted `view.record.body`, retains original bytes only in `view.request_body`, rejects serialization of the view, and produces no raw query/variable/header/response values in the sanitized HAR or persistent state.

---

## File Structure

- `src/openbola/providers/hasura.py` — Hasura marker detection, safe GraphQL lexer/parser, resource normalization, variable-to-root association, and `HasuraAdapter`.
- `tests/test_providers_hasura.py` — deterministic request/response fixtures and the adapter's unit/regression contract.
- `tests/test_capture.py` — P3b-owned integration fixture proving the ephemeral view crosses capture-to-discovery without persistence; P4d adds only the Hasura assertion after P3b lands.
- `src/openbola/providers/__init__.py` — provider registry decision point. Add `HasuraAdapter` only if the pre-existing application uses this module as its explicit registry; otherwise leave this intentionally empty and register in the actual discovery orchestrator created by its owning phase.

## Provider Registration Decision

There is currently no provider registry or discovery orchestrator in `src/openbola`; P4a-c adapters are independent modules and no application code instantiates them. P4d must **not** invent a hidden registry in `providers/__init__.py`, because that would create an untested second orchestration path. The P4d deliverable is therefore a conforming, importable adapter plus a `TYPE_CHECKING` Protocol sentinel. The first phase that introduces the discovery orchestrator (P5/P8, unless a dedicated integration plan is scheduled first) must own an explicit ordered registry:

```python
def provider_adapters(registry: InMemorySessionValueRegistry) -> tuple[ProviderAdapter, ...]:
    return (
        GenericAdapter(registry),
        SupabaseAdapter(registry),
        FirebaseRealtimeDatabaseAdapter(registry),
        HasuraAdapter(registry),
    )
```

That later owner must add an end-to-end registration test. P4d's capture-to-discovery proof calls `HasuraAdapter` directly, which proves the new adapter boundary without claiming automatic app integration that does not yet exist.

---

### Task 1: Add parser contracts and failing parser tests

**Files:**
- Create: `src/openbola/providers/hasura.py`
- Create: `tests/test_providers_hasura.py`

**Interfaces:**
- Consumes: `AdapterRecordView` from P3b, whose `record` property supplies safe URL/header/method metadata and whose `request_body` is ephemeral-only.
- Produces: private immutable parser values used only in this module:

```python
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

def _parse_operation(document: str) -> _ParsedOperation | None: ...
def _resource_name(root_field: str) -> str | None: ...
```

- [ ] **Step 1: Write failing parser tests**

Create the test helper and parser-contract tests:

```python
from __future__ import annotations

import json

from openbola.capture import AdapterRecordView
from openbola.models import RequestRecord
from openbola.providers.hasura import _ParsedOperation, _RootSelection, _parse_operation, _resource_name


def _view(
    body: dict[str, object],
    *,
    url: str = "https://api.example.test/v1/graphql",
    headers: dict[str, str] | None = None,
    method: str = "POST",
    response: dict[str, object] | None = None,
) -> AdapterRecordView:
    record = RequestRecord("alice", method, url, headers or {}, b'{"query":"[REDACTED]"}', 200)
    return AdapterRecordView(
        record=record,
        request_body=json.dumps(body).encode(),
        response_body=json.dumps(response).encode() if response is not None else None,
    )


def test_parse_query_root_alias_variables_and_selected_fields() -> None:
    parsed = _parse_operation(
        "query Get($orderId: uuid!) { order: orders_by_pk(id: $orderId) { id total } }"
    )
    assert parsed is not None
    assert parsed.operation_kind == "query"
    assert parsed.roots == (
        _RootSelection(
            field_name="orders_by_pk",
            variable_names=frozenset({"orderId"}),
            selected_fields=frozenset({"id", "total"}),
            mutation_returning_fields=frozenset(),
        ),
    )
    assert _resource_name("orders_by_pk") == "orders"


def test_parse_mutation_uses_returning_fields_not_wrapper_fields() -> None:
    parsed = _parse_operation(
        "mutation Update($id: uuid!, $name: String!) { "
        "update_orders(where: {id: {_eq: $id}}, _set: {name: $name}) "
        "{ affected_rows returning { id name } } }"
    )
    assert parsed is not None
    root = parsed.roots[0]
    assert parsed.operation_kind == "mutation"
    assert root.field_name == "update_orders"
    assert root.variable_names == frozenset({"id", "name"})
    assert root.selected_fields == frozenset({"affected_rows", "returning"})
    assert root.mutation_returning_fields == frozenset({"id", "name"})
    assert _resource_name(root.field_name) == "orders"


def test_parse_ignores_variable_lookalikes_in_comments_and_strings() -> None:
    assert _parse_operation('# $fake\nquery { orders { note } }') is not None
    assert _parse_operation('query { orders { note(format: "$fake") } }') is not None
    assert _parse_operation('fragment OrderFields on orders { id }') is None
    assert _parse_operation('query { __schema { types { name } } }') is None
```

- [ ] **Step 2: Run parser tests to verify they fail**

Run: `uv run pytest tests/test_providers_hasura.py -k 'parse' -v`

Expected: FAIL during import because `openbola.providers.hasura` and its private parser contracts do not exist.

- [ ] **Step 3: Implement the bounded stdlib lexer/parser**

In `src/openbola/providers/hasura.py`, add a token scanner which returns only names, `$` variable references, punctuation, and quoted-string placeholders. It must skip `#` comments, regular quoted strings with escapes, and triple-quoted block strings. Do not return string contents. Parse only a `query` or `mutation` operation and its first-level selection set. For each top-level field, consume an optional alias (`alias: field`), balanced argument parentheses, and the direct selection set. Collect variable names from the balanced argument tokens. For mutations, inspect the direct root selection and collect direct names under a `returning { ... }` child selection; do not treat wrapper names as record fields.

Use this exact normalization rule:

```python
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
```

Return `None` on malformed syntax, subscriptions, fragment-only documents, empty root selections, or introspection-only roots. Never raise parser errors using any document substring.

- [ ] **Step 4: Run parser tests to verify they pass**

Run: `uv run pytest tests/test_providers_hasura.py -k 'parse' -v`

Expected: PASS.

### Task 2: Implement Hasura detection, origin gate, and inventory tests

**Files:**
- Modify: `src/openbola/providers/hasura.py`
- Modify: `tests/test_providers_hasura.py`

**Interfaces:**
- Consumes: `_parse_operation`, `_resource_name`; `AdapterRecordView`; `ProviderConfidence`, `ProviderDetection`, `ResourceInventory`, `FieldInventory`; `InMemorySessionValueRegistry`.
- Produces:

```python
class HasuraAdapter:
    name = "hasura"
    def __init__(self, registry: InMemorySessionValueRegistry) -> None: ...
    def detect(self, records: Sequence[AdapterRecordView]) -> ProviderDetection: ...
    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]: ...
```

- [ ] **Step 1: Write failing detection and inventory tests**

Append these tests (keep the helper from Task 1):

```python
from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.providers.hasura import HasuraAdapter


def test_detect_confirmed_from_graphql_payload_and_case_insensitive_hasura_header() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {"query": "query { orders { id total } }"},
        headers={"X-Hasura-Role": "user"},
    )
    assert adapter.detect([record]).confidence is ProviderConfidence.CONFIRMED


def test_detect_inferred_without_a_hasura_marker_and_unknown_without_graphql() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    inferred = _view({"query": "query { orders { id } }"})
    unknown = _view({"queryText": "not graphql"})
    assert adapter.detect([inferred]).confidence is ProviderConfidence.INFERRED
    assert adapter.detect([unknown]).confidence is ProviderConfidence.UNKNOWN


def test_inventory_requires_confirmed_hasura_evidence_per_origin() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    confirmed = _view(
        {"query": "query { orders { id total } }"},
        headers={"x-hasura-role": "user"},
        url="https://tenant-a.example.test/v1/graphql",
    )
    generic = _view(
        {"query": "query { orders { id leaked } }"},
        url="https://tenant-b.example.test/v1/graphql",
    )
    inventories = adapter.inventory([confirmed, generic])
    assert len(inventories) == 1
    assert inventories[0].resource_name == "orders"
    assert {field.name for field in inventories[0].fields} == {"id", "total"}
    assert inventories[0].endpoint_template == "/v1/graphql"
    assert inventories[0].observed_methods == frozenset({"POST"})


def test_inventory_does_not_merge_same_resource_across_origins_or_ports() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    body = {"query": "query { orders { id } }"}
    records = [
        _view(body, headers={"x-hasura-role": "user"}, url="https://API.example.test:8443/v1/graphql"),
        _view(body, headers={"x-hasura-role": "user"}, url="https://api.example.test:9443/v1/graphql"),
    ]
    assert len(adapter.inventory(records)) == 2


def test_detection_never_exposes_header_values() -> None:
    sentinel = "this-admin-secret-must-never-appear"  # noqa: S105
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    detection = adapter.detect([
        _view({"query": "query { orders { id } }"}, headers={"x-hasura-admin-secret": sentinel})
    ])
    assert sentinel not in repr(detection)
```

- [ ] **Step 2: Run detection/inventory tests to verify they fail**

Run: `uv run pytest tests/test_providers_hasura.py -k 'detect or origin or requires_confirmed or exposes_header' -v`

Expected: FAIL because `HasuraAdapter` does not exist.

- [ ] **Step 3: Implement detection and grouping**

Implement these private helpers and use them in both methods:

```python
_HASURA_HEADER_NAMES = frozenset({"x-hasura-role", "x-hasura-admin-secret"})
_GRAPHQL_PATHS = frozenset({"/graphql", "/v1/graphql"})


def _origin(url: str) -> str | None: ...
def _request_json(view: AdapterRecordView) -> Mapping[str, object] | None: ...
def _graphql_document(view: AdapterRecordView) -> str | None: ...
def _has_hasura_header(headers: Mapping[str, str]) -> bool: ...
def _is_graphql_payload(view: AdapterRecordView) -> bool: ...
```

`_has_hasura_header` compares `header_name.casefold()` against `_HASURA_HEADER_NAMES` and ignores each value. `_request_json` accepts only a UTF-8 JSON object from `view.request_body`; malformed input returns `None`. `_graphql_document` returns the `query` value only when it is a string different from `"[REDACTED]"`. A record is confirmed only when it has a parseable non-redacted GraphQL document and a Hasura header. A GraphQL document or known GraphQL path alone is inferred. Inventory first partitions views by `_origin(view.record.url)`, retains only partitions whose local `detect()` is confirmed, then partitions by `(origin, urlsplit(view.record.url).path, resource_name)`.

Create one `ResourceInventory` for each sorted group. Its provider is `"hasura"`, confidence is the group-local detection confidence, endpoint template is the queryless path, methods are uppercased, and fields are the union of safe parsed selected fields. Never include alias text, source documents, or header values.

- [ ] **Step 4: Run detection/inventory tests to verify they pass**

Run: `uv run pytest tests/test_providers_hasura.py -k 'detect or origin or requires_confirmed or exposes_header' -v`

Expected: PASS.

### Task 3: Add variable association, sensitive-ID guards, and handle inventory

**Files:**
- Modify: `src/openbola/providers/hasura.py`
- Modify: `tests/test_providers_hasura.py`

**Interfaces:**
- Consumes: group-local `_ParsedOperation.roots`, parsed request `variables`, `_id_field`, `_is_sensitive_field`, `is_object_id`, and `InMemorySessionValueRegistry.store_value(kind="record_id", value=...)`.
- Produces:

```python
def _record_ids_for_variable(name: str, value: object) -> set[str]: ...
```

The function receives one root-referenced variable and returns zero or more eligible, raw IDs only to the caller; the caller immediately turns them into handles and must not expose the set.

- [ ] **Step 1: Write failing sensitive-variable and association tests**

Append these tests:

```python
def test_inventory_maps_each_variable_to_its_own_root_resource() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = HasuraAdapter(registry)
    record = _view(
        {
            "query": (
                "query($orderId: uuid!, $userId: uuid!) { "
                "orders_by_pk(id: $orderId) { id } users_by_pk(id: $userId) { id } }"
            ),
            "variables": {
                "orderId": "550e8400-e29b-41d4-a716-446655440000",
                "userId": "507f1f77bcf86cd799439011",
            },
        },
        headers={"x-hasura-role": "user"},
    )
    inventories = {item.resource_name: item for item in adapter.inventory([record])}
    assert {registry.resolve_value(h) for h in inventories["orders"].record_handles} == {
        "550e8400-e29b-41d4-a716-446655440000"
    }
    assert {registry.resolve_value(h) for h in inventories["users"].record_handles} == {
        "507f1f77bcf86cd799439011"
    }


def test_inventory_extracts_only_id_and_id_eq_variables() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = HasuraAdapter(registry)
    record = _view(
        {
            "query": "query($id: uuid!, $where: orders_bool_exp!) { orders_by_pk(id: $id) { id } orders(where: $where) { id } }",
            "variables": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "where": {"id": {"_eq": "507f1f77bcf86cd799439011"}, "status": {"_in": ["paid", "new"]}},
            },
        },
        headers={"x-hasura-role": "user"},
    )
    values = {
        registry.resolve_value(handle)
        for inventory in adapter.inventory([record])
        for handle in inventory.record_handles
    }
    assert values == {"550e8400-e29b-41d4-a716-446655440000", "507f1f77bcf86cd799439011"}


def test_sensitive_variable_or_sensitive_parent_never_becomes_a_handle() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = HasuraAdapter(registry)
    sentinel = "opaque_secret_record_4eC39HqLyjWDarjtT1zdp7dc"  # noqa: S105
    record = _view(
        {
            "query": "query($apiTokenId: uuid!, $where: api_keys_bool_exp!) { api_keys_by_pk(id: $apiTokenId) { id } api_keys(where: $where) { id } }",
            "variables": {"apiTokenId": sentinel, "where": {"secret_token": {"_eq": sentinel}}},
        },
        headers={"x-hasura-role": "user"},
    )
    inventory = adapter.inventory([record])[0]
    assert inventory.record_handles == ()
    assert sentinel not in repr(inventory)


def test_inline_literals_and_in_filters_never_mint_handles() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {
            "query": "query { orders(where: {id: {_in: [1, 2]}}) { id } }",
            "variables": {},
        },
        headers={"x-hasura-role": "user"},
    )
    assert adapter.inventory([record])[0].record_handles == ()
```

- [ ] **Step 2: Run ID-guard tests to verify they fail**

Run: `uv run pytest tests/test_providers_hasura.py -k 'variable or sensitive or inline or eq' -v`

Expected: FAIL because inventory does not yet associate root argument variables to safe record IDs.

- [ ] **Step 3: Implement the guarded ID extractor**

Implement `_record_ids_for_variable` as a recursive walker. Immediately return an empty set when `name` is sensitive. For a mapping, skip every key whose name is sensitive. Add a scalar only when either (a) its own key is an ID field, or (b) its key is `_eq`, its parent key is an ID field, and `is_object_id(str(value))` is true. Recurse into mappings/lists otherwise, but never collect from `_in`, `_nin`, `gt`, `gte`, `lt`, `lte`, `like`, `ilike`, `regex`, or their children. A direct scalar variable is eligible only when its variable name itself satisfies `_id_field` and its value satisfies `is_object_id`.

For each `_RootSelection`, look up only `root.variable_names` in the request `variables` mapping. Pass each selected pair to `_record_ids_for_variable`; add the resulting values only to that root's `(origin, path, resource)` group. Convert the final sorted set immediately with `self._registry.store_value(kind="record_id", value=value)`.

- [ ] **Step 4: Run ID-guard tests to verify they pass**

Run: `uv run pytest tests/test_providers_hasura.py -k 'variable or sensitive or inline or eq' -v`

Expected: PASS.

### Task 4: Add mutation, malformed-input, Protocol, and capture-to-discovery acceptance proof

**Files:**
- Modify: `src/openbola/providers/hasura.py`
- Modify: `tests/test_providers_hasura.py`
- Modify: `tests/test_capture.py`

**Interfaces:**
- Consumes: all Task 1–3 contracts and P3b's non-serializable `AdapterRecordView` capture output.
- Produces: a type-checked `HasuraAdapter` and deterministic acceptance evidence for the real capture-to-discovery boundary.

- [ ] **Step 1: Write failing acceptance tests**

Add these tests:

```python
def test_mutation_inventory_uses_returning_fields_and_post_method() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    record = _view(
        {
            "query": "mutation($id: uuid!, $name: String!) { update_orders(where: {id: {_eq: $id}}, _set: {name: $name}) { affected_rows returning { id name } } }",
            "variables": {"id": "550e8400-e29b-41d4-a716-446655440000", "name": "changed"},
        },
        headers={"x-hasura-role": "user"},
    )
    inventory = adapter.inventory([record])[0]
    assert inventory.resource_name == "orders"
    assert {field.name for field in inventory.fields} == {"id", "name"}
    assert inventory.observed_methods == frozenset({"POST"})


def test_redacted_or_malformed_payload_is_skipped_without_exception() -> None:
    adapter = HasuraAdapter(InMemorySessionValueRegistry())
    redacted = AdapterRecordView(
        record=RequestRecord("alice", "POST", "https://api.example.test/v1/graphql", {"x-hasura-role": "[REDACTED]"}, b'{"query":"[REDACTED]"}', 200),
        request_body=b'{"query":"[REDACTED]"}',
    )
    malformed = AdapterRecordView(
        record=RequestRecord("alice", "POST", "https://api.example.test/v1/graphql", {"x-hasura-role": "[REDACTED]"}, b"[REDACTED]", 200),
        request_body=b"not-json",
    )
    assert adapter.inventory([redacted, malformed]) == ()
```

In `tests/test_capture.py`, extend P3b's existing local-fake capture test with a `POST /v1/graphql` request whose original body is the Task 3 `orders_by_pk` payload and whose response is `{"data":{"orders_by_pk":{"id":"...","total":9.5}}}`. Assert all of the following:

```python
view = captured_adapter_views[0]
assert view.record.body == b'{"query":"[REDACTED]","variables":{"id":"[REDACTED]"}}'
assert view.request_body is not None
inventory = HasuraAdapter(registry).inventory([view])[0]
assert inventory.resource_name == "orders"
assert {field.name for field in inventory.fields} == {"id", "total"}
assert len(inventory.record_handles) == 1
assert raw_id not in repr(inventory)
assert raw_id not in sanitized_har.read_text()
with pytest.raises(TypeError):
    pickle.dumps(view)
```

- [ ] **Step 2: Run acceptance tests to verify they fail**

Run: `uv run pytest tests/test_providers_hasura.py tests/test_capture.py -k 'mutation or malformed or hasura or adapter_view' -v`

Expected: FAIL until the adapter handles mutation fields and P3b's capture fixture exposes the ephemeral view.

- [ ] **Step 3: Complete implementation and type sentinel**

Use `root.mutation_returning_fields` instead of `root.selected_fields` when `operation_kind == "mutation"` and the returning set is non-empty. If a mutation has no `returning` selection, leave its fields empty rather than reporting mutation envelope keys. Add this source-only `TYPE_CHECKING` sentinel to the bottom of `hasura.py` (mypy checks `src`, not tests):

```python
if TYPE_CHECKING:

    def _hasura_adapter_satisfies_provider_adapter(
        registry: InMemorySessionValueRegistry,
    ) -> ProviderAdapter:
        return HasuraAdapter(registry)
```

Ensure every malformed parse/json/URL condition returns no inventory for that record; error messages must be constant strings and must not interpolate URL query values, GraphQL text, headers, variables, or response content.

- [ ] **Step 4: Run focused acceptance tests to verify they pass**

Run: `uv run pytest tests/test_providers_hasura.py tests/test_capture.py -k 'mutation or malformed or hasura or adapter_view' -v`

Expected: PASS. This is the required deterministic capture-to-discovery acceptance proof for the Hasura portion of spec acceptance criterion 4.

- [ ] **Step 5: Run required repository validation**

Run:

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

Expected: all commands pass. Treat a failure in unrelated parallel work as a separate finding; do not suppress, revert, or edit it inside P4d.

## Self-Review Notes

- **Spec coverage:** spec §5 requires Hasura as a provider adapter; Tasks 1–4 provide detection and normalized inventory without network execution. Spec §7's read-only discovery requirement is enforced by the no-client constraint. Acceptance criterion 4 is covered by deterministic parser/provider fixtures plus Task 4's capture-to-discovery proof.
- **Safety coverage:** P4a's internal origin isolation, P4b's sensitive query-field guard, and P4c's sensitive parent guard are explicit requirements in Tasks 2–3. Header values, GraphQL values, inline literals, and response values are excluded from all output contracts.
- **P3b dependency:** this plan does not pretend today's sanitized `RequestRecord` can support Hasura inventory. The prerequisite makes raw bytes process-local and non-serializable while preserving the public inventory/report boundary.
- **Provider registry:** no unowned registration abstraction is added. The later discovery-orchestrator phase owns actual automatic registration and must test it; P4d proves the adapter itself directly.
- **Known intentional limits:** subscriptions, batches, multipart uploads, remote-schema fields, fragments, schema introspection, arbitrary custom root naming, `_in`, and inline literals do not become provider-specific records in v1. They remain generic discovery evidence and never trigger network traffic.
