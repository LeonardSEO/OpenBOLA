# OpenBOLA P4b: Supabase/PostgREST Provider Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `SupabaseAdapter`, the first provider-specific `ProviderAdapter` (spec §5), which detects Supabase-hosted or self-hosted PostgREST REST APIs from already-captured `RequestRecord`s and produces per-table `ResourceInventory` entries — including PostgREST's distinctive query-string-based record-ID filtering (`?id=eq.<value>`), which is structurally different from the path-embedded IDs `GenericAdapter` (P4a) already handles.

**Architecture:** PostgREST (the engine Supabase's REST API wraps) never embeds a record ID in the URL path — filtering happens entirely through query-string operators (`?id=eq.<uuid>`, `?status=eq.active`, `?age=gt.18`, ...). This makes `openbola.endpoints.extract_object_ids`/`templatize` (path-only, reused unchanged by P4a's `GenericAdapter`) inapplicable for ID extraction here, though still safe to reuse for path normalization since a PostgREST path never *has* an embedded ID to templatize away. Two reusable primitives from P4a's `discovery.py` — the JSON-top-level-key extraction and its ID/email-shaped-key routing — are promoted from private to public in Task 1 so this adapter (and P4c/P4d after it) can reuse them instead of re-implementing the same redaction-safety logic a second time. `SupabaseAdapter` itself lives in a new `openbola.providers` subpackage — `discovery.py` stays the contracts-plus-generic-fallback module; provider-specific adapters get their own package so P4c (Firebase) and P4d (Hasura) don't keep growing one file.

**Tech Stack:** Python 3.11+, stdlib only (`urllib.parse.urlsplit`/`parse_qsl`), reuses `openbola.endpoints.is_object_id`, `openbola.discovery.top_level_json_keys`/`classify_key` (promoted in Task 1), and `openbola.handles.InMemorySessionValueRegistry`.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 Resource and provider inventory: "Supabase/PostgREST, Firebase, and Hasura are the required v1 adapters")

## Global Constraints

- Adapters consume already captured evidence and produce normalized resource and capability contracts without sending requests themselves (spec §5) — `openbola/providers/supabase.py` must not import `httpx` or open any socket.
- `FieldInventory` tracks field **names only**, never inferred value types or query-filter values beyond the specific "is this a record ID" check this plan adds. This is the same deliberate, ledgered scope decision from P4a (see the roadmap's P4 entry), not an oversight to fix here.
- `record_handles` on a `ResourceInventory` must be `ValueHandle`s (`openbola.handles.ValueHandle`, `kind="record_id"`), never raw ID strings — persisted state, reports, and AI context see handles only (spec §5's overarching handle rule). This applies equally to IDs extracted from PostgREST's `eq.` query filters, not just path segments.
- Only the `eq.` (equality) PostgREST operator is used for record-ID extraction in v1. Range/membership operators (`gt.`, `lt.`, `in.`, `like.`, etc.) do not identify a single record and are out of scope — ledgered, not a gap to close in this plan.
- `SupabaseAdapter.name = "supabase"` (spec §5 names it explicitly as a required v1 adapter).

---

### Task 1: Promote `discovery.py`'s JSON-key helpers to public API

**Files:**
- Modify: `src/openbola/discovery.py`
- Modify: `tests/test_discovery.py` (comment references only — no behavior change)

**Interfaces:**
- Consumes: nothing new.
- Produces: `top_level_json_keys(body: bytes | None) -> set[str]` (renamed from `_top_level_json_keys`), `classify_key(key: str, field_names: set[str], object_ids: set[str]) -> None` (renamed from `_classify_key`). Both keep their exact existing signatures and behavior — this is a rename only, so `openbola.providers.supabase` (Task 2) can import and reuse them instead of duplicating the ID/email-shaped-key routing logic.

- [ ] **Step 1: Rename the two functions in `src/openbola/discovery.py`**

In `src/openbola/discovery.py`, rename `_classify_key` to `classify_key` and `_top_level_json_keys` to `top_level_json_keys` — both the `def` lines and every call site. After the rename, the two functions (in their existing position, near the bottom of the file, unchanged otherwise) read:

```python
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
```

And in `GenericAdapter.inventory`, update the two call sites (currently `_top_level_json_keys(...)` and `_classify_key(...)`) to the renamed `top_level_json_keys(...)` / `classify_key(...)`.

- [ ] **Step 2: Update stale comment references in the test file**

In `tests/test_discovery.py`, two comments reference the old private names (search for `_top_level_json_keys`). Update both occurrences of `_top_level_json_keys` in comments to `top_level_json_keys` — no test assertions or code change, comment text only.

- [ ] **Step 3: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/discovery.py tests/test_discovery.py
.venv/bin/mypy src/openbola/discovery.py
```

Expected: all 316 pre-existing tests still pass unchanged (pure rename, zero behavior change), ruff and mypy clean.

- [ ] **Step 4: Commit**

```bash
git add src/openbola/discovery.py tests/test_discovery.py
git commit -m "refactor: promote discovery.py JSON-key helpers to public API"
```

---

### Task 2: `SupabaseAdapter`

**Files:**
- Create: `src/openbola/providers/__init__.py`
- Create: `src/openbola/providers/supabase.py`
- Test: `tests/test_providers_supabase.py`

**Interfaces:**
- Consumes: `top_level_json_keys`/`classify_key` (`openbola.discovery`, Task 1), `is_object_id` (`openbola.endpoints`, pre-existing, unmodified), `ProviderConfidence`/`ProviderDetection`/`ResourceInventory`/`FieldInventory`/`ProviderAdapter` (`openbola.discovery`, P4a), `InMemorySessionValueRegistry` (`openbola.handles`, P1) via constructor injection — the concrete class, matching P4a's `GenericAdapter` precedent (write access to mint handles is deliberately narrower than the read-only `SessionValueRegistry` Protocol).
- Produces: `SupabaseAdapter(registry: InMemorySessionValueRegistry)` implementing `ProviderAdapter` with `name = "supabase"`. Runs alongside `GenericAdapter`, not instead of it (spec §5: generic discovery is always present).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_providers_supabase.py`:

```python
from __future__ import annotations

from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.providers.supabase import SupabaseAdapter


def _record(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    response_body: bytes | None = None,
    response_status: int | None = 200,
) -> RequestRecord:
    return RequestRecord(
        "alice",
        method,
        url,
        headers or {},
        body,
        response_status,
        {},
        response_body,
    )


def test_detect_confirmed_with_apikey_header_and_rest_path() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.42",
            headers={"apikey": "abc123", "Authorization": "Bearer jwt"},
        ),
    ]
    detection = adapter.detect(records)
    assert detection.provider == "supabase"
    assert detection.confidence == ProviderConfidence.CONFIRMED


def test_detect_confirmed_apikey_header_lookup_is_case_insensitive() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders",
            headers={"ApiKey": "abc123"},
        ),
    ]
    assert adapter.detect(records).confidence == ProviderConfidence.CONFIRMED


def test_detect_inferred_from_rest_path_without_apikey() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://self-hosted.example.com/rest/v1/orders?id=eq.42")]
    detection = adapter.detect(records)
    assert detection.confidence == ProviderConfidence.INFERRED


def test_detect_inferred_from_postgrest_operator_without_rest_prefix() -> None:
    # Plain self-hosted PostgREST is commonly mounted at root, with no
    # "/rest/v1/" prefix at all -- the operator-shaped query value is the
    # only signal available in that deployment shape.
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.com/orders?id=eq.42")]
    detection = adapter.detect(records)
    assert detection.confidence == ProviderConfidence.INFERRED


def test_detect_unknown_with_no_signals() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.test/v1/orders")]
    detection = adapter.detect(records)
    assert detection.confidence == ProviderConfidence.UNKNOWN


def test_detect_unknown_on_empty_records() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    assert adapter.detect(()).confidence == ProviderConfidence.UNKNOWN


def test_inventory_ignores_non_rest_records() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.test/v1/orders")]
    assert adapter.inventory(records) == ()


def test_inventory_extracts_table_fields_and_eq_filter_handle() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders"
            "?id=eq.550e8400-e29b-41d4-a716-446655440000",
            headers={"apikey": "k"},
            response_body=b'{"id": "550e8400-e29b-41d4-a716-446655440000", "total": 9.5}',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.provider == "supabase"
    assert inv.provider_confidence == ProviderConfidence.CONFIRMED
    assert inv.resource_name == "orders"
    assert inv.endpoint_template == "/rest/v1/orders"
    assert inv.observed_methods == frozenset({"GET"})
    assert {f.name for f in inv.fields} == {"id", "total"}
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"550e8400-e29b-41d4-a716-446655440000"}


def test_inventory_ignores_non_object_id_eq_filter_values() -> None:
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?status=eq.active",
            headers={"apikey": "k"},
        ),
    ]
    inv = adapter.inventory(records)[0]
    assert inv.record_handles == ()


def test_inventory_deduplicates_record_handles_within_a_table() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "PATCH",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "GET",
            "https://xyzcompany.supabase.co/rest/v1/orders?id=eq.2",
            headers={"apikey": "k"},
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.observed_methods == frozenset({"GET", "PATCH"})
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"1", "2"}
    assert len(inv.record_handles) == 2


def test_inventory_does_not_merge_tables_across_origins() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://tenant-a.supabase.co/rest/v1/orders?id=eq.1",
            headers={"apikey": "k"},
        ),
        _record(
            "GET",
            "https://tenant-b.supabase.co/rest/v1/orders?id=eq.2",
            headers={"apikey": "k"},
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    for inv in inventories:
        assert inv.endpoint_template == "/rest/v1/orders"
        assert len(inv.record_handles) == 1


def test_inventory_separates_multiple_tables() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = SupabaseAdapter(registry)
    records = [
        _record(
            "GET", "https://xyzcompany.supabase.co/rest/v1/orders", headers={"apikey": "k"}
        ),
        _record(
            "GET", "https://xyzcompany.supabase.co/rest/v1/customers", headers={"apikey": "k"}
        ),
    ]

    inventories = adapter.inventory(records)
    assert {inv.resource_name for inv in inventories} == {"orders", "customers"}


def test_inventory_rpc_calls_collapse_to_a_single_rpc_pseudo_table() -> None:
    # PostgREST RPC calls (POST /rest/v1/rpc/<function_name>) are grouped
    # under one "rpc" resource_name rather than one per function -- a known
    # v1 scope limitation (see the plan's Global Constraints / ledger).
    adapter = SupabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "POST",
            "https://xyzcompany.supabase.co/rest/v1/rpc/calculate_total",
            headers={"apikey": "k"},
            body=b'{"order_id": "550e8400-e29b-41d4-a716-446655440000"}',
        ),
    ]
    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    assert inventories[0].resource_name == "rpc"
    assert inventories[0].endpoint_template == "/rest/v1/rpc"
    assert {f.name for f in inventories[0].fields} == {"order_id"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_providers_supabase.py -v`
Expected: `ModuleNotFoundError: No module named 'openbola.providers'`

- [ ] **Step 3: Write the implementation**

Create `src/openbola/providers/__init__.py` (empty file — marks the package):

```python
```

Create `src/openbola/providers/supabase.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_providers_supabase.py -v`
Expected: all 13 tests pass.

- [ ] **Step 5: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/providers/ tests/test_providers_supabase.py
.venv/bin/mypy src/openbola/providers/
```

Expected: full suite passes (316 pre-existing + 13 new = 329), ruff and mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/openbola/providers/__init__.py src/openbola/providers/supabase.py tests/test_providers_supabase.py
git commit -m "feat: add SupabaseAdapter for PostgREST-based provider inventory"
```

---

## Self-Review Notes

- **Spec coverage:** §5's "Supabase/PostgREST ... are the required v1 adapters" → Task 2. The `ProviderAdapter` Protocol itself was already delivered in P4a; this plan implements one concrete adapter against it, confirming the Protocol shape (fixed in P4a's final review to use a read-only `@property` for `name`) is actually usable by a second, independent implementer — `SupabaseAdapter.name = "generic"`-style bare class attribute works unchanged.
- **Design validation:** every code path in Task 2's implementation (detect confidence tiers, table-name extraction including the RPC pseudo-table case, `eq.`-filter record-ID extraction, cross-origin non-merging, non-object-id filter values being ignored) was executed against the real `openbola.endpoints.is_object_id`/`openbola.handles.InMemorySessionValueRegistry` before this plan was written, not merely reasoned about — see the ledger for this plan's pre-flight notes.
- **Placeholder scan:** every step has literal, already-validated code; no "add error handling" or "similar to Task N" placeholders.
- **Type consistency:** `SupabaseAdapter` matches `ProviderAdapter`'s `name`/`detect`/`inventory` shape exactly as defined in `discovery.py` (P4a, already fixed to use a `@property` for `name`); `ResourceInventory`/`FieldInventory` field names match P4a's contract verbatim.
- **Known v1 scope limitations (ledgered, not gaps to close here):** RPC calls (`POST /rest/v1/rpc/<fn>`) collapse into a single `"rpc"` resource_name rather than one per function; only the `eq.` operator is used for record-ID extraction (`in.`/`gt.`/etc. are ignored); like P4a's `GenericAdapter`, `ResourceInventory` carries no explicit origin/base_url field even though grouping is origin-aware internally — same deferred design question as P4a, now confirmed to recur across two independent adapters, worth resolving in P4c or P4d rather than being pushed indefinitely.
