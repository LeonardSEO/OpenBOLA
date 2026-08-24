# OpenBOLA P4c: Firebase Realtime Database Provider Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `FirebaseRealtimeDatabaseAdapter`, a `ProviderAdapter` (spec §5) for Firebase Realtime Database's REST API — the classic BOLA/IDOR surface where misconfigured security rules leave a project's entire JSON tree readable/writable without authentication. Detects `*.firebaseio.com`/`*.firebasedatabase.app` traffic with the mandatory `.json` REST suffix, and produces per-path-shape `ResourceInventory` entries.

**Architecture:** Unlike PostgREST (P4b, IDs live in query filters), Firebase RTDB embeds record IDs directly in the URL path — e.g. `/messages/-NqA1bC2dEfGhIjKlMn.json` — so this adapter reuses `openbola.endpoints.templatize`/`extract_object_ids` exactly as `GenericAdapter` (P4a) does, just after stripping RTDB's mandatory `.json` path suffix first (every RTDB REST call ends in `.json`; nothing else in this codebase strips it). Firebase's own opaque push-ID format (`-NqA1bC2dEfGhIjKlMn`, 20 chars from a URL-safe alphabet) is already recognized by `endpoints.is_object_id` (confirmed by an executable probe before this plan was written — see Self-Review Notes), so no new ID-shape regex is needed. RTDB's "list" nodes (e.g. `/messages.json` returning `{"-NqA...": {...}, "-NqB...": {...}}`) hit the exact same "JSON object keys can themselves be record IDs" case P4a's `classify_key`/`top_level_json_keys` (already public, P4b) were built to handle — reused unchanged, no Firebase-specific key-routing logic needed.

**Tech Stack:** Python 3.11+, stdlib only (`urllib.parse.urlsplit`), reuses `openbola.endpoints.templatize`/`extract_object_ids` (unmodified), `openbola.discovery.classify_key`/`top_level_json_keys` (public since P4b), and `openbola.handles.InMemorySessionValueRegistry`.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 Resource and provider inventory: "Supabase/PostgREST, Firebase, and Hasura are the required v1 adapters")

## Global Constraints

- Adapters consume already captured evidence and produce normalized resource and capability contracts without sending requests themselves (spec §5) — `openbola/providers/firebase.py` must not import `httpx` or open any socket.
- `FieldInventory` tracks field **names only**, never inferred value types. Same deliberate, ledgered scope decision from P4a/P4b (see the roadmap's P4 entry).
- `record_handles` on a `ResourceInventory` must be `ValueHandle`s (`openbola.handles.ValueHandle`, `kind="record_id"`), never raw ID strings — this applies to both path-embedded IDs (via `extract_object_ids`) and Firebase push-ID-shaped JSON object keys (via `classify_key`).
- Detection never inspects or stores the RTDB `auth` query parameter's value — the parameter, when present, carries a live database secret or ID token, and RTDB's whole threat model is that misconfigured rules make requests work *without* it. Host+path shape alone is sufficient signal; there is no reason to touch a credential value even for a presence check.
- v1 scope covers Firebase **Realtime Database** only. Firestore's REST API (`firestore.googleapis.com`, a structurally different typed-document envelope) is explicitly out of scope for this plan — tracked separately on the roadmap as a follow-up, not a gap to close here.
- `FirebaseRealtimeDatabaseAdapter.name = "firebase-rtdb"` (distinguishes this from a future `"firebase-firestore"` adapter — the spec names the family "Firebase" but the two products have unrelated wire formats and deserve distinct provider names in reports).

---

### Task 1: `FirebaseRealtimeDatabaseAdapter`

**Files:**
- Create: `src/openbola/providers/firebase.py`
- Test: `tests/test_providers_firebase.py`

**Interfaces:**
- Consumes: `templatize`, `extract_object_ids` (`openbola.endpoints`, both already public, unmodified); `classify_key`, `top_level_json_keys` (`openbola.discovery`, public since P4b); `_resource_name_from_template` (`openbola.discovery`, still private — imported directly rather than promoted, since this is its second reuse and a third adapter, P4d, may or may not need it; promoting it is a decision for whenever a third consumer actually shows up, matching the precedent set by P4b's direct import of `endpoints._is_sensitive_field`); `InMemorySessionValueRegistry` (`openbola.handles`, P1) via constructor injection.
- Produces: `FirebaseRealtimeDatabaseAdapter(registry: InMemorySessionValueRegistry)` implementing `ProviderAdapter` with `name = "firebase-rtdb"`. Runs alongside `GenericAdapter` and `SupabaseAdapter`, not instead of them.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_providers_firebase.py`:

```python
from __future__ import annotations

from openbola.discovery import ProviderConfidence
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord
from openbola.providers.firebase import FirebaseRealtimeDatabaseAdapter


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


def test_detect_confirmed_with_firebaseio_host_and_json_suffix() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://myproj.firebaseio.com/users/42.json")]
    detection = adapter.detect(records)
    assert detection.provider == "firebase-rtdb"
    assert detection.confidence == ProviderConfidence.CONFIRMED


def test_detect_confirmed_with_regional_firebasedatabase_app_host() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [
        _record(
            "GET",
            "https://myproj-default-rtdb.europe-west1.firebasedatabase.app/users.json",
        ),
    ]
    assert adapter.detect(records).confidence == ProviderConfidence.CONFIRMED


def test_detect_inferred_from_firebase_host_without_json_suffix() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://myproj.firebaseio.com/users/42")]
    assert adapter.detect(records).confidence == ProviderConfidence.INFERRED


def test_detect_inferred_from_json_suffix_without_firebase_host() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://random.example.com/users/42.json")]
    assert adapter.detect(records).confidence == ProviderConfidence.INFERRED


def test_detect_unknown_with_no_signals() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://api.example.test/v1/orders")]
    assert adapter.detect(records).confidence == ProviderConfidence.UNKNOWN


def test_detect_unknown_on_empty_records() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    assert adapter.detect(()).confidence == ProviderConfidence.UNKNOWN


def test_inventory_ignores_records_without_json_suffix() -> None:
    adapter = FirebaseRealtimeDatabaseAdapter(InMemorySessionValueRegistry())
    records = [_record("GET", "https://myproj.firebaseio.com/users/42")]
    assert adapter.inventory(records) == ()


def test_inventory_extracts_path_embedded_push_id_and_fields() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://myproj.firebaseio.com/users/42/profile.json",
            response_body=b'{"email": "alice@example.test", "name": "Alice"}',
        ),
        _record(
            "PUT",
            "https://myproj.firebaseio.com/users/42/profile.json",
            body=b'{"name": "Alice Updated"}',
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.provider == "firebase-rtdb"
    assert inv.provider_confidence == ProviderConfidence.CONFIRMED
    assert inv.resource_name == "profile"
    assert inv.endpoint_template == "/users/{id}/profile"
    assert inv.observed_methods == frozenset({"GET", "PUT"})
    assert {f.name for f in inv.fields} == {"email", "name"}
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"42"}


def test_inventory_routes_push_id_shaped_list_keys_to_handles_not_fields() -> None:
    # A "list" node's response is a JSON object keyed by each child's push ID
    # -- structurally the same case P4a's classify_key/top_level_json_keys
    # were built for (Firebase-shaped keys), reused here unchanged.
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record(
            "GET",
            "https://myproj.firebaseio.com/messages.json",
            response_body=(
                b'{"-NqA1bC2dEfGhIjKlMn": {"text": "hi"}, '
                b'"-NqB2cD3eFgHiJkLmN": {"text": "yo"}}'
            ),
        ),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 1
    inv = inventories[0]
    assert inv.resource_name == "messages"
    assert inv.endpoint_template == "/messages"
    assert inv.fields == ()
    resolved = {registry.resolve_value(h) for h in inv.record_handles}
    assert resolved == {"-NqA1bC2dEfGhIjKlMn", "-NqB2cD3eFgHiJkLmN"}


def test_inventory_does_not_merge_across_origins() -> None:
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://tenant-a.firebaseio.com/users/42/profile.json"),
        _record("GET", "https://tenant-b.firebaseio.com/users/99/profile.json"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    for inv in inventories:
        assert inv.endpoint_template == "/users/{id}/profile"
        assert len(inv.record_handles) == 1


def test_inventory_confidence_is_scoped_per_group() -> None:
    # Mirrors the P4b final-review fix: confidence must never bleed across
    # groups that happen to share a path shape.
    registry = InMemorySessionValueRegistry()
    adapter = FirebaseRealtimeDatabaseAdapter(registry)
    records = [
        _record("GET", "https://tenant-a.firebaseio.com/users/1.json"),
        _record("GET", "https://random.example.com/users/2.json"),
    ]

    inventories = adapter.inventory(records)
    assert len(inventories) == 2
    confidences = {inv.provider_confidence for inv in inventories}
    assert confidences == {ProviderConfidence.CONFIRMED, ProviderConfidence.INFERRED}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_providers_firebase.py -v`
Expected: `ModuleNotFoundError: No module named 'openbola.providers.firebase'`

- [ ] **Step 3: Write the implementation**

Create `src/openbola/providers/firebase.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_providers_firebase.py -v`
Expected: all 11 tests pass.

- [ ] **Step 5: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/providers/firebase.py tests/test_providers_firebase.py
.venv/bin/mypy src/openbola/providers/firebase.py
```

Expected: full suite passes (332 pre-existing + 11 new = 343), ruff and mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/openbola/providers/firebase.py tests/test_providers_firebase.py
git commit -m "feat: add FirebaseRealtimeDatabaseAdapter for RTDB provider inventory"
```

---

## Self-Review Notes

- **Spec coverage:** §5's "Firebase ... [is a] required v1 adapter" → Task 1, scoped to Realtime Database (the classic misconfigured-rules BOLA surface). Firestore is explicitly out of scope (Global Constraints) and tracked on the roadmap as a follow-up rather than silently dropped.
- **Design validation:** every code path (detect confidence tiers including the two-way host/`.json` combination, path-suffix stripping including the root-path edge case `templatize("") == "/"`, push-ID recognition via the pre-existing `is_object_id`, list-node key routing via `classify_key`, cross-origin non-merging, per-group confidence scoping mirroring P4b's final-review fix) was executed against the real `openbola.endpoints`/`openbola.discovery`/`openbola.handles` dependencies before this plan was written, not merely reasoned about.
- **Placeholder scan:** every step has literal, already-validated code.
- **Type consistency:** `FirebaseRealtimeDatabaseAdapter` matches `ProviderAdapter`'s `name`/`detect`/`inventory` shape exactly (the `name = "firebase-rtdb"` bare class attribute form is already confirmed compatible with the Protocol's `@property` member by both P4a's and P4b's final reviews); `ResourceInventory`/`FieldInventory` field names match the P4a contract verbatim.
- **Applied precedent, not repeated bugs:** confidence is computed per-group inside the loop from the start (P4b's final review caught this as a bug fixed after the fact; this plan builds it in correctly the first time). Cross-origin grouping via `(origin, template)` is likewise built in from the start rather than needing a review-driven fix.
- **Known v1 scope limitations (ledgered, not gaps to close here):** Firestore's REST API (`firestore.googleapis.com`) is a separate, structurally different adapter, tracked as a roadmap follow-up; the Firebase Local Emulator Suite's URL shape (`?ns=<project>` query param, non-standard hosts like `localhost:9000`) is not detected — real deployed RTDB traffic only.
