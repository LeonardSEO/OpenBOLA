# OpenBOLA P3b: Full-Fidelity In-Session Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture complete request, response, and browser-session material only behind process-local handles, while preserving the existing sanitized HAR contract and enabling an active TUI to inspect values and run provider discovery without making those values transferable or persistent.

**Architecture:** Keep `RequestRecord` as the sanitized, transferable evidence contract. `capture_session()` performs one scope-routed Playwright run with two collectors: the current sanitized HAR collector and a new full-fidelity collector that stores raw material only in `SessionValueStore` and returns handle-only `InSessionCapture` exchanges. The only bridge to provider discovery is an explicit callback that resolves temporary full `RequestRecord` instances, invokes the callback synchronously, and drops its local references before returning.

**Tech Stack:** Python 3.11+, stdlib `asyncio`/`dataclasses`/`typing`, existing optional `playwright.async_api`, pytest with `asyncio.run()`, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 opaque handles, §7 steps 4 and 9, §8 storage/privacy, §9 local finding detail, acceptance criterion 8).

## Global Constraints

- Python is 3.11+; retain the `src/` layout, typed public APIs, pytest tests, standard-library-first implementation, and existing project formatting.
- Every browser navigation and captured request must pass the confirmed `ScopeGuard`; redirects remain explicit and no route may bypass `_scoped_route`.
- `capture_har()`, `parse_har_records()`, `RequestRecord`, and every HAR written to disk retain their existing sanitized-only behavior.
- Raw request URLs, query values, headers, cookies, request bodies, response headers, response bodies, IDs, and browser storage state may exist only in the active `SessionValueStore`; no raw field is added to `RequestRecord`, state, reports, MCP outputs, AI payloads, logs, progress events, or exceptions.
- The full collector has hard limits of 10,000 exchanges, 1 MiB for one captured request/response body, 1 MiB for browser storage state, and 25 MiB total raw in-session material. Hitting a limit fails the capture before a HAR is written or a session result is returned.
- The collector must await every scheduled response-body task, convert collector failures into `CaptureError` without embedding a raw value, and close the session-value store on capture failure.
- `InSessionCapture.close()` is a logical access revocation: it clears the in-memory store and causes all subsequent resolve/view calls to fail. It makes no secure-erasure claim for Python objects or filesystem remnants.
- Full values are visible only through explicit active-session methods. The TUI must mask header/cookie material by default; this phase provides the data boundary, not a UI.
- No new dependency is added. Do not modify pipeline, reporting, state, MCP, AI, provider, scope, or executor production code in this phase.

---

## File structure

| File | Responsibility |
|---|---|
| `src/openbola/handles.py` | Define the runtime-checkable write/close capability needed by in-session capture and make the concrete registry revoke values on close. |
| `src/openbola/capture.py` | Define handle-only session exchanges and raw-material private types; collect raw Playwright material in parallel with sanitized HAR entries; expose `capture_session()` and the narrowly scoped adapter callback. |
| `tests/test_handles.py` | Prove the new store capability and lifecycle revocation without serializing a registry. |
| `tests/test_capture.py` | Fake Playwright tests for full capture, limits, async response task completion, scope failure, lifecycle, sanitized HAR compatibility, and the ephemeral adapter callback. |
| `tests/test_reporting.py` | Prove reporting rejects/omits handle-only session material and emitted report files have no full-value sentinel. |
| `tests/test_ai.py` | Prove the sanitized planning context constructed from the adapter callback contains no full-value sentinel. |
| `tests/test_mcp_server.py` | Prove MCP can import only the session's sanitized HAR and never receives the full-value sentinel. |
| `tests/test_state.py` | Prove a handle-only session exchange is rejected by the persistent audit allowlist and the database/WAL/SHM contain no full-value sentinel. |
| `tests/conftest.py` | Provide one in-memory `captured_session_with_sentinels` fixture with a deliberately sanitized HAR for cross-boundary negative tests. |

`RequestRecord` intentionally remains in `src/openbola/models.py` unchanged. It is used by HAR import, pipeline, MCP, state-adjacent code, and provider adapters; enriching it with raw fields would erase the transferable-versus-session-only boundary this plan establishes.

### Task 1: Session-value store capability and lifecycle

**Files:**
- Modify: `src/openbola/handles.py:14-100`
- Test: `tests/test_handles.py`

**Interfaces:**
- Consumes: existing `SecretHandle`, `ValueHandle`, `ValueKind`, and `SessionValueRegistry`.
- Produces:

```python
@runtime_checkable
class SessionValueStore(SessionValueRegistry, Protocol):
    def store_value(self, *, kind: ValueKind, value: object) -> ValueHandle: ...
    def close(self) -> None: ...

class InMemorySessionValueRegistry:
    def close(self) -> None: ...
```

After `close()`, `store_secret`, `store_value`, `resolve_secret`, and `resolve_value` must all raise `RuntimeError("session value registry is closed")`. `close()` is idempotent.

- [ ] **Step 1: Write the failing lifecycle and protocol tests**

Append these tests to `tests/test_handles.py`:

```python
from typing import assert_type

from openbola.handles import SessionValueStore


def test_registry_satisfies_session_value_store_and_revokes_values_on_close() -> None:
    registry = InMemorySessionValueRegistry()
    assert isinstance(registry, SessionValueStore)
    secret = registry.store_secret(purpose="login_password", value="HANDLE_SECRET_SENTINEL")
    value = registry.store_value(kind="body", value=b"HANDLE_BODY_SENTINEL")

    registry.close()
    registry.close()

    for operation in (
        lambda: registry.resolve_secret(secret),
        lambda: registry.resolve_value(value),
        lambda: registry.store_secret(purpose="x", value="y"),
        lambda: registry.store_value(kind="body", value=b"x"),
    ):
        with pytest.raises(RuntimeError, match="registry is closed"):
            operation()


def test_session_value_store_protocol_has_only_handle_operations() -> None:
    registry: SessionValueStore = InMemorySessionValueRegistry()
    handle = registry.store_value(kind="session_state", value={"cookie": "opaque"})
    assert_type(handle, ValueHandle)
    assert registry.resolve_value(handle) == {"cookie": "opaque"}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `uv run pytest tests/test_handles.py -k "session_value_store or revokes_values" -v`

Expected: FAIL because `SessionValueStore` and `InMemorySessionValueRegistry.close()` do not exist.

- [ ] **Step 3: Implement the closed-store state**

In `src/openbola/handles.py`, add `runtime_checkable` to the typing import and add the protocol directly after `SessionValueRegistry`:

```python
@runtime_checkable
class SessionValueStore(SessionValueRegistry, Protocol):
    """Process-local registry capability required by full-fidelity capture."""

    def store_value(self, *, kind: ValueKind, value: object) -> ValueHandle: ...
    def close(self) -> None: ...
```

Extend `InMemorySessionValueRegistry.__slots__` with `_closed`, initialize it to `False`, and add these methods/helpers:

```python
def _require_open(self) -> None:
    if self._closed:
        raise RuntimeError("session value registry is closed")

def close(self) -> None:
    with self._lock:
        self._secrets.clear()
        self._values.clear()
        self._closed = True
```

Call `_require_open()` while holding `_lock` at the start of `store_secret`, `store_value`, `resolve_secret`, and `resolve_value`. Keep unknown-handle failures as `LookupError`; only a closed registry raises `RuntimeError`.

- [ ] **Step 4: Run focused checks to verify the implementation passes**

Run:

```bash
uv run pytest tests/test_handles.py -v
uv run ruff check src/openbola/handles.py tests/test_handles.py
uv run mypy src/openbola/handles.py
```

Expected: all tests pass; Ruff and mypy report no errors.

- [ ] **Step 5: Commit the independently testable handle boundary**

```bash
git add src/openbola/handles.py tests/test_handles.py
git commit -m "feat: add closable session value store"
```

### Task 2: Handle-only full-session read model

**Files:**
- Modify: `src/openbola/capture.py:20-188`
- Test: `tests/test_capture.py`

**Interfaces:**
- Consumes: `RequestRecord`, `ValueHandle`, `SessionValueStore`, existing `_MAX_CAPTURE_ENTRIES`, and `CaptureError`.
- Produces:

```python
@dataclass(frozen=True)
class SessionRequestMaterial:
    url: str
    headers: Mapping[str, str]
    body: bytes | None

@dataclass(frozen=True)
class SessionResponseMaterial:
    status: int
    headers: Mapping[str, str]
    body: bytes | None

@dataclass(frozen=True)
class SessionExchange:
    record: RequestRecord
    request_material_handle: ValueHandle
    response_material_handle: ValueHandle

@dataclass(frozen=True, init=False)
class InSessionCapture:
    har_path: Path
    exchanges: tuple[SessionExchange, ...]
    browser_state_handle: ValueHandle

    def __init__(
        self,
        har_path: Path,
        exchanges: tuple[SessionExchange, ...],
        browser_state_handle: ValueHandle,
        registry: SessionValueStore,
    ) -> None: ...
    def request_material(self, exchange: SessionExchange) -> SessionRequestMaterial: ...
    def response_material(self, exchange: SessionExchange) -> SessionResponseMaterial: ...
    def browser_state(self) -> Mapping[str, object]: ...
    def with_adapter_records(
        self, consumer: Callable[[Sequence[RequestRecord]], T]
    ) -> T: ...
    def close(self) -> None: ...
```

`SessionRequestMaterial` and `SessionResponseMaterial` are frozen private-to-capture dataclasses with `repr=False` on raw fields. They contain the raw URL, header mapping, and body for an exchange; both are stored only as `ValueHandle(kind="session_state")` values. `InSessionCapture` stores the `SessionValueStore` in a non-repr private field, disables pickle via `__reduce__`, and rejects a foreign exchange, a closed capture, a wrong handle kind, or a malformed resolved value with a non-sensitive `CaptureError`.

- [ ] **Step 1: Write failing boundary tests**

Append these tests to `tests/test_capture.py`:

```python
def test_in_session_capture_exposes_raw_material_only_via_session_handles(tmp_path: Path) -> None:
    from openbola.capture import InSessionCapture, SessionExchange
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    safe = RequestRecord("alice", "GET", "https://api.example.test/v1/items/[REDACTED]")
    request_handle = registry.store_value(kind="session_state", value=object())
    response_handle = registry.store_value(kind="session_state", value=object())
    state_handle = registry.store_value(kind="session_state", value={"cookies": []})
    exchange = SessionExchange(safe, request_handle, response_handle)

    capture = InSessionCapture(tmp_path / "capture.har", (exchange,), state_handle, registry)

    assert "FULL_VALUE_SENTINEL" not in repr(capture)
    assert capture.exchanges[0].record.url.endswith("[REDACTED]")
    with pytest.raises(CaptureError, match="request material"):
        capture.request_material(exchange)
    with pytest.raises(TypeError, match="serialization"):
        import pickle
        pickle.dumps(capture)


def test_in_session_capture_close_revokes_every_handle(tmp_path: Path) -> None:
    from openbola.capture import InSessionCapture, SessionExchange, SessionRequestMaterial, SessionResponseMaterial
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    request_handle = registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial("https://api.example.test/v1/items/42", {}, None),
    )
    response_handle = registry.store_value(
        kind="session_state", value=SessionResponseMaterial(200, {}, b"FULL_VALUE_SENTINEL")
    )
    state_handle = registry.store_value(kind="session_state", value={"cookies": []})
    exchange = SessionExchange(RequestRecord("alice", "GET", "https://api.example.test/v1/items/42"), request_handle, response_handle)
    capture = InSessionCapture(tmp_path / "capture.har", (exchange,), state_handle, registry)

    assert capture.response_material(exchange).body == b"FULL_VALUE_SENTINEL"
    capture.close()
    with pytest.raises(CaptureError, match="closed"):
        capture.response_material(exchange)
    with pytest.raises(RuntimeError, match="registry is closed"):
        registry.resolve_value(response_handle)
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_capture.py -k "in_session_capture" -v`

Expected: FAIL because `SessionExchange`, `InSessionCapture`, and the material dataclasses do not exist.

- [ ] **Step 3: Add the handle-only data model without changing `RequestRecord`**

Add imports for `Callable`, `Iterator`, `Sequence`, `TypeVar`, `NoReturn`, `SessionValueStore`, and `ValueHandle`. Define `T = TypeVar("T")`, then add these exact raw-material types after `LoginRecipe`:

```python
@dataclass(frozen=True)
class SessionRequestMaterial:
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None = field(repr=False)


@dataclass(frozen=True)
class SessionResponseMaterial:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None = field(repr=False)


@dataclass(frozen=True)
class SessionExchange:
    record: RequestRecord
    request_material_handle: ValueHandle
    response_material_handle: ValueHandle
```

Implement `InSessionCapture` with a custom `__init__` that validates a regular, non-symlink HAR path, non-empty exchanges, handle kind `session_state`, and `isinstance(registry, SessionValueStore)`. Resolve material through one private `_resolve_material(handle, expected_type, label)` method, and make `close()` delegate to `self._registry.close()` exactly once. `with_adapter_records()` must create a local tuple of raw `RequestRecord` instances from the two resolved material objects, call `consumer(records)`, and in `finally` replace the local tuple with `()`; it must never return the raw records themselves. Make `__reduce__` raise `TypeError("InSessionCapture serialization is disabled.")`.

The `RequestRecord` constructed inside `with_adapter_records()` uses raw values only in this local expression:

```python
RequestRecord(
    exchange.record.identity,
    exchange.record.method,
    request.url,
    request.headers,
    request.body,
    response.status,
    response.headers,
    response.body,
)
```

- [ ] **Step 4: Run the focused read-model tests**

Run:

```bash
uv run pytest tests/test_capture.py -k "in_session_capture" -v
uv run ruff check src/openbola/capture.py tests/test_capture.py
uv run mypy src/openbola/capture.py
```

Expected: all selected tests pass; no Ruff or mypy diagnostics.

- [ ] **Step 5: Commit the read-model contract**

```bash
git add src/openbola/capture.py tests/test_capture.py
git commit -m "feat: add handle-only in-session capture model"
```

### Task 3: Parallel full-fidelity collector and one scoped browser run

**Files:**
- Modify: `src/openbola/capture.py:136-247, 583-609`
- Test: `tests/test_capture.py`

**Interfaces:**
- Consumes: `InMemoryEventCollector`, `CaptureCollector`, `InSessionCapture`, `SessionValueStore`, `ScopeGuard`, `_sanitize_*`, `_write_sanitized_har`, and the login path.
- Produces:

```python
async def capture_session(
    config: CaptureConfig,
    scope_guard: ScopeGuard,
    *,
    registry: SessionValueStore,
) -> InSessionCapture: ...
```

`capture_har()` retains its signature and return type. Both entrypoints call one private `_run_scoped_capture(...)` function; it creates one browser and one isolated context, calls `context.route("**/*", _scoped_route(...))` before attaching collectors or creating a page, performs the existing login branch once, waits for all response-body tasks, checks scope failures, and only then lets the caller write the sanitized HAR.

- [ ] **Step 1: Write failing dual-collector, async, and limit tests**

Add a fake Playwright harness to `tests/test_capture.py` in which `Context.on()` records handlers, `Page.click()` emits one request/response, and `FakeResponse.body()` is async. Add these tests with the literal sentinels shown:

```python
def test_capture_session_writes_sanitized_har_and_keeps_full_values_in_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, config = _full_session_harness(tmp_path, monkeypatch)

    session = asyncio.run(capture.capture_session(config, Guard(), registry=registry))

    [exchange] = session.exchanges
    assert session.response_material(exchange).body == b'{"id":"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc","name":"FULL_VALUE_SENTINEL"}'
    assert session.request_material(exchange).headers["Authorization"] == "Bearer REQUEST_SECRET_SENTINEL"
    har_bytes = session.har_path.read_bytes()
    assert b"FULL_VALUE_SENTINEL" not in har_bytes
    assert b"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc" not in har_bytes
    assert b"REQUEST_SECRET_SENTINEL" not in har_bytes
    [record] = capture.parse_har_records(session.har_path, "alice")
    assert record.response_body is None
    assert record.body != b'{"id":"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc"}'


def test_capture_session_awaits_response_body_before_returning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, config = _full_session_harness(tmp_path, monkeypatch, response_body_delay=True)
    session = asyncio.run(capture.capture_session(config, Guard(), registry=registry))
    assert session.response_material(session.exchanges[0]).body == b"FULL_VALUE_SENTINEL"


@pytest.mark.parametrize(
    ("body_bytes", "total_bytes", "message"),
    [
        (capture._MAX_FULL_BODY_BYTES + 1, 0, "body"),
        (16, capture._MAX_FULL_SESSION_BYTES + 1, "session material"),
    ],
)
def test_capture_session_fails_closed_at_full_material_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body_bytes: int,
    total_bytes: int,
    message: str,
) -> None:
    registry, config = _full_session_harness(
        tmp_path, monkeypatch, response_body=b"x" * body_bytes, extra_state_bytes=total_bytes
    )
    with pytest.raises(CaptureError, match=message):
        asyncio.run(capture.capture_session(config, Guard(), registry=registry))
    assert not (config.capture_root / config.output_path).exists()
    with pytest.raises(RuntimeError, match="registry is closed"):
        registry.store_value(kind="body", value=b"x")
```

- [ ] **Step 2: Run the selected tests to verify they fail**

Run: `uv run pytest tests/test_capture.py -k "capture_session and (sanitized_har or awaits_response or full_material_limits)" -v`

Expected: FAIL because `capture_session` and full-material limits do not exist.

- [ ] **Step 3: Implement the raw collector and shared runner**

Add these constants next to `_MAX_CAPTURE_ENTRIES`:

```python
_MAX_FULL_BODY_BYTES = 1024 * 1024
_MAX_FULL_STATE_BYTES = 1024 * 1024
_MAX_FULL_SESSION_BYTES = 25 * 1024 * 1024
```

Implement a private `_FullFidelityEventCollector` with these rules:

```python
class _FullFidelityEventCollector:
    def __init__(self, registry: SessionValueStore) -> None: ...
    def attach(self, context: Any) -> None: ...
    async def finalize(self, context: Any) -> tuple[tuple[SessionExchange, ...], ValueHandle]: ...
```

- On `request`, reject exchange counts above `_MAX_CAPTURE_ENTRIES`, read the request URL, headers, and `post_data_buffer` (fall back to encoded `post_data` only for the test doubles), require bytes or `None`, validate the body limit, and store a `SessionRequestMaterial` under `kind="session_state"`.
- On `response`, schedule an async task with `asyncio.create_task`; the task obtains `await response.body()`, requires bytes, validates its body limit, then stores a `SessionResponseMaterial` under `kind="session_state"`. It records task exceptions for `finalize()` rather than letting them become unhandled task exceptions.
- Maintain one protected counter of byte lengths for raw URLs, header names/values, bodies, and JSON-serialized `await context.storage_state()`. Reject total material above `_MAX_FULL_SESSION_BYTES`; reject storage state above `_MAX_FULL_STATE_BYTES`. The exception messages are exactly `"full capture body exceeds the safe limit"`, `"full capture state exceeds the safe limit"`, or `"full capture session material exceeds the safe limit"` and never interpolate a raw value.
- Pair request and response by `id(response.request)`. A response with no captured request, a duplicate response, a missing response body task, malformed browser state, or an unfinished exchange at finalization raises `CaptureError("full capture event stream is incomplete")`.
- Create each public `SessionExchange` from the already-sanitized `RequestRecord` made by a private `_entry_to_record`-equivalent conversion of the sanitized collector entry. Do not derive a public record from raw material.

Extract the browser/context setup from `capture_har()` into `_run_scoped_capture(config, scope_guard, sanitized_collector, full_collector, registry)`. It returns sanitized entries and, if requested, full exchanges/state. It preserves existing cleanup order (`page`, `context`, `browser`) and runs `await full_collector.finalize(context)` before `context.close()`. On any exception it calls `registry.close()` when a full collector was requested and does not call `_write_sanitized_har`.

Implement `capture_session()` by creating `InMemoryEventCollector` and `_FullFidelityEventCollector`, calling `_run_scoped_capture()` once, writing the sanitized HAR with `_write_sanitized_har()`, and returning `InSessionCapture`. Keep `capture_har()` on the same runner with `full_collector=None`; its custom collector behavior remains unchanged.

- [ ] **Step 4: Run capture regression checks**

Run:

```bash
uv run pytest tests/test_capture.py -v
uv run ruff check src/openbola/capture.py tests/test_capture.py
uv run mypy src/openbola/capture.py
```

Expected: all capture tests pass; the existing `capture_har` and login-recipe tests remain green; Ruff and mypy report no errors.

- [ ] **Step 5: Commit the single-run collector integration**

```bash
git add src/openbola/capture.py tests/test_capture.py
git commit -m "feat: capture full session material in memory"
```

### Task 4: Scope, lifecycle, and ephemeral discovery-view proof

**Files:**
- Modify: `src/openbola/capture.py:190-247`
- Test: `tests/test_capture.py`, `tests/test_discovery.py`

**Interfaces:**
- Consumes: `capture_session()`, `InSessionCapture.with_adapter_records()`, `ProviderAdapter`, and existing `GenericAdapter`.
- Produces: a callback-only full-record bridge. No function returns `Sequence[RequestRecord]` containing raw data.

- [ ] **Step 1: Write failing scope and discovery bridge tests**

Append these tests:

```python
def test_capture_session_rejects_wrong_registry_capability(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    with pytest.raises(CaptureError, match="SessionValueStore"):
        asyncio.run(capture.capture_session(config, Guard(), registry=object()))  # type: ignore[arg-type]


def test_capture_session_scope_failure_returns_no_full_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, config = _full_session_harness(tmp_path, monkeypatch, off_scope_request=True)
    guard = make_scope_guard(
        tmp_path, allowed_hosts=["api.example.test"], allowed_cidrs=["203.0.113.0/24"]
    )
    with pytest.raises(CaptureError, match="confirmed scope"):
        asyncio.run(capture.capture_session(config, guard, registry=registry))
    assert not (config.capture_root / config.output_path).exists()
    with pytest.raises(RuntimeError, match="registry is closed"):
        registry.store_value(kind="body", value=b"x")


def test_session_adapter_callback_sees_full_records_but_publishes_only_inventory_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.discovery import GenericAdapter

    registry, config = _full_session_harness(tmp_path, monkeypatch)
    session = asyncio.run(capture.capture_session(config, Guard(), registry=registry))
    inventory = session.with_adapter_records(GenericAdapter(registry).inventory)

    assert {field.name for field in inventory[0].fields} == {"id", "name"}
    assert "FULL_VALUE_SENTINEL" not in repr(inventory)
    assert registry.resolve_value(inventory[0].record_handles[0]) == "RAW_ID_4eC39HqLyjWDarjtT1zdp7dc"
```

- [ ] **Step 2: Run the selected tests to verify they fail**

Run: `uv run pytest tests/test_capture.py -k "wrong_registry or scope_failure or adapter_callback" -v`

Expected: FAIL until runtime capability validation, failure cleanup, and `with_adapter_records()` are complete.

- [ ] **Step 3: Harden capability validation and the ephemeral callback**

At the start of `capture_session()`, reject `not isinstance(registry, SessionValueStore)` with `CaptureError("registry must implement SessionValueStore")`. In `with_adapter_records()`, validate that every exchange belongs to the capture, resolve raw materials only after `_require_open()`, create local `RequestRecord` values, invoke `consumer`, and clear the local tuple in a `finally` block. Do not add a public `records`, `raw_records`, `to_records`, `export`, or iterator property.

Preserve `_scoped_route` unchanged. In `_run_scoped_capture()`, call `full_collector.finalize()` only after the page/login flow has completed and before writing any HAR. If `_scoped_route` recorded a failure, close the registry and raise the existing scope error before a session object can be constructed.

In `tests/test_discovery.py`, keep the assertion limited to inventory field names and `ValueHandle` resolution. Do not write a raw provider result to disk or add raw type inference; P4's `FieldInventory` remains name-only.

- [ ] **Step 4: Run focused integration checks**

Run:

```bash
uv run pytest tests/test_capture.py tests/test_discovery.py -q
uv run ruff check src/openbola/capture.py tests/test_capture.py tests/test_discovery.py
uv run mypy src/openbola/capture.py src/openbola/discovery.py
```

Expected: all selected tests pass and static checks are clean.

- [ ] **Step 5: Commit the scoped ephemeral adapter view**

```bash
git add src/openbola/capture.py tests/test_capture.py tests/test_discovery.py
git commit -m "feat: expose full records only through session callback"
```

### Task 5: Negative persistence, reporting, AI, and MCP boundaries

**Files:**
- Create: `tests/conftest.py`
- Test: `tests/test_state.py`, `tests/test_reporting.py`, `tests/test_ai.py`, `tests/test_mcp_server.py`

**Interfaces:**
- Consumes: existing fail-closed persistence/reporting/AI/MCP public APIs and the `capture_session()` harness from Task 3.
- Produces: regression evidence that only the sanitized HAR may cross the session boundary; no production-code changes are expected in this task. A failing test indicates an existing boundary was widened and must be repaired in its owning module before P3b can be completed.

- [ ] **Step 1: Add the reusable in-memory-session fixture**

Create `tests/conftest.py` with this exact fixture. It writes only a structural sanitized HAR and keeps every raw sentinel behind `InSessionCapture` handles:

```python
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openbola.capture import (
    InSessionCapture,
    SessionExchange,
    SessionRequestMaterial,
    SessionResponseMaterial,
)
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord


@pytest.fixture
def captured_session_with_sentinels(tmp_path: Path) -> InSessionCapture:
    har_path = tmp_path / "session.har"
    har_path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://api.example.test/v1/items/[REDACTED]",
                                "headers": [],
                                "postData": {"mimeType": "application/json", "text": "[REDACTED]"},
                            },
                            "response": {"status": 200, "headers": [], "content": {}},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    registry = InMemorySessionValueRegistry()
    request_handle = registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial(
            "https://api.example.test/v1/items/RAW_ID_4eC39HqLyjWDarjtT1zdp7dc",
            {"Authorization": "Bearer REQUEST_SECRET_SENTINEL"},
            b'{"id":"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc"}',
        ),
    )
    response_handle = registry.store_value(
        kind="session_state",
        value=SessionResponseMaterial(
            200,
            {"Set-Cookie": "sid=COOKIE_SECRET_SENTINEL"},
            b'{"id":"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc","name":"FULL_VALUE_SENTINEL"}',
        ),
    )
    browser_state_handle = registry.store_value(
        kind="session_state",
        value={"cookies": [{"name": "sid", "value": "COOKIE_SECRET_SENTINEL"}], "origins": []},
    )
    exchange = SessionExchange(
        RequestRecord("alice", "POST", "https://api.example.test/v1/items/[REDACTED]"),
        request_handle,
        response_handle,
    )
    capture = InSessionCapture(har_path, (exchange,), browser_state_handle, registry)
    yield capture
    capture.close()
```

- [ ] **Step 2: Add full-value sentinel regression tests**

Add one test per boundary, all using `FULL_VALUE_SENTINEL`, `RAW_ID_4eC39HqLyjWDarjtT1zdp7dc`, and `REQUEST_SECRET_SENTINEL` from the Task 3 fake session:

```python
def test_state_rejects_session_capture_and_persists_no_full_value_sentinel(
    tmp_path: Path, captured_session_with_sentinels: InSessionCapture
) -> None:
    store = StateStore(tmp_path / "state.db")
    with pytest.raises(ValueError):
        store.add_audit_event(
            AuditEventType.RUN_STARTED, {"capture_exchange": captured_session_with_sentinels.exchanges[0]}
        )
    db_path = tmp_path / "state.db"
    artifact_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm"))
        if candidate.exists()
    )
    assert b"FULL_VALUE_SENTINEL" not in artifact_bytes
    assert b"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc" not in artifact_bytes
    assert b"REQUEST_SECRET_SENTINEL" not in artifact_bytes


def test_reports_reject_session_material_and_emit_no_full_value_sentinel(
    tmp_path: Path, captured_session_with_sentinels: InSessionCapture
) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        serialize_evidence({"capture_exchange": captured_session_with_sentinels.exchanges[0]})
    paths = write_reports(_bundle(), output_dir=tmp_path / "reports")
    assert all(b"FULL_VALUE_SENTINEL" not in path.read_bytes() for path in paths.values())


def test_ai_context_from_session_adapter_has_no_full_value_sentinel(
    captured_session_with_sentinels: InSessionCapture,
) -> None:
    context = captured_session_with_sentinels.with_adapter_records(
        lambda records: {
            "endpoint_patterns": [
                {"endpoint_template": "/v1/items/{id}", "allowed_methods": [records[0].method]}
            ],
            "candidates": [],
        }
    )
    assert b"FULL_VALUE_SENTINEL" not in json.dumps(sanitize_context(context)).encode()


def test_mcp_imports_only_sanitized_session_har(
    tmp_path: Path, captured_session_with_sentinels: InSessionCapture
) -> None:
    service = MCPService()
    assert service.load_scope(_write_scope(tmp_path / "scope.yaml"))["ok"] is True
    assert service.init_state(tmp_path / "state.db")["ok"] is True
    service.import_har(captured_session_with_sentinels.har_path, "alice")
    assert all(
        "FULL_VALUE_SENTINEL" not in repr(record)
        and "RAW_ID_4eC39HqLyjWDarjtT1zdp7dc" not in repr(record)
        and "REQUEST_SECRET_SENTINEL" not in repr(record)
        for record in service.session.records
    )
```

Import `InSessionCapture` in each test module that uses the fixture. `tests/test_reporting.py` already supplies `_bundle()`, and `tests/test_mcp_server.py` already supplies `_write_scope()`. No raw body, header, cookie, or full `RequestRecord` is written by the fixture's HAR.

- [ ] **Step 3: Run the new negative tests to establish the current boundary**

Run:

```bash
uv run pytest tests/test_state.py -k "session_capture" -v
uv run pytest tests/test_reporting.py -k "session_material" -v
uv run pytest tests/test_ai.py -k "session_adapter" -v
uv run pytest tests/test_mcp_server.py -k "sanitized_session_har" -v
```

Expected: PASS. If any test fails because a sentinel reaches a generated file, SQLite artifact, MCP session, or AI context, stop and repair the owning boundary before committing P3b.

- [ ] **Step 4: Add only the minimal owning-boundary fix if a negative test fails**

Use these fail-closed fixes only when the corresponding test demonstrates the leak:

```python
# reporting.py: retain the existing unknown-key rejection.
raise ValueError("report evidence contains a field outside the allowlist")

# state.py: retain the existing closed audit-data allowlist.
raise ValueError("audit event data contains an unsupported field")

# ai.py: construct context from endpoint templates, methods, locations, and field names only.
return {"endpoint_patterns": endpoint_patterns, "candidates": candidates}

# mcp_server.py: import only parse_har_records(path, identity), never an InSessionCapture.
records = parse_har_records(path, identity_value)
```

Do not add a generic redaction fallback that silently accepts a full session object. The correct behavior at these boundaries is rejection or omission by an explicit allowlist.

- [ ] **Step 5: Run the complete verification suite**

Run:

```bash
uv run ruff check .
uv run mypy src
uv run pytest
git diff --check
```

Expected: all commands exit zero. The final pytest run proves: an active session resolves full values; the HAR, HAR parser, state/SQLite sidecars, report files, AI context, and MCP-imported records do not contain the sentinels.

- [ ] **Step 6: Commit the acceptance regression tests**

```bash
git add tests/conftest.py tests/test_state.py tests/test_reporting.py tests/test_ai.py tests/test_mcp_server.py
git add src/openbola/reporting.py src/openbola/state.py src/openbola/ai.py src/openbola/mcp_server.py
git commit -m "test: prove full session values stay in memory"
```

The second `git add` is intentionally conditional: omit every production file that did not need the minimal fail-closed repair from Step 4. Do not stage unrelated changes.

## Capture-to-discovery acceptance proof

The final Task 5 pytest run is the criterion-8 proof when it includes this deterministic sequence:

1. Fake Playwright emits one in-scope `POST` with a bearer-header sentinel, raw request ID, full response ID/value, and browser storage-state cookie sentinel.
2. `capture_session()` completes one routed browser/context run, returns a handle-only `InSessionCapture`, and resolves the exact response body only while the session remains open.
3. `with_adapter_records(GenericAdapter(registry).inventory)` observes the raw response body synchronously and returns only field names and `ValueHandle`s; no raw `RequestRecord` is returned or stored.
4. The session HAR and parsed HAR are scanned and contain none of the three sentinels; response bodies remain absent from parsed HAR records.
5. State/SQLite sidecars, all report outputs, sanitized AI context, and MCP session records are byte/repr-scanned and contain none of the sentinels.
6. A scope-denied request and each full-material limit fail before HAR/session return and revoke the registry; `InSessionCapture.close()` also revokes all handles.

## Self-review

**Spec coverage:** §5 is covered by Task 1's non-semantic, process-local write/resolve/close capability. §7 step 4 is preserved by Task 3's single scope-routed browser run; §7 step 9 and §9's local full detail are covered by Tasks 2–4. §8's memory-only/full-value destruction requirement is covered by Tasks 1–5's handle-only model, revocation, no-write rule, and artifact scans. Acceptance criterion 8 is covered by the explicit six-step proof above. P4 inventory remains name-only, but Task 4 supplies an intentionally ephemeral raw adapter callback so a later P4d/P8 consumer can use full captured evidence without making the shared `RequestRecord` contract raw.

**Placeholder scan:** This plan defines every production interface, limit, failure message, test command, test sentinel, and commit command. It contains no deferred implementation markers or cross-task shorthand.

**Type consistency:** `SessionValueStore` is defined in Task 1 and used by Tasks 2–4. `SessionExchange`, `SessionRequestMaterial`, `SessionResponseMaterial`, and `InSessionCapture` are defined in Task 2 and consumed by Tasks 3–5. `capture_session()` is defined in Task 3 and used by Tasks 4–5. The raw-to-provider bridge is only `InSessionCapture.with_adapter_records()` throughout.

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-24-openbola-p3b-full-fidelity-session-capture.md`. Two execution options:

1. Subagent-Driven (recommended) - I dispatch a fresh subagent per task, review between tasks, fast iteration.

2. Inline Execution - Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
