# OpenBOLA P1: Foundation & Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the existing `bola_checker`/`bolacheck` engine to `openbola` everywhere it appears as a product/package identifier, and add the two foundational contracts every later OpenBOLA v1 subsystem plan (P2–P11) depends on: platform data-root paths and the non-secret `ValueHandle`/`SessionValueRegistry` pair that parallels the existing `CredentialRef`/`CredentialVault`.

**Architecture:** The rename is mechanical (directory move + literal string replace) and is verified by the pre-existing 246-test suite staying green under the new name. The two new modules are additive, dependency-light (stdlib only, matching the rest of `models.py`/`credentials.py`), and follow the exact patterns those files already establish (frozen dataclasses, `StrEnum`, non-serializable in-memory wrapper for anything sensitive).

**Tech Stack:** Python 3.11+, stdlib only for this plan (`dataclasses`, `enum`, `os`, `secrets`, `pathlib`, `sys`), pytest, existing `bola_checker`/`openbola` package layout under `src/`.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§4 command surface / naming, §5 opaque handles, §8 storage roots)

## Global Constraints

- No `bolacheck` compatibility alias — the console script is `openbola` only (spec §4).
- Import root, console script, distribution name, MCP server name, and report schema id all become `openbola` (spec §4).
- Handle ids are random and non-semantic; persisted state may contain handles or one-way fingerprints, never resolved values (spec §5).
- Platform data roots are exactly `~/Library/Application Support/OpenBOLA/` on macOS and `%LOCALAPPDATA%\OpenBOLA\` on Windows (spec §8).
- Existing git history is preserved; do not rewrite historical authorship (spec §4).
- `bola-tool-plan.md` and `README.md` are explicitly **out of scope** for this plan — README gets a full visual rebrand in the later GitHub-launch plan (P11); rewriting it now would be throwaway work.

---

### Task 1: Rename `bola_checker` → `openbola` across source, tests, config, and CI

**Files:**
- Move: `src/bola_checker/` → `src/openbola/` (all 14 modules + `py.typed`)
- Move: `tests/test_*.py` stay in place, content updated (13 files)
- Modify: `pyproject.toml` (package name, console script, hatch targets, mypy packages)
- Modify: `.github/workflows/ci.yml:25` (coverage target)
- Modify: `AGENTS.md`, `AUTHORIZATION.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md` (prose product-name mentions only)
- Test: the existing suite under `tests/`, run as the verification for this task (no new test file — a rename has no new behavior to assert beyond "everything still works under the new name")

**Interfaces:**
- Consumes: nothing (first task).
- Produces: importable package `openbola` (was `bola_checker`); console script `openbola` (was `bolacheck`); PyPI/dist name `openbola`; FastMCP server name `"openbola"` (was `"bolacheck"`); report format id `"openbola-report-v1"` (was `"bolacheck-report-v1"`); JUnit testsuite name `"openbola.bola_idor"` (was `"bolacheck.bola_idor"`). Every later plan imports from `openbola.<module>`, not `bola_checker.<module>`.

- [ ] **Step 1: Confirm the pre-rename baseline is green**

Run: `.venv/bin/python -m pytest -q`
Expected: `246 passed` (record the count — if it differs, stop and investigate before renaming anything).

- [ ] **Step 2: Move the package directory with git, preserving history**

```bash
git mv src/bola_checker src/openbola
```

- [ ] **Step 3: Rewrite every identifier occurrence across the moved package and tests**

Run this from the repo root. It rewrites, in order, the three casings found in the codebase (`bola_checker` import identifier, `bolacheck` product/console name, `BOLACheck` title-case docstring header) inside `src/openbola/`, `tests/`, and `pyproject.toml`:

```bash
FILES=$(grep -rlE "bola_checker|bolacheck|BOLACheck" src/openbola tests pyproject.toml)
for f in $FILES; do
  sed -i '' \
    -e 's/bola_checker/openbola/g' \
    -e 's/bolacheck/openbola/g' \
    -e 's/BOLACheck/OpenBOLA/g' \
    "$f"
done
grep -rn "bola_checker\|bolacheck\|BOLACheck" src/openbola tests pyproject.toml || echo "clean"
```

Expected final line: `clean` (no remaining matches). This single pass also covers the special-case strings that already contained `bolacheck`/`bola_checker` as a substring: the FastMCP server name (`mcp_server.py`), the report format id and JUnit testsuite name (`reporting.py`), the mock-server thread name (`mock_target.py`), the pipeline run-label salt (`pipeline.py`), and the `importlib.metadata.version("bolacheck")` lookup in `__init__.py`.

- [ ] **Step 4: Rewrite `pyproject.toml`'s remaining name-shaped fields**

`pyproject.toml` after Step 3 will have had `bola_checker`→`openbola` and `bolacheck`→`openbola` applied to every occurrence, so `name = "bolacheck"` is already `name = "openbola"`, the console script line is already `openbola = "openbola.cli:app"`, `packages = ["src/bola_checker"]` is already `packages = ["src/openbola"]`, and `[tool.mypy] packages = ["bola_checker"]` is already `packages = ["openbola"]`. Read the file and confirm:

```bash
grep -n '^name = \|openbola = "openbola.cli:app"\|packages = ' pyproject.toml
```

Expected output:
```
name = "openbola"
packages = ["src/openbola"]
openbola = "openbola.cli:app"
packages = ["openbola"]
```

If any line still shows the old form, fix it directly with Edit — Step 3's blanket sed only touches files matched by the grep in that step, and `pyproject.toml` was included, so this should already be correct; this step is the verification, not new work.

- [ ] **Step 5: Update the CI workflow's coverage target**

Modify `.github/workflows/ci.yml:25`:

```yaml
      - run: uv run pytest --cov=openbola --cov-report=term-missing
```

- [ ] **Step 6: Update prose product-name mentions in root policy docs**

In `AGENTS.md`, `AUTHORIZATION.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, replace every standalone mention of `BOLACheck` with `OpenBOLA` and `bolacheck` with `openbola` (these files only contain the title-case product name and, in `SECURITY.md`, one lowercase mention — there is no `bola_checker` import-path text in any of them):

```bash
for f in AGENTS.md AUTHORIZATION.md CODE_OF_CONDUCT.md CONTRIBUTING.md SECURITY.md; do
  sed -i '' -e 's/BOLACheck/OpenBOLA/g' -e 's/bolacheck/openbola/g' "$f"
done
grep -n "BOLACheck\|bolacheck" AGENTS.md AUTHORIZATION.md CODE_OF_CONDUCT.md CONTRIBUTING.md SECURITY.md || echo "clean"
```

Expected final line: `clean`.

- [ ] **Step 7: Reinstall the editable package under the new name and run the full suite**

```bash
.venv/bin/pip install -e . --quiet
.venv/bin/python -m pytest -q
```

Expected: `246 passed` (same count as Step 1 — a rename must not change behavior or test count).

- [ ] **Step 8: Add a one-line console-script smoke check**

```bash
.venv/bin/python -c "import importlib.metadata as m; print(m.version('openbola'))"
.venv/bin/openbola --version 2>&1 | head -1 || .venv/bin/python -m openbola --version 2>&1 | head -1
```

Expected: the version string prints without a `PackageNotFoundError` or `ModuleNotFoundError`. (If `openbola --version` isn't wired as a Typer option yet, `python -m openbola --help` printing the Typer help text is an acceptable substitute — the CLI's `--version` flag is not part of this task's scope; it only needs to confirm the console entry point resolves to the renamed `app`.)

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "rename: bola_checker/bolacheck -> openbola package and identifiers"
```

---

### Task 2: Platform data-root path resolution

**Files:**
- Create: `src/openbola/paths.py`
- Test: `tests/test_paths.py`

**Interfaces:**
- Consumes: nothing beyond stdlib (`os`, `pathlib.Path`, `sys`).
- Produces: `data_root() -> Path`, used by every later plan that needs to read or write persistent sanitized state (config, recipes, scope files, the SQLite audit store, reports, update metadata, diagnostics — spec §8). No later task in this plan calls it yet; P2+ plans wire it in when they add persistence.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_paths.py
from __future__ import annotations

import sys

import pytest

from openbola.paths import data_root


def test_macos_data_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("HOME", "/Users/testuser")
    assert data_root() == "/Users/testuser/Library/Application Support/OpenBOLA"


def test_windows_data_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\testuser\AppData\Local")
    assert data_root() == r"C:\Users\testuser\AppData\Local\OpenBOLA"


def test_windows_data_root_requires_localappdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    with pytest.raises(RuntimeError, match="LOCALAPPDATA"):
        data_root()


def test_unsupported_platform_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="linux"):
        data_root()
```

Note: assertions compare against plain strings via `Path.__eq__`, which compares by parts, so passing a `str` on the right-hand side to a `Path.__eq__` fails (`Path != str`). Use `str(data_root()) ==` instead — write the tests exactly as:

```python
    assert str(data_root()) == "/Users/testuser/Library/Application Support/OpenBOLA"
```

and equivalently for the other `data_root()` assertions above (Windows case and the two error-path tests keep `pytest.raises`, no comparison needed there).

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_paths.py -v`
Expected: `ModuleNotFoundError: No module named 'openbola.paths'`

- [ ] **Step 3: Write the implementation**

```python
# src/openbola/paths.py
"""Platform-specific data root for persisted sanitized OpenBOLA state."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_APP_DIR_NAME = "OpenBOLA"


def data_root() -> Path:
    """Return the platform data root, creating no directories itself.

    macOS: ``~/Library/Application Support/OpenBOLA/``
    Windows: ``%LOCALAPPDATA%\\OpenBOLA\\``

    Callers are responsible for creating the directory (and any parents)
    before writing into it; this function only computes the path.
    """

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / _APP_DIR_NAME

    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise RuntimeError("LOCALAPPDATA is not set; cannot resolve the OpenBOLA data root.")
        return Path(local_app_data) / _APP_DIR_NAME

    raise RuntimeError(
        f"Unsupported platform {sys.platform!r}: OpenBOLA v1 supports macOS and Windows only."
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_paths.py -v`
Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add src/openbola/paths.py tests/test_paths.py
git commit -m "feat: add platform data-root path resolution"
```

---

### Task 3: `ValueHandle` and `SessionValueRegistry`

**Files:**
- Create: `src/openbola/handles.py`
- Test: `tests/test_handles.py`

**Interfaces:**
- Consumes: nothing beyond stdlib (`dataclasses`, `enum`, `secrets`, `threading.RLock`). Deliberately does not import from `openbola.credentials` — `SecretHandle` here is the spec-shaped read side of the existing `CredentialRef`/`CredentialVault` pair (spec §5's contract uses `SecretHandle`, not `CredentialRef`, as the type carried by `LoginRecipe` and `AIProviderConfig`); a later plan (P3, when `LoginRecipe` is introduced) decides whether `SecretHandle` wraps `CredentialVault` or `CredentialVault` grows a `SecretHandle`-returning method. This task only builds the standalone contract the spec defines, plus the non-secret `ValueHandle` side which has no existing equivalent.
- Produces: `SecretHandle(id: str, purpose: str)`, `ValueHandle(id: str, kind: Literal["record_id", "field_value", "body", "session_state"])`, `SessionValueRegistry` protocol with `resolve_secret(handle) -> str` / `resolve_value(handle) -> object`, and `InMemorySessionValueRegistry` — a concrete registry that mints random non-semantic ids via `secrets.token_urlsafe`. Later plans (P3 capture, P5 AI planning) register real secrets/values here and pass only the handles into persisted state, reports, and AI context, per spec §5's rule that only the active process resolves a handle immediately before a policy-approved operation.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_handles.py
from __future__ import annotations

import pytest

from openbola.handles import (
    InMemorySessionValueRegistry,
    SecretHandle,
    ValueHandle,
)


def test_secret_handle_is_frozen_and_non_semantic() -> None:
    handle = SecretHandle(id="abc123", purpose="login_password")
    with pytest.raises(AttributeError):
        handle.id = "changed"  # type: ignore[misc]


def test_value_handle_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="kind"):
        ValueHandle(id="abc123", kind="not_a_real_kind")  # type: ignore[arg-type]


def test_registry_stores_secret_and_returns_random_handle() -> None:
    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="login_password", value="hunter2")
    assert isinstance(handle, SecretHandle)
    assert handle.purpose == "login_password"
    assert registry.resolve_secret(handle) == "hunter2"


def test_registry_secret_handle_ids_are_random_and_non_semantic() -> None:
    registry = InMemorySessionValueRegistry()
    first = registry.store_secret(purpose="login_password", value="hunter2")
    second = registry.store_secret(purpose="login_password", value="hunter2")
    assert first.id != second.id
    assert "hunter2" not in first.id
    assert "login_password" not in first.id


def test_registry_stores_value_and_returns_random_handle() -> None:
    registry = InMemorySessionValueRegistry()
    handle = registry.store_value(kind="record_id", value=42)
    assert isinstance(handle, ValueHandle)
    assert handle.kind == "record_id"
    assert registry.resolve_value(handle) == 42


def test_registry_resolve_secret_unknown_handle_raises() -> None:
    registry = InMemorySessionValueRegistry()
    stray = SecretHandle(id="never-stored", purpose="login_password")
    with pytest.raises(LookupError):
        registry.resolve_secret(stray)


def test_registry_resolve_value_unknown_handle_raises() -> None:
    registry = InMemorySessionValueRegistry()
    stray = ValueHandle(id="never-stored", kind="record_id")
    with pytest.raises(LookupError):
        registry.resolve_value(stray)


def test_registry_is_not_serializable() -> None:
    import pickle

    registry = InMemorySessionValueRegistry()
    registry.store_secret(purpose="login_password", value="hunter2")
    with pytest.raises(TypeError):
        pickle.dumps(registry)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_handles.py -v`
Expected: `ModuleNotFoundError: No module named 'openbola.handles'`

- [ ] **Step 3: Write the implementation**

```python
# src/openbola/handles.py
"""Opaque, non-semantic handles for secrets and in-session values.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Handle ids are random (``secrets.token_urlsafe``), never derived from the
value or its purpose/kind, so a handle leaked into persisted state, a
report, or an AI provider payload carries no information about what it
refers to. Only the process holding the registry that minted a handle can
resolve it, and only immediately before a policy-approved operation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from threading import RLock
from typing import Literal, NoReturn, Protocol, SupportsIndex

ValueKind = Literal["record_id", "field_value", "body", "session_state"]
_VALUE_KINDS: frozenset[str] = frozenset({"record_id", "field_value", "body", "session_state"})


@dataclass(frozen=True)
class SecretHandle:
    id: str
    purpose: str


@dataclass(frozen=True)
class ValueHandle:
    id: str
    kind: ValueKind

    def __post_init__(self) -> None:
        if self.kind not in _VALUE_KINDS:
            raise ValueError(f"Unknown ValueHandle kind: {self.kind!r}")


class SessionValueRegistry(Protocol):
    def resolve_secret(self, handle: SecretHandle) -> str: ...
    def resolve_value(self, handle: ValueHandle) -> object: ...


def _random_id() -> str:
    return secrets.token_urlsafe(32)


class InMemorySessionValueRegistry:
    """Process-local registry minting random handles for secrets and values.

    Never serializable: state is destroyed when the process exits, matching
    the spec's requirement that full values are absent from every persisted
    artifact after the session ends.
    """

    __slots__ = ("_secrets", "_values", "_lock")

    def __init__(self) -> None:
        self._secrets: dict[str, tuple[str, str]] = {}
        self._values: dict[str, tuple[ValueKind, object]] = {}
        self._lock = RLock()

    def __reduce__(self) -> NoReturn:
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def store_secret(self, *, purpose: str, value: str) -> SecretHandle:
        handle_id = _random_id()
        with self._lock:
            self._secrets[handle_id] = (purpose, value)
        return SecretHandle(id=handle_id, purpose=purpose)

    def store_value(self, *, kind: ValueKind, value: object) -> ValueHandle:
        handle_id = _random_id()
        with self._lock:
            self._values[handle_id] = (kind, value)
        return ValueHandle(id=handle_id, kind=kind)

    def resolve_secret(self, handle: SecretHandle) -> str:
        with self._lock:
            entry = self._secrets.get(handle.id)
        if entry is None or entry[0] != handle.purpose:
            raise LookupError("Secret handle cannot be resolved.")
        return entry[1]

    def resolve_value(self, handle: ValueHandle) -> object:
        with self._lock:
            entry = self._values.get(handle.id)
        if entry is None or entry[0] != handle.kind:
            raise LookupError("Value handle cannot be resolved.")
        return entry[1]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_handles.py -v`
Expected: `8 passed`

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `.venv/bin/python -m pytest -q`
Expected: `258 passed` (246 pre-existing + 4 from `test_paths.py` + 8 from `test_handles.py`)

- [ ] **Step 6: Run lint and type checks**

```bash
.venv/bin/ruff check src/openbola/paths.py src/openbola/handles.py tests/test_paths.py tests/test_handles.py
.venv/bin/mypy src/openbola/paths.py src/openbola/handles.py
```

Expected: no errors from either command. If `ruff` flags the `S101` rule inside the test files, it is already globally ignored in `pyproject.toml`'s `[tool.ruff.lint] ignore`; any other finding must be fixed, not suppressed.

- [ ] **Step 7: Commit**

```bash
git add src/openbola/handles.py tests/test_handles.py
git commit -m "feat: add SecretHandle/ValueHandle session value registry"
```

---

## Self-Review Notes

- **Spec coverage:** §4 naming → Task 1. §8 platform roots → Task 2. §5 handle contracts (the `SecretHandle`/`ValueHandle`/`SessionValueRegistry` portion only — `LoginRecipe`, `ResourceInventory`, `ProviderAdapter`, `AIProviderConfig`, `ProposedTest` are deferred to the plans that first need them, per the roadmap's just-in-time sequencing) → Task 3.
- **Placeholder scan:** every step has literal code or literal shell commands; no "TBD"/"similar to Task N" remain.
- **Type consistency:** `ValueHandle.kind` is the same `Literal["record_id", "field_value", "body", "session_state"]` union used in the spec's own dataclass at §5; `SecretHandle`/`ValueHandle` field names match the spec verbatim so P3/P5 can import them without renaming.
