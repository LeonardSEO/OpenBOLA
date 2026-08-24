# OpenBOLA P2: Scope & Mutation Grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing fail-closed `MutationGrant` contract in `src/openbola/scope.py` with the field, record-scope, and budget constraints spec §6 requires (`allowed_fields`, `record_scope`, `max_records`, `max_requests`, `allow_canary_create_delete`), so a scope file can authorize an all-discovered-record mutation sweep with an explicit, validated budget instead of only a method+path grant.

**Architecture:** This is a same-file extension of `src/openbola/scope.py`'s existing YAML-parsing and defense-in-depth revalidation pattern — every new field gets a parse-time validator (used when loading YAML) and is re-validated by `_normalise_mutation_grants` (used both at parse time and whenever a `ScopeGuard` is constructed directly from a `ScopeConfig`, so a handmade/bypassed config can never skip validation). No other module is touched: wiring these constraints into the executor (record enumeration, budget enforcement, canary lifecycle) is P6's job, not this plan's — P2 only makes the constraints loadable and validated.

**Tech Stack:** Python 3.11+, stdlib `enum.StrEnum` (already used elsewhere in this codebase, e.g. `src/openbola/models.py`), the existing `pyyaml`-based scope loader, pytest.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§6 Scope and all-record mutation grants)

## Global Constraints

- The scope YAML remains fail-closed and rejects unknown keys — this applies per-mutation-grant too: a grant mapping must contain exactly the required keys, no more, no fewer.
- `max_requests` must never exceed the existing global executor hard limit of 100,000 requests (spec §6 last sentence; mirrored from `ExecutorLimits.max_requests`'s existing `1 <= x <= 100_000` bound in `src/openbola/executor.py:164` — do not import `executor.py` from `scope.py`; these two modules stay decoupled, so the bound is intentionally duplicated as its own named constant in `scope.py`).
- Booleans (`confirmed`, and now `allow_canary_create_delete`) must be the *exact* YAML boolean, never a truthy string like `"true"` — this file's established pattern (see `_confirmed()` at `scope.py:438`) is `type(value) is not bool` (not `isinstance`, which would accept `bool` subclasses, and not plain truthiness, which would accept `1`).
- `record_scope` values are exactly `"explicit"` or `"all_discovered"` — spec §6's `MutationRecordScope` StrEnum, verbatim member names.
- Every dataclass field this plan adds must be re-validated by `_normalise_mutation_grants`, not only by the YAML parser — that function is the one defense-in-depth gate a directly-constructed `ScopeConfig`/`MutationGrant` (bypassing `load_scope`) still passes through, per this file's existing `test_scope_guard_revalidates_direct_scope_config_bypasses` test pattern.

---

### Task 1: Extend `MutationGrant` with field, record-scope, and budget constraints

**Files:**
- Modify: `src/openbola/scope.py` (imports, constants, `MutationGrant` dataclass, `_mutation_grants`, `_normalise_mutation_grants`, four new helper functions)
- Modify: `tests/test_scope.py` (update one existing test's fixture, add new tests)
- Modify: `tests/test_executor.py:41-43` (the `_scope_file()` fixture's `mutation_grants` block — it currently uses the old 2-key grant shape and five of its tests pass `mutation=True`, so it must gain the five new required keys or every mutation-path executor test breaks)
- Modify: `examples/scope.example.yaml` (its `mutation_grants` example, lines 40-44 — not loaded by any test, but it is the schema example linked from `README.md` and would otherwise document a shape `load_scope` no longer accepts)

**Interfaces:**
- Consumes: nothing new — this task only extends existing internal contracts (`MutationGrant`, `_mutation_grants`, `_normalise_mutation_grants`) already private to `scope.py`.
- Produces: `MutationRecordScope` (new public `StrEnum` with members `EXPLICIT = "explicit"` and `ALL_DISCOVERED = "all_discovered"`) and the extended `MutationGrant` dataclass with fields `methods`, `path_rules`, `allowed_fields: frozenset[str]`, `record_scope: MutationRecordScope`, `max_records: int`, `max_requests: int`, `allow_canary_create_delete: bool` — later plans (P6's executor wiring) import both by these exact names from `openbola.scope`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_scope.py`, first add `MutationRecordScope` to the existing import block at the top of the file:

```python
from openbola.scope import (
    MutationRecordScope,
    ScopeConfig,
    ScopeDecision,
    ScopeError,
    ScopeGuard,
    load_scope,
    require_in_scope,
)
```

Then replace the existing `test_read_methods_and_mutation_grants_are_separate` test (currently at `tests/test_scope.py:224-241`) with this updated version — the grant dict now needs all seven required keys, and the test also asserts the new fields loaded correctly:

```python
def test_read_methods_and_mutation_grants_are_separate(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[
            {
                "methods": ["POST"],
                "path_patterns": ["glob:/v1/reports"],
                "allowed_fields": ["title"],
                "record_scope": "explicit",
                "max_records": 10,
                "max_requests": 20,
                "allow_canary_create_delete": True,
            }
        ],
    )
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    guard.require_allowed("https://api.example.test/v1/items", "OPTIONS", now=NOW)
    guard.require_allowed("https://api.example.test/v1/reports", "POST", now=NOW)
    with pytest.raises(ScopeError, match="method"):
        guard.require_allowed("https://api.example.test/v1/items", "POST", now=NOW)
    with pytest.raises(ScopeError, match="exact uppercase"):
        guard.require_allowed("https://api.example.test/v1/items", "get", now=NOW)

    grant = guard.config.mutation_grants[0]
    assert grant.allowed_fields == frozenset({"title"})
    assert grant.record_scope is MutationRecordScope.EXPLICIT
    assert grant.max_records == 10
    assert grant.max_requests == 20
    assert grant.allow_canary_create_delete is True
```

Then append these new tests to the end of `tests/test_scope.py`. Each builds a scope file with one mutation grant, varying exactly one field away from a valid baseline:

```python
def _mutation_grant(**overrides: Any) -> dict[str, Any]:
    grant: dict[str, Any] = {
        "methods": ["PATCH"],
        "path_patterns": ["glob:/v1/users/*"],
        "allowed_fields": ["email"],
        "record_scope": "all_discovered",
        "max_records": 100,
        "max_requests": 200,
        "allow_canary_create_delete": False,
    }
    grant.update(overrides)
    return grant


def test_mutation_grant_full_valid_grant_round_trips(tmp_path: Path) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", mutation_grants=[_mutation_grant()])
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    grant = guard.config.mutation_grants[0]
    assert grant.allowed_fields == frozenset({"email"})
    assert grant.record_scope is MutationRecordScope.ALL_DISCOVERED
    assert grant.max_records == 100
    assert grant.max_requests == 200
    assert grant.allow_canary_create_delete is False


def test_mutation_grant_rejects_missing_key(tmp_path: Path) -> None:
    grant = _mutation_grant()
    del grant["allowed_fields"]
    scope_file = _write_scope(tmp_path / "scope.yaml", mutation_grants=[grant])

    with pytest.raises(ScopeError, match="must contain exactly"):
        load_scope(scope_file, now=NOW)


def test_mutation_grant_rejects_unknown_key(tmp_path: Path) -> None:
    grant = _mutation_grant(unexpected_field="x")
    scope_file = _write_scope(tmp_path / "scope.yaml", mutation_grants=[grant])

    with pytest.raises(ScopeError, match="must contain exactly"):
        load_scope(scope_file, now=NOW)


def test_mutation_grant_rejects_empty_allowed_fields(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(allowed_fields=[])],
    )

    with pytest.raises(ScopeError, match="allowed_fields"):
        load_scope(scope_file, now=NOW)


def test_mutation_grant_rejects_duplicate_allowed_fields(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(allowed_fields=["email", "email"])],
    )

    with pytest.raises(ScopeError, match="duplicate"):
        load_scope(scope_file, now=NOW)


def test_mutation_grant_rejects_unknown_record_scope(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(record_scope="every_record")],
    )

    with pytest.raises(ScopeError, match="record_scope"):
        load_scope(scope_file, now=NOW)


@pytest.mark.parametrize("bad_value", [0, -1, 100_001, True])
def test_mutation_grant_rejects_out_of_range_max_records(tmp_path: Path, bad_value: object) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(max_records=bad_value)],
    )

    with pytest.raises(ScopeError, match="max_records"):
        load_scope(scope_file, now=NOW)


@pytest.mark.parametrize("bad_value", [0, -1, 100_001, True])
def test_mutation_grant_rejects_out_of_range_max_requests(tmp_path: Path, bad_value: object) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(max_requests=bad_value)],
    )

    with pytest.raises(ScopeError, match="max_requests"):
        load_scope(scope_file, now=NOW)


def test_mutation_grant_rejects_max_records_exceeding_max_requests(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(max_records=50, max_requests=10)],
    )

    with pytest.raises(ScopeError, match="max_records must not exceed max_requests"):
        load_scope(scope_file, now=NOW)


@pytest.mark.parametrize("bad_value", ["true", 1, 0])
def test_mutation_grant_rejects_non_boolean_allow_canary_create_delete(
    tmp_path: Path,
    bad_value: object,
) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[_mutation_grant(allow_canary_create_delete=bad_value)],
    )

    with pytest.raises(ScopeError, match="allow_canary_create_delete"):
        load_scope(scope_file, now=NOW)


def test_mutation_grant_handmade_bypass_with_invalid_record_scope_is_rejected(
    tmp_path: Path,
) -> None:
    config = load_scope(
        _write_scope(tmp_path / "scope.yaml", mutation_grants=[_mutation_grant()]),
        now=NOW,
    )
    tampered_grant = replace(config.mutation_grants[0], record_scope="nonsense")

    with pytest.raises(ScopeError, match="record_scope"):
        ScopeGuard(replace(config, mutation_grants=(tampered_grant,)), now=NOW)
```

Also update the two other fixtures that build a mutation grant against the old 2-key shape, so they keep exercising the same POST/DELETE-on-`/v1/**` grant this task doesn't change the meaning of:

In `tests/test_executor.py`, the `_scope_file()` fixture currently has (lines 41-43):

```python
    if mutation:
        document["mutation_grants"] = [
            {"methods": ["POST", "DELETE"], "path_patterns": ["glob:/v1/**"]}
        ]
```

Replace with:

```python
    if mutation:
        document["mutation_grants"] = [
            {
                "methods": ["POST", "DELETE"],
                "path_patterns": ["glob:/v1/**"],
                "allowed_fields": ["status"],
                "record_scope": "explicit",
                "max_records": 100,
                "max_requests": 1000,
                "allow_canary_create_delete": True,
            }
        ]
```

In `examples/scope.example.yaml`, the current mutation grant example reads (lines 40-44):

```yaml
mutation_grants:
  - methods:
      - "POST"
    path_patterns:
      - "glob:/v1/reports"
```

Replace with:

```yaml
mutation_grants:
  - methods:
      - "POST"
    path_patterns:
      - "glob:/v1/reports"
    allowed_fields:
      - "status"
    record_scope: "explicit"
    max_records: 500
    max_requests: 5000
    allow_canary_create_delete: false
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_scope.py tests/test_executor.py -v`
Expected: multiple failures. The updated `test_read_methods_and_mutation_grants_are_separate` and the new `_mutation_grant`-based tests fail with `ScopeError: Each mutation grant must contain exactly methods and path_patterns.` (the current, unextended message) or with an `AttributeError`/`ImportError` for `MutationRecordScope` and the new dataclass fields. The five `test_executor.py` tests using `mutation=True` fail the same way, now that their fixture also has seven keys. This confirms the current code does not yet accept or expose the extended shape.

- [ ] **Step 3: Add the `enum` import**

In `src/openbola/scope.py`, the import block currently reads (lines 8-19):

```python
from __future__ import annotations

import hashlib
import ipaddress
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit, urlunsplit
```

Add `from enum import StrEnum` before `import hashlib`, keeping the block alphabetically sorted (this project's `ruff` config enables the `I` isort rule):

```python
from __future__ import annotations

from enum import StrEnum
import hashlib
import ipaddress
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit, urlunsplit
```

(If `ruff check --fix` reorders this differently, defer to its output — the goal is a clean `ruff check`, not this exact byte layout.)

- [ ] **Step 4: Add the two new module constants**

In `src/openbola/scope.py`, find the existing `_SCOPE_KEYS` definition (around line 51-61):

```python
_SCOPE_KEYS = frozenset(
    {
        "client_name",
        "authorization_reference",
        "confirmed",
        "starts_at",
        "expires_at",
        "allowed_hosts",
        "allowed_cidrs",
        "allowed_paths",
        "read_methods",
        "mutation_grants",
    }
)
```

Immediately after it, insert:

```python
_MUTATION_GRANT_KEYS = frozenset(
    {
        "methods",
        "path_patterns",
        "allowed_fields",
        "record_scope",
        "max_records",
        "max_requests",
        "allow_canary_create_delete",
    }
)
# Mirrors ExecutorLimits.max_requests's existing 1..100_000 bound in executor.py.
# Duplicated deliberately: scope.py does not import executor.py.
_MUTATION_REQUEST_HARD_CAP = 100_000
```

- [ ] **Step 5: Add `MutationRecordScope` and extend `MutationGrant`**

In `src/openbola/scope.py`, the current `MutationGrant` class reads (around line 101-108):

```python
@dataclass(frozen=True)
class MutationGrant:
    """An explicit authorization for mutation methods on the listed paths."""

    methods: frozenset[str]
    path_rules: tuple[PathRule, ...]

    def permits(self, method: str, path: str) -> bool:
        return method in self.methods and any(rule.matches(path) for rule in self.path_rules)
```

Replace it with:

```python
class MutationRecordScope(StrEnum):
    EXPLICIT = "explicit"
    ALL_DISCOVERED = "all_discovered"


@dataclass(frozen=True)
class MutationGrant:
    """An explicit authorization for mutation methods on the listed paths."""

    methods: frozenset[str]
    path_rules: tuple[PathRule, ...]
    allowed_fields: frozenset[str]
    record_scope: MutationRecordScope
    max_records: int
    max_requests: int
    allow_canary_create_delete: bool

    def permits(self, method: str, path: str) -> bool:
        return method in self.methods and any(rule.matches(path) for rule in self.path_rules)
```

- [ ] **Step 6: Replace `_mutation_grants` and `_normalise_mutation_grants`**

In `src/openbola/scope.py`, the current pair reads (around line 613-653):

```python
def _mutation_grants(document: Mapping[object, object]) -> tuple[MutationGrant, ...]:
    if "mutation_grants" not in document:
        return ()
    raw_grants = document.get("mutation_grants")
    if not isinstance(raw_grants, list):
        raise ScopeError("mutation_grants must be a list.")
    grants: list[MutationGrant] = []
    for raw_grant in raw_grants:
        if not isinstance(raw_grant, Mapping) or set(raw_grant) != {"methods", "path_patterns"}:
            raise ScopeError("Each mutation grant must contain exactly methods and path_patterns.")
        methods = frozenset(_methods(raw_grant.get("methods"), "mutation grant methods"))
        grants.append(
            MutationGrant(
                methods=methods,
                path_rules=_path_rules(raw_grant, "path_patterns"),
            )
        )
    return _normalise_mutation_grants(tuple(grants))


def _normalise_mutation_grants(value: object) -> tuple[MutationGrant, ...]:
    if not isinstance(value, tuple) or not all(isinstance(grant, MutationGrant) for grant in value):
        raise ScopeError("mutation_grants must be a tuple of MutationGrant objects.")
    grants: list[MutationGrant] = []
    for grant in value:
        if not isinstance(grant.methods, frozenset) or not grant.methods:
            raise ScopeError("Mutation grants require a non-empty frozenset of methods.")
        if not all(
            isinstance(method, str) and _HTTP_METHOD_RE.fullmatch(method)
            for method in grant.methods
        ):
            raise ScopeError("Mutation grants must contain exact uppercase HTTP methods.")
        if not grant.methods.issubset(_MUTATION_METHODS):
            raise ScopeError("Mutation grants may contain only POST, PUT, PATCH, and DELETE.")
        grants.append(
            MutationGrant(
                methods=grant.methods,
                path_rules=_normalise_path_rules(grant.path_rules, "mutation grant path_patterns"),
            )
        )
    return tuple(grants)
```

Replace both functions with:

```python
def _mutation_grants(document: Mapping[object, object]) -> tuple[MutationGrant, ...]:
    if "mutation_grants" not in document:
        return ()
    raw_grants = document.get("mutation_grants")
    if not isinstance(raw_grants, list):
        raise ScopeError("mutation_grants must be a list.")
    grants: list[MutationGrant] = []
    for raw_grant in raw_grants:
        if not isinstance(raw_grant, Mapping) or set(raw_grant) != _MUTATION_GRANT_KEYS:
            raise ScopeError(
                "Each mutation grant must contain exactly methods, path_patterns, "
                "allowed_fields, record_scope, max_records, max_requests, and "
                "allow_canary_create_delete."
            )
        methods = frozenset(_methods(raw_grant.get("methods"), "mutation grant methods"))
        grants.append(
            MutationGrant(
                methods=methods,
                path_rules=_path_rules(raw_grant, "path_patterns"),
                allowed_fields=_allowed_fields(raw_grant),
                record_scope=_mutation_grant_record_scope(raw_grant),
                max_records=_mutation_grant_positive_int(
                    raw_grant, "max_records", max_value=_MUTATION_REQUEST_HARD_CAP
                ),
                max_requests=_mutation_grant_positive_int(
                    raw_grant, "max_requests", max_value=_MUTATION_REQUEST_HARD_CAP
                ),
                allow_canary_create_delete=_mutation_grant_bool(
                    raw_grant, "allow_canary_create_delete"
                ),
            )
        )
    return _normalise_mutation_grants(tuple(grants))


def _normalise_mutation_grants(value: object) -> tuple[MutationGrant, ...]:
    if not isinstance(value, tuple) or not all(isinstance(grant, MutationGrant) for grant in value):
        raise ScopeError("mutation_grants must be a tuple of MutationGrant objects.")
    grants: list[MutationGrant] = []
    for grant in value:
        if not isinstance(grant.methods, frozenset) or not grant.methods:
            raise ScopeError("Mutation grants require a non-empty frozenset of methods.")
        if not all(
            isinstance(method, str) and _HTTP_METHOD_RE.fullmatch(method)
            for method in grant.methods
        ):
            raise ScopeError("Mutation grants must contain exact uppercase HTTP methods.")
        if not grant.methods.issubset(_MUTATION_METHODS):
            raise ScopeError("Mutation grants may contain only POST, PUT, PATCH, and DELETE.")
        if (
            not isinstance(grant.allowed_fields, frozenset)
            or not grant.allowed_fields
            or not all(
                isinstance(name, str) and name and name == name.strip()
                for name in grant.allowed_fields
            )
        ):
            raise ScopeError(
                "allowed_fields must be a non-empty frozenset of non-empty field names."
            )
        if not isinstance(grant.record_scope, MutationRecordScope):
            raise ScopeError("record_scope must be a MutationRecordScope value.")
        if (
            isinstance(grant.max_records, bool)
            or not isinstance(grant.max_records, int)
            or not 1 <= grant.max_records <= _MUTATION_REQUEST_HARD_CAP
        ):
            raise ScopeError(
                f"max_records must be an integer between 1 and {_MUTATION_REQUEST_HARD_CAP}."
            )
        if (
            isinstance(grant.max_requests, bool)
            or not isinstance(grant.max_requests, int)
            or not 1 <= grant.max_requests <= _MUTATION_REQUEST_HARD_CAP
        ):
            raise ScopeError(
                f"max_requests must be an integer between 1 and {_MUTATION_REQUEST_HARD_CAP}."
            )
        if grant.max_records > grant.max_requests:
            raise ScopeError("max_records must not exceed max_requests.")
        if type(grant.allow_canary_create_delete) is not bool:
            raise ScopeError(
                "allow_canary_create_delete must be the exact YAML boolean true or false."
            )
        grants.append(
            MutationGrant(
                methods=grant.methods,
                path_rules=_normalise_path_rules(grant.path_rules, "mutation grant path_patterns"),
                allowed_fields=frozenset(grant.allowed_fields),
                record_scope=grant.record_scope,
                max_records=grant.max_records,
                max_requests=grant.max_requests,
                allow_canary_create_delete=grant.allow_canary_create_delete,
            )
        )
    return tuple(grants)
```

- [ ] **Step 7: Add the four new helper functions**

In `src/openbola/scope.py`, immediately after `_normalise_mutation_grants` (before the existing `_methods` function), insert:

```python
def _allowed_fields(raw_grant: Mapping[object, object]) -> frozenset[str]:
    values = _string_list(raw_grant, "allowed_fields", required=True)
    if len(set(values)) != len(values):
        raise ScopeError("allowed_fields must not contain duplicate field names.")
    return frozenset(values)


def _mutation_grant_record_scope(raw_grant: Mapping[object, object]) -> MutationRecordScope:
    value = raw_grant.get("record_scope")
    if not isinstance(value, str):
        raise ScopeError("record_scope must be a string.")
    try:
        return MutationRecordScope(value)
    except ValueError as error:
        allowed = ", ".join(member.value for member in MutationRecordScope)
        raise ScopeError(f"record_scope must be one of: {allowed}.") from error


def _mutation_grant_positive_int(
    raw_grant: Mapping[object, object],
    field_name: str,
    *,
    max_value: int,
) -> int:
    value = raw_grant.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= max_value:
        raise ScopeError(f"{field_name} must be an integer between 1 and {max_value}.")
    return value


def _mutation_grant_bool(raw_grant: Mapping[object, object], field_name: str) -> bool:
    value = raw_grant.get(field_name)
    if type(value) is not bool:
        raise ScopeError(f"{field_name} must be the exact YAML boolean true or false.")
    return value
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_scope.py tests/test_executor.py -v`
Expected: all tests in both files pass, including the updated and new ones (16 new/changed test functions plus 3 parametrized cases across two of them in `test_scope.py` — check the exact count `pytest` reports rather than assuming a number, since this file has existing parametrized tests too) and the five previously-failing `mutation=True` tests in `test_executor.py` now passing again.

- [ ] **Step 9: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/scope.py tests/test_scope.py tests/test_executor.py
.venv/bin/mypy src/openbola/scope.py
```

Expected: full suite passes (258 pre-existing + the new test_scope.py tests, none removed), `ruff check` clean, `mypy` clean (this file already has full type coverage under `strict = true`; the new functions must too — every parameter and return type is annotated above).

- [ ] **Step 10: Commit**

```bash
git add src/openbola/scope.py tests/test_scope.py tests/test_executor.py examples/scope.example.yaml
git commit -m "feat: add field/record-scope/budget constraints to mutation grants"
```

---

## Self-Review Notes

- **Spec coverage:** §6's YAML example (`allowed_fields`, `record_scope`, `max_records`, `max_requests`, `allow_canary_create_delete`) and its `MutationRecordScope`/`MutationGrant` Python contract are both fully covered by Task 1. §6's executor-side behavior (auto-expansion for `all_discovered`, snapshot/canary/verify/restore, the "first unverified cleanup stops all further writes" rule, the global 100,000-request executor limit *enforcement*) is explicitly P6's job per the roadmap — this plan only makes the grant loadable and validated, matching the roadmap's dependency-driven sequencing.
- **Placeholder scan:** every step has literal code; no "TBD"/"add validation"/"similar to Task N" remain.
- **Type consistency:** `MutationRecordScope` and the extended `MutationGrant` field names/types match spec §6's own dataclass verbatim, so P6 (the next plan to touch mutation grants) can import them unchanged.
