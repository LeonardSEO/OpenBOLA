# OpenBOLA P6: All-record Mutation Verification and Crash Recovery

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Implement this plan task-by-task, with a fresh implementer and an independent review for each task.

**Goal:** Replace the current single canary/cleanup mutation path with a
deterministic, grant-bound all-record verification sweep. Every authorized
record is snapshotted, mutated, checked through the unauthorized identity,
restored, and checked again before the next record is touched. A crash-safe,
AES-GCM encrypted journal and a startup recovery gate ensure that a mutation
cannot leave the application silently continuing with an unknown cleanup
state.

**Architecture:** Keep `ScopeGuard` and `ProbeExecutor` as the only target
network boundary. Add a typed mutation-sweep coordinator that receives an
immutable tuple of discovery candidates and a validated `MutationGrant`; it
performs a complete preflight (record count, request budget, concrete method,
path, field, scope, and mutation authorization) before dispatching any write.
The coordinator uses a small executor request primitive rather than creating an
HTTP client of its own. Before the first write it commits an encrypted journal
containing only the minimum restore material; the journal key is obtained from
an OS credential-vault adapter. A recovery manager validates the journal, the
current confirmed scope, and the same mutation grant before restoring and
verifying the value. A non-empty or invalid journal blocks new assessments at
startup; explicit manual escalation is append-only and permits diagnostics only
until the journal is cleared.

**Tech Stack:** Python 3.11+, existing `ScopeGuard`, `MutationGrant`,
`MutationRecordScope`, `PathRule`, `ProbeExecutor`, `CredentialRef`, and
`SessionValueRegistry`; `cryptography`'s `AESGCM` for authenticated encryption;
an OS-vault adapter with a test double (macOS Keychain and Windows Credential
Manager through the approved backend). No target request may be
issued by the journal or recovery modules directly. Adding the cryptography or
OS-vault runtime dependency is an explicit implementation checkpoint: do not
modify `pyproject.toml`/`uv.lock` until that dependency is approved and a
locked, offline test path is available.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§6 Scope
and all-record mutation grants, §7 verification flow, §8 storage/privacy/crash
recovery, §13 acceptance criteria 6–7) and
`docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P6).

## Global constraints

- A mutation sweep has two independent authorities: the currently confirmed
  target `ScopeGuard` and a separate `MutationGrant`. A valid AI proposal,
  `ProbeTarget`, or provider adapter result never authorizes a write by itself.
- `record_scope=all_discovered` means the complete immutable candidate set.
  The coordinator must fail before any write when the set is incomplete,
  exceeds `max_records`, or the calculated request count exceeds either
  `max_requests` or the executor's global 100,000-request hard limit. There is
  no sampling, truncation, retry-based budget expansion, or silent skip.
- Every concrete request (snapshot, canary mutation, unauthorized check,
  restore, restore verification, and canary lifecycle operation) goes through
  `ScopeGuard.require_allowed`. Redirects remain explicit and are checked by
  the existing executor before any follow-up request. A failed/uncertain
  cleanup stops all later writes.
- Existing records are never deleted. `DELETE` is legal only for a canary
  created by the same case and only when `allow_canary_create_delete=True`.
  Canary creation and deletion are bound to an opaque case token and a distinct
  path; the coordinator rejects a pre-existing-record DELETE.
- The journal is the sole persistence exception for a mutation. It contains no
  plaintext credentials, cookies, tokens, raw object IDs, full response bodies,
  or resolved handle values. Its encrypted payload may contain only the exact
  request/restore material and opaque references needed to recover. The key is
  never in the journal or SQLite state. No secure-erasure claim is made for
  filesystem/SSD remnants.
- Journal files are written atomically with restrictive permissions and fsync;
  malformed, truncated, replayed, or tampered journals fail closed without
  echoing bytes, paths, secrets, or values in exceptions/logs.
- Startup recovery never bypasses an expired, changed, or unconfirmed scope.
  A failed recovery leaves the gate closed. Manual escalation records an
  append-only audit event and enables read-only diagnostics only; it does not
  authorize new writes.
- Full original values may exist in process memory only. Reports, AI context,
  MCP responses, SQLite state, and exceptions receive opaque handles/fingerprints
  and coverage status, never resolved values.
- Preserve the existing public `MutationSpec` behavior and regression tests
  while adding the all-record path. Do not weaken existing read, redirect,
  peer-pinning, credential, or request-limit checks.
- Before declaring P6 complete, run `uv run ruff check .`, `uv run mypy src`,
  and `uv run pytest` in addition to the focused mutation/recovery suites.

## File structure and contracts

- `src/openbola/mutations.py` — immutable candidate/case contracts, preflight
  budget calculation, sweep state machine, typed outcomes, and executor-facing
  request orchestration. It imports no HTTP client and does not resolve a
  credential or value except immediately before a request delegated to the
  executor.
- `src/openbola/recovery.py` — AES-GCM journal envelope, OS key-vault protocol
  and platform adapter, atomic journal store, `RecoveryGate`, and recovery
  coordinator. It delegates restore requests to `ProbeExecutor`.
- `src/openbola/executor.py` — expose a narrow, typed, scope-checked request
  primitive used by `mutations.py` and `recovery.py`; retain `run()` and
  `MutationSpec` compatibility. The primitive returns status/fingerprint/error
  metadata, never a persisted body.
- `src/openbola/models.py` — add closed audit event names and typed mutation
  outcome/coverage values only when they are shared by state, reporting, or the
  TUI; keep raw restore material out of these models.
- `src/openbola/state.py` — append only sanitized sweep/audit outcomes and
  recovery transitions; do not add a plaintext journal column or migration
  that stores mutation values.
- `tests/test_mutations.py` — preflight, immutable set, ordering, budgets,
  grant/ScopeGuard binding, snapshot/canary/verify/restore behavior, and
  stop-on-unverified-cleanup tests using fake executor transports.
- `tests/test_recovery.py` — encryption, atomicity, key-vault, tamper,
  startup-gate, crash simulation, scope revalidation, and plaintext absence
  tests using a temporary directory and an in-memory vault double.
- `tests/test_executor.py` — focused tests for the new request primitive and
  preservation of current public mutation behavior.
- `tests/test_state.py` — append-only, secret-safe mutation outcome tests if
  `state.py` is extended.
- `pyproject.toml`, `uv.lock` — touch only at the approved dependency
  checkpoint; pin a compatible `cryptography` range and the selected OS-vault
  backend, then verify lockfile integrity offline.

### Public contracts

The names below are the implementation target. Field additions are allowed
only when required to preserve the existing `ProbeTarget`/`MutationGrant`
contracts; do not put resolved values into a frozen contract that can cross a
persistence boundary.

```python
@dataclass(frozen=True)
class MutationCandidate:
    endpoint_handle: str
    record_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    target: ProbeTarget                 # runtime-only raw object id
    field: str
    original_value: ValueHandle         # resolves only in the active process
    canary_value: str                   # runtime-only, bounded, not persisted
    mutation: MutationOperation         # method/path/field template

@dataclass(frozen=True)
class MutationOperation:
    method: str                         # PATCH or PUT for existing records
    endpoint_template: str
    field: str
    allowed_path: str

@dataclass(frozen=True)
class MutationSweepPlan:
    candidates: tuple[MutationCandidate, ...]
    grant: MutationGrant
    scope_digest: str
    request_count: int

@dataclass(frozen=True)
class MutationOutcome:
    record_handle: str
    status: Literal["verified", "inconclusive", "skipped"]
    mutation_verified: bool
    restore_verified: bool
    error_code: str | None = None

@dataclass(frozen=True)
class ScopedExchange:
    status: int | None
    body_fingerprint: str | None
    object_values: tuple[str, ...]
    error_code: str | None = None
    sent: bool = False

@dataclass(frozen=True)
class RecoveryStatus:
    state: Literal["clear", "required", "escalated", "blocked"]
    journal_present: bool
    reason_code: str | None = None
```

`MutationCandidate.target.object_id` is used only in memory by the executor
and is never copied into `MutationSweepPlan` serialization, audit evidence, or
the journal envelope. `MutationOperation` must construct bounded request bodies
without arbitrary callbacks or unvalidated user strings. `MutationSweepPlan`
sorts and deduplicates candidates by opaque handles and concrete method/path;
the tuple is frozen before preflight and any changed candidate source after
that point is rejected.

The deterministic request formula is five target operations per existing
record: owner snapshot read, owner canary write, attacker verification read,
owner restore write, and owner restore-verification read. A lifecycle canary
case has an explicit formula documented in code (create, unauthorized read,
owner delete, and deletion verification) and is counted before dispatch. A
case that cannot calculate an exact bounded count fails preflight.

## Task 1: Define mutation candidates and fail-closed preflight

**Files:**

- Create `src/openbola/mutations.py` and `tests/test_mutations.py`.
- Modify `src/openbola/scope.py` only if a read-only helper is needed to select
  the already validated `MutationGrant`; do not change grant semantics.

**Interfaces:**

- Consumes: `MutationGrant`, `MutationRecordScope`, `ScopeGuard`, typed
  discovery/P5 candidates, `ProbeTarget`, `ValueHandle`.
- Produces: `MutationCandidate`, `MutationOperation`, `MutationSweepPlan`,
  `MutationOutcome`, `preflight_sweep(...)`, and `MutationSweepExecutor`.

- [ ] **Step 1: Write failing preflight tests.**

  Cover one valid explicit candidate, complete `all_discovered` expansion,
  duplicate candidates, zero candidates, missing field/handle bindings,
  mismatched owner/attacker identities, denied concrete method/path, expired
  scope, grant field denial, `max_records`, `max_requests`, and the 100,000
  global cap. Assert that a failing preflight invokes no transport and does not
  create a journal. Use three discovered records with a deliberately too-small
  budget to prove no first-record write occurs.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_mutations.py -k 'preflight or budget or grant' -v`

- [ ] **Step 3: Implement immutable candidates and exact budget checks.**

  Normalize methods to uppercase, validate safe relative endpoint templates,
  require non-empty opaque handles and unique field handles, and freeze the
  sorted candidate tuple before computing the request count. For
  `ALL_DISCOVERED`, require that the caller supplies the complete discovery
  result (the exact typed `discovery_complete=True` marker on the caller's
  inventory, or an equivalent explicitly named field approved by the
  integration owner); do not infer completeness from a non-empty list. Select a grant
  whose methods/path rules/allowed fields cover every concrete operation and
  call the target `ScopeGuard` for each request shape. Reject any unknown or
  duplicate candidate before opening a transport. Return a `MutationSweepPlan`
  containing only opaque metadata plus the current scope digest.

- [ ] **Step 4: Run focused tests to verify they pass.**

  `uv run pytest tests/test_mutations.py -k 'preflight or budget or grant' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/mutations.py tests/test_mutations.py && git commit -m "feat: add all-record mutation preflight"`

## Task 2: Add the scoped executor request primitive and verification state machine

**Files:**

- Modify `src/openbola/executor.py` and `tests/test_executor.py`.
- Modify `src/openbola/mutations.py` and `tests/test_mutations.py`.

**Interfaces:**

- Consumes: a preflighted `MutationSweepPlan`, `ProbeExecutor`, and an
  in-memory value registry.
- Produces: an executor method named
  `request_scoped(target, credential, *, method, endpoint_template, body,
  content_type, id_field) -> ScopedExchange` that returns status/body
  fingerprint/error metadata, and the sweep implementation. The method is
  package-visible (not a second HTTP client) and is the only request primitive
  imported by `mutations.py` and `recovery.py`.

- [ ] **Step 1: Write failing state-machine tests.**

  Use an `httpx.MockTransport` fixture and assert the exact per-record order:
  snapshot → canary write → attacker verify → restore → restore verify. Assert
  that the next record starts only after restoration verification. Cover owner
  snapshot failure (no write), attacker verification failure (restore still
  attempted, then stop), restore failure (stop all later writes), restore
  verification mismatch (stop), cancellation after dispatch (restore is still
  attempted), safe redirects, and no response body in outcomes. Assert that
  every call reaches a guard spy and that the attacker never receives the
  owner credential.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_mutations.py tests/test_executor.py -k 'sweep or snapshot or restore or request_primitive' -v`

- [ ] **Step 3: Implement the primitive and state machine.**

  Factor the existing `_request_with_redirects` path into a typed internal or
  public-for-package-use operation that accepts one `ProbeTarget`/credential,
  calls `ScopeGuard` for the exact URL/method, rejects implicit redirects, and
  returns only status, bounded object comparison data, fingerprints, and
  generic error codes. Keep retries disabled for writes. Resolve the credential
  only after the guard decision. The sweep resolves `original_value` only when
  constructing the restore body, and releases it after that request. It writes
  no evidence containing the value.

  For each candidate, snapshot the owner-visible field, generate a unique
  process-local canary, commit the journal (Task 3 API), send the owner canary
  write, verify the canary through the attacker identity, restore the exact
  snapshot, and verify the restored value through the owner identity. Mark the
  outcome only after both verification checks; on any uncertain cleanup, stop
  all subsequent writes and surface a generic `cleanup_unverified` status.
  Preserve the existing public `MutationSpec` tests and `run()` semantics.

- [ ] **Step 4: Run focused tests to verify they pass.**

  `uv run pytest tests/test_mutations.py tests/test_executor.py -k 'sweep or snapshot or restore or request_primitive' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/executor.py src/openbola/mutations.py tests/test_executor.py tests/test_mutations.py && git commit -m "feat: verify and restore every mutation record"`

## Task 3: Implement the encrypted journal and OS-vault key boundary

**Files:**

- Create `src/openbola/recovery.py` and `tests/test_recovery.py`.
- Modify `pyproject.toml`/`uv.lock` only after the dependency approval checkpoint.
- Add focused dependency/packaging notes to the plan ledger, not to runtime
  error messages.

**Interfaces:**

- Consumes: opaque scope digest, `MutationCandidate` restore metadata,
  `CredentialRef` handles, and an OS-vault key provider.
- Produces: `RecoveryKeyStore` protocol, `AESGCMJournal`, atomic journal store,
  `JournalRecord`, and generic `RecoveryError`/`JournalTamperError` types.

- [ ] **Step 1: Dependency approval checkpoint.**

  Confirm that the selected `cryptography` release and OS-vault backend are
  allowed runtime dependencies. If approval is not available, stop at the
  plan boundary and report the blocker; do not substitute unauthenticated
  encryption, plaintext files, or an environment-variable key. Once approved,
  pin compatible ranges, update `uv.lock`, and verify the lock diff contains no
  unrelated upgrades.

- [ ] **Step 2: Write failing cryptographic and atomicity tests.**

  With a fake in-memory `RecoveryKeyStore`, assert AES-GCM round trips, unique
  nonce per write, associated-data mismatch rejection, malformed/base64/size
  rejection, wrong-key rejection, atomic replace, restrictive file mode on
  POSIX, and cleanup after a successful restore. Store a raw-ID and original
  value sentinel in the journal payload, then assert neither appears in the
  journal bytes or directory listing. Assert that `repr`, exceptions, and
  audit metadata omit the sentinel. A torn temp file or interrupted replace
  must leave the last complete journal readable, never a partially decrypted
  value.

- [ ] **Step 3: Implement strict AES-GCM envelope and key provider.**

  Use a 32-byte key from the OS vault and a fresh 96-bit nonce for each write;
  authenticate a fixed schema/version and opaque run/scope identifiers as
  associated data. Encode only bounded base64 fields in the on-disk envelope;
  encrypt the entire restore record, including path/body metadata. Validate
  exact keys, size limits, nonce length, and version before decrypting. Use an
  atomic sibling temp file, flush/fsync the file, `os.replace`, and fsync the
  parent where supported. Do not log subprocess output or key material. The
  platform adapter must use macOS Keychain and Windows Credential Manager (or
  the approved OS-vault library) without putting a key in argv, reports, or
  SQLite.

- [ ] **Step 4: Run focused tests to verify they pass.**

  `uv run pytest tests/test_recovery.py -k 'journal or aes or atomic or secret' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/recovery.py tests/test_recovery.py pyproject.toml uv.lock && git commit -m "feat: add encrypted mutation recovery journal"`

## Task 4: Add startup recovery gate and crash recovery orchestration

**Files:**

- Modify `src/openbola/recovery.py`, `src/openbola/mutations.py`, and
  `src/openbola/executor.py`.
- Modify `src/openbola/state.py`/`src/openbola/models.py` only for sanitized,
  append-only recovery events.
- Add or extend `tests/test_recovery.py`, `tests/test_mutations.py`, and
  `tests/test_state.py`.

**Interfaces:**

- Consumes: `AESGCMJournal`, the current scope file, `ScopeGuard`, the same
  `MutationGrant`, credential references, and `ProbeExecutor`.
- Produces: `RecoveryGate`, `RecoveryCoordinator.recover()`,
  `RecoveryCoordinator.escalate()`, and startup diagnostics used later by P8/P9.

- [ ] **Step 1: Write failing gate/crash tests.**

  Simulate a process stop after the canary write and before restore. On a fresh
  coordinator, assert `RecoveryGate` reports `required` and blocks both scan
  and mutation entry points until recovery succeeds. Recovery must load the
  current confirmed scope, re-check the exact restore method/path and mutation
  grant, resolve credentials through the approved vault reference, restore,
  verify, and remove the journal atomically. Assert that an expired/changed/
  unconfirmed scope, missing credential, tampered journal, failed restore, or
  failed verification leaves the gate blocked and the journal present. Assert
  that manual escalation creates one append-only sanitized event and permits
  read-only diagnostics but not a new mutation.

- [ ] **Step 2: Run focused tests to verify they fail.**

  `uv run pytest tests/test_recovery.py tests/test_mutations.py -k 'startup or gate or crash or escalation or recover' -v`

- [ ] **Step 3: Implement gate and recovery coordinator.**

  Make `RecoveryGate` a process-start check before any assessment session is
  created. A missing journal is `clear`; a valid journal is `required`; an
  invalid/tampered journal is `blocked`. `recover()` must use the journal's
  opaque scope provenance to load the same scope file and verify its digest and
  current time, then delegate the restore request to the executor. Only after
  verified restoration may it atomically replace the journal with an empty
  state and unlink it. Any exception is converted to a generic reason code.
  `escalate(reason)` validates a bounded operator reason, appends a sanitized
  audit event, and leaves mutation entry disabled. Do not auto-retry a restore
  or bypass a changed scope.

- [ ] **Step 4: Run focused tests and existing state tests.**

  `uv run pytest tests/test_recovery.py tests/test_mutations.py tests/test_state.py -k 'recovery or journal or gate or mutation or audit' -v`

- [ ] **Step 5: Commit.**

  `git add src/openbola/recovery.py src/openbola/mutations.py src/openbola/executor.py src/openbola/state.py src/openbola/models.py tests/test_recovery.py tests/test_mutations.py tests/test_state.py && git commit -m "feat: block startup until mutation recovery is verified"`

## Task 5: Prove the P6 boundary, integrate sanitized outcomes, and update the roadmap

**Files:**

- Create or extend `tests/test_mutation_boundary.py`.
- Modify `src/openbola/state.py`/`src/openbola/models.py` for sanitized
  outcome persistence if not completed in Task 4.
- Modify `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` only in
  the P6 status paragraph after all checks pass.

**Interfaces:**

- Consumes: completed sweep, journal, recovery gate, P2 grant fixtures, P3b
  session handles, P5 typed proposals, and the real `ScopeGuard` fixture.
- Produces: deterministic acceptance proof and a roadmap marker identifying
  the merge date and exact validation commands.

- [ ] **Step 1: Add end-to-end local boundary proof.**

  Build three in-memory discovered records, a complete `all_discovered`
  grant, two identities, and a fake transport. Assert the full request order,
  that every record is exercised, and that the first unverified cleanup stops
  all later writes. Simulate a crash after the second record's canary write,
  restart with a fresh coordinator, recover and verify the original value, and
  assert the journal is gone. Assert all persisted state/report/MCP payloads
  contain only record handles/object references and no raw-ID, original-value,
  cookie, token, or response-body sentinels. Assert a proposed AI write cannot
  enter the sweep without a separate valid grant.

- [ ] **Step 2: Run the focused P6 acceptance suite.**

  `uv run pytest tests/test_mutations.py tests/test_recovery.py tests/test_mutation_boundary.py tests/test_executor.py tests/test_state.py -v`

- [ ] **Step 3: Run the mandatory repository checks.**

  ```bash
  uv run ruff check .
  uv run mypy src
  uv run pytest
  ```

  Fix only failures caused by P6. Report unrelated pre-existing failures
  separately; do not weaken tests, scope checks, encryption, or cleanup gates.

- [ ] **Step 4: Update roadmap status.**

  Mark P6 complete only after the focused and full checks pass. Record the
  exact acceptance commands and the dependency/OS-vault implementation used.
  Preserve the P11 external-publication approval gate and do not rewrite other
  phase markers.

- [ ] **Step 5: Commit the acceptance proof and status marker.**

  `git add tests/test_mutation_boundary.py src/openbola/state.py src/openbola/models.py docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md && git commit -m "test: close P6 mutation recovery boundary"`

## Self-review checklist

- The sweep cannot dispatch a write until all records, fields, paths, methods,
  grant limits, and scope decisions are preflighted.
- `all_discovered` is a complete immutable set with an exact request budget;
  no silent sample, truncation, or retry expansion exists.
- Snapshot, canary, unauthorized verification, restore, and restore
  verification are visible state transitions, and the first uncertain cleanup
  stops every later write.
- Existing-record DELETE is impossible; canary DELETE requires an explicit
  grant and a distinct, same-case canary path.
- Every target request and redirect is still routed through `ScopeGuard` and
  the existing executor boundary; mutation code does not instantiate its own
  HTTP client.
- AES-GCM uses an OS-vault key, fresh nonces, authenticated version/scope
  metadata, atomic fsync writes, and strict bounded parsing. No plaintext
  restore material or secrets reaches disk, SQLite, reports, AI, MCP, logs, or
  exception text.
- Startup blocks on a valid, invalid, or tampered journal; scope changes and
  expiry fail closed; successful recovery verifies before deletion.
- The public legacy `MutationSpec` API and all current executor safety tests
  remain green.
- Dependency and lockfile changes are explicit, minimal, and tested; no
  unapproved runtime fallback weakens the recovery guarantees.
