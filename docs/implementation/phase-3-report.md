# Phase 3: persistent audit state

Implemented `bola_checker.state.StateStore` as a local SQLite store with a
migration ledger and schema-version record. Ordinary connections enable foreign
keys, a five-second busy timeout, and WAL where SQLite supports it. The v2-to-v3
secret-removal migration temporarily uses an exclusive DELETE-journal gate as
described below.

The store persists endpoint/method pairs, identities with allowlisted metadata
and only a credential-reference ID, ownership evidence with confidence and source,
append-only runs, probe attempts, findings, and audit events.  Database
triggers prevent updates and deletes to runs, attempts, findings, and audit
events.  Findings are deduplicated by endpoint, content, and a canonical hash
of redacted evidence.

`record_probe_result()` consumes the shared `ProbeResult` and related typed
models.  A retryable inconclusive result is retained as an attempt but remains
pending; only non-retryable `protected` and `bola` attempts satisfy a tested
combination.

Every mapping persisted by this module passes through a fail-closed JSON guard.
Only explicitly allowed evidence/audit/metadata keys and JSON scalar values are
accepted. Request/response containers, including `headers`, `cookies`, `query`,
and `body`, are rejected; unsupported mapping keys and non-JSON values fail
rather than being serialized implicitly. This keeps credential material out of
the database while retaining only typed, safe audit evidence.

Focused tests cover schema migration/init, foreign-key enforcement, ownership
persistence and the pending matrix, retry behavior, finding deduplication,
append-only audit ordering, and a database-byte scan for credential values.

## Validation evidence

Executed successfully on 2026-08-23:

```text
uv run ruff check src/bola_checker/state.py tests/test_state.py
All checks passed!

uv run pytest tests/test_state.py
7 passed

uv run mypy src/bola_checker/state.py
Success: no issues found in 1 source file

git diff --check
(no output)
```

The repository-wide Ruff check was also attempted.  It currently reports
formatting violations in concurrent, out-of-scope files
`src/bola_checker/endpoints.py` and `tests/test_scope.py`; no phase-3 file is
reported by that command.

## Fix round 1: stricter persistence and atomicity

Credential reference IDs now have a separate fail-closed validator. It accepts
only the `env:`, `keyring:`, `vault:`, and `memory:` schemes followed by a safe,
non-empty identifier. Raw values, whitespace/control characters, bearer forms,
JWT-shaped values, and cookie-shaped values are rejected before a connection
can write them. `record_probe_result()` validates both references through this
same path.

The JSON guard is now an allowlist, not a sensitive-key heuristic: unknown
mapping keys fail, and the traffic-bearing containers `headers`, `cookies`,
`query`, `body`, `request`, and `response` always fail. This means a custom
`X-Auth` value under `headers` cannot be persisted or merely hidden by a
redaction convention.

`start_run()` now inserts its run and `run_started` event with one connection
and transaction. `record_probe_result()` similarly creates endpoint/identity
references, its attempt, and its audit event in one transaction; a failed audit
insert rolls all of them back. `mark_tested()` follows the same transactional
attempt-plus-audit pattern. The typed
`ownership_evidence_for(endpoint_template, method, object_id)` read API returns
persisted `OwnershipEvidence` values for strong ownership checks in phase 4.

Validation for this fix round, executed on 2026-08-23:

```text
uv run ruff check src/bola_checker/state.py tests/test_state.py
All checks passed!

uv run mypy src/bola_checker/state.py
Success: no issues found in 1 source file

uv run pytest tests/test_state.py
15 passed

git diff --check
(no output)
```

The 15 focused tests include raw-sentinel rejection plus a database-byte scan,
raw/bearer/JWT/cookie-like reference rejection, unknown-key and `X-Auth` header
rejection, injected audit-write rollback with zero durable records, concurrent
audit writers, and typed ownership-evidence retrieval.

## Fix round 2: opaque credential references and atomic strong ownership

SQLite now stores a credential reference only as
`ref_<sha256(kind|name|secret_ref)>`. `add_identity()` accepts either a typed
`CredentialRef`, which is validated and fingerprinted before a connection is
opened, or an already-shaped `ref_` fingerprint. It rejects a literal
reference string. `record_probe_result()` fingerprints both credentials before
its transaction; `list_identities()` exposes only the opaque ID. Migration 2
irreversibly replaces any pre-v2 literal reference values with a legacy opaque
fingerprint.

Evidence, audit data, and identity metadata now use per-key validators rather
than a generic scalar policy. Integer IDs and HTTP statuses have ranges,
`retryable` is boolean, verdict/confidence/severity/comparison fields are
closed enums, and identifiers, methods, and paths use constrained formats.
Only a bounded `error_code` identifier is accepted—free `error` or
`description` evidence strings are not. This prevents a sentinel from being
stored beneath an otherwise allowed key.

`persist_ownership_evidence()` (also exposed as
`add_ownership_evidence()`) makes strong ownership persistence atomic. For
explicit, observed-create, and response-match evidence it starts `BEGIN
IMMEDIATE`, reads existing strong owners of the exact
endpoint/method/object tuple, raises typed `OwnershipConflictError` for a
different identity, and otherwise writes evidence plus its audit event in the
same transaction. The lower-level ID-based insert applies the same rule.

Validation for this fix round, executed on 2026-08-24:

```text
uv run ruff check src/bola_checker/state.py tests/test_state.py
All checks passed!

uv run mypy src/bola_checker/state.py
Success: no issues found in 1 source file

uv run pytest tests/test_state.py tests/test_endpoints.py
27 passed
```

The focused tests verify that a valid `env:STATE_SENTINEL` reference becomes an
opaque `ref_` ID and is absent from database/WAL/SHM bytes; a sentinel supplied
to allowed `error_code` is rejected; and two synchronized strong-owner writers
produce exactly one stored owner and one `OwnershipConflictError`.

## Fix round 3: closed error codes and canonical findings

`error_code` is now the closed `ErrorCode` set: `timeout`,
`transport_error`, `invalid_response`, `scope_denied`, `rate_limited`, and
`redirect_blocked`. It is no longer a regex-validated arbitrary identifier, so
an alphanumeric sentinel cannot be retained under an otherwise allowed key.

`add_finding()` now derives the only persistable title and description through
`canonical_finding_text()`. Its inputs are validated severity, method,
endpoint template, and a transient evidence `object_id`. Caller-provided
`Finding.title` and `Finding.description` must
exactly match those canonical values; otherwise the write is rejected before
any custom text reaches SQLite. The legacy overload applies the same equality
rule after resolving its existing endpoint ID.

The v2 credential-reference migration now checkpoints and truncates WAL after
replacing literal references. This removes old WAL frames that could otherwise
physically retain a pre-migration credential-reference string.

Validation for this fix round, executed on 2026-08-24:

```text
uv run ruff check src/bola_checker/state.py tests/test_state.py
All checks passed!

uv run mypy src/bola_checker/state.py
Success: no issues found in 1 source file

uv run pytest tests/test_state.py tests/test_endpoints.py
31 passed
```

The added coverage rejects an alphanumeric `error_code` sentinel, verifies a
custom title/description sentinel is absent from database/WAL/SHM bytes, checks
canonical finding round-trip equality, and simulates a v1-to-v2 upgrade before
scanning all SQLite artifacts for the removed literal credential reference.

## Fix round 4: opaque object references and route-only endpoints

Schema version 3 replaces both persisted `object_id` columns with
`object_ref`. All public StateStore operations may still receive a concrete
object ID, but every ownership row, tested combination, audit event, and
finding stores only a deterministic `obj_<sha256>` reference. Lookups apply the
same fingerprint, and already-opaque references remain stable so pending work
can be passed back to `mark_tested()` and `has_been_tested()`. Finding evidence
is returned under the typed `object_ref` key; the legacy `object_id` key never
appears in persisted or listed JSON. Canonical finding text contains only the
validated route template and opaque object reference.

Endpoint persistence now accepts route-only templates such as
`/documents/{id}` and nested `{id2}` placeholders. Concrete numeric, UUID,
Mongo, encoded, high-entropy, JWT-like, and known credential-shaped literal
segments are rejected before SQL receives them. Version numbers, calendar
dates, and standalone route years remain compatible with Phase 4 discovery.
This validation is state-local, so `state.py` does not import `endpoints.py`
and the existing one-way Phase 4 integration remains cycle-free.

The v2-to-v3 migration fingerprints existing ownership and attempt values,
renames the columns, transforms finding/audit JSON from `object_id` to
`object_ref`, regenerates canonical finding text, and converts unsafe endpoint
literals to placeholders. Append-only triggers are restored before migration
completion. Strong-ownership conflict detection still runs
under `BEGIN IMMEDIATE`; candidate inputs remain unchanged in memory while
persisted and returned evidence uses the opaque reference.

Validation for this fix round, executed on 2026-08-24:

```text
uv run ruff check src/bola_checker/state.py tests/test_state.py tests/test_endpoints.py
All checks passed!

uv run mypy src/bola_checker/state.py
Success: no issues found in 1 source file

uv run pytest tests/test_state.py tests/test_endpoints.py
40 passed
```

The added sentinel coverage exercises ownership, attempts, audit events,
findings, canonical text, rejected endpoint literals, raw and opaque lookup
round trips, and a synthetic v2-to-v3 upgrade. Each security test scans the
database, WAL, and SHM artifacts and confirms that the concrete object/secret
sentinel is absent.

Repository-wide validation was also green on 2026-08-24:

```text
uv run ruff check .
All checks passed!

uv run mypy src
Success: no issues found in 12 source files

uv run pytest
187 passed
```

## Fix round 5: closed audit inputs and scrub-gated migration

Audit event names are now the closed `AuditEventType` enum. The public API also
accepts the exact historical string value of a known enum member at runtime,
but rejects every unknown string before opening a write connection. Internal
events are limited to run start, ownership import, ownership persistence, and
probe-attempt persistence. Unknown pre-v3 event names are converted to the
constant `legacy_event_redacted` during migration and on defensive reads.

Run labels remain accepted as transient operator input, but SQLite and the
`run_started` audit event receive only a deterministic `run_<sha256>` reference.
Already opaque references remain stable. The raw label is neither interpolated
into persisted text nor passed as a SQL parameter. Pre-v3 run labels and audit
label fields are fingerprinted by the secret-removal migration.

Endpoint templates persisted by StateStore are now percent-free. Any percent
character is rejected, regardless of whether it forms a valid escape or how
many nested encoding layers it represents. During v2-to-v3 migration, any
legacy segment containing a percent character becomes an `{id}` placeholder;
the migration never uses a bounded decode loop to decide whether the value is
safe.

The v2-to-v3 migration no longer records version 3 before physical removal is
complete. It first checkpoints WAL, switches to DELETE journal mode, requests
exclusive locking, and acquires `BEGIN EXCLUSIVE` before changing object state.
An active reader therefore makes the migration fail with the version row,
ledger, columns, and values still at v2. After the transformation transaction
commits, `VACUUM` runs outside any SQLite transaction while the same connection
retains exclusive locking. Only after `VACUUM` succeeds does a second exclusive
transaction append ledger version 3 and update `schema_version`. If a non-reader
failure occurs after the transform commit but before the ledger write, retry
detects the physical v3 columns, repeats the scrub, and then records version 3.
No claim is made that one SQLite transaction includes `VACUUM`.

Regression coverage uses long unique values for raw file scans instead of the
tiny value `42`, which can occur naturally in SQLite timestamps and page data.
It also covers one, four, five, and eight percent-encoding layers; closed event
names and raw run labels; migration of legacy event names and labels; an active
reader leaving v2 unchanged; an injected `VACUUM` failure leaving the ledger at
v2; successful retry; and absence of raw sentinels from the database, WAL, and
SHM artifacts after success.

Validation for this fix round, executed on 2026-08-24:

```text
uv run pytest tests/test_models.py tests/test_state.py tests/test_endpoints.py tests/test_reporting.py -q
66 passed

uv run ruff check src/bola_checker/models.py src/bola_checker/state.py src/bola_checker/endpoints.py src/bola_checker/reporting.py tests/test_models.py tests/test_state.py tests/test_endpoints.py tests/test_reporting.py
All checks passed!

uv run mypy src/bola_checker/models.py src/bola_checker/state.py src/bola_checker/endpoints.py src/bola_checker/reporting.py
Success: no issues found in 4 source files

uv run pytest -q
214 passed

uv run ruff check .
All checks passed!

uv run mypy src
Success: no issues found in 15 source files

git diff --check
(no output)
```
