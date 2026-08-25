# OpenBOLA v1 Roadmap

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md`

This design spans multiple independent subsystems (TUI shell, Playwright
capture, provider adapters, BYOK AI planning, mutation-grant verification,
multi-format reporting, cross-platform distribution). Per
`superpowers:writing-plans`, each subsystem gets its own plan document under
`docs/superpowers/plans/`, written just-in-time (right before it starts)
so each plan reflects the real state of the code after the plans before it
land, instead of guessing ahead.

## Sequencing

Order is dependency-driven: each plan only assumes contracts produced by
plans before it.

1. **P1 — Foundation & rename** (`2026-08-24-openbola-p1-foundation.md`).
   Rename `bola_checker` → `openbola` everywhere (package, console script,
   distribution name, MCP server name, report schema id). Add platform
   data-root path resolution (spec §8). Add the `ValueHandle` /
   `SessionValueRegistry` contract (spec §5) alongside the existing
   `CredentialVault`/`CredentialRef` pattern it extends. *Status: complete,
   merged to main (2026-08-24).*
2. **P2 — Scope & mutation grants**. Extend `scope.py`'s YAML/contract with
   `MutationGrant`/`MutationRecordScope`/`PathRule` (spec §6): explicit
   fields, `all_discovered` record scope, `max_records`/`max_requests`
   budgets, canary create/delete flag. Fail-closed on unknown keys.
   *Status: complete, merged to main (2026-08-24).*
3. **P3 — Login recipes & Playwright capture**. Replace HAR/replay-only
   `capture.py` with live Playwright identity capture: `LoginRecipe`
   contract (spec §5), isolated per-identity browser contexts, scope
   enforcement on navigation/replay, sanitized persistent traffic vs.
   memory-only replay material (spec §7 step 4, §8).
   *Status: complete, merged to main (2026-08-24), with the deferred P8
   integration items closed locally on 2026-08-25: SSO start URLs may contain
   query parameters but never fragments or userinfo, `capture_har` validates
   the registry capability before login, and the capture/login boundary emits
   only fixed safe errors without local-variable traceback rendering.*
4. **P4 — Resource/provider inventory**. `ResourceInventory`/
   `ProviderAdapter` contracts (spec §5) plus the four required adapters:
   generic HTTP/OpenAPI/GraphQL, Supabase/PostgREST, Firebase, Hasura, each
   against deterministic fixtures (acceptance criterion 4). This is itself
   a multi-subsystem plan (4 largely-independent adapters sharing one
   contract) — split into sequential sub-plans rather than one giant plan:
   - **P4a** — contracts (`ProviderConfidence`, `FieldInventory`,
     `ResourceInventory`, `ProviderDetection`, `ProviderAdapter`) plus the
     generic HTTP adapter, reusing `endpoints.py`'s existing `templatize()`
     path-templating rather than reimplementing it. *Status: complete,
     merged to main (2026-08-24).* Final review (opus) surfaced and fixed
     before merge: JSON-object-key IDs (Firebase/Stripe-shaped, and
     email-shaped keys) now route to `record_handles` instead of leaking
     into `FieldInventory.name`; `ProviderAdapter.name` is a read-only
     `@property` (a bare `name: str` member would have broken any P4b/c/d
     adapter using `ClassVar[str]` under mypy strict); `GenericAdapter`
     groups internally by `(origin, template)` so same-shaped paths on
     different hosts/tenants no longer merge into one `ResourceInventory`
     (the public contract itself still carries no origin/base_url field —
     see the deferred note below); HTTP methods are `.upper()`-normalized.
     Deferred to later plans: `pipeline.py`'s `_record_from_mapping`/
     `_normalize_record` path does NOT redact request/response bodies
     (only `capture.py`'s ingestion path does) — `discovery.py` is safe by
     construction (names only), but the "every RequestRecord is
     body-redacted" premise doesn't hold project-wide and shouldn't be
     trusted elsewhere without checking the ingestion path; whether
     `ResourceInventory` needs an `origin`/`base_url` field is an open
     design question for P4b (first adapter that actually needs to know
     its host); `GenericAdapter.inventory()` mints a fresh handle per call
     and isn't idempotent across reruns — relevant once P8's TUI
     recomputes discovery incrementally as capture progresses; sub-
     threshold IDs (rejected by `endpoints.is_object_id`) still survive
     into `endpoint_template`/`resource_name` verbatim — pre-existing in
     `endpoints.templatize`, same leak class as the JSON-key issue just
     fixed, tracked together for a future `endpoints.py` pass.
   - **P4b** — Supabase/PostgREST adapter (`SupabaseAdapter`). *Status:
     complete, merged to main (2026-08-24).* PostgREST embeds record IDs
     only in query-string `eq.` filters, never the path, so this adapter
     reads `?id=eq.<value>` rather than reusing `GenericAdapter`'s
     path-based extraction. Promoted `discovery.py`'s JSON-key-routing
     helpers (`top_level_json_keys`/`classify_key`) from private to
     public so P4c/P4d can reuse them too. Final review (opus) surfaced
     and fixed before merge: `provider_confidence` was computed once
     globally instead of per `(origin, table)` group, letting one
     tenant's confirmed-provider evidence bleed onto an unrelated
     tenant's inventory (same leak class P4a's own final review closed
     for `GenericAdapter`, recurring — worth treating "confidence/fields
     must never cross origins" as a standing invariant for every future
     adapter, not a one-off fix); `eq.` filter extraction minted a
     `record_id` handle for any opaque-ID-shaped value regardless of the
     filter's parameter name, so `?secret_token=eq.sk_live_...` would
     have treated a live secret as a probeable record ID — fixed by
     reusing `endpoints.py`'s existing `_is_sensitive_field` guard (a
     private helper, imported directly rather than promoted, since only
     one call site needed it); RPC calls (`POST /rest/v1/rpc/<fn>`) all
     collapsed into one `"rpc"` pseudo-table regardless of function name,
     unioning different (possibly differently-privileged) functions'
     field surfaces — fixed so each function gets its own inventory with
     a real, callable `endpoint_template`. Deferred to later plans:
     `_is_rest_path` is a substring match, not a path-segment-boundary
     match, so a gateway-proxied static-asset path containing
     `/rest/v1/` literally would be misread as a table (defensible
     leniency for reverse-proxied deployments, but worth tightening once
     P4c/P4d reveal more real-world path shapes); `urlsplit()` runs twice
     per record in `inventory()` (perf only); `urlsplit` can raise on a
     malformed URL — shared, pre-existing exposure with `GenericAdapter`,
     tracked for a future hardening pass since captured traffic is
     well-formed by construction.
   - **P4c** — Firebase Realtime Database adapter
     (`FirebaseRealtimeDatabaseAdapter`, `name="firebase-rtdb"`). *Status:
     complete, merged to main (2026-08-24).* Scoped to Realtime Database
     only, the classic misconfigured-rules BOLA surface (unauthenticated
     read/write on `*.firebaseio.com`/`*.firebasedatabase.app`). RTDB
     embeds record IDs directly in the path (unlike PostgREST's
     query-string filters), so this adapter reuses
     `endpoints.templatize`/`endpoints._path_ids` after stripping RTDB's
     mandatory `.json` REST suffix. Final review (opus) surfaced and
     fixed before merge: path-embedded IDs had no sensitivity guard on
     the parent segment, and RTDB's "key a node by the secret itself"
     idiom (`/passwordResetTokens/<token>.json`, `/apiKeys/<key>.json` —
     necessary because RTDB has no query-by-value) meant a live secret
     could be minted as a probeable `record_id` handle — same leak class
     as P4b's `eq.`-filter finding, one structural layer down (path
     segment vs. query param); fixed by gating path-ID extraction through
     `endpoints._is_sensitive_field` on each ID's parent segment. RTDB's
     push-create response envelope (`POST .../messages.json` →
     `{"name": "-NqA..."}`) was misread — the new record's own ID was
     silently discarded and `"name"` was reported as a fabricated field —
     fixed to route the envelope's ID to a handle and exclude `"name"`
     from that record's fields. `inventory()` had no host gate, so any
     `*.json` URL on any host (a web app's `manifest.json`, locale files,
     etc. — extremely common in real traffic) was misreported as
     `firebase-rtdb`; fixed by requiring `_is_rtdb_host` in addition to
     the `.json` suffix (kept `detect()`'s looser signal for the
     whole-record-set "should this adapter run" decision). Also fixed:
     case-insensitive/userinfo-safe host matching via
     `urlsplit(...).hostname`, and trailing-slash path normalization so
     `/users/42/.json` groups with `/users/42.json`. Deferred to later
     work: `classify_key`'s JSON-object-key routing (used for RTDB
     "list" nodes) has no sensitivity gate on the key itself — only
     path-embedded IDs got the new guard; worth a pass across
     P4a/P4b/P4c's shared `classify_key` for JSON-body-key sensitivity
     parity with the path/query-param guards now in place elsewhere.
     **Firestore** (`firestore.googleapis.com`, a structurally different
     typed-document REST envelope — fields are wrapped as
     `{"fields": {"name": {"stringValue": "..."}}}`, not plain JSON) is
     explicitly out of scope for P4c and not yet planned; a P4c-2 slot is
     reserved for it, written just-in-time whenever it's prioritized.
   - **P3b** — Full-fidelity in-session capture. This is a separate plan,
     `2026-08-24-openbola-p3b-full-fidelity-session-capture.md`, and is
     sequenced **before P4d**. It preserves `RequestRecord` as sanitized,
     transferable evidence; full request/response/session material lives only
     behind process-local session handles. A callback-only ephemeral adapter
     view may resolve raw `RequestRecord` values during one synchronous
     provider call, but may not return, persist, report, send to AI, or expose
     them through MCP. *Status: complete, merged to main (2026-08-24).* The
     `AdapterRecordView` boundary now explicitly blocks `__getstate__`,
     `__reduce__`, and `__reduce_ex__` serialization hooks.
   - **P4d** — Hasura adapter, written just-in-time after P3b and now that
     P4a/P4b/P4c's contracts and the origin/tenant-isolation and
     sensitive-field/sensitive-parent-guard precedents have landed. *Status:
     complete, merged to main (2026-08-24).* A typed provider registry now
     assembles the four built-in adapters without adding a network path.

   Ruling: every `RequestRecord` this codebase produces today (from both
   `capture.py`'s live collector and its HAR parser) already has its body
   *leaf values* redacted to the literal string `"[REDACTED]"` by
   `_sanitize_body`/`_redact_json` — only JSON *key names* and *path
   segments* survive redaction; query-parameter values are redacted too.
   Historical ruling (before P3b): every persisted `RequestRecord` had only
   redacted leaf values, so a full-fidelity path was required for the active
   TUI. P3b now supplies that path through process-local session handles and
   the ephemeral `AdapterRecordView`; P4d consumes only that callback view.
   `FieldInventory` still tracks field *names* only, while P7 retains its
   sanitized-only reporting boundary. Full values remain forbidden in state,
   reports, AI payloads, MCP, and serialization; acceptance criterion 8 is
   closed by P8's active-session registry lifecycle and TUI boundary tests.
5. **P5 — BYOK AI planning**. `AIProviderConfig`/`ProposedTest` contracts,
   `openai_compatible` + `azure_openai` clients, sanitized-context builder,
   and the validator that intersects every proposed handle/method/field/path
   against observed inventory and confirmed scope (spec §5, acceptance
   criterion 5 — no credentials/cookies/raw IDs/full values ever leave).
   *Status: complete, merged to main (2026-08-24). Acceptance checks:
   `uv run pytest tests/test_ai.py tests/test_ai_clients.py
   tests/test_ai_boundary.py -v`, `uv run ruff check .`, `uv run mypy src`,
   and `uv run pytest`.*
6. **P6 — All-record mutation verification & crash recovery**. Wire
   `MutationGrant` into the executor: snapshot → canary → verify → restore →
   verify-restore per record, `all_discovered` auto-expansion with no silent
   sampling, AES-GCM recovery journal keyed via the OS vault, startup
   recovery gate (spec §6, §8, acceptance criteria 6–7). **Status: complete
   locally (2026-08-25).** Mutation writes now require an encrypted recovery
   journal before dispatch, recovery revalidates the current scope and grant,
   and exact typed live snapshot values are restored and verified before the
   journal is cleared. `openbola recover --scope PATH` provides the explicit,
   scope- and grant-bound production recovery route. macOS uses Keychain and
   Windows uses Credential Manager through a native-only keyring boundary.
   Acceptance checks:
   `uv run pytest tests/test_mutations.py tests/test_recovery.py
   tests/test_mutation_boundary.py tests/test_executor.py tests/test_state.py -q`
   (116 passed), `uv run ruff check .`, `uv run mypy src`, and `uv run pytest -q`
   (668 passed).
7. **P7 — Typed findings & new export formats**. **Status: complete, merged to
   main (2026-08-24).** The report boundary now uses immutable typed
   `FindingEvidence`/`CapabilityProof` contracts with a legacy-safe adapter;
   deterministic JSON, Markdown, CSV, HTML, JUnit, and SARIF renderers share
   the `openbola-report-v1` schema and publish the six v1 filenames atomically.
   The cross-phase sentinel proof covers session handles, state, canonical
   documents, all artifacts, and serialization; local full field values remain
   P8 TUI-only. Acceptance checks:
   `uv run pytest tests/test_report_boundary.py tests/test_reporting.py
   tests/test_e2e.py tests/test_cli.py -v`, `uv run ruff check .`,
   `uv run mypy src`, and `uv run pytest`.
8. **P8 — Textual TUI shell**. Home/target/identity/capture/discovery/grant
   review/verification/findings/export/recovery screens (spec §7, §10)
   wired to the engine from P1–P7 through session services (config,
   progress events, cancellation). `openbola` with no args launches this.
   **Status: TUI shell complete locally; production engine-service binding is
   still open (2026-08-25).** The Textual flow is covered at 80x24, delegates
   through typed session operations, revalidates scope binding
   before grant confirmation, filters sensitive projections, enforces the P6
   startup gate, clears finding detail state on navigation, and restricts
   export to the six P7 artifact names. Acceptance checks:
   `uv run pytest tests/test_tui.py tests/test_tui_boundary.py
   tests/test_session.py tests/test_cli.py -q` (35 passed),
   `uv run ruff check .`, `uv run mypy src`, and `uv run pytest -q`
   (668 passed). A PTY smoke also confirmed that `uv run openbola` renders the
   full-screen Home screen and exits cleanly with `q`.
   The default no-argument session currently fails closed when capture or
   discovery is requested because production capture/discovery callbacks are
   not yet bound; recovery itself is available through the explicit CLI command.
9. **P9 — Setup/doctor/report/update subcommands**. `openbola setup`
   (Playwright browser install + self-test), `openbola doctor`,
   `openbola report RUN`, `openbola update` (GitHub Release check, checksum
   verify, explicit-confirm replace), local read-only `openbola mcp` reusing
   the renamed MCP server from P1. **P9 command/services are implemented;
   acceptance remains gated by a ScopeGuard-aware browser provisioner and an
   explicit distribution scope for update traffic. Recovery-vault setup,
   diagnostics, and the no-argument TUI launch are now integrated; an absent
   browser is reported as a local prerequisite instead of bypassing
   `ScopeGuard`.**
10. **P10 — Distribution packaging**. PyInstaller specs for the three
    platform targets, `install.sh`/`install.ps1`, `SHA256SUMS`, release
    workflow. **P10 local packaging implementation is complete.** *This
    machine is macOS — the Windows x64 build, macOS x64 build, clean-machine
    acceptance require native CI/target evidence. Textual is now included in
    the runtime dependency graph and local packaging contracts, but this plan
    does not claim unobserved native artifacts from this checkout.*
11. **P11 — Visual design & GitHub launch**. README hero/badges/demo,
    social-preview image, repository rename/topics/security URL. **P11 local launch materials complete; external GitHub launch pending approval.** The
    approval-gated checklist is [docs/launch/github-launch-checklist.md](../../launch/github-launch-checklist.md);
    no publish/transfer/rename/release action is claimed here. The spec itself
    (§12) requires separate explicit approval at execution time.

## Out-of-session acceptance criteria

Acceptance criteria 1–2 (clean-machine install/launch on Windows x64 and
macOS x64/arm64 without system Python) cannot be verified from this single
macOS development session — they need the actual packaged artifacts run on
those platforms. P10 produces everything up to that verification; closing
those two criteria requires running the built artifact on real target
machines (e.g. via CI runners), which is tracked but not claimed done here.

## Execution mode

Each plan is executed with `superpowers:subagent-driven-development`
(fresh subagent per task, two-stage review) immediately after being
written. Progress against this roadmap is the single source of truth for
"done" — update the status markers here as each plan completes.
