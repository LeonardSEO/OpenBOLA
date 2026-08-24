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
   *Status: complete, merged to main (2026-08-24). Deferred to P8:
   `LoginRecipe.start_url` rejects query parameters (real SSO entry points
   often need them); `capture_har`'s `registry` param isn't hasattr-checked;
   avoid `show_locals`-style traceback rendering anywhere in the
   capture/login path (a resolved secret can linger in frame locals across
   the extra-fields fill loop).*
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
   - **P4c/P4d** — Firebase, Hasura adapters, written just-in-time now
     that P4a/P4b's contracts and the origin/tenant-isolation and
     sensitive-field-guard precedents have landed.

   Ruling: every `RequestRecord` this codebase produces today (from both
   `capture.py`'s live collector and its HAR parser) already has its body
   *leaf values* redacted to the literal string `"[REDACTED]"` by
   `_sanitize_body`/`_redact_json` — only JSON *key names* and *path
   segments* survive redaction; query-parameter values are redacted too.
   There is currently no full-fidelity in-session `RequestRecord` path
   anywhere in the codebase, even transiently. Spec §7 step 9 / §8 /
   acceptance criterion 8 ("full values visible during the active TUI
   session") therefore needs a new full-fidelity capture/collector path
   that does not exist yet and is out of scope for both P3 (already
   shipped, sanitized-only, correctly so per its own non-goals) and P4
   (inventory only ever sees what `RequestRecord` already carries). Cost
   if wrong: acceptance criterion 8 silently has no implementation owner
   until this is caught. Resolution: `FieldInventory` (P4a) tracks field
   *names* only, not value types (type inference from a redacted body
   would be meaningless — every leaf is the string `"[REDACTED]"`). The
   full-fidelity in-session path becomes explicit new work, tracked as
   **P3b — full-fidelity in-session capture**, inserted before P8 (the TUI
   needs it) and revisited once P4-P7 clarify exactly what "full value" a
   findings/reporting view actually needs to hold in memory.
5. **P5 — BYOK AI planning**. `AIProviderConfig`/`ProposedTest` contracts,
   `openai_compatible` + `azure_openai` clients, sanitized-context builder,
   and the validator that intersects every proposed handle/method/field/path
   against observed inventory and confirmed scope (spec §5, acceptance
   criterion 5 — no credentials/cookies/raw IDs/full values ever leave).
6. **P6 — All-record mutation verification & crash recovery**. Wire
   `MutationGrant` into the executor: snapshot → canary → verify → restore →
   verify-restore per record, `all_discovered` auto-expansion with no silent
   sampling, AES-GCM recovery journal keyed via the OS vault, startup
   recovery gate (spec §6, §8, acceptance criteria 6–7).
7. **P7 — Typed findings & new export formats**. Replace generic
   `Mapping[str, Any]` evidence with typed `FindingEvidence`/
   `CapabilityProof` (spec §9); add `report.html` (self-contained, CSP-safe)
   and `junit.xml`; align existing Markdown/CSV/JSON/SARIF to the new
   filenames and `openbola-report-v1` schema id.
8. **P8 — Textual TUI shell**. Home/target/identity/capture/discovery/grant
   review/verification/findings/export/recovery screens (spec §7, §10)
   wired to the engine from P1–P7 through session services (config,
   progress events, cancellation). `openbola` with no args launches this.
9. **P9 — Setup/doctor/report/update subcommands**. `openbola setup`
   (Playwright browser install + self-test), `openbola doctor`,
   `openbola report RUN`, `openbola update` (GitHub Release check, checksum
   verify, explicit-confirm replace), local read-only `openbola mcp` reusing
   the renamed MCP server from P1.
10. **P10 — Distribution packaging**. PyInstaller specs for the three
    platform targets, `install.sh`/`install.ps1`, `SHA256SUMS`, release
    workflow. *This machine is macOS — the Windows x64 build must run on
    Windows CI; this plan produces the build config and macOS-side
    verification, not a cross-compiled Windows artifact.*
11. **P11 — Visual design & GitHub launch**. README hero/badges/demo,
    social-preview image, repository rename/topics/security URL. **Not
    started without separate explicit approval at execution time** — the
    spec itself (§12) requires that for publish/transfer/rename/release
    actions, independent of this roadmap.

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
