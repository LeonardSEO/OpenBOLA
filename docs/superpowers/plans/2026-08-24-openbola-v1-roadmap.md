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
   against deterministic fixtures (acceptance criterion 4).
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
