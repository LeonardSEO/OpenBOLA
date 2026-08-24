# SDD ledger — plan: docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md

## Objective

Complete P3b, P4d, and P5-P11 against the approved v1 design, preserving all
authorization, credential, AI non-execution, append-only audit, and recovery
boundaries. External P11 publication actions remain separately approval-gated.

## Baseline

- Branch: `main` (the user explicitly requested integration on main).
- Starting commit: `954e93e3ffb1aad1f24ad642046bff96478e57df`.
- Repository status at start: clean and tracking `origin/main`.
- Existing roadmap completion: P1, P2, P3, P4a, P4b, P4c.
- Required remaining work: P3b, P4d, P5, P6, P7, P8, P9, P10, P11.

## Coordination rulings

- Ruling: use one implementation agent at a time for shared code, while using
  parallel read-only audit agents for independent subsystems — this preserves
  the shared-worktree safety required by the harness; cost if wrong: less
  implementation concurrency than the user's ideal one-shot fan-out.
- Ruling: build P11 assets and documentation locally, but do not publish a
  release or mutate external repository metadata without a new explicit
  approval — required by design section 12; cost if wrong: the technical goal
  may finish while the public launch remains pending.
- Ruling: clean-machine Windows x64 and macOS x64/arm64 acceptance requires
  native CI or machines; local static checks are not equivalent — cost if
  wrong: completion remains unproven until platform runs exist.
- Ruling: execute P3b before P4d, because sanitized capture removes GraphQL
  documents and PostgREST query values that provider inventory needs — cost if
  wrong: P4d planning waits on a larger capture change, but avoids claiming
  synthetic-fixture coverage as production capture evidence.
- Ruling: raw capture material remains stored only behind session handles; an
  explicit ephemeral in-memory adapter view may resolve it for discovery, but
  transferable/persisted records remain sanitized — this reconciles the spec's
  `RequestRecord` adapter signature with its no-full-value-persistence rule;
  cost if wrong: the ephemeral boundary needs unusually strong negative tests
  against state, reports, AI payloads, MCP, and serialization.

## Audit workstreams

| Workstream | Scope | Shared producers/consumers | Status |
|---|---|---|---|
| A | P3b full-fidelity session capture | produces handles/session data for P5, P6, P8 | in progress |
| B | P4d Hasura adapter | consumes discovery contracts; produces inventory for P5/P8 | in progress |
| C | P5 BYOK AI planning | consumes handles/inventory/scope; produces typed plans for P6/P8 | in progress |
| D | P6 mutations/recovery | consumes grants/registry/state; produces recovery/progress for P8/P9 | in progress |
| E | P7 typed reporting | consumes findings/state; produces artifacts for P8/P9/P10 | in progress |
| F | P8/P9 TUI and command shell | consumes P3b-P7 services; produces application UX for P10 | in progress |
| G | P10/P11 distribution/launch | consumes complete app; produces artifacts and local launch assets | in progress |

## Completion audit findings

- P3b: no full response or browser-state capture existed; implementation plan
  now exists and is sequenced before P4d.
- P4d: Hasura inventory requires P3b's ephemeral full-fidelity adapter view;
  sanitized HAR alone redacts GraphQL documents and variables.
- P5: legacy LiteLLM planning is not the spec's `AIProviderConfig` /
  `ProposedTest` contract and does not bind suggestions to inventory identities,
  handles, fields, and current scope.
- P6: existing mutation flow is mutation-plus-status-cleanup, not snapshot ->
  unauthorized canary -> verify -> restore -> verify; no sweep preflight,
  encrypted journal, OS vault, or startup gate exists.
- P7: current deterministic reporting is four-format and generic-map based;
  JUnit already exists, while CSV and HTML do not. The roadmap wording must be
  corrected in the P7 plan.
- P8/P9: no Textual/session/event layer exists; the CLI exposes only `scan`.
  Windows-safe filesystem publication and MCP import primitives are also
  missing.
- P10/P11: no PyInstaller specs, native platform jobs, installers, checksum
  manifest, attestations, or launch assets exist. Existing ignored `dist/`
  artifacts are legacy BOLACheck artifacts and are not release inputs.

## Additional rulings

- Ruling: P5 provider traffic must use a separate confirmed `ScopeGuard`
  constructed from a provider scope file, and every provider request must call
  it; `AIProviderConfig` alone is not network authority — this preserves the
  non-negotiable every-network-operation boundary; cost if wrong: BYOK setup
  requires one additional explicit scope file.
- Ruling: P6 may add `cryptography` and an explicit OS-vault dependency only
  in its dedicated plan/task, with locked versions and native/fake-backend
  tests — required to implement AES-GCM and persistent recovery keys; cost if
  wrong: larger runtime and packaging surface.
- Ruling: P7 introduces typed report-boundary models and a legacy-safe adapter,
  not a hidden SQLite v4 migration — this avoids fabricating unavailable
  capability/cleanup facts from historic rows; cost if wrong: richer typed
  capability state may require a later explicit schema migration.
- Ruling: split P9 into P9a command/services before packaging and P9b packaged
  updater integration after P10 defines the install unit — cost if wrong: the
  roadmap execution order becomes P9a -> P10 -> P9b rather than one atomic P9.
- Ruling: setup/update distribution network cannot bypass `ScopeGuard`; if the
  Playwright installer cannot expose every redirect for checking, P9 must use
  an OpenBOLA-controlled downloader under a confirmed distribution scope or
  remain unproven — cost if wrong: substantially more setup implementation.

## P3b execution status

- Task 1 complete: `258c750` (`SessionValueStore` lifecycle), independently
  reviewed and approved.
- Task 2 complete: `99d2003`, `0b34eb4`, and `d373cf8` (handle-only
  in-session model, serialization blocking, strict adapter-result containment,
  and subclass/extra-state regression coverage), independently re-reviewed and
  approved. Focused capture tests: 5 passed; implementer reported full suite
  357 passed with Ruff and strict mypy green.
- Contract gate before P4d: the P3b plan must explicitly expose the
  non-serializable `AdapterRecordView` required by the P4d plan; current
  `with_adapter_records()` wording still names raw `RequestRecord` values.
- Task 3 implementation complete at `73d8e77` (bounded full-fidelity
  collector, dual event multiplexer, shared scoped browser run, async response
  draining, safe limits, and sanitized HAR publication). Implementer reported
  55 capture tests passing with Ruff and strict mypy green; independent review
  is pending.
- Follow-up `f6b1c44` closes the duplicate-response race while an earlier body
  task is still draining; it is included in the pending independent review.
- Follow-ups `4288ea3`, `5d97a11`, `1babdf1`, and `b55d3f4` close the registry
  on setup failure, expose the reviewed `AdapterRecordView` callback contract,
  and sanitize hostile request/response exception text. Task 3 is complete and
  independently approved; capture tests 56 and full suite 362 passed with Ruff
  and strict mypy green. Task 4 remains the next P3b gate.
- Task 4 implementation is committed as `f57b8e0`: provider discovery
  interfaces consume `AdapterRecordView`, and scope/lifecycle/capture-to-
  discovery regressions are present. Focused capture/discovery tests: 77
  passed; Ruff and strict mypy passed. Independent review is pending.
- Task 4 fix `0155fc4` (plus contract documentation `f226cff`) removes all
  `RequestRecord` compatibility bypasses, defaults both ephemeral body fields,
  and makes GenericAdapter's synchronous body-ID inspection explicit. Review
  approved; 112 focused provider/discovery/capture tests passed with Ruff and
  strict mypy. P3b is now ready for final report-boundary checks before P4d.
- Task 5 implementation is committed as `6977c2a`: sentinel fixture plus
  negative persistence/reporting/AI/MCP tests; no production changes were
  needed. Implementer reports targeted modules 102 passed and full pytest 373
  passed with Ruff, strict mypy, and diff-check green. Independent review is
  pending; after approval P3b is complete.
- Task 5 independently approved: no raw sentinel crosses state, SQLite,
  reporting, AI, or MCP boundaries; 373 full-suite tests passed. **P3b is
  complete** across Tasks 1–5. P4d may now begin against the locked
  `AdapterRecordView` contract.

## P4d execution status

- P3b prerequisite is complete and approved. P4d Task 1 parser/contracts is
  now in progress against `AdapterRecordView`; Hasura implementation must stay
  stdlib-only and perform no network operation.
- P4d Task 1 implementation is committed as `e4522ce`: bounded stdlib GraphQL
  lexer/parser contracts and tests. Parser review is pending; Task 2 will add
  detection/inventory only after approval.
- P4d Task 1 fixes `e4d7a07`, `4d87149`, and `0edfea7` harden delimiter,
  argument/directive grammar, depth bounds, and valid variable definitions.
  Final review approved: 8 parser tests passed with Ruff and strict mypy.
  Task 2 may begin.
- P4d Task 2 implementation is committed as `f0fd64b`: Hasura detection,
  origin-gated inventory, query/body helpers, and mutation-returning handling.
  Implementer reports 13 parser/provider tests plus targeted checks green;
  independent review is pending.
- P4d Task 2 independently approved: origin partitions, header-only detection,
  malformed fail-closed parsing, safe inventories, and mutation returning are
  covered; targeted tests/Ruff/mypy passed. Task 3 (variable association and
  sensitive-ID guards) may begin.
- P4d Task 3 implementation is committed as `a87c4ea`: guarded variable
  association, opaque record handles, and sensitive/operator/parent guards.
  Implementer reports targeted 9 and full Hasura 17 tests green; independent
  review is pending.
- P4d Task 3 independently approved: variable/root association, direct-ID and
  parent `_eq` handling, sensitive/range/pattern exclusions, opaque handle
  conversion, and origin isolation all pass review. Task 4 acceptance proof is
  next.
- P4d Task 4 implementation is committed as `6034f83`: mutation/malformed/
  protocol acceptance and capture→AdapterRecordView→Hasura proof with
  sanitized HAR/raw-serialization assertions. Implementer reports focused 22
  and full pytest 394 passed; independent review is pending.
- P4d Task 4 independently approved: returning-field/malformed/redacted
  acceptance, protocol checks, and deterministic capture→Hasura proof all pass;
  no network path or raw serialization exists. **P4d is complete** across
  Tasks 1–4. P5 BYOK AI planning is the next roadmap gate.

## P5 execution status

- Executable P5 plan committed as `362dcd7`: typed BYOK contracts/context,
  strict proposal validation, explicit provider-scope HTTP clients, legacy
  LiteLLM migration, and privacy/redirect/fake-transport acceptance tests.
- P5 implementation has not started; runtime dependency additions are not
  expected because existing `httpx` is reused.
- P5 Task 1 implementation is committed as `da2d223` (report finalized in
  `2841e48`): typed AI contracts and bounded privacy-safe context. Local tests
  34 passed with Ruff and strict mypy; independent review is pending.
- P5 Task 1 independently approved: immutable bounded contracts, exact
  context allowlist, endpoint safety, deterministic sorting/dedup, and no
  handle/secret resolution all pass. Task 2 strict proposal parsing/binding
  may begin.
- P5 Task 2 implementation is committed as `264e76d`: strict proposal JSON
  parsing and exact inventory/target-scope validation. Local AI tests reached
  51 passed with Ruff and strict mypy; independent review is pending.
- P5 Task 2 fix `d0a308b` adds strict canonical HTTPS target-origin validation
  including invalid/zero/out-of-range ports and exact ScopeGuard path proof.
  Re-review approved; 28 focused tests, Ruff, and strict mypy pass. Task 3
  provider clients may begin.
- P5 Task 3 implementation is committed as `d4f0d7f`: scope-guarded BYOK
  OpenAI-compatible/Azure clients with fake-transport privacy, redirect,
  bounds, and error tests. Implementer reports 82 combined AI/client tests
  passed with Ruff/mypy; independent review is pending.
- P5 Task 3 hardening commits `00eb794`, `2a8eca9`, `48d8821`, and `3572e92`
  (reports `3e67fd3`, `d6f65da`) close ScopeGuard provenance/peer policy,
  routing headers, strict JSON recursion, streaming bounds, and header/secret
  encoding. Final review approved; 97 focused AI/client tests pass with Ruff
  and strict mypy. Task 4 legacy migration/acceptance is next.
- P5 Task 4 implementation is committed as `b67c993`: legacy LiteLLM planning
  delegates through typed contracts while preserving a deprecation shim and
  no target execution. AI tests: 66 passed; Ruff/mypy green. Independent review
  is pending.
- P5 Task 4 independently approved. Obsolete `litellm` optional extra and its
  lockfile graph were removed in `454b7c2`; typed compatibility shim remains
  deprecation-safe and non-executing. AI tests 66 passed with Ruff/mypy. P5
  Task 5 is the final acceptance/roadmap update gate.
- P5 Task 5 acceptance is committed as `6eb2dab`: separate provider-scope
  boundary test, strict fake transport privacy/binding checks, close fail-
  closed proof, and roadmap P5 marker. Implementer reports focused 106, full
  pytest 475, Ruff, and strict mypy green; independent review is pending.
- P5 Task 5 independently approved: separate real provider ScopeGuard,
  MockTransport-only boundary, payload privacy, proposal binding rejection, and
  registry close proof all pass. **P5 is complete** across Tasks 1–5; P6
  mutation/recovery planning is next.

## P6 execution status

- Executable P6 plan committed as `e70b8fe`: all-record immutable preflight,
  scoped executor-only writes, snapshot/canary/verify/restore state machine,
  AES-GCM journal, OS-vault checkpoint, startup recovery gate, and append-only
  manual escalation. Cryptography/vault dependency changes remain an explicit
  implementation checkpoint; no P6 product code has started.
- P6 Task 1 implementation is committed as `de0421c`: immutable mutation
  candidates/operations/inventory/plan/outcome and strict all-record preflight
  with exact grant/scope/budget checks. Fourteen mutation tests passed; Ruff
  and strict mypy are green. Independent review is pending.
- P6 Task 1 redaction fix is in `a0d08b0`: runtime target/canary/credential
  material is omitted from repr and plan/candidate pickling fails closed.
  Re-review approved; 15 focused tests and full 490-suite regression pass.
- P6 Task 2 implementation is committed as `5b13b52`, with executor metadata
  coverage in `4bee740`. It adds the single guarded `request_scoped` primitive
  and deterministic snapshot → canary → unauthorized verify → restore →
  restore verify sweep, with cancellation-safe cleanup and global stop on
  unverified restoration. Review fixes `d922480`/`ad99830` normalize opaque
  handle generation, reject query/fragment endpoint smuggling, and export the
  bounded exchange type. Scope provenance is exposed by `c1e9e36` for the
  in-process plan boundary. Independent review approved Task 2: 58 focused
  tests, 60 repeated sweep runs, full pytest 495, Ruff and strict mypy pass.
- P7 executable plan is committed as `ceedede`; its typed reporting boundary
  is now implemented in Task 1 as `71188ce` (report `task-1-report.md`). The
  immutable `FindingEvidence`/`CapabilityProof`/resource contracts, hashed
  identity references, bounded endpoint/status/text validation, and fail-closed
  legacy adapter preserve `serialize_evidence` compatibility without allowing
  legacy data to imply write/delete proof. Independent review approved Task 1:
  18 focused tests, full pytest 498, Ruff and strict mypy pass.
- P7 Task 2 is committed as `0574607` (reporting boundary report included).
  `ReportBundle` normalizes legacy findings without retaining source mappings,
  validates and deterministically orders `ResourceReport` values, and exposes
  the typed `canonical_report_document()` with schema id
  `openbola-report-v1`/version 1. Independent review approved Task 2: 20
  focused reporting/boundary tests, full pytest 500, Ruff and strict mypy pass.
- P7 Task 3 is committed as `3b5ffd4` with CSV/HTML and six deterministic v1
  artifact payloads, plus follow-up `e7e3b91` for canonical CSV projection.
  Independent review approved the six renderers (CSP-safe self-contained HTML,
  escaped values, synthetic SARIF locations, typed evidence): 33 focused
  reporting/E2E/CLI tests and full pytest 503 passed with Ruff and strict mypy.
- P7 Task 4 integration is committed as `316d810`: existing atomic six-payload
  publication was aligned with CLI/E2E/reporting assertions and sixth-write
  failure leaves no destination or staging directory. Task 4 is approved by
  the full 503-test regression; P7 Task 5 acceptance/roadmap gate remains.
- P7 Task 5 is complete in `8ae388c`: cross-phase sentinel acceptance covers
  ValueHandle capture, StateStore, canonical documents, repr/asdict/pickle,
  all six renderers, and atomic persisted artifacts. It also proves legacy
  evidence cannot infer mutation proof. Independent review approved the gate:
  37 focused tests, full pytest 505, Ruff, and strict mypy pass. **P7 is
  complete across Tasks 1–5.**
