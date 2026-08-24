# OpenBOLA v1 Textual TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Implement this plan task-by-task, with a fresh implementer and an independent review for each task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `openbola` (without a subcommand) launch an accessible, full-screen Textual application that guides an operator through a confirmed target, two-identity capture, read-only discovery, optional typed AI planning, grant review, all-record verification, findings, export, and recovery while keeping all resolved values process-local and every target request behind the existing policy engine.

**Architecture:** Add a small session-service layer between Textual widgets and the existing P1–P7 engine. The service owns the in-memory `SessionValueStore`, typed assessment state, progress events, cancellation, and the recovery gate; screens only validate input, render safe projections, and dispatch typed commands. Network-capable work remains in `capture.py`, `pipeline.py`, `ProbeExecutor`, `MutationSweepExecutor`, and the P7 reporting boundary. The UI may resolve a `ValueHandle` only while rendering an active finding detail and must clear those views before leaving the session.

**Tech Stack:** Python 3.11+, Textual (added as a runtime dependency at the dependency checkpoint), existing Rich/Textual terminal widgets, `ScopeGuard`, `InMemorySessionValueRegistry`/`SessionValueStore`, Playwright capture contracts, P5 typed planning clients, P6 `RecoveryGate`/mutation contracts, and P7 typed reporting contracts.

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§3, §5, §7, §8, §9, §10, §13) and `docs/superpowers/plans/2026-08-24-openbola-v1-roadmap.md` (P8).

## Global Constraints

- `openbola` launches the TUI; `openbola scan` remains the existing headless read-only command and all existing flags and JSON output stay compatible.
- Every target or provider request is delegated to an existing `ScopeGuard`-bound engine (`capture`, `ProbeExecutor`, `MutationSweepExecutor`, or P6 recovery coordinator); `tui.py` and `session.py` must not import `httpx`, create transports, follow redirects, or resolve credentials for their own requests.
- The first assessment screen requires a normalized target origin, a readable confirmed scope file, and an authorization reference; an expired, changed, unconfirmed, or missing scope is a denied state, never an editable warning that permits continuing.
- At least two distinct identities are required before capture and every secret input is stored as a `SecretHandle`/OS-vault reference. Secret values, cookies, raw IDs, full bodies, and resolved restore values must not enter widget labels, events, exceptions, logs, SQLite, reports, or AI context.
- Full response material may be resolved from the active `InSessionCapture`/`SessionValueStore` only for the current local finding view. Navigating away, cancelling, or closing the app clears the view and closes the registry; no serialization, clipboard copy, debug repr, or crash traceback may include it.
- Read-only discovery completes before any grant can be confirmed. An `all_discovered` mutation plan is displayed with the exact record/request count produced by P6 preflight; there is no sample, truncation, or implicit grant.
- Mutation confirmation is a distinct action from grant review. Cancellation is cooperative between requests; a cancellation after a write has been dispatched is handed to P6 cleanup and the UI cannot start another write until restore verification or an explicit recovery gate state.
- A non-clear P6 recovery status blocks New Assessment and Verification. The recovery screen can retry safe recovery or record manual escalation through the P6 append-only API; escalation enables diagnostics only and never authorizes writes.
- The TUI must render at 80x24, maintain keyboard focus, expose status by text/icon as well as colour, and render loading, empty, denied, error, recovery, cancelled, and success states. English copy must say “no confirmed findings in recorded coverage,” never “safe,” when no BOLA is found.
- Reports are produced only through P7 typed `ReportBundle`/`write_reports` contracts. The TUI does not add a private report schema or persist full in-session values. Export errors are displayed without paths, values, or exception locals that could disclose sensitive material.
- Add/update the Textual dependency only at the explicit dependency checkpoint as `textual>=0.70,<1`, lock it with `uv`, and keep the dependency range compatible with Python 3.11. Before completion run `uv run ruff check .`, `uv run mypy src`, and `uv run pytest`.

## File Map

- Create `src/openbola/session.py` — typed TUI session state, command/service protocols, safe progress events, cancellation token, and lifecycle cleanup.
- Create `src/openbola/tui.py` — Textual `App`, screen stack, widgets, keyboard actions, safe render projections, and adapter calls into `SessionController`.
- Modify `src/openbola/cli.py` — launch the TUI when no subcommand is supplied while preserving `scan`, help, and machine-readable error behavior.
- Modify `pyproject.toml` and `uv.lock` — add Textual only at the approved dependency checkpoint.
- Create `tests/test_session.py` — session lifecycle, event ordering, cancellation, recovery gate, and value-clearing boundaries.
- Create `tests/test_tui.py` — Textual Pilot tests at 80x24 covering navigation, focus, status states, secret redaction, and confirmation boundaries.
- Modify `tests/test_cli.py` — no-argument launch delegation and unchanged `scan`/`--help` behavior.

## Public Contracts

The following contracts are the stable boundary between screens and the engine. They contain only handles, counts, labels, and typed safe summaries; implementations must not add resolved values to them.

```python
class SessionPhase(StrEnum):
    HOME = "home"
    TARGET = "target"
    IDENTITIES = "identities"
    CAPTURE = "capture"
    DISCOVERY = "discovery"
    AI_PLAN = "ai_plan"
    GRANT_REVIEW = "grant_review"
    VERIFICATION = "verification"
    FINDINGS = "findings"
    EXPORT = "export"
    RECOVERY = "recovery"

class ProgressState(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass(frozen=True)
class ProgressEvent:
    phase: SessionPhase
    state: ProgressState
    completed: int
    total: int | None
    message: str

@dataclass(frozen=True)
class TargetSummary:
    origin: str
    scope_digest: str
    authorization_reference_fingerprint: str

@dataclass(frozen=True)
class IdentitySummary:
    name: str
    recipe_name: str | None
    credential_handle_id: str

@dataclass(frozen=True)
class DiscoverySummary:
    provider_count: int
    resource_count: int
    record_count: int
    field_count: int
    complete: bool

@dataclass(frozen=True)
class GrantSummary:
    method_labels: tuple[str, ...]
    path_labels: tuple[str, ...]
    field_labels: tuple[str, ...]
    record_count: int
    request_count: int
    cleanup_policy: str
    scope_digest: str

class CancellationToken(Protocol):
    def is_cancelled(self) -> bool: ...
    def cancel(self) -> None: ...

class SessionController(Protocol):
    def snapshot(self) -> Mapping[str, object]: ...
    def subscribe(self, callback: Callable[[ProgressEvent], None]) -> Callable[[], None]: ...
    def configure_target(self, *, target_url: str, scope_path: Path) -> TargetSummary: ...
    def add_identity(self, summary: IdentitySummary) -> None: ...
    def start_capture(self, token: CancellationToken) -> None: ...
    def start_discovery(self, token: CancellationToken) -> DiscoverySummary: ...
    def review_grant(self) -> GrantSummary: ...
    def confirm_grant(self) -> None: ...
    def start_verification(self, token: CancellationToken) -> None: ...
    def list_findings(self) -> Sequence[Mapping[str, object]]: ...
    def finding_detail(self, handle_id: str) -> Mapping[str, object]: ...
    def export(self, output_dir: Path) -> Mapping[str, Path]: ...
    def recovery_status(self) -> RecoveryStatus: ...
    def recover(self) -> RecoveryStatus: ...
    def record_manual_escalation(self) -> RecoveryStatus: ...
    def close(self) -> None: ...
```

`SessionController.snapshot()` and every mapping returned above are safe UI projections: opaque handles, fingerprints, bounded labels, counts, statuses, and coverage only. A controller implementation may keep raw `ProbeTarget`, `InSessionCapture`, `MutationCandidate`, and restore values internally, but it must not return them or expose them through `repr`, pickling, event callbacks, or exceptions.

## Task 1: Add the session service boundary and dependency checkpoint

**Files:**

- Create `src/openbola/session.py` and `tests/test_session.py`.
- Modify `pyproject.toml` and `uv.lock` only after the dependency checkpoint.

**Interfaces:**

- Consumes: `ScopeGuard`, `ScopeConfig`, `InMemorySessionValueRegistry`, `InSessionCapture`, P5 planning summaries, P6 `RecoveryStatus`/`RecoveryGate`, and P7 report summaries.
- Produces: `SessionPhase`, `ProgressState`, `ProgressEvent`, `TargetSummary`, `IdentitySummary`, `DiscoverySummary`, `GrantSummary`, `CancellationToken`, `SessionController`, and a concrete `AssessmentSession` implementing the lifecycle.

- [ ] **Step 1: Write failing session-contract tests.**

  Assert that a new session is `HOME`; a target cannot be configured from an unconfirmed/expired scope; the second identity is required before capture; event callbacks receive monotonically ordered `(phase, completed)` values; cancelling a read operation results in `CANCELLED`; closing the session closes the registry and makes all handles unresolvable. Assert that `repr(snapshot())`, event messages, and controller exceptions never contain test secrets, cookies, raw IDs, or full bodies.

- [ ] **Step 2: Run the focused tests to verify they fail.**

  Run: `uv run pytest tests/test_session.py -v`
  Expected: FAIL because the session contracts and implementation do not exist.

- [ ] **Step 3: Add Textual at the dependency checkpoint.**

  Add `textual>=0.70,<1` to the main runtime dependencies, run `uv lock`, and run `uv lock --check`. Do not add a second terminal UI framework. If the dependency approval checkpoint has not been granted, stop after the contract tests and report the exact `pyproject.toml`/`uv.lock` change required instead of installing an unpinned package.

- [ ] **Step 4: Implement the session lifecycle.**

  Use a private `InMemorySessionValueRegistry`, a bounded callback list, and a `threading.Event`-backed cancellation token. Run blocking capture/discovery/verification work in a worker (`ThreadPoolExecutor` or an equivalent one-worker executor), marshal only `ProgressEvent` values back to the UI, and shut the worker down before `close()` returns. Gate every operation by the current `SessionPhase`; after `close()` all commands fail with the fixed message `session is closed`. Implement `recover()` and `record_manual_escalation()` by delegating to P6 and expose only `RecoveryStatus`.

- [ ] **Step 5: Run focused tests and static checks.**

  Run: `uv run pytest tests/test_session.py -v && uv run ruff check src/openbola/session.py tests/test_session.py && uv run mypy src/openbola/session.py`
  Expected: PASS with no raw-value assertion failures.

- [ ] **Step 6: Commit.**

  ```bash
  git add src/openbola/session.py tests/test_session.py pyproject.toml uv.lock
  git commit -m "feat: add typed TUI assessment session boundary"
  ```

## Task 2: Build the Textual application shell and no-argument launch

**Files:**

- Create `src/openbola/tui.py`.
- Modify `src/openbola/cli.py`.
- Create or extend `tests/test_tui.py` and `tests/test_cli.py`.

**Interfaces:**

- Consumes: `SessionController`, `ProgressEvent`, and safe summaries from Task 1.
- Produces: `OpenBOLAApp(session: SessionController)`, screen classes keyed by `SessionPhase`, and `launch_tui() -> None`.

- [ ] **Step 1: Write failing Pilot and CLI tests.**

  Instantiate `OpenBOLAApp` with a fake controller and `size=(80, 24)`. Assert Home renders the title, `New Assessment`, `Resume Sanitized Run`, `Recovery`, `Setup`, `Doctor`, and `Update` actions; focus order follows visual order; pressing `n` opens Target; pressing `g` opens Recovery. Assert `CliRunner.invoke(app, [])` calls the injected `launch_tui` exactly once, `--help` prints help without launching, and `scan` still calls `run_pipeline` and returns the existing JSON shape.

- [ ] **Step 2: Run focused tests to verify they fail.**

  Run: `uv run pytest tests/test_tui.py tests/test_cli.py -k 'launch or home or focus' -v`
  Expected: FAIL because the Textual app and no-argument callback are not present.

- [ ] **Step 3: Implement the app shell.**

  Create a `textual.app.App` with a single controller, a `Screen` for each `SessionPhase`, `Header`/`Footer`, a persistent status line, and a safe event subscription. Use actions (`action_new_assessment`, `action_recovery`, `action_cancel`, `action_back`) instead of widget-specific network callbacks. Render state words/icons (`RUNNING`, `DENIED`, `FAILED`, `CANCELLED`, `OK`) in addition to colour and set a reduced-colour stylesheet mode without relying on colour alone. All worker callbacks must use Textual's message queue/call-from-thread mechanism; never mutate widgets from a worker.

- [ ] **Step 4: Change CLI dispatch without changing scan.**

  Set the Typer callback to `invoke_without_command=True`, accept `typer.Context`, and call `launch_tui()` only when `ctx.invoked_subcommand is None`; keep `no_args_is_help=False` so the no-argument path is the TUI. Preserve `scan` parsing, `--json` error output, and `if __name__ == "__main__"` behavior. The import must remain lazy enough that `openbola scan` has no Textual startup side effect.

- [ ] **Step 5: Verify.**

  Run: `uv run pytest tests/test_tui.py tests/test_cli.py -v && uv run ruff check . && uv run mypy src`
  Expected: PASS; no-argument app starts only in the launch test and headless scan remains machine-safe.

- [ ] **Step 6: Commit.**

  ```bash
  git add src/openbola/tui.py src/openbola/cli.py tests/test_tui.py tests/test_cli.py
  git commit -m "feat: launch Textual app from openbola"
  ```

## Task 3: Implement target, identity, capture, discovery, and AI screens

**Files:**

- Modify `src/openbola/tui.py` and `src/openbola/session.py`.
- Extend `tests/test_tui.py` and `tests/test_session.py`.

**Interfaces:**

- Consumes: `CaptureConfig`, `LoginRecipe`, `SecretHandle`, `CaptureCollector`, P4 provider inventory, P5 sanitized planning APIs, and Task 1 progress/cancellation contracts.
- Produces: target and identity forms that call `configure_target()`/`add_identity()`, a capture progress view, a discovery matrix, and an optional AI-plan preview that displays typed proposed handles only.

- [ ] **Step 1: Write failing workflow tests.**

  Cover invalid URL, missing scope, scope denial, duplicate identity, one-identity capture, capture cancellation, discovery with zero resources, discovery completion, and AI context preview. Submit username/password through password inputs and assert the fake controller receives only secret handles; assert the rendered DOM, event messages, and AI preview contain neither the supplied secret nor a raw object ID. Verify a provider adapter is called through its typed callback view and the screen never gets an HTTP client.

- [ ] **Step 2: Run focused tests to verify they fail.**

  Run: `uv run pytest tests/test_tui.py tests/test_session.py -k 'target or identity or capture or discovery or ai' -v`
  Expected: FAIL until the forms and controller commands are wired.

- [ ] **Step 3: Implement Target and Identity screens.**

  Target accepts an HTTPS/HTTP origin and scope path, normalizes the origin using the same URL rules as `ScopeGuard`, shows the authorization-reference fingerprint after scope validation, and disables Continue on denial. Identity setup requires two distinct safe names, recipe selectors/patterns, and vault-backed `SecretHandle`s; secret fields use `Input(password=True)` and are cleared after submission. Do not echo file contents, environment values, cookies, or selectors containing secret values.

- [ ] **Step 4: Implement Capture and Discovery screens.**

  Start capture only after target and identity validation, subscribe to bounded progress events, show per-identity counts, and offer cooperative Cancel. Keep the `InSessionCapture` and registry inside `AssessmentSession`; render only sanitized traffic counts and provider/resource/record/field names. Require `DiscoverySummary.complete is True` before enabling AI Plan or Grant Review. A zero-resource result is an explicit empty state with a next-step explanation, not a success claim.

- [ ] **Step 5: Implement optional AI Plan preview.**

  Show the sanitized P5 context summary (provider confidence, route templates, opaque handle IDs, budgets) before sending; require a separate operator confirmation. Display returned typed `ProposedPlan` entries after P5 validation and show rejected entries by bounded reason. The screen has no provider credential field and no direct provider/network call; `AssessmentSession` delegates to P5 clients with their separate provider `ScopeGuard`.

- [ ] **Step 6: Verify and commit.**

  Run: `uv run pytest tests/test_tui.py tests/test_session.py -k 'target or identity or capture or discovery or ai' -v && uv run ruff check . && uv run mypy src`

  ```bash
  git add src/openbola/tui.py src/openbola/session.py tests/test_tui.py tests/test_session.py
  git commit -m "feat: add target capture discovery and planning screens"
  ```

## Task 4: Add grant review, verification progress, and recovery gate screens

**Files:**

- Modify `src/openbola/tui.py` and `src/openbola/session.py`.
- Extend `tests/test_tui.py` and `tests/test_session.py`.

**Interfaces:**

- Consumes: P6 `MutationCandidateInventory`, `MutationSweepPlan`, `MutationOutcome`, `RecoveryStatus`, `RecoveryGate`, `ScopeGuard`, and `CancellationToken`.
- Produces: an exact grant-review projection, a confirmation barrier, verification outcome matrix, and startup/recovery screen.

- [ ] **Step 1: Write failing safety tests.**

  Assert that Grant Review displays methods, path rules, allowed fields, record count, exactly calculated request count, scope digest, and cleanup policy. Confirm is disabled when discovery is incomplete, the grant is absent/mismatched, a budget is exceeded, or `RecoveryStatus.state` is not `clear`. Assert that one click calls `confirm_grant()` once and a second click does not dispatch another write. Simulate cancellation after a canary write and require the UI to show `cleanup in progress`, disable New Assessment/Verify, and wait for P6 restore verification. Simulate `required`, `blocked`, and `escalated` recovery states and assert that each blocks writes.

- [ ] **Step 2: Run focused tests to verify they fail.**

  Run: `uv run pytest tests/test_tui.py tests/test_session.py -k 'grant or verification or recovery' -v`
  Expected: FAIL until the barriers and state transitions are implemented.

- [ ] **Step 3: Implement Grant Review.**

  Call P6 preflight before rendering the review. Bind the displayed `scope_digest` to the plan and reject a changed scope by re-running preflight. Use a checkbox or explicit `Confirm mutation grant` button separate from navigation. Never render `MutationCandidate.target.object_id`, `ValueHandle` contents, credentials, original values, or journal bytes; show opaque record handles only.

- [ ] **Step 4: Implement Verification and cancellation.**

  Start `MutationSweepExecutor.sweep()` only after the immutable plan and explicit confirmation. Map each `MutationOutcome` to a row with status text (`verified`, `inconclusive`, `skipped`) and cleanup status; stream counts without carrying response bodies. The cancellation token stops before the next candidate; P6 owns in-flight cleanup and the UI remains in a guarded state until the service reports `restore_verified` or `RecoveryStatus.required`.

- [ ] **Step 5: Implement Recovery.**

  On app startup, query P6 recovery status before enabling New Assessment. Show journal-present reason codes without displaying journal paths or bytes. `Recover` invokes `RecoveryGate.recover()` with the current scope and grant validation; `Manual escalation` invokes the append-only escalation method and changes the app to read-only diagnostics. Recovery success clears the gate and returns to Home; failure keeps the gate closed.

- [ ] **Step 6: Verify and commit.**

  Run: `uv run pytest tests/test_tui.py tests/test_session.py -k 'grant or verification or recovery' -v && uv run ruff check . && uv run mypy src`

  ```bash
  git add src/openbola/tui.py src/openbola/session.py tests/test_tui.py tests/test_session.py
  git commit -m "feat: gate mutation verification and recovery in TUI"
  ```

## Task 5: Add findings detail and sanitized export screens

**Files:**

- Modify `src/openbola/tui.py` and `src/openbola/session.py`.
- Extend `tests/test_tui.py` and `tests/test_session.py`.

**Interfaces:**

- Consumes: P7 `FindingEvidence`, `CapabilityProof`, `ReportBundle`, `write_reports`, deterministic report paths, and process-local `ValueHandle` resolution.
- Produces: resource matrix, finding detail, reproduction/cleanup status, and export screens using only the P7 report boundary.

- [ ] **Step 1: Write failing findings/export tests.**

  Assert the matrix displays provider/confidence, resource/endpoint, discovered records, field names/types, identity statuses, capabilities, and coverage. Select a finding and assert detail shows severity, impacted identities, body/status comparison, exact in-session reproduce action, remediation, and restore verification. Assert resolved full values are visible only while the detail screen is mounted, disappear on Back/Export/Close, never enter a `ProgressEvent`, and cannot be copied through a debug or clipboard action. Assert export calls `write_reports()` once, reports all six expected filenames, and displays a deterministic “export complete” state without exposing a temporary path or exception text.

- [ ] **Step 2: Run focused tests to verify they fail.**

  Run: `uv run pytest tests/test_tui.py tests/test_session.py -k 'finding or export' -v`
  Expected: FAIL until the report screens are wired.

- [ ] **Step 3: Implement the resource matrix and finding detail.**

  Render stable table columns with textual status labels and a non-colour legend. Resolve a `ValueHandle` only inside the detail render method, format it through a bounded safe display helper, and clear the widget contents plus the controller's detail cache on every screen transition. Reproduce invokes a typed session command that routes through the existing scope/executor path; it never constructs a request from UI text.

- [ ] **Step 4: Implement exports.**

  Pass a P7 `ReportBundle` to `write_reports()` and show the six artifact labels (`report.html`, `report.csv`, `report.json`, `report.md`, `junit.xml`, `report.sarif`) as safe basenames. Use the already atomic report writer; do not write from the TUI and do not add a remote viewer or local report server. If no findings exist, display the coverage limitation from P7 instead of claiming safety.

- [ ] **Step 5: Verify and commit.**

  Run: `uv run pytest tests/test_tui.py tests/test_session.py -k 'finding or export' -v && uv run ruff check . && uv run mypy src`

  ```bash
  git add src/openbola/tui.py src/openbola/session.py tests/test_tui.py tests/test_session.py
  git commit -m "feat: browse findings and export reports in TUI"
  ```

## Task 6: Accessibility, boundary, and acceptance verification

**Files:**

- Modify `src/openbola/tui.py`, `src/openbola/session.py`, and `tests/test_tui.py` only for defects discovered by the checks.
- Add `tests/test_tui_boundary.py`.

**Interfaces:**

- Consumes: all completed P8 screens and the P1–P7 safety contracts.
- Produces: a deterministic local TUI demo fixture and evidence for the P8 acceptance slice; no new target capability.

- [ ] **Step 1: Add boundary tests.**

  Use a fake controller and `httpx.MockTransport` only behind the existing executor fixture. Assert TUI modules import no HTTP client, never call a transport directly, reject a scope mismatch before dispatch, reject mutation without a confirmed grant, keep raw IDs and secrets out of `repr`/events/screenshots, close the session registry on every exit path, and refuse to proceed after a recovery gate failure. Assert no-value persistence by serializing the controller snapshot/events and scanning all report/export fixture bytes for sentinel secrets and IDs.

- [ ] **Step 2: Exercise the 80x24/reduced-colour matrix.**

  Run Pilot at `80x24` through every screen, including loading, empty, denied, failed, recovery, cancelled, and success states. Verify the focused widget is visible, every action has a keyboard binding, and status remains understandable with colour disabled. Use the deterministic local mock target and two fake identities; do not make a network call outside the pre-existing test transport.

- [ ] **Step 3: Run the complete validation suite.**

  ```bash
  uv run pytest tests/test_tui.py tests/test_tui_boundary.py tests/test_session.py -v
  uv run ruff check .
  uv run mypy src
  uv run pytest
  ```

  Expected: all focused and repository tests pass. If a failure is unrelated to P8, record its existing owner and leave its files untouched.

- [ ] **Step 4: Commit verification fixes and report evidence.**

  ```bash
  git add src/openbola/tui.py src/openbola/session.py tests/test_tui.py tests/test_tui_boundary.py
  git commit -m "test: verify OpenBOLA TUI safety and accessibility"
  ```

## Self-review checklist

- Spec §7 steps 1–10 map to Home/Target/Identity/Capture/Discovery/AI/Grant/Verification/Findings/Export screens and the session controller.
- Spec §8 persistence and recovery rules are enforced by the registry lifecycle, P6 recovery gate, and no-value boundary tests.
- Spec §9 typed findings and six exports are consumed from P7 rather than reimplemented in the UI.
- Spec §10 80x24, focus, reduced-colour, and all required status states are covered by Pilot tests.
- Spec §13 acceptance checks 3, 5, 6, 7, 8, and 9 receive local deterministic coverage; clean-machine packaging checks remain P10 and external launch/publish work remains P11.
- No TUI task grants network authority, weakens scope/mutation checks, follows redirects, or stores raw values.
