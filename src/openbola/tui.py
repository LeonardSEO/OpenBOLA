"""Accessible Textual front end for the OpenBOLA assessment lifecycle.

The application is deliberately a thin adapter.  It owns no transport and
does not resolve credentials or values; all work is delegated to a
``SessionController`` and all values displayed here are bounded projections.
This makes the application useful with the real session service as well as a
deterministic fake in local demos and tests.
"""

from __future__ import annotations

import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

from openbola.mutations import RecoveryStatus
from openbola.session import (
    CancellationToken,
    IdentitySummary,
    ProgressEvent,
    ProgressState,
    SessionCancellationToken,
    SessionController,
    SessionError,
    SessionPhase,
)


def _safe_text(value: object, fallback: str = "—", limit: int = 160) -> str:
    """Return a bounded single-line label, never an exception or raw object."""

    if not isinstance(value, str) or not value:
        return fallback
    cleaned = " ".join(value.split())
    return cleaned[:limit] if cleaned else fallback


def _status_text(event: ProgressEvent) -> str:
    state = event.state.value.upper()
    total = f"/{event.total}" if event.total is not None else ""
    phase = event.phase.value.replace("_", " ")
    return f"{state}  {phase}  {event.completed}{total}  {_safe_text(event.message)}"


class BaseScreen(Screen[None]):
    """Shared chrome and safe navigation for every workflow screen."""

    phase = SessionPhase.HOME
    screen_title = "OpenBOLA"

    def __init__(self, app: OpenBOLAApp, *, name: str | None = None) -> None:
        super().__init__(name=name)
        self.openbola_app = app

    @property
    def controller(self) -> SessionController:
        return self.openbola_app.session

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(self.screen_title, id="screen-title")
        yield Static("IDLE  ready", id="status")
        with VerticalScroll(id="screen-body"):
            yield from self.body()
        yield Footer()

    def body(self) -> ComposeResult:
        yield Static("This screen is not available in the current session state.")

    def set_status(self, text: str) -> None:
        status = self.query_one("#status", Static)
        status.update(_safe_text(text))

    def button(self, label: str, button_id: str, *, variant: str = "default") -> Button:
        return Button(label, id=button_id, variant=cast(Any, variant))

    def action_back(self) -> None:
        self.openbola_app.back()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_back()


class HomeScreen(BaseScreen):
    screen_title = "OpenBOLA — authorization-first BOLA testing"

    def body(self) -> ComposeResult:
        yield Static(
            "A local, read-only-first assessment workflow. Every target operation "
            "is delegated through the confirmed scope and policy engine.",
            id="home-intro",
        )
        with Vertical(id="home-actions"):
            yield Button("New Assessment", id="new-assessment", variant="primary")
            yield Button("Resume Sanitized Run", id="resume")
            yield Button("Recovery", id="recovery")
            yield Button("Setup", id="setup")
            yield Button("Doctor", id="doctor")
            yield Button("Update", id="update")
        yield Static(
            "Keyboard: n new assessment · g recovery · q quit · Esc back",
            id="home-help",
        )

    def on_mount(self) -> None:
        self.set_status(self.openbola_app.recovery_banner())
        self.query_one("#new-assessment", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        action = event.button.id
        if action == "new-assessment":
            self.openbola_app.action_new_assessment()
        elif action == "recovery":
            self.openbola_app.action_recovery()
        elif action == "resume":
            self.set_status("IDLE  no resumable values are retained after session close")
        elif action in {"setup", "doctor", "update"}:
            self.set_status(f"IDLE  use openbola {action} from a terminal")


class TargetScreen(BaseScreen):
    phase = SessionPhase.TARGET
    screen_title = "1 · Confirm target scope"

    def body(self) -> ComposeResult:
        yield Label("Target origin (for example https://api.example.test)")
        yield Input(placeholder="https://api.example.test", id="target-url")
        yield Label("Confirmed scope file")
        yield Input(placeholder="/path/to/scope.yaml", id="scope-path")
        yield Static(
            "The scope must be confirmed, active, readable, and match the target. "
            "Only a digest and authorization fingerprint are shown.",
            id="target-help",
        )
        with Horizontal(classes="actions"):
            yield Button("Continue", id="target-continue", variant="primary")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.query_one("#target-url", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id in {"target-url", "scope-path"}:
            self.query_one("#target-continue", Button).disabled = not (
                self.query_one("#target-url", Input).value.strip()
                and self.query_one("#scope-path", Input).value.strip()
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id != "target-continue":
            return
        try:
            summary = self.controller.configure_target(
                target_url=self.query_one("#target-url", Input).value,
                scope_path=Path(self.query_one("#scope-path", Input).value),
            )
        except (SessionError, OSError, ValueError):
            self.set_status("DENIED  target or confirmed scope rejected")
            return
        self.set_status(
            f"OK  target {summary.origin}  scope {summary.scope_digest[:12]}…  "
            f"authorization {summary.authorization_reference_fingerprint[:12]}…"
        )
        self.openbola_app.show(SessionPhase.IDENTITIES)


class IdentitiesScreen(BaseScreen):
    phase = SessionPhase.IDENTITIES
    screen_title = "2 · Add two distinct identities"

    def body(self) -> ComposeResult:
        yield Input(placeholder="Identity A name (owner)", id="identity-a-name")
        yield Input(
            placeholder="Identity A credential (opaque handle)",
            password=True,
            id="identity-a-secret",
        )
        yield Input(placeholder="Identity B name (attacker)", id="identity-b-name")
        yield Input(
            placeholder="Identity B credential (opaque handle)",
            password=True,
            id="identity-b-secret",
        )
        yield Static("Secrets are cleared immediately after submit.", id="identity-help")
        with Horizontal(classes="actions"):
            yield Button("Continue to capture", id="identities-continue", variant="primary")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.query_one("#identity-a-name", Input).focus()

    def _secret_handle(self, secret: str, purpose: str) -> str:
        # If an injected controller exposes the optional local registry, use it;
        # otherwise mint only a random opaque identifier.  The secret itself is
        # never passed through the SessionController protocol.
        registry = getattr(self.controller, "_registry", None)
        store_secret = getattr(registry, "store_secret", None)
        if callable(store_secret):
            return str(store_secret(purpose=purpose, value=secret).id)
        return f"h-{uuid.uuid4().hex}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id != "identities-continue":
            return
        name_a = self.query_one("#identity-a-name", Input).value.strip()
        name_b = self.query_one("#identity-b-name", Input).value.strip()
        secret_a = self.query_one("#identity-a-secret", Input).value
        secret_b = self.query_one("#identity-b-secret", Input).value
        if not name_a or not name_b or name_a == name_b or not secret_a or not secret_b:
            self.set_status("DENIED  two distinct names and credentials are required")
            return
        try:
            self.controller.add_identity(
                IdentitySummary(name_a[:128], None, self._secret_handle(secret_a, "identity-a"))
            )
            self.controller.add_identity(
                IdentitySummary(name_b[:128], None, self._secret_handle(secret_b, "identity-b"))
            )
        except (SessionError, TypeError, ValueError):
            self.set_status("DENIED  identities were rejected")
            return
        for widget_id in ("#identity-a-secret", "#identity-b-secret"):
            self.query_one(widget_id, Input).value = ""
        self.openbola_app.show(SessionPhase.CAPTURE)


class CaptureScreen(BaseScreen):
    phase = SessionPhase.CAPTURE
    screen_title = "3 · Capture two-identity traffic"

    def body(self) -> ComposeResult:
        yield Static("Capture is delegated to the policy-bound collector.", id="capture-help")
        yield Static("IDLE  waiting to start", id="capture-state")
        with Horizontal(classes="actions"):
            yield Button("Start capture", id="capture-start", variant="primary")
            yield Button("Cancel", id="capture-cancel")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.query_one("#capture-start", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id == "capture-start":
            token = SessionCancellationToken()
            self.openbola_app.active_token = token
            self.query_one("#capture-start", Button).disabled = True
            self.set_status("RUNNING  capture")
            try:
                self.controller.start_capture(token)
            except (SessionError, TypeError):
                self.query_one("#capture-start", Button).disabled = False
                self.set_status("DENIED  capture prerequisites are incomplete")
        elif event.button.id == "capture-cancel":
            self.openbola_app.cancel_active()

    def update_progress(self, event: ProgressEvent) -> None:
        self.query_one("#capture-state", Static).update(_status_text(event))
        self.set_status(_status_text(event))
        if event.state is ProgressState.SUCCEEDED:
            self.openbola_app.show(SessionPhase.DISCOVERY)


class DiscoveryScreen(BaseScreen):
    phase = SessionPhase.DISCOVERY
    screen_title = "4 · Complete read-only discovery"

    def body(self) -> ComposeResult:
        yield Static(
            "Discovery must be complete before planning or mutation review. "
            "A zero-resource result is an explicit empty state.",
            id="discovery-help",
        )
        yield Static("IDLE  waiting to start", id="discovery-state")
        yield Static("No discovery has run.", id="discovery-summary")
        with Horizontal(classes="actions"):
            yield Button("Start discovery", id="discovery-start", variant="primary")
            yield Button("Cancel", id="discovery-cancel")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.query_one("#discovery-start", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id == "discovery-start":
            token = SessionCancellationToken()
            self.openbola_app.active_token = token
            self.query_one("#discovery-start", Button).disabled = True
            try:
                self.controller.start_discovery(token)
            except (SessionError, TypeError):
                self.query_one("#discovery-start", Button).disabled = False
                self.set_status("DENIED  discovery prerequisites are incomplete")
        elif event.button.id == "discovery-cancel":
            self.openbola_app.cancel_active()

    def update_progress(self, event: ProgressEvent) -> None:
        self.query_one("#discovery-state", Static).update(_status_text(event))
        self.set_status(_status_text(event))
        if event.state is ProgressState.SUCCEEDED:
            summary = self.controller.snapshot().get("discovery")
            if summary is not None:
                values = (
                    getattr(summary, "provider_count", 0),
                    getattr(summary, "resource_count", 0),
                    getattr(summary, "record_count", 0),
                    getattr(summary, "field_count", 0),
                )
                self.query_one("#discovery-summary", Static).update(
                    f"Providers {values[0]} · resources {values[1]} · "
                    f"records {values[2]} · fields {values[3]}"
                    if any(values)
                    else "EMPTY  no resources discovered in recorded coverage"
                )
            if getattr(summary, "complete", False):
                self.openbola_app.show(SessionPhase.AI_PLAN)


class AIPlanScreen(BaseScreen):
    phase = SessionPhase.AI_PLAN
    screen_title = "5 · Review optional typed plan"

    def body(self) -> ComposeResult:
        yield Static(
            "Only bounded provider, route, handle, and budget summaries are shown. "
            "The UI never sends an AI or provider request.",
            id="ai-plan-help",
        )
        yield Static("IDLE  discovery summary unavailable", id="ai-plan-summary")
        with Horizontal(classes="actions"):
            yield Button("Review mutation grant", id="ai-plan-review", variant="primary")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        discovery = self.controller.snapshot().get("discovery")
        complete = bool(getattr(discovery, "complete", False))
        self.query_one("#ai-plan-review", Button).disabled = not complete
        if discovery is None:
            self.query_one("#ai-plan-summary", Static).update("EMPTY  no discovery coverage")
        else:
            self.query_one("#ai-plan-summary", Static).update(
                f"Discovery complete: {'YES' if complete else 'NO'} · "
                f"resources {getattr(discovery, 'resource_count', 0)} · "
                f"records {getattr(discovery, 'record_count', 0)}"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id != "ai-plan-review":
            return
        try:
            self.controller.review_grant()
        except (SessionError, RuntimeError):
            self.set_status("DENIED  typed grant review is unavailable")
            return
        self.openbola_app.show(SessionPhase.GRANT_REVIEW)


class GrantReviewScreen(BaseScreen):
    phase = SessionPhase.GRANT_REVIEW
    screen_title = "6 · Confirm exact mutation grant"

    def body(self) -> ComposeResult:
        yield Static(
            "This is a separate confirmation barrier. No write is dispatched by navigation.",
            id="grant-help",
        )
        yield Static("DENIED  no grant loaded", id="grant-summary")
        with Horizontal(classes="actions"):
            yield Button("Confirm mutation grant", id="grant-confirm", variant="error")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.refresh_grant()

    def refresh_grant(self) -> None:
        grant = self.controller.snapshot().get("grant")
        recovery = self.controller.snapshot().get("recovery")
        if grant is None:
            self.query_one("#grant-confirm", Button).disabled = True
            return
        methods = ", ".join(getattr(grant, "method_labels", ())) or "—"
        paths = ", ".join(getattr(grant, "path_labels", ())) or "—"
        fields = ", ".join(getattr(grant, "field_labels", ())) or "—"
        self.query_one("#grant-summary", Static).update(
            f"Methods {methods} · paths {paths} · fields {fields}\n"
            f"Records {getattr(grant, 'record_count', 0)} · requests "
            f"{getattr(grant, 'request_count', 0)} · cleanup "
            f"{_safe_text(getattr(grant, 'cleanup_policy', None))} · "
            f"scope {getattr(grant, 'scope_digest', '')}"
        )
        self.query_one("#grant-confirm", Button).disabled = getattr(
            recovery, "state", "blocked"
        ) != "clear"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id != "grant-confirm":
            return
        button = self.query_one("#grant-confirm", Button)
        if button.disabled:
            return
        button.disabled = True
        try:
            self.controller.confirm_grant()
        except (SessionError, RuntimeError):
            self.set_status("DENIED  grant confirmation rejected by policy or recovery gate")
            self.refresh_grant()
            return
        self.openbola_app.show(SessionPhase.VERIFICATION)


class VerificationScreen(BaseScreen):
    phase = SessionPhase.VERIFICATION
    screen_title = "7 · Verify authorized combinations"

    def body(self) -> ComposeResult:
        yield Static(
            "Verification is policy-bound and reversible. "
            "Cancellation leaves the recovery gate in control.",
            id="verification-help",
        )
        yield Static("IDLE  waiting for explicit confirmation", id="verification-state")
        with Horizontal(classes="actions"):
            yield Button("Start verification", id="verification-start", variant="primary")
            yield Button("Cancel", id="verification-cancel")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.query_one("#verification-start", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id == "verification-start":
            token = SessionCancellationToken()
            self.openbola_app.active_token = token
            self.query_one("#verification-start", Button).disabled = True
            try:
                self.controller.start_verification(token)
            except (SessionError, TypeError):
                self.query_one("#verification-start", Button).disabled = False
                self.set_status("DENIED  verification is not ready")
        elif event.button.id == "verification-cancel":
            self.openbola_app.cancel_active()

    def update_progress(self, event: ProgressEvent) -> None:
        self.query_one("#verification-state", Static).update(_status_text(event))
        self.set_status(_status_text(event))
        if event.state is ProgressState.SUCCEEDED:
            self.openbola_app.show(SessionPhase.FINDINGS)


class FindingsScreen(BaseScreen):
    phase = SessionPhase.FINDINGS
    screen_title = "8 · Findings and recorded coverage"

    def body(self) -> ComposeResult:
        yield Static("Findings are rendered from the typed report boundary.", id="findings-help")
        with Vertical(id="finding-list"):
            yield Static("IDLE  loading findings", id="findings-state")
        with Horizontal(classes="actions"):
            yield Button("Export reports", id="findings-export", variant="primary")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.load_findings()

    def load_findings(self) -> None:
        try:
            findings = tuple(self.controller.list_findings())
        except (SessionError, RuntimeError):
            self.query_one("#findings-state", Static).update("FAILED  findings unavailable")
            return
        state = self.query_one("#findings-state", Static)
        if not findings:
            state.update("EMPTY  no confirmed findings in recorded coverage")
            return
        state.display = False
        listing = self.query_one("#finding-list", Vertical)
        for index, finding in enumerate(findings[:64]):
            handle = _safe_text(finding.get("handle"), "")
            if not handle or any(
                character.isspace() or ord(character) < 0x21 for character in handle
            ):
                continue
            button_id = f"finding-{index}"
            label = (
                f"{_safe_text(finding.get('severity'), 'unknown').upper()}  "
                f"{_safe_text(finding.get('resource', finding.get('endpoint')), 'finding')}  "
                f"[{handle[:48]}]"
            )
            listing.mount(Button(label, id=button_id))
            setattr(self, f"_finding_handle_{index}", handle)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id == "findings-export":
            self.openbola_app.show(SessionPhase.EXPORT)
            return
        if event.button.id and event.button.id.startswith("finding-"):
            index = event.button.id.removeprefix("finding-")
            handle = getattr(self, f"_finding_handle_{index}", "")
            if handle:
                self.openbola_app.show_finding_detail(handle)


class FindingDetailScreen(BaseScreen):
    phase = SessionPhase.FINDINGS
    screen_title = "Finding detail (local, transient)"

    def __init__(self, app: OpenBOLAApp, handle_id: str) -> None:
        super().__init__(app)
        self.handle_id = handle_id

    def body(self) -> ComposeResult:
        yield Static("IDLE  loading finding detail", id="finding-detail")
        yield Static(
            "Full values, if locally resolved by the controller, are cleared "
            "when this screen closes.",
            id="finding-detail-help",
        )
        yield Button("Back", id="back")

    def on_mount(self) -> None:
        try:
            detail = self.controller.finding_detail(self.handle_id)
        except (SessionError, RuntimeError):
            self.query_one("#finding-detail", Static).update("FAILED  finding detail unavailable")
            return
        lines = [f"{_safe_text(key)}: {_safe_text(value)}" for key, value in detail.items()]
        self.query_one("#finding-detail", Static).update("\n".join(lines[:32]))

    def on_unmount(self) -> None:
        clear_detail = getattr(self.controller, "clear_finding_detail", None)
        if callable(clear_detail):
            with suppress(Exception):
                clear_detail()


class ExportScreen(BaseScreen):
    phase = SessionPhase.EXPORT
    screen_title = "9 · Export sanitized reports"

    def body(self) -> ComposeResult:
        yield Static(
            "Exports are written through the existing atomic report boundary; "
            "local paths are not shown.",
            id="export-help",
        )
        yield Static("IDLE  ready", id="export-state")
        yield Button("Write reports", id="export-run", variant="primary")
        yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.query_one("#export-run", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        if event.button.id != "export-run":
            return
        button = self.query_one("#export-run", Button)
        button.disabled = True
        try:
            artifacts = self.controller.export(Path("reports"))
        except (SessionError, RuntimeError):
            self.query_one("#export-state", Static).update("FAILED  export denied")
            button.disabled = False
            return
        names = ", ".join(Path(value).name for value in artifacts.values())
        self.query_one("#export-state", Static).update(
            f"OK  export complete: {names or 'no artifacts'}"
        )


class RecoveryScreen(BaseScreen):
    phase = SessionPhase.RECOVERY
    screen_title = "Recovery gate"

    def body(self) -> ComposeResult:
        yield Static(
            "A non-clear recovery state blocks new assessments and verification. "
            "Journal contents and paths are never displayed.",
            id="recovery-help",
        )
        yield Static("IDLE  checking recovery", id="recovery-state")
        with Horizontal(classes="actions"):
            yield Button("Recover safely", id="recover", variant="primary")
            yield Button("Manual escalation", id="escalate")
            yield Button("Back", id="back")

    def on_mount(self) -> None:
        self.refresh_status()
        self.query_one("#recover", Button).focus()

    def refresh_status(self) -> None:
        try:
            status = self.controller.recovery_status()
        except (SessionError, RuntimeError):
            status = RecoveryStatus("blocked", True, "recovery_blocked")
        state = _safe_text(getattr(status, "state", "blocked")).upper()
        reason = _safe_text(getattr(status, "reason_code", None), "recovery status unavailable")
        self.query_one("#recovery-state", Static).update(f"{state}  {reason}")
        self.set_status(f"{state}  recovery")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        super().on_button_pressed(event)
        try:
            if event.button.id == "recover":
                status = self.controller.recover()
            elif event.button.id == "escalate":
                status = self.controller.record_manual_escalation()
            else:
                return
        except (SessionError, RuntimeError):
            self.set_status("FAILED  recovery remains blocked")
            self.refresh_status()
            return
        self.refresh_status()
        if getattr(status, "state", "blocked") == "clear":
            self.openbola_app.show(SessionPhase.HOME)


class PlaceholderScreen(BaseScreen):
    def __init__(self, app: OpenBOLAApp, phase: SessionPhase, title: str) -> None:
        super().__init__(app)
        self.phase = phase
        self.screen_title = title

    def body(self) -> ComposeResult:
        yield Static("This stage is available after its policy-bound service is configured.")
        yield Button("Back", id="back")


class OpenBOLAApp(App[None]):
    """Textual application shell around one injected session controller."""

    TITLE = "OpenBOLA"
    SUB_TITLE = "authorization-first BOLA/IDOR testing"
    CSS = """
    Screen { layout: vertical; }
    #screen-title { height: 2; padding: 0 1; text-style: bold; }
    #status { height: 1; padding: 0 1; color: $text; background: $panel; }
    #screen-body { padding: 0 1; }
    #home-actions { width: 36; }
    Button { margin: 0; min-width: 28; }
    .actions { height: 3; align: left middle; }
    .actions Button { margin: 0 1 0 0; }
    Input { margin: 0 0 1 0; }
    #home-help, #target-help, #identity-help, #capture-help, #discovery-help, #recovery-help {
        color: $text-muted;
        margin: 1 0;
    }
    """
    BINDINGS = [
        Binding("n", "new_assessment", "New assessment", show=True),
        Binding("g", "recovery", "Recovery", show=True),
        Binding("c", "cancel", "Cancel", show=False),
        Binding("escape", "back", "Back", show=False),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, session: SessionController | None = None, **kwargs: Any) -> None:
        self.session = session if session is not None else _default_session()
        self.active_token: CancellationToken | None = None
        self._unsubscribe: Any = None
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        # The initial screen is pushed in on_mount so tests and embeddings can
        # inject a controller before any UI work starts.  The base screen is
        # intentionally empty; screen widgets own their lifecycle.
        yield Static("", id="app-host")

    def on_mount(self) -> None:
        self._unsubscribe = self.session.subscribe(self._progress_from_worker)
        self.push_screen(HomeScreen(self))
        if self._recovery_blocked():
            self.call_after_refresh(lambda: self.show(SessionPhase.RECOVERY))

    def on_unmount(self) -> None:
        if callable(self._unsubscribe):
            self._unsubscribe()
        with suppress(Exception):
            self.session.close()

    def _progress_from_worker(self, event: ProgressEvent) -> None:
        if self.is_running:
            try:
                self.call_from_thread(self._handle_progress, event)
            except RuntimeError:
                # Deterministic fakes may emit synchronously from a button
                # callback; real session workers always take the queue path.
                self._handle_progress(event)

    def _handle_progress(self, event: ProgressEvent) -> None:
        screen = self.screen
        if isinstance(screen, (CaptureScreen, DiscoveryScreen, VerificationScreen)):
            screen.update_progress(event)
        else:
            with suppress(Exception):
                screen.query_one("#status", Static).update(_status_text(event))

    def _recovery_blocked(self) -> bool:
        try:
            status = self.session.recovery_status()
        except Exception:
            return True
        return getattr(status, "state", "blocked") != "clear"

    def recovery_banner(self) -> str:
        try:
            status = self.session.recovery_status()
            state = _safe_text(getattr(status, "state", "blocked")).upper()
            return "OK  recovery clear" if state == "CLEAR" else f"{state}  recovery gate"
        except Exception:
            return "BLOCKED  recovery status unavailable"

    def show(self, phase: SessionPhase) -> None:
        while len(self.screen_stack) > 1:
            self.pop_screen()
        screen: Screen[None]
        if phase is SessionPhase.HOME:
            screen = HomeScreen(self)
        elif phase is SessionPhase.TARGET:
            screen = TargetScreen(self)
        elif phase is SessionPhase.IDENTITIES:
            screen = IdentitiesScreen(self)
        elif phase is SessionPhase.CAPTURE:
            screen = CaptureScreen(self)
        elif phase is SessionPhase.DISCOVERY:
            screen = DiscoveryScreen(self)
        elif phase is SessionPhase.AI_PLAN:
            screen = AIPlanScreen(self)
        elif phase is SessionPhase.GRANT_REVIEW:
            screen = GrantReviewScreen(self)
        elif phase is SessionPhase.VERIFICATION:
            screen = VerificationScreen(self)
        elif phase is SessionPhase.FINDINGS:
            screen = FindingsScreen(self)
        elif phase is SessionPhase.EXPORT:
            screen = ExportScreen(self)
        elif phase is SessionPhase.RECOVERY:
            screen = RecoveryScreen(self)
        else:
            screen = PlaceholderScreen(self, phase, phase.value.replace("_", " ").title())
        self.push_screen(screen)

    def show_finding_detail(self, handle_id: str) -> None:
        self.pop_screen()
        self.push_screen(FindingDetailScreen(self, handle_id))

    def back(self) -> None:
        if isinstance(self.screen, HomeScreen):
            return
        if len(self.screen_stack) > 2:
            self.pop_screen()
        else:
            self.show(SessionPhase.HOME)

    def action_new_assessment(self) -> None:
        if self._recovery_blocked():
            self.show(SessionPhase.RECOVERY)
        else:
            self.show(SessionPhase.TARGET)

    def action_recovery(self) -> None:
        self.show(SessionPhase.RECOVERY)

    def action_cancel(self) -> None:
        self.cancel_active()

    async def action_back(self) -> None:
        self.back()

    def cancel_active(self) -> None:
        token = self.active_token
        if token is not None:
            token.cancel()
        with suppress(AttributeError, SessionError, RuntimeError):
            cast(Any, self.session).cancel()  # optional concrete-session convenience


def _default_session() -> SessionController:
    from openbola.session import AssessmentSession

    def unavailable_capture(_guard: Any, _identities: Any, _token: Any) -> None:
        raise SessionError("capture service is unavailable")

    def unavailable_discovery(_guard: Any, _identities: Any, _token: Any) -> Any:
        raise SessionError("discovery service is unavailable")

    recovery_status, recover, escalate = _default_recovery_callbacks()
    return AssessmentSession(
        capture=unavailable_capture,
        discovery=unavailable_discovery,
        recovery=recover,
        recovery_status=recovery_status,
        escalation=escalate,
    )


def _default_recovery_callbacks() -> tuple[Any, Any, Any]:
    """Resolve the process-start journal gate without creating a transport."""

    try:
        from openbola.recovery import default_recovery_gate

        gate = default_recovery_gate()

        def status() -> RecoveryStatus:
            try:
                return gate.recovery_status()
            except Exception:
                return RecoveryStatus("blocked", True, "recovery_blocked")
    except Exception:
        return (
            lambda: RecoveryStatus("blocked", True, "recovery_blocked"),
            lambda: RecoveryStatus("blocked", True, "recovery_blocked"),
            lambda: RecoveryStatus("blocked", True, "recovery_blocked"),
        )
    return (
        status,
        lambda: RecoveryStatus("blocked", True, "recovery_required"),
        lambda: RecoveryStatus("blocked", True, "recovery_blocked"),
    )


def launch_tui(session: SessionController | None = None) -> None:
    """Run the full-screen app; kept as a function for CLI and test injection."""

    app = OpenBOLAApp(session=session)
    try:
        app.run()
    finally:
        # ``on_unmount`` handles normal exits.  Calling close here also covers
        # startup failures before Textual mounts the app.
        with suppress(Exception):
            app.session.close()


__all__ = [
    "BaseScreen",
    "CaptureScreen",
    "DiscoveryScreen",
    "ExportScreen",
    "FindingDetailScreen",
    "FindingsScreen",
    "HomeScreen",
    "IdentitiesScreen",
    "AIPlanScreen",
    "GrantReviewScreen",
    "OpenBOLAApp",
    "RecoveryScreen",
    "TargetScreen",
    "VerificationScreen",
    "launch_tui",
]
