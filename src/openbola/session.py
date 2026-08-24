"""Dependency-free session boundary for the future OpenBOLA TUI.

This module deliberately does not import Textual, an HTTP client, a
credential resolver, or a provider adapter.  It owns only the safe, typed
projection that a UI may render and delegates optional work to injected
callables which already own the relevant policy boundary.

Full-fidelity values stay in the supplied :class:`SessionValueStore` and are
never copied into a summary, progress event, snapshot, or exception.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Event, RLock
from types import MappingProxyType
from typing import Protocol, cast
from urllib.parse import urlsplit

from openbola.handles import InMemorySessionValueRegistry, SessionValueStore
from openbola.mutations import RecoveryStatus
from openbola.scope import ScopeError, ScopeGuard

_SAFE_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_SAFE_REASON_CODES = frozenset(
    {
        "recovery_clear",
        "recovery_required",
        "recovery_escalated",
        "recovery_blocked",
        "journal_present",
        "restore_unverified",
        "manual_escalation",
    }
)
_MAX_MESSAGE_LENGTH = 160


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


class SessionError(RuntimeError):
    """A bounded session error whose text contains no caller data."""


@dataclass(frozen=True)
class ProgressEvent:
    phase: SessionPhase
    state: ProgressState
    completed: int
    total: int | None
    message: str

    def __post_init__(self) -> None:
        if type(self.completed) is not int or self.completed < 0:
            raise ValueError("progress completed value is invalid")
        if self.total is not None and (
            type(self.total) is not int or self.total < 0 or self.total < self.completed
        ):
            raise ValueError("progress total value is invalid")
        if (
            type(self.message) is not str
            or not self.message
            or len(self.message) > _MAX_MESSAGE_LENGTH
        ):
            raise ValueError("progress message is invalid")
        if any(ord(character) < 0x20 for character in self.message):
            raise ValueError("progress message is invalid")


@dataclass(frozen=True)
class TargetSummary:
    origin: str
    scope_digest: str
    authorization_reference_fingerprint: str

    def __post_init__(self) -> None:
        if type(self.origin) is not str or not self.origin or len(self.origin) > 255:
            raise ValueError("target origin is invalid")
        try:
            normalized = _normalize_origin(self.origin)
        except SessionError:
            raise ValueError("target origin is invalid") from None
        if normalized != self.origin:
            raise ValueError("target origin is invalid")
        for value, label in (
            (self.scope_digest, "scope digest"),
            (self.authorization_reference_fingerprint, "authorization fingerprint"),
        ):
            if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"{label} is invalid")


@dataclass(frozen=True)
class IdentitySummary:
    name: str
    recipe_name: str | None
    credential_handle_id: str

    def __post_init__(self) -> None:
        _require_bounded_text(self.name, "identity name", 64)
        if self.recipe_name is not None:
            _require_bounded_text(self.recipe_name, "recipe name", 128)
        if type(self.credential_handle_id) is not str or not _SAFE_HANDLE.fullmatch(
            self.credential_handle_id
        ):
            raise ValueError("credential handle id is invalid")


@dataclass(frozen=True)
class DiscoverySummary:
    provider_count: int
    resource_count: int
    record_count: int
    field_count: int
    complete: bool

    def __post_init__(self) -> None:
        for value in (
            self.provider_count,
            self.resource_count,
            self.record_count,
            self.field_count,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("discovery count is invalid")
        if type(self.complete) is not bool:
            raise ValueError("discovery completeness is invalid")


@dataclass(frozen=True)
class GrantSummary:
    method_labels: tuple[str, ...]
    path_labels: tuple[str, ...]
    field_labels: tuple[str, ...]
    record_count: int
    request_count: int
    cleanup_policy: str
    scope_digest: str

    def __post_init__(self) -> None:
        for labels, label in (
            (self.method_labels, "method labels"),
            (self.path_labels, "path labels"),
            (self.field_labels, "field labels"),
        ):
            if not isinstance(labels, tuple) or any(
                type(item) is not str or not item or len(item) > 256 for item in labels
            ):
                raise ValueError(f"{label} are invalid")
        if type(self.record_count) is not int or self.record_count < 0:
            raise ValueError("grant record count is invalid")
        if type(self.request_count) is not int or self.request_count < 0:
            raise ValueError("grant request count is invalid")
        _require_bounded_text(self.cleanup_policy, "cleanup policy", 64)
        if type(self.scope_digest) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", self.scope_digest
        ):
            raise ValueError("grant scope digest is invalid")


class CancellationToken(Protocol):
    def is_cancelled(self) -> bool: ...

    def cancel(self) -> None: ...


class SessionCancellationToken:
    """Thread-safe cooperative cancellation token."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = Event()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()


CaptureOperation = Callable[[ScopeGuard, tuple[IdentitySummary, ...], CancellationToken], None]
DiscoveryOperation = Callable[
    [ScopeGuard, tuple[IdentitySummary, ...], CancellationToken], DiscoverySummary
]
RecoveryOperation = Callable[[], RecoveryStatus]


class SessionController(Protocol):
    def snapshot(self) -> Mapping[str, object]: ...

    def subscribe(self, callback: Callable[[ProgressEvent], None]) -> Callable[[], None]: ...

    def configure_target(self, *, target_url: str, scope_path: Path) -> TargetSummary: ...

    def add_identity(self, summary: IdentitySummary) -> None: ...

    def start_capture(self, token: CancellationToken) -> None: ...

    def start_discovery(self, token: CancellationToken) -> DiscoverySummary | None: ...

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


class AssessmentSession:
    """Safe lifecycle service used by a UI or another local adapter.

    The operation callables are intentionally narrow and receive only the
    validated scope guard, safe identity summaries, and a cancellation token.
    They may delegate to capture/discovery/P6 engines but this class itself
    cannot send a request.
    """

    def __init__(
        self,
        *,
        registry: SessionValueStore | None = None,
        capture: CaptureOperation | None = None,
        discovery: DiscoveryOperation | None = None,
        recovery: RecoveryOperation | None = None,
    ) -> None:
        self._registry = registry or InMemorySessionValueRegistry()
        self._capture = capture
        self._discovery = discovery
        self._recovery = recovery
        self._lock = RLock()
        self._callbacks: list[Callable[[ProgressEvent], None]] = []
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="openbola-session")
        self._future: Future[object] | None = None
        self._active_token: CancellationToken | None = None
        self._closed = False
        self._phase = SessionPhase.HOME
        self._target: TargetSummary | None = None
        self._scope_guard: ScopeGuard | None = None
        self._identities: list[IdentitySummary] = []
        self._discovery_summary: DiscoverySummary | None = None
        self._grant_summary: GrantSummary | None = None
        self._recovery_status = RecoveryStatus("clear", False, None)

    @property
    def phase(self) -> SessionPhase:
        with self._lock:
            return self._phase

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            self._require_open_locked()
            return MappingProxyType(
                {
                    "phase": self._phase,
                    "target": self._target,
                    "identities": tuple(self._identities),
                    "discovery": self._discovery_summary,
                    "grant": self._grant_summary,
                    "recovery": self._public_recovery(self._recovery_status),
                }
            )

    def subscribe(self, callback: Callable[[ProgressEvent], None]) -> Callable[[], None]:
        if not callable(callback):
            raise TypeError("progress callback is invalid")
        with self._lock:
            self._require_open_locked()
            if len(self._callbacks) >= 32:
                raise SessionError("too many progress subscribers")
            self._callbacks.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                try:
                    self._callbacks.remove(callback)
                except ValueError:
                    return

        return unsubscribe

    def configure_target(self, *, target_url: str, scope_path: Path) -> TargetSummary:
        with self._lock:
            self._require_open_locked()
            if self._phase not in (SessionPhase.HOME, SessionPhase.TARGET):
                raise SessionError("target cannot be configured in the current phase")
        origin = _normalize_origin(target_url)
        try:
            guard = ScopeGuard.from_file(Path(scope_path))
            digest = guard.scope_digest
            authorization_fingerprint = hashlib.sha256(
                guard.config.authorization_reference.encode("utf-8")
            ).hexdigest()
            summary = TargetSummary(origin, digest, authorization_fingerprint)
        except (OSError, ScopeError, UnicodeError, ValueError):
            raise SessionError("target configuration denied") from None
        with self._lock:
            self._require_open_locked()
            self._scope_guard = guard
            self._target = summary
            self._identities.clear()
            self._discovery_summary = None
            self._grant_summary = None
            self._phase = SessionPhase.IDENTITIES
        return summary

    def add_identity(self, summary: IdentitySummary) -> None:
        if type(summary) is not IdentitySummary:
            raise TypeError("identity summary is invalid")
        with self._lock:
            self._require_open_locked()
            if self._phase not in (SessionPhase.IDENTITIES, SessionPhase.TARGET):
                raise SessionError("identity cannot be added in the current phase")
            if any(item.name == summary.name for item in self._identities):
                raise SessionError("identity names must be distinct")
            if any(
                item.credential_handle_id == summary.credential_handle_id
                for item in self._identities
            ):
                raise SessionError("identity handles must be distinct")
            self._identities.append(summary)
            self._phase = SessionPhase.IDENTITIES

    def start_capture(self, token: CancellationToken) -> None:
        self._start_worker(
            phase=SessionPhase.CAPTURE,
            token=token,
            operation=self._run_capture,
            prerequisite=lambda: len(self._identities) >= 2,
            prerequisite_message="at least two identities are required",
        )

    def start_discovery(self, token: CancellationToken) -> DiscoverySummary | None:
        with self._lock:
            self._require_open_locked()
            if self._phase is not SessionPhase.DISCOVERY:
                raise SessionError("discovery cannot start in the current phase")
            self._phase = SessionPhase.DISCOVERY
            self._active_token = token
            self._emit_locked(
                ProgressEvent(
                    SessionPhase.DISCOVERY,
                    ProgressState.RUNNING,
                    0,
                    1,
                    "discovery running",
                )
            )
            future = self._executor.submit(self._run_discovery, token)
            self._future = cast(Future[object], future)
        return None

    def review_grant(self) -> GrantSummary:
        raise SessionError("grant review is not available in this session adapter")

    def confirm_grant(self) -> None:
        raise SessionError("mutation grant confirmation is unavailable")

    def start_verification(self, token: CancellationToken) -> None:
        del token
        raise SessionError("verification is not available in this session adapter")

    def list_findings(self) -> Sequence[Mapping[str, object]]:
        raise SessionError("findings are not available in this session adapter")

    def finding_detail(self, handle_id: str) -> Mapping[str, object]:
        del handle_id
        raise SessionError("finding details are not available in this session adapter")

    def export(self, output_dir: Path) -> Mapping[str, Path]:
        del output_dir
        raise SessionError("export is not available in this session adapter")

    def recovery_status(self) -> RecoveryStatus:
        with self._lock:
            self._require_open_locked()
            return self._public_recovery(self._recovery_status)

    def recover(self) -> RecoveryStatus:
        return self._run_recovery("recovery")

    def record_manual_escalation(self) -> RecoveryStatus:
        with self._lock:
            self._require_open_locked()
            self._recovery_status = RecoveryStatus("escalated", True, "manual_escalation")
            self._phase = SessionPhase.RECOVERY
            return self._public_recovery(self._recovery_status)

    def cancel(self) -> None:
        with self._lock:
            self._require_open_locked()
            token = self._active_token
        if token is not None:
            token.cancel()

    def wait_for_idle(self, timeout: float | None = None) -> bool:
        with self._lock:
            future = self._future
        if future is None:
            return True
        try:
            future.result(timeout=timeout)
        except Exception:
            return False
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            token = self._active_token
            self._callbacks.clear()
        if token is not None:
            token.cancel()
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._registry.close()

    def _start_worker(
        self,
        *,
        phase: SessionPhase,
        token: CancellationToken,
        operation: Callable[[CancellationToken], None],
        prerequisite: Callable[[], bool],
        prerequisite_message: str,
    ) -> None:
        if not hasattr(token, "is_cancelled") or not hasattr(token, "cancel"):
            raise TypeError("cancellation token is invalid")
        with self._lock:
            self._require_open_locked()
            if self._phase is not SessionPhase.IDENTITIES:
                raise SessionError(f"{phase.value} cannot start in the current phase")
            if not prerequisite():
                raise SessionError(prerequisite_message)
            self._phase = phase
            self._active_token = token
            self._emit_locked(
                ProgressEvent(phase, ProgressState.RUNNING, 0, 1, f"{phase.value} running")
            )
            future = self._executor.submit(operation, token)
            self._future = cast(Future[object], future)

    def _run_capture(self, token: CancellationToken) -> None:
        with self._lock:
            guard = self._scope_guard
            identities = tuple(self._identities)
        try:
            if guard is None:
                raise SessionError("capture prerequisites are missing")
            if self._capture is not None:
                self._capture(guard, identities, token)
            cancelled = token.is_cancelled()
        except Exception:
            self._finish_worker(SessionPhase.CAPTURE, ProgressState.FAILED, "capture failed", False)
            return
        self._finish_worker(
            SessionPhase.CAPTURE,
            ProgressState.CANCELLED if cancelled else ProgressState.SUCCEEDED,
            "capture cancelled" if cancelled else "capture complete",
            not cancelled,
        )

    def _run_discovery(self, token: CancellationToken) -> None:
        with self._lock:
            guard = self._scope_guard
            identities = tuple(self._identities)
        try:
            if guard is None:
                raise SessionError("discovery prerequisites are missing")
            summary = (
                self._discovery(guard, identities, token)
                if self._discovery is not None
                else DiscoverySummary(0, 0, 0, 0, True)
            )
            if type(summary) is not DiscoverySummary:
                raise SessionError("discovery result is invalid")
            cancelled = token.is_cancelled()
        except Exception:
            self._finish_worker(
                SessionPhase.DISCOVERY, ProgressState.FAILED, "discovery failed", False
            )
            return
        with self._lock:
            if not self._closed and not cancelled:
                self._discovery_summary = summary
                self._phase = SessionPhase.AI_PLAN if summary.complete else SessionPhase.DISCOVERY
        self._finish_worker(
            SessionPhase.DISCOVERY,
            ProgressState.CANCELLED if cancelled else ProgressState.SUCCEEDED,
            "discovery cancelled" if cancelled else "discovery complete",
            False,
        )

    def _finish_worker(
        self,
        phase: SessionPhase,
        state: ProgressState,
        message: str,
        advance: bool,
    ) -> None:
        with self._lock:
            if self._closed:
                return
            if advance and phase is SessionPhase.CAPTURE:
                self._phase = SessionPhase.DISCOVERY
            self._active_token = None
            self._emit_locked(ProgressEvent(phase, state, 1, 1, message))

    def _run_recovery(self, message_prefix: str) -> RecoveryStatus:
        with self._lock:
            self._require_open_locked()
            self._phase = SessionPhase.RECOVERY
            callback = self._recovery
        try:
            status = callback() if callback is not None else RecoveryStatus("clear", False, None)
            public = self._public_recovery(status)
        except Exception:
            public = RecoveryStatus("blocked", True, "recovery_blocked")
        with self._lock:
            self._recovery_status = public
            if public.state == "clear":
                self._phase = SessionPhase.HOME
        del message_prefix
        return public

    def _emit_locked(self, event: ProgressEvent) -> None:
        callbacks = tuple(self._callbacks)
        for callback in callbacks:
            with suppress(Exception):
                callback(event)

    def _require_open_locked(self) -> None:
        if self._closed:
            raise SessionError("session is closed")

    @staticmethod
    def _public_recovery(status: RecoveryStatus) -> RecoveryStatus:
        if type(status) is not RecoveryStatus or status.state not in {
            "clear",
            "required",
            "escalated",
            "blocked",
        }:
            return RecoveryStatus("blocked", True, "recovery_blocked")
        reason = (
            status.reason_code
            if type(status.reason_code) is str and status.reason_code in _SAFE_REASON_CODES
            else None
        )
        if type(status.journal_present) is not bool:
            return RecoveryStatus("blocked", True, "recovery_blocked")
        return RecoveryStatus(status.state, status.journal_present, reason)


def _require_bounded_text(value: object, label: str, limit: int) -> None:
    if type(value) is not str or not value or len(value) > limit:
        raise ValueError(f"{label} is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} is invalid")


def _normalize_origin(value: str) -> str:
    if type(value) is not str or not value or len(value) > 8192:
        raise SessionError("target configuration denied")
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError
        hostname = parsed.hostname
        if hostname is None or any(
            character.isspace() or ord(character) < 0x21 or ord(character) > 0x7E
            for character in value
        ):
            raise ValueError
        port = parsed.port
    except (TypeError, ValueError):
        raise SessionError("target configuration denied") from None
    host = hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    port_suffix = "" if port is None or default_port else f":{port}"
    return f"{parsed.scheme.lower()}://{host}{port_suffix}"


__all__ = [
    "AssessmentSession",
    "CancellationToken",
    "DiscoverySummary",
    "GrantSummary",
    "IdentitySummary",
    "ProgressEvent",
    "ProgressState",
    "SessionCancellationToken",
    "SessionController",
    "SessionError",
    "SessionPhase",
    "TargetSummary",
]
