"""Contract tests for the dependency-free TUI session boundary."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from openbola.handles import InMemorySessionValueRegistry
from openbola.mutations import RecoveryStatus
from openbola.session import (
    AssessmentSession,
    DiscoverySummary,
    IdentitySummary,
    ProgressState,
    SessionCancellationToken,
    SessionError,
    SessionPhase,
)

NOW = datetime.now(UTC).replace(microsecond=0)


def _scope(path: Path, *, confirmed: str = "true") -> Path:
    path.write_text(
        "\n".join(
            (
                "client_name: session-tests",
                "authorization_reference: AUTHORIZATION_SENTINEL",
                f"confirmed: {confirmed}",
                f"starts_at: '{(NOW - timedelta(minutes=1)).isoformat()}'",
                f"expires_at: '{(NOW + timedelta(hours=1)).isoformat()}'",
                "allowed_hosts:",
                "  - api.example.test",
                "allowed_cidrs: []",
                "allowed_paths: [glob:/v1/**]",
                "read_methods: [GET]",
                "mutation_grants: []",
            )
        ),
        encoding="utf-8",
    )
    return path


def _identity(name: str, suffix: str) -> IdentitySummary:
    return IdentitySummary(name, "login", f"handle-{suffix}")


def test_new_session_starts_at_home_and_snapshot_is_safe() -> None:
    session = AssessmentSession()
    try:
        snapshot = session.snapshot()
        assert snapshot["phase"] is SessionPhase.HOME
        assert snapshot["identities"] == ()
        assert "AUTHORIZATION_SENTINEL" not in repr(snapshot)
    finally:
        session.close()


def test_target_requires_confirmed_active_scope_and_returns_only_fingerprints(
    tmp_path: Path,
) -> None:
    session = AssessmentSession()
    try:
        with pytest.raises(SessionError, match="target configuration denied"):
            session.configure_target(
                target_url="https://api.example.test",
                scope_path=_scope(tmp_path / "denied.yaml", confirmed="false"),
            )

        summary = session.configure_target(
            target_url="HTTPS://api.example.test:443/",
            scope_path=_scope(tmp_path / "scope.yaml"),
        )
        assert summary.origin == "https://api.example.test"
        assert summary.scope_digest == hashlib.sha256(
            (tmp_path / "scope.yaml").read_bytes()
        ).hexdigest()
        assert summary.authorization_reference_fingerprint == hashlib.sha256(
            b"AUTHORIZATION_SENTINEL"
        ).hexdigest()
        assert "AUTHORIZATION_SENTINEL" not in repr(summary)
        assert session.phase is SessionPhase.IDENTITIES
    finally:
        session.close()


def test_capture_requires_two_distinct_identities(tmp_path: Path) -> None:
    session = AssessmentSession()
    token = SessionCancellationToken()
    try:
        session.configure_target(
            target_url="https://api.example.test",
            scope_path=_scope(tmp_path / "scope.yaml"),
        )
        session.add_identity(_identity("owner", "one"))
        with pytest.raises(SessionError, match="at least two identities"):
            session.start_capture(token)
        session.add_identity(_identity("attacker", "two"))
        session.start_capture(token)
        assert session.wait_for_idle(2)
        assert session.phase is SessionPhase.DISCOVERY
    finally:
        session.close()


def test_capture_events_are_bounded_and_cancellation_is_cooperative(tmp_path: Path) -> None:
    events = []

    def capture(_guard: object, _identities: tuple[IdentitySummary, ...], token: object) -> None:
        while not token.is_cancelled():  # type: ignore[union-attr]
            time.sleep(0.001)

    session = AssessmentSession(capture=capture)  # type: ignore[arg-type]
    token = SessionCancellationToken()
    try:
        session.configure_target(
            target_url="https://api.example.test",
            scope_path=_scope(tmp_path / "scope.yaml"),
        )
        session.add_identity(_identity("owner", "one"))
        session.add_identity(_identity("attacker", "two"))
        session.subscribe(events.append)
        session.start_capture(token)
        session.cancel()
        assert session.wait_for_idle(2)
        assert [event.state for event in events] == [ProgressState.RUNNING, ProgressState.CANCELLED]
        assert all(len(event.message) <= 160 for event in events)
        assert "AUTHORIZATION_SENTINEL" not in repr(events)
    finally:
        session.close()


def test_discovery_only_advances_when_complete(tmp_path: Path) -> None:
    def discovery(
        _guard: object, _identities: tuple[IdentitySummary, ...], _token: object
    ) -> DiscoverySummary:
        return DiscoverySummary(1, 2, 3, 4, False)

    session = AssessmentSession(discovery=discovery)  # type: ignore[arg-type]
    token = SessionCancellationToken()
    try:
        session.configure_target(
            target_url="https://api.example.test",
            scope_path=_scope(tmp_path / "scope.yaml"),
        )
        session.add_identity(_identity("owner", "one"))
        session.add_identity(_identity("attacker", "two"))
        session.start_capture(token)
        assert session.wait_for_idle(2)
        session.start_discovery(token)
        assert session.wait_for_idle(2)
        assert session.snapshot()["discovery"] == DiscoverySummary(1, 2, 3, 4, False)
        assert session.phase is SessionPhase.DISCOVERY
    finally:
        session.close()


def test_recovery_reason_is_allowlisted_and_close_revokes_registry(tmp_path: Path) -> None:
    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="password", value="SECRET_SENTINEL")
    session = AssessmentSession(
        registry=registry,
        recovery=lambda: RecoveryStatus("required", True, "SECRET_SENTINEL"),
    )
    session.configure_target(
        target_url="https://api.example.test",
        scope_path=_scope(tmp_path / "scope.yaml"),
    )
    status = session.recover()
    assert status.state == "required"
    assert status.reason_code is None
    assert "SECRET_SENTINEL" not in repr(session.snapshot())
    session.close()
    with pytest.raises(RuntimeError, match="registry is closed"):
        registry.resolve_secret(handle)
    with pytest.raises(SessionError, match="session is closed"):
        session.snapshot()


def test_manual_escalation_blocks_new_work() -> None:
    session = AssessmentSession()
    try:
        status = session.record_manual_escalation()
        assert status == RecoveryStatus("escalated", True, "manual_escalation")
        with pytest.raises(SessionError, match="target cannot"):
            session.configure_target(target_url="https://api.example.test", scope_path=Path("x"))
    finally:
        session.close()
