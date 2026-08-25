"""Deterministic 80x24 Pilot coverage for the OpenBOLA terminal UI."""

from __future__ import annotations

import asyncio

from openbola.mutations import RecoveryStatus
from openbola.session import (
    DiscoverySummary,
    GrantSummary,
    IdentitySummary,
    ProgressEvent,
    ProgressState,
    SessionPhase,
    TargetSummary,
)
from openbola.tui import OpenBOLAApp


class FakeSession:
    def __init__(self, recovery: str = "clear") -> None:
        self.events = []
        self.identities: list[IdentitySummary] = []
        self.closed = False
        self.recovery = recovery
        self.grant = None
        self.confirmations = 0
        self.detail_cleared = False
        self._snapshot = {
            "discovery": DiscoverySummary(0, 0, 0, 0, True),
            "recovery": RecoveryStatus("clear", False, None),
        }

    def snapshot(self):
        return self._snapshot

    def subscribe(self, callback):
        self.events.append(callback)
        return lambda: self.events.remove(callback)

    def recovery_status(self):
        return RecoveryStatus(self.recovery, self.recovery != "clear", None)

    def configure_target(self, **kwargs):
        return TargetSummary("https://api.example.test", "a" * 64, "b" * 64)

    def add_identity(self, summary: IdentitySummary) -> None:
        self.identities.append(summary)

    def start_capture(self, token) -> None:
        self.events[0](ProgressEvent(SessionPhase.CAPTURE, ProgressState.SUCCEEDED, 1, 1, "done"))

    def start_discovery(self, token) -> None:
        self.events[0](
            ProgressEvent(SessionPhase.DISCOVERY, ProgressState.SUCCEEDED, 1, 1, "done")
        )

    def review_grant(self):
        self.grant = GrantSummary(("PATCH",), ("/v1/{id}",), ("name",), 1, 5, "restore", "a" * 64)
        self._snapshot["grant"] = self.grant
        return self.grant

    def confirm_grant(self):
        self.confirmations += 1

    def start_verification(self, token) -> None:
        self.events[0](
            ProgressEvent(SessionPhase.VERIFICATION, ProgressState.SUCCEEDED, 1, 1, "verified")
        )

    def list_findings(self):
        return ({"handle": "finding-handle", "severity": "high", "body": "secret"},)

    def finding_detail(self, handle):
        return {"severity": "high", "handle": handle, "body": "secret"}

    def clear_finding_detail(self):
        self.detail_cleared = True

    def export(self, output_dir):
        return {
            "html": output_dir / "report.html",
            "csv": output_dir / "report.csv",
            "json": output_dir / "report.json",
            "md": output_dir / "report.md",
            "junit": output_dir / "junit.xml",
            "sarif": output_dir / "report.sarif",
        }

    def recover(self):
        self.recovery = "clear"
        return self.recovery_status()

    def record_manual_escalation(self):
        self.recovery = "escalated"
        return self.recovery_status()

    def close(self) -> None:
        self.closed = True


def test_home_keyboard_navigation_and_focus_at_80x24() -> None:
    async def run() -> None:
        session = FakeSession()
        app = OpenBOLAApp(session)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert type(app.screen).__name__ == "HomeScreen"
            assert app.screen.query_one("#new-assessment").has_focus
            assert "New Assessment" in str(app.screen.query_one("#new-assessment").label)
            await pilot.press("n")
            await pilot.pause()
            assert type(app.screen).__name__ == "TargetScreen"
            assert app.screen.query_one("#target-url").has_focus
            await pilot.press("escape")
            await pilot.pause()
            assert type(app.screen).__name__ == "HomeScreen"

    asyncio.run(run())


def test_target_and_identity_inputs_never_render_secret(tmp_path) -> None:
    async def run() -> None:
        session = FakeSession()
        app = OpenBOLAApp(session)
        credential_fixture = "UI_CREDENTIAL_FIXTURE"
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            app.screen.query_one("#target-url").value = "https://api.example.test"
            app.screen.query_one("#scope-path").value = str(tmp_path / "confirmed-scope.yaml")
            await pilot.click("#target-continue")
            await pilot.pause()
            assert type(app.screen).__name__ == "IdentitiesScreen"
            app.screen.query_one("#identity-a-name").value = "owner"
            app.screen.query_one("#identity-b-name").value = "attacker"
            app.screen.query_one("#identity-a-secret").value = credential_fixture
            app.screen.query_one("#identity-b-secret").value = "other"
            await pilot.click("#identities-continue")
            await pilot.pause()
            assert credential_fixture not in str(app.screen)
            assert credential_fixture not in repr(session.identities)
            assert all(
                identity.credential_handle_id != credential_fixture
                for identity in session.identities
            )

    asyncio.run(run())


def test_recovery_gate_blocks_new_assessment_and_can_recover() -> None:
    async def run() -> None:
        session = FakeSession("required")
        app = OpenBOLAApp(session)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert type(app.screen).__name__ == "RecoveryScreen"
            await pilot.click("#recover")
            await pilot.pause()
            assert type(app.screen).__name__ == "HomeScreen"

    asyncio.run(run())


def test_plan_grant_verification_findings_and_export_flow_at_80x24() -> None:
    async def run() -> None:
        session = FakeSession()
        app = OpenBOLAApp(session)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.show(SessionPhase.AI_PLAN)
            await pilot.pause()
            await pilot.click("#ai-plan-review")
            await pilot.pause()
            assert type(app.screen).__name__ == "GrantReviewScreen"
            await pilot.click("#grant-confirm")
            await pilot.pause()
            assert type(app.screen).__name__ == "VerificationScreen"
            await pilot.click("#verification-start")
            await pilot.pause()
            assert type(app.screen).__name__ == "FindingsScreen"
            assert "no confirmed findings" not in str(app.screen)
            await pilot.click("#findings-export")
            await pilot.pause()
            await pilot.click("#export-run")
            await pilot.pause()
            assert "report.html" in str(app.screen.query_one("#export-state").render())
            assert "secret" not in str(app.screen.query_one("#export-state").render())

    asyncio.run(run())
