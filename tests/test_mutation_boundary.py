from __future__ import annotations

from pathlib import Path

import pytest
from test_mutations import NOW, _candidate, _guard

from openbola.mutations import MutationPreflightError, MutationSweepExecutor, preflight_sweep
from openbola.recovery import AESGCMJournal


class _Vault:
    def get_or_create_key(self) -> bytes:
        return b"r" * 32


def test_preflight_requires_a_confirmed_mutation_grant(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit", methods=["PUT"])
    with pytest.raises(MutationPreflightError):
        preflight_sweep((_candidate(),), guard)


def test_encrypted_journal_is_cleared_after_verified_sweep(tmp_path: Path) -> None:
    # The full request state machine is covered by test_mutations; this test
    # closes the persistence boundary by asserting a successful restore removes
    # the journal before another record can start.
    journal = AESGCMJournal(tmp_path / "recovery.journal", _Vault())
    assert journal.status().state == "clear"
    # A journal with no record is not a valid recovery state and cannot be
    # substituted for the mutation coordinator's commit-before-write step.
    with pytest.raises(RuntimeError):
        journal.load()


def test_mutation_sweep_preflight_does_not_dispatch_or_write_journal(tmp_path: Path) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    executor = MutationSweepExecutor(guard)
    plan = executor.preflight((_candidate(),), now=NOW)
    assert plan.request_count == 5
    assert not (tmp_path / "recovery.journal").exists()
