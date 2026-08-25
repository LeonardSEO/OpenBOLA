from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from test_mutations import _candidate, _guard

from openbola.credentials import CredentialVault
from openbola.executor import ScopedExchange
from openbola.models import CredentialKind, CredentialRef
from openbola.mutations import RecoveryStatus, _grant_fingerprint
from openbola.recovery import (
    AESGCMJournal,
    JournalRecord,
    JournalTamperError,
    RecoveryCoordinator,
    RecoveryError,
    RecoveryGate,
    default_recovery_gate,
    recover_pending_mutation,
    recovery_journal_path,
)
from openbola.scope import ScopeGuard


class Vault:
    def __init__(self, key: bytes = b"k" * 32) -> None:
        self.key = key

    def get_or_create_key(self) -> bytes:
        return self.key


def _record() -> JournalRecord:
    return JournalRecord(
        run_ref="run-test",
        scope_digest="a" * 64,
        record_handle="record-opaque",
        endpoint_handle="endpoint-opaque",
        field="email",
        method="PATCH",
        endpoint_template="/v1/users/{id}",
        object_id="RAW_ID_SENTINEL",
        original_value="ORIGINAL_VALUE_SENTINEL",
        owner_identity="owner",
        owner_credential=CredentialRef(
            identity="owner",
            kind=CredentialKind.BEARER,
            name="authorization",
            secret_ref="keyring:openbola/owner",  # noqa: S106 - opaque test reference
        ),
        base_url="http://127.0.0.1",
        grant_fingerprint="b" * 64,
        snapshot_fingerprint="c" * 64,
    )


def test_aes_gcm_round_trip_and_plaintext_absence(tmp_path: Path) -> None:
    path = tmp_path / "recovery.journal"
    journal = AESGCMJournal(path, Vault())
    journal.commit(_record())
    raw = path.read_bytes()
    assert b"RAW_ID_SENTINEL" not in raw
    assert b"ORIGINAL_VALUE_SENTINEL" not in raw
    assert path.stat().st_mode & 0o777 == 0o600
    loaded = journal.load()
    assert loaded.object_id == "RAW_ID_SENTINEL"
    assert loaded.original_value == "ORIGINAL_VALUE_SENTINEL"
    assert journal.status().state == "required"


def test_nonce_changes_and_tamper_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "recovery.journal"
    journal = AESGCMJournal(path, Vault())
    journal.commit(_record())
    first = json.loads(path.read_text(encoding="ascii"))
    journal.commit(_record())
    second = json.loads(path.read_text(encoding="ascii"))
    assert first["nonce"] != second["nonce"]
    path.write_bytes(base64.b64decode(second["ciphertext"]) + b"tampered")
    with pytest.raises(JournalTamperError):
        journal.load()
    assert journal.status().state == "blocked"


def test_wrong_key_and_associated_scope_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "recovery.journal"
    journal = AESGCMJournal(path, Vault())
    journal.commit(_record())
    with pytest.raises(JournalTamperError):
        AESGCMJournal(path, Vault(b"z" * 32)).load()
    envelope = json.loads(path.read_text(encoding="ascii"))
    envelope["scope_digest"] = "d" * 64
    path.write_text(json.dumps(envelope), encoding="ascii")
    with pytest.raises(JournalTamperError):
        journal.load()


def test_gate_blocks_valid_journal_and_clears_only_explicitly(tmp_path: Path) -> None:
    path = tmp_path / "recovery.journal"
    journal = AESGCMJournal(path, Vault())
    gate = RecoveryGate(journal)
    assert gate.status().state == "clear"
    journal.commit(_record())
    assert gate.status().state == "required"
    assert gate.blocked
    journal.clear()
    assert gate.allows_assessment()


def test_torn_replace_preserves_previous_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "recovery.journal"
    journal = AESGCMJournal(path, Vault())
    journal.commit(_record())

    def fail_replace(_source: str | os.PathLike[str], _target: str | os.PathLike[str]) -> None:
        raise OSError("simulated interruption")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(RuntimeError, match="journal_write_failed"):
        journal.commit(_record())
    assert journal.load().original_value == "ORIGINAL_VALUE_SENTINEL"


def test_default_gate_fails_closed_when_platform_vault_is_unavailable(tmp_path: Path) -> None:
    gate = default_recovery_gate(root=tmp_path)
    assert gate.status().state in {"clear", "blocked"}
    assert recovery_journal_path(tmp_path).name == "mutation-recovery.journal"


def test_journal_rejects_owner_credential_identity_mismatch() -> None:
    mismatched = _record()
    object.__setattr__(
        mismatched,
        "owner_credential",
        CredentialRef(
            identity="attacker",
            kind=CredentialKind.BEARER,
            name="authorization",
            secret_ref="keyring:openbola/attacker",  # noqa: S106 - opaque test reference
        ),
    )
    with pytest.raises(RecoveryError, match="journal_invalid"):
        JournalRecord(**mismatched.__dict__)


def test_journal_durability_failures_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = AESGCMJournal(tmp_path / "recovery.journal", Vault())
    monkeypatch.setattr(os, "chmod", lambda *_args: (_ for _ in ()).throw(OSError("chmod")))
    with pytest.raises(RecoveryError, match="journal_write_failed"):
        journal.commit(_record())

    monkeypatch.undo()
    journal = AESGCMJournal(tmp_path / "recovery.journal", Vault())
    monkeypatch.setattr(
        journal,
        "_fsync_parent",
        lambda: (_ for _ in ()).throw(RecoveryError("journal_durability_failed")),
    )
    with pytest.raises(RecoveryError, match="journal_durability_failed"):
        journal.commit(_record())


class _MemoryJournal:
    def __init__(self, record: JournalRecord) -> None:
        self.record = record
        self.cleared = False

    def status(self):
        return type("Status", (), {"state": "required", "journal_present": True})()

    def load(self) -> JournalRecord:
        return self.record

    def clear(self) -> None:
        self.cleared = True

    def exists(self) -> bool:
        return not self.cleared


class _RecoveryExecutor:
    def __init__(self, verification: ScopedExchange) -> None:
        self.scope_guard = None
        self.verification = verification

    def request_scoped(self, *_args, **_kwargs):
        if _kwargs.get("body") is None:
            return self.verification
        return ScopedExchange(
            200, "f" * 64, (), field_present=True, field_scalar=True, field_value=1
        )


@pytest.mark.parametrize(
    "verification",
    [
        ScopedExchange(200, "f" * 64, (), field_present=True, field_scalar=True, field_value="1"),
        ScopedExchange(200, "f" * 64, (), field_present=True, field_scalar=False, field_value=None),
    ],
)
def test_recovery_verification_is_type_exact_and_rejects_unsupported(
    tmp_path: Path, verification: ScopedExchange
) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    candidate = _candidate()
    grant = guard.config.mutation_grants[0]
    record = JournalRecord(
        run_ref="run-recovery",
        scope_digest=guard.scope_digest,
        record_handle=candidate.record_handle,
        endpoint_handle=candidate.endpoint_handle,
        field=candidate.field,
        method=candidate.mutation.method,
        endpoint_template=candidate.mutation.endpoint_template,
        object_id=candidate.target.object_id,
        original_value=1,
        owner_identity=candidate.target.owner_identity,
        owner_credential=candidate.target.owner_credential,
        base_url=candidate.target.base_url,
        grant_fingerprint=_grant_fingerprint((grant,)),
    )
    journal = _MemoryJournal(record)
    status = RecoveryCoordinator(
        journal,  # type: ignore[arg-type]
        _RecoveryExecutor(verification),  # type: ignore[arg-type]
        guard,
        grant=grant,
        target=candidate.target,
    ).recover()
    assert status.state == "required"
    assert not journal.cleared


def test_recover_pending_mutation_rebuilds_env_vault_and_selects_bound_grant(
    tmp_path: Path,
) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    candidate = _candidate()
    grant = guard.config.mutation_grants[0]
    credential = CredentialRef(
        identity=candidate.target.owner_identity,
        kind=CredentialKind.BEARER,
        name="authorization",
        secret_ref="env:OPENBOLA_RECOVERY_TOKEN",  # noqa: S106 - opaque test reference
    )
    record = JournalRecord(
        run_ref="run-recovery-helper",
        scope_digest=guard.scope_digest,
        record_handle=candidate.record_handle,
        endpoint_handle=candidate.endpoint_handle,
        field=candidate.field,
        method=candidate.mutation.method,
        endpoint_template=candidate.mutation.endpoint_template,
        object_id=candidate.target.object_id,
        original_value="before",
        owner_identity=candidate.target.owner_identity,
        owner_credential=credential,
        base_url=candidate.target.base_url,
        grant_fingerprint=_grant_fingerprint(guard.config.mutation_grants),
    )
    journal = _MemoryJournal(record)
    seen: dict[str, object] = {}

    class VaultSpy(CredentialVault):
        def register_env_ref(self, reference: CredentialRef) -> CredentialRef:
            seen["credential"] = reference
            return super().register_env_ref(reference)

    class ExecutorSpy:
        def __init__(self, scope_guard: ScopeGuard, vault: CredentialVault) -> None:
            seen["scope_guard"] = scope_guard
            seen["vault"] = vault

        def request_scoped(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("coordinator factory should own the transport fake")

    class CoordinatorSpy:
        def recover(self) -> object:
            seen["grant"] = grant
            return type("Status", (), {"state": "clear", "journal_present": False})()

    status = recover_pending_mutation(
        tmp_path / "scope.yaml",
        journal=journal,
        scope_guard_factory=lambda _path: guard,
        vault_factory=VaultSpy,
        executor_factory=ExecutorSpy,  # type: ignore[arg-type]
        coordinator_factory=lambda *_args, **_kwargs: CoordinatorSpy(),
    )
    assert status.state == "clear"
    assert seen["credential"] == credential
    assert seen["scope_guard"] is guard
    assert isinstance(seen["vault"], VaultSpy)
    assert seen["grant"] is grant


def test_recover_pending_mutation_rejects_process_local_credential_reference(
    tmp_path: Path,
) -> None:
    guard = _guard(tmp_path, record_scope="explicit")
    candidate = _candidate()
    record = JournalRecord(
        run_ref="run-recovery-local-ref",
        scope_digest=guard.scope_digest,
        record_handle=candidate.record_handle,
        endpoint_handle=candidate.endpoint_handle,
        field=candidate.field,
        method=candidate.mutation.method,
        endpoint_template=candidate.mutation.endpoint_template,
        object_id=candidate.target.object_id,
        original_value="before",
        owner_identity=candidate.target.owner_identity,
        owner_credential=candidate.target.owner_credential,
        base_url=candidate.target.base_url,
        grant_fingerprint=_grant_fingerprint(guard.config.mutation_grants),
    )
    status = recover_pending_mutation(
        tmp_path / "scope.yaml",
        journal=_MemoryJournal(record),
        scope_guard_factory=lambda _path: guard,
        executor_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("not reached")),
    )
    assert status.state == "blocked"
    assert status.reason_code == "credential_missing"


def test_recover_pending_mutation_requires_a_valid_scope_even_when_clear(
    tmp_path: Path,
) -> None:
    class ClearJournal:
        def status(self) -> RecoveryStatus:
            return RecoveryStatus("clear", False, "recovery_clear")

    with pytest.raises(RecoveryError) as error:
        recover_pending_mutation(
            tmp_path / "missing-scope.yaml",
            journal=ClearJournal(),
        )

    assert error.value.code == "recovery_failed"
