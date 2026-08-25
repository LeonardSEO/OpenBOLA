"""Crash-safe mutation recovery with an encrypted, fail-closed journal.

The journal is deliberately a very small persistence boundary.  Its payload
is authenticated and encrypted before it reaches disk; the key is obtained
from an operating-system credential vault and is never accepted from an
environment variable or a file.  This module never creates a transport: all
restore requests are delegated to :class:`openbola.executor.ProbeExecutor`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import secrets
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openbola.credentials import CredentialVault
from openbola.executor import ProbeExecutor, ScopedExchange
from openbola.models import CredentialKind, CredentialRef, ProbeMode, ProbeTarget
from openbola.mutations import RecoveryStatus
from openbola.paths import data_root
from openbola.scope import MutationGrant, ScopeGuard

_SCHEMA = "openbola-recovery-v1"
_VERSION = 1
_NONCE_BYTES = 12
_KEY_BYTES = 32
_MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 1024 * 1024
_MAX_RECORDS = 1
_SAFE = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z"


class RecoveryError(RuntimeError):
    """A generic recovery failure that never includes journal contents."""

    def __init__(self, code: str = "recovery_failed") -> None:
        self.code = code if code in _PUBLIC_CODES else "recovery_failed"
        super().__init__(self.code)


class JournalTamperError(RecoveryError):
    """Raised when a journal cannot be authenticated or parsed safely."""

    def __init__(self) -> None:
        super().__init__("journal_tampered")


class RecoveryKeyStore(Protocol):
    """The minimum OS-vault API required by the journal."""

    def get_or_create_key(self) -> bytes:
        """Return a stable 32-byte key held by the platform credential vault."""


class KeyringRecoveryKeyStore:
    """Keyring-backed key store for macOS Keychain/Windows Credential Manager."""

    def __init__(self, *, service: str = "openbola", username: str = "recovery-key") -> None:
        if not service or not username or any(ord(c) < 0x20 for c in service + username):
            raise ValueError("vault identifiers are invalid")
        self.service = service
        self.username = username

    def get_or_create_key(self) -> bytes:
        import keyring

        try:
            backend = keyring.get_keyring()
            if sys.platform == "darwin":
                from keyring.backends.macOS import Keyring as NativeKeyring

                allowed = (NativeKeyring,)
            elif sys.platform == "win32":
                from keyring.backends.Windows import WinVaultKeyring as NativeKeyring

                allowed = (NativeKeyring,)
            else:
                # Linux Secret Service/KWallet support is intentionally not a
                # silent fallback: P6's approved vault boundary is explicit.
                raise RecoveryError("vault_unavailable")
            if not isinstance(backend, allowed):
                raise RecoveryError("vault_unavailable")
            encoded = keyring.get_password(self.service, self.username)
            if encoded is None:
                key = secrets.token_bytes(_KEY_BYTES)
                keyring.set_password(self.service, self.username, _b64(key))
                return key
            key = _b64decode(encoded, _KEY_BYTES)
            return key
        except Exception as error:
            raise RecoveryError("vault_unavailable") from error


@dataclass(frozen=True, repr=False)
class JournalRecord:
    """In-memory restore material.  Raw values never cross the disk boundary."""

    run_ref: str
    scope_digest: str
    record_handle: str
    endpoint_handle: str
    field: str
    method: str
    endpoint_template: str
    object_id: str = dataclass_field(repr=False)
    original_value: Any = dataclass_field(repr=False)
    owner_identity: str = ""
    owner_credential: CredentialRef | None = dataclass_field(default=None, repr=False)
    base_url: str = dataclass_field(default="", repr=False)
    grant_fingerprint: str | None = dataclass_field(default=None, repr=False)
    snapshot_fingerprint: str | None = dataclass_field(default=None, repr=False)

    def __repr__(self) -> str:
        return (
            "JournalRecord("
            f"run_ref={self.run_ref!r}, scope_digest={self.scope_digest!r}, "
            f"record_handle={self.record_handle!r}, endpoint_handle={self.endpoint_handle!r}, "
            f"field={self.field!r}, method={self.method!r}, "
            f"endpoint_template={self.endpoint_template!r}, owner_identity={self.owner_identity!r})"
        )

    def __post_init__(self) -> None:
        for value, _label in (
            (self.run_ref, "run reference"),
            (self.record_handle, "record handle"),
            (self.endpoint_handle, "endpoint handle"),
            (self.owner_identity, "owner identity"),
        ):
            if not isinstance(value, str) or not __import__("re").fullmatch(_SAFE, value):
                raise RecoveryError("journal_invalid")
        if not isinstance(self.scope_digest, str) or not __import__("re").fullmatch(
            r"[0-9a-f]{64}", self.scope_digest
        ):
            raise RecoveryError("journal_invalid")
        if self.method not in {"PATCH", "PUT"}:
            raise RecoveryError("journal_invalid")
        if not isinstance(self.field, str) or not self.field or len(self.field) > 256:
            raise RecoveryError("journal_invalid")
        if not isinstance(self.endpoint_template, str) or not self.endpoint_template.startswith(
            "/"
        ):
            raise RecoveryError("journal_invalid")
        if (
            not isinstance(self.object_id, str)
            or not self.object_id
            or len(self.object_id) > 512
            or any(ord(c) < 0x20 or c in "/\\?#%" for c in self.object_id)
        ):
            raise RecoveryError("journal_invalid")
        if self.owner_credential is not None:
            if type(self.owner_credential) is not CredentialRef:
                raise RecoveryError("journal_invalid")
            if self.owner_credential.identity != self.owner_identity:
                raise RecoveryError("journal_invalid")
            if (
                not self.owner_credential.name
                or len(self.owner_credential.name) > 256
                or not self.owner_credential.secret_ref
                or len(self.owner_credential.secret_ref) > 512
            ):
                raise RecoveryError("journal_invalid")
        if self.base_url:
            from urllib.parse import urlsplit

            parsed = urlsplit(self.base_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                raise RecoveryError("journal_invalid")
        if self.grant_fingerprint is None or not __import__("re").fullmatch(
            r"[0-9a-f]{64}", self.grant_fingerprint
        ):
            raise RecoveryError("journal_invalid")
        try:
            encoded = json.dumps(self.original_value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError, OverflowError) as error:
            raise RecoveryError("journal_invalid") from error
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise RecoveryError("journal_invalid")


class AESGCMJournal:
    """Strict encrypted journal with atomic replacement and restrictive mode."""

    def __init__(
        self,
        path: Path,
        key_store: RecoveryKeyStore,
        *,
        run_ref: str | None = None,
        scope_digest: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.key_store = key_store
        self.run_ref = run_ref
        self.scope_digest = scope_digest
        self._validate_path()

    def __repr__(self) -> str:
        return "AESGCMJournal(<encrypted>)"

    def exists(self) -> bool:
        try:
            return self.path.exists()
        except OSError:
            return True

    def commit(self, record: JournalRecord | None = None, **kwargs: Any) -> JournalRecord:
        if record is None:
            record = self._record_from_kwargs(kwargs)
        if type(record) is not JournalRecord:
            raise RecoveryError("journal_invalid")
        key = self._key()
        payload = self._encode_record(record)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        aad = _aad(record.run_ref, record.scope_digest)
        ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
        envelope = {
            "schema": _SCHEMA,
            "version": _VERSION,
            "run_ref": record.run_ref,
            "scope_digest": record.scope_digest,
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        }
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(encoded) > _MAX_ENVELOPE_BYTES:
            raise RecoveryError("journal_too_large")
        self._atomic_write(encoded)
        return record

    # ``begin`` is retained for the pre-existing mutation adapter.
    begin = commit

    def load(self) -> JournalRecord:
        try:
            data = self.path.read_bytes()
        except (OSError, ValueError) as error:
            raise JournalTamperError from error
        if not data or len(data) > _MAX_ENVELOPE_BYTES:
            raise JournalTamperError()
        try:
            envelope = json.loads(data.decode("ascii"))
            if type(envelope) is not dict or set(envelope) != {
                "schema", "version", "run_ref", "scope_digest", "nonce", "ciphertext"
            }:
                raise ValueError
            if envelope["schema"] != _SCHEMA or envelope["version"] != _VERSION:
                raise ValueError
            run_ref = envelope["run_ref"]
            scope_digest = envelope["scope_digest"]
            if not isinstance(run_ref, str) or not __import__("re").fullmatch(_SAFE, run_ref):
                raise ValueError
            if not isinstance(scope_digest, str) or not __import__("re").fullmatch(
                r"[0-9a-f]{64}", scope_digest
            ):
                raise ValueError
            nonce = _b64decode(envelope["nonce"], _NONCE_BYTES)
            ciphertext = _b64decode(
                envelope["ciphertext"], min_size=16, max_size=_MAX_PAYLOAD_BYTES
            )
            plaintext = AESGCM(self._key()).decrypt(nonce, ciphertext, _aad(run_ref, scope_digest))
            if len(plaintext) > _MAX_PAYLOAD_BYTES:
                raise ValueError
            decoded = json.loads(plaintext.decode("utf-8"))
            return self._decode_record(decoded, run_ref, scope_digest)
        except (
            InvalidTag,
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
            binascii.Error,
            RecoveryError,
        ):
            raise JournalTamperError from None

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
            self._fsync_parent()
        except OSError as error:
            raise RecoveryError("journal_clear_failed") from error

    def status(self) -> RecoveryStatus:
        if not self.exists():
            return RecoveryStatus("clear", False, None)
        try:
            self.load()
        except JournalTamperError:
            return RecoveryStatus("blocked", True, "journal_tampered")
        except RecoveryError:
            return RecoveryStatus("blocked", True, "journal_unavailable")
        return RecoveryStatus("required", True, "journal_present")

    def _key(self) -> bytes:
        try:
            method = getattr(self.key_store, "get_or_create_key", None)
            if not callable(method):
                method = getattr(self.key_store, "get_key", None)
            key = method() if callable(method) else None
        except Exception as error:
            raise RecoveryError("vault_unavailable") from error
        if type(key) is not bytes or len(key) != _KEY_BYTES:
            raise RecoveryError("vault_unavailable")
        return key

    def _validate_path(self) -> None:
        if self.path.name in {"", ".", ".."} or self.path.is_dir():
            raise ValueError("journal path is invalid")
        try:
            if self.path.is_symlink():
                raise ValueError("journal path is untrusted")
        except OSError as error:
            raise ValueError("journal path is untrusted") from error
        parent = self.path.parent
        if parent.exists():
            try:
                metadata = parent.stat()
                if parent.is_symlink() or not parent.is_dir():
                    raise ValueError("journal parent is untrusted")
                if os.name != "nt":
                    uid = getattr(os, "getuid", lambda: metadata.st_uid)()
                    if metadata.st_uid != uid or metadata.st_mode & 0o077:
                        raise ValueError("journal parent is untrusted")
            except OSError as error:
                raise ValueError("journal parent is untrusted") from error

    def _atomic_write(self, content: bytes) -> None:
        parent = self.path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = parent.stat()
            if parent.is_symlink() or not parent.is_dir():
                raise OSError
            if os.name != "nt":
                uid = getattr(os, "getuid", lambda: metadata.st_uid)()
                if metadata.st_uid != uid or metadata.st_mode & 0o077:
                    raise OSError
            if self.path.is_symlink():
                raise OSError
        except OSError as error:
            raise RecoveryError("journal_path_untrusted") from error
        fd, temporary = tempfile.mkstemp(prefix=".openbola-recovery-", dir=parent)
        temporary_path = Path(temporary)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            self._fsync_parent()
        except (OSError, RecoveryError) as error:
            with suppress(OSError):
                temporary_path.unlink(missing_ok=True)
            if isinstance(error, RecoveryError):
                raise
            raise RecoveryError("journal_write_failed") from error

    def _fsync_parent(self) -> None:
        if os.name == "nt":
            return
        try:
            fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as error:
            raise RecoveryError("journal_durability_failed") from error

    @staticmethod
    def _encode_record(record: JournalRecord) -> bytes:
        payload = {
            "record_handle": record.record_handle,
            "endpoint_handle": record.endpoint_handle,
            "field": record.field,
            "method": record.method,
            "endpoint_template": record.endpoint_template,
            "object_id": record.object_id,
            "original_value": record.original_value,
            "owner_identity": record.owner_identity,
            "base_url": record.base_url,
            "grant_fingerprint": record.grant_fingerprint,
            "snapshot_fingerprint": record.snapshot_fingerprint,
            "owner_credential": _credential_json(record.owner_credential),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _decode_record(value: Any, run_ref: str, scope_digest: str) -> JournalRecord:
        if type(value) is not dict:
            raise ValueError
        required = {
            "record_handle", "endpoint_handle", "field", "method", "endpoint_template",
            "object_id", "original_value", "owner_identity", "base_url", "grant_fingerprint",
            "owner_credential", "snapshot_fingerprint",
        }
        if set(value) != required:
            raise ValueError
        credential = _credential_from_json(value["owner_credential"])
        return JournalRecord(
            run_ref=run_ref,
            scope_digest=scope_digest,
            record_handle=value["record_handle"],
            endpoint_handle=value["endpoint_handle"],
            field=value["field"],
            method=value["method"],
            endpoint_template=value["endpoint_template"],
            object_id=value["object_id"],
            original_value=value["original_value"],
            owner_identity=value["owner_identity"],
            owner_credential=credential,
            base_url=value["base_url"],
            grant_fingerprint=value["grant_fingerprint"],
            snapshot_fingerprint=value["snapshot_fingerprint"],
        )

    def _record_from_kwargs(self, values: Mapping[str, Any]) -> JournalRecord:
        # The mutation adapter passes metadata first; callers may also provide
        # a complete typed record.  Missing restore fields are rejected rather
        # than writing a journal that cannot be recovered.
        candidate = values.get("candidate")
        if candidate is not None:
            original = values.get("original_value")
            if original is None and values.get("registry") is not None:
                original = values["registry"].resolve_value(candidate.original_value)
            target = candidate.target
            return JournalRecord(
                run_ref=str(
                    values.get(
                        "run_ref",
                        self.run_ref
                        or "run_" + hashlib.sha256(candidate.record_handle.encode()).hexdigest(),
                    )
                ),
                scope_digest=str(values.get("scope_digest", self.scope_digest or "")),
                record_handle=candidate.record_handle,
                endpoint_handle=candidate.endpoint_handle,
                field=candidate.field,
                method=candidate.mutation.method,
                endpoint_template=candidate.mutation.endpoint_template,
                object_id=target.object_id,
                original_value=original,
                owner_identity=target.owner_identity,
                owner_credential=target.owner_credential,
                base_url=target.base_url,
                grant_fingerprint=values.get("grant_fingerprint"),
                snapshot_fingerprint=values.get("snapshot_fingerprint"),
            )
        return JournalRecord(**cast(dict[str, Any], dict(values)))


class RecoveryGate:
    """Process-start gate; a journal always blocks new assessment writes."""

    def __init__(self, journal: AESGCMJournal) -> None:
        if not hasattr(journal, "status") or not hasattr(journal, "load"):
            raise TypeError("recovery journal is invalid")
        self.journal = journal

    def status(self) -> RecoveryStatus:
        return self.journal.status()

    def recovery_status(self) -> RecoveryStatus:
        return self.status()

    @property
    def blocked(self) -> bool:
        return self.status().state != "clear"

    def allows_assessment(self) -> bool:
        return self.status().state == "clear"

    def allows_mutation(self) -> bool:
        return self.status().state == "clear"


class _UnavailableJournal:
    """Secret-free fail-closed stand-in used when platform setup is unsafe."""

    def status(self) -> RecoveryStatus:
        return RecoveryStatus("blocked", True, "recovery_unavailable")

    def exists(self) -> bool:
        return True

    def load(self) -> JournalRecord:
        raise JournalTamperError()


def recovery_journal_path(root: Path | None = None) -> Path:
    """Return the private journal location without creating or exposing it."""

    selected = root if root is not None else data_root()
    if not isinstance(selected, Path) or selected.name in {"", ".", ".."}:
        raise RecoveryError("journal_path_untrusted")
    return selected / "mutation-recovery.journal"


def default_recovery_gate(*, root: Path | None = None) -> RecoveryGate:
    """Build the production startup gate, failing closed on platform setup."""

    try:
        selected_root = root if root is not None else data_root()
        store = KeyringRecoveryKeyStore()
        journal = AESGCMJournal(recovery_journal_path(selected_root), store)
        if not journal.exists():
            return RecoveryGate(journal)
        # A vault failure must not silently become a clear startup state.  The
        # check only touches the OS vault; no key is returned or persisted here.
        store.get_or_create_key()
        return RecoveryGate(journal)
    except Exception:
        return RecoveryGate(cast(Any, _UnavailableJournal()))


class RecoveryCoordinator:
    """Validate provenance and restore one journaled record through the executor."""

    def __init__(
        self,
        journal: AESGCMJournal,
        executor: ProbeExecutor,
        scope_guard: ScopeGuard | None = None,
        *,
        grant: MutationGrant | None = None,
        target: ProbeTarget | None = None,
        target_factory: Callable[[JournalRecord], ProbeTarget] | None = None,
        state_store: Any | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> None:
        if not hasattr(journal, "load") or not hasattr(journal, "status"):
            raise TypeError("recovery coordinator dependencies are invalid")
        if not hasattr(executor, "request_scoped"):
            raise TypeError("recovery coordinator dependencies are invalid")
        self.journal = journal
        self.executor = executor
        self.scope_guard = scope_guard or executor.scope_guard
        self.grant = grant
        self.target = target
        self.target_factory = target_factory
        self.state_store = state_store
        if callable(now):
            self._clock = now
        elif now is None:
            self._clock = lambda: datetime.now(UTC)
        else:
            self._clock = lambda: now

    def status(self) -> RecoveryStatus:
        return self.journal.status()

    def recover(self) -> RecoveryStatus:
        current = self.status()
        if current.state == "clear":
            return current
        if current.state == "blocked":
            return current
        try:
            record = self.journal.load()
            guard = self.scope_guard
            if record.scope_digest != guard.scope_digest:
                return RecoveryStatus("blocked", True, "scope_changed")
            if self.grant is None or record.grant_fingerprint is None:
                return RecoveryStatus("blocked", True, "grant_missing")
            if self.grant not in guard.config.mutation_grants:
                return RecoveryStatus("blocked", True, "grant_changed")
            from openbola.mutations import _grant_fingerprint

            # A recovery journal is bound to the complete, confirmed grant
            # set.  Accepting a fingerprint for only one grant would permit
            # an operator to remove or alter a sibling grant unnoticed.
            if record.grant_fingerprint != _grant_fingerprint(guard.config.mutation_grants):
                return RecoveryStatus("blocked", True, "grant_changed")
            target = self.target_factory(record) if self.target_factory is not None else self.target
            if target is None:
                target = _target_from_record(record)
            if target.owner_identity != record.owner_identity:
                return RecoveryStatus("blocked", True, "credential_missing")
            if record.owner_credential is None:
                return RecoveryStatus("blocked", True, "credential_missing")
            if target.owner_credential != record.owner_credential:
                return RecoveryStatus("blocked", True, "credential_missing")
            concrete_path = record.endpoint_template.replace("{id}", record.object_id, 1)
            if (
                record.field not in self.grant.allowed_fields
                or not self.grant.permits(record.method, concrete_path)
            ):
                return RecoveryStatus("blocked", True, "grant_changed")
            guard.require_allowed(target.base_url.rstrip("/") + concrete_path, record.method)
            body = json.dumps({record.field: record.original_value}, separators=(",", ":"))
            restore = self.executor.request_scoped(
                target,
                record.owner_credential,
                method=record.method,
                endpoint_template=record.endpoint_template,
                body=body,
                content_type="application/json",
                id_field=record.field,
            )
            if not _successful(restore):
                return RecoveryStatus("required", True, "restore_unverified")
            verification = self.executor.request_scoped(
                target,
                record.owner_credential,
                method="GET",
                endpoint_template=record.endpoint_template,
                body=None,
                content_type="application/json",
                id_field=record.field,
            )
            original = record.original_value
            supported = (
                isinstance(original, str)
                or type(original) is int
                or (type(original) is float and math.isfinite(original))
            )
            if (
                not supported
                or not _successful(verification)
                or not verification.field_present
                or not verification.field_scalar
                or verification.field_value != original
                or type(verification.field_value) is not type(original)
            ):
                return RecoveryStatus("required", True, "restore_unverified")
            self.journal.clear()
            self._audit("recovery_completed", record.record_handle)
            return RecoveryStatus("clear", False, "recovery_clear")
        except Exception:
            return RecoveryStatus("blocked", True, "recovery_blocked")

    def escalate(self, reason: str) -> RecoveryStatus:
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 160:
            raise ValueError("recovery escalation reason is invalid")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in reason):
            raise ValueError("recovery escalation reason is invalid")
        self._audit("recovery_escalated", hashlib.sha256(reason.encode()).hexdigest())
        return RecoveryStatus("escalated", self.journal.exists(), "manual_escalation")

    def _audit(self, event: str, reference: str) -> None:
        if self.state_store is None:
            return
        try:
            from openbola.models import AuditEventType

            event_type = getattr(AuditEventType, event.upper(), None)
            if event_type is None:
                event_type = AuditEventType.RECOVERY_TRANSITION
            self.state_store.add_audit_event(
                event_type,
                {"object_ref": _opaque_reference(reference)},
            )
        except Exception:
            # Persistence cannot make recovery appear successful; the caller
            # still receives a safe status and the journal remains present.
            return


def recover_pending_mutation(
    scope_path: str | Path,
    *,
    root: Path | None = None,
    journal: Any | None = None,
    key_store: RecoveryKeyStore | None = None,
    scope_guard_factory: Callable[[Path], ScopeGuard] | None = None,
    vault_factory: Callable[[], CredentialVault] | None = None,
    executor_factory: Callable[[ScopeGuard, CredentialVault], ProbeExecutor] | None = None,
    coordinator_factory: Callable[..., RecoveryCoordinator] | None = None,
) -> RecoveryStatus:
    """Recover one pending mutation after an operator supplied a scope file.

    This is intentionally an explicit, narrow orchestration boundary.  It
    never runs at import or startup, and all transport remains inside
    :class:`ProbeExecutor`.  Factories are injectable so tests can provide
    in-memory journals, guards, vaults, and executors without touching a
    keychain or making a network request.
    """

    if not isinstance(scope_path, (str, Path)) or not str(scope_path):
        raise RecoveryError("scope_required")
    try:
        selected_scope = Path(scope_path).absolute()
        make_guard = scope_guard_factory or ScopeGuard.from_file
        guard = make_guard(selected_scope)
        selected_root = root if root is not None else data_root()
        active_journal = journal
        if active_journal is None:
            store = key_store if key_store is not None else KeyringRecoveryKeyStore()
            active_journal = AESGCMJournal(recovery_journal_path(selected_root), store)
        status = active_journal.status()
        if status.state == "clear":
            return status
        if status.state == "blocked":
            return status
        record = active_journal.load()
        if record.scope_digest != guard.scope_digest:
            return RecoveryStatus("blocked", True, "scope_changed")

        # A current grant must preserve the exact full set recorded at the
        # mutation boundary, then cover this concrete method/path/field.
        from openbola.mutations import _grant_fingerprint

        if record.grant_fingerprint != _grant_fingerprint(guard.config.mutation_grants):
            return RecoveryStatus("blocked", True, "grant_changed")
        concrete_path = record.endpoint_template.replace("{id}", record.object_id, 1)
        matching = tuple(
            grant
            for grant in guard.config.mutation_grants
            if record.field in grant.allowed_fields
            and grant.permits(record.method, concrete_path)
        )
        if len(matching) != 1:
            return RecoveryStatus("blocked", True, "grant_changed")

        credential = record.owner_credential
        if credential is None or not credential.secret_ref.startswith("env:"):
            # Process-local vault references cannot be reconstructed in a new
            # process.  Never attempt to resolve or report their value.
            return RecoveryStatus("blocked", True, "credential_missing")
        make_vault = vault_factory or CredentialVault
        vault = make_vault()
        vault.register_env_ref(credential)
        make_executor = executor_factory or ProbeExecutor
        executor = make_executor(guard, vault)
        make_coordinator = coordinator_factory or RecoveryCoordinator
        coordinator = make_coordinator(
            active_journal,
            executor,
            guard,
            grant=matching[0],
            target=_target_from_record(record),
        )
        return coordinator.recover()
    except RecoveryError:
        raise
    except Exception as error:
        raise RecoveryError("recovery_failed") from error


def _aad(run_ref: str, scope_digest: str) -> bytes:
    return f"{_SCHEMA}|{_VERSION}|{run_ref}|{scope_digest}".encode("ascii")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(
    value: Any,
    exact: int | None = None,
    *,
    min_size: int = 1,
    max_size: int = 65_536,
) -> bytes:
    if not isinstance(value, str) or len(value) > 2 * max_size:
        raise ValueError
    decoded = base64.b64decode(value.encode("ascii"), validate=True)
    if exact is not None and len(decoded) != exact:
        raise ValueError
    if not min_size <= len(decoded) <= max_size:
        raise ValueError
    return decoded


def _credential_json(value: CredentialRef | None) -> dict[str, str] | None:
    if value is None:
        return None
    return {
        "identity": value.identity,
        "kind": value.kind.value,
        "name": value.name,
        "secret_ref": value.secret_ref,
    }


def _credential_from_json(value: Any) -> CredentialRef | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {"identity", "kind", "name", "secret_ref"}:
        raise ValueError
    return CredentialRef(
        identity=value["identity"],
        kind=CredentialKind(value["kind"]),
        name=value["name"],
        secret_ref=value["secret_ref"],
    )


def _target_from_record(record: JournalRecord) -> ProbeTarget:
    if record.owner_credential is None or not record.base_url:
        raise RecoveryError("credential_missing")
    return ProbeTarget(
        base_url=record.base_url,
        endpoint_template=record.endpoint_template,
        method=record.method,
        object_id=record.object_id,
        owner_identity=record.owner_identity,
        attacker_identity=f"recovery-{record.owner_identity}",
        owner_credential=record.owner_credential,
        attacker_credential=record.owner_credential,
        mode=ProbeMode.MUTATION,
    )


def _successful(exchange: ScopedExchange) -> bool:
    return (
        exchange.error_code is None
        and exchange.status is not None
        and 200 <= exchange.status < 300
    )


def _opaque_reference(value: str) -> str:
    return "obj_" + hashlib.sha256(value.encode("utf-8")).hexdigest()


_PUBLIC_CODES = frozenset(
    {
        "recovery_failed", "journal_tampered", "journal_invalid", "journal_too_large",
        "vault_unavailable", "journal_clear_failed", "journal_write_failed",
        "journal_durability_failed", "journal_path_untrusted",
    }
)


__all__ = [
    "AESGCMJournal",
    "JournalRecord",
    "JournalTamperError",
    "KeyringRecoveryKeyStore",
    "RecoveryCoordinator",
    "RecoveryError",
    "RecoveryGate",
    "RecoveryKeyStore",
    "RecoveryStatus",
    "recover_pending_mutation",
]
