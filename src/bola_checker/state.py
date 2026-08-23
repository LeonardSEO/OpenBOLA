"""Persistent, credential-safe SQLite audit state for BOLACheck.

This module deliberately stores references to credentials, never credential
values.  Probe attempts and audit events are append-only so that a later run
can explain what was attempted without turning a retryable failure into a
completed test.

SQLite is opened only below a trusted, non-symlink parent owned by the current
user and not writable by group/other users.  New database leaves are created
with an exclusive 0600 open; existing database and sidecar files are validated
as regular, current-user-owned files and made 0600.  Python's sqlite3 API is
path-based rather than fd-based, so the trusted private parent is the explicit
TOCTOU boundary and the database inode is verified before and after each open.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, overload

from bola_checker.models import (
    AuditEventType,
    CredentialRef,
    Finding,
    OwnershipConfidence,
    OwnershipConflictError,
    OwnershipEvidence,
    ProbeResult,
    Verdict,
)

_FINAL_ATTEMPT_STATUSES = (Verdict.BOLA.value, Verdict.PROTECTED.value)
_STRONG_OWNERSHIP_CONFIDENCES = frozenset(
    {
        OwnershipConfidence.EXPLICIT,
        OwnershipConfidence.OBSERVED_CREATE,
        OwnershipConfidence.RESPONSE_MATCH,
    }
)
_EXECUTABLE_OWNERSHIP_VALUES = tuple(
    confidence.value
    for confidence in (
        OwnershipConfidence.EXPLICIT,
        OwnershipConfidence.OBSERVED_CREATE,
        OwnershipConfidence.RESPONSE_MATCH,
    )
)
_MIGRATION_BUSY_TIMEOUT_MS = 250
_PRIVATE_FILE_MODE = 0o600
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CREDENTIAL_REFERENCE = re.compile(
    r"(?:env|keyring|vault|memory):[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z"
)
_OPAQUE_CREDENTIAL_REF_ID = re.compile(r"ref_[a-f0-9]{64}\Z")
_OPAQUE_OBJECT_REF = re.compile(r"obj_[a-f0-9]{64}\Z")
_OPAQUE_RUN_LABEL_REF = re.compile(r"run_[a-f0-9]{64}\Z")
_JWT_LIKE_VALUE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")
_BEARER_VALUE = re.compile(r"bearer(?:\s|%20)", re.IGNORECASE)
_COOKIE_VALUE = re.compile(r"(?:^|[;,])\s*[A-Za-z][A-Za-z0-9_-]*\s*=", re.IGNORECASE)
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_SOURCE = re.compile(r"[A-Za-z][A-Za-z0-9_:-]*(?::[A-Za-z0-9_.$-]+)*\Z")
_SAFE_PATH = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;:@{}-]+/?)*\Z")
_LEGACY_SAFE_PATH = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;:@%{}-]+/?)*\Z")
_ROUTE_PLACEHOLDER = re.compile(r"\{id(?:[2-9][0-9]*)?\}\Z")
_UUID_LITERAL = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_HEX_LITERAL = re.compile(r"[0-9a-f]{16,}\Z", re.IGNORECASE)
_URLSAFE_LITERAL = re.compile(r"[A-Za-z0-9_-]{16,}\Z")
_BASE64_LITERAL = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}\Z")
_SECRET_PREFIX = re.compile(
    r"(?:sk|pk)_(?:live|test)_|gh[pousr]_|github_pat_|xox[baprs]-|akia[0-9a-z]",
    re.IGNORECASE,
)
_SAFE_METHOD = re.compile(r"[A-Z]{1,10}\Z")
_JSON_INTEGER_KEYS = frozenset(
    {
        "attempt_id",
        "attacker_identity_id",
        "attacker_status",
        "count",
        "endpoint_id",
        "identity_id",
        "owner_identity_id",
        "owner_status",
        "preserved_count",
        "coalesced_count",
    }
)
_JSON_IDENTIFIER_KEYS = frozenset(
    {"id_field", "identity", "migration_marker", "subject", "tenant", "user_id"}
)
_JSON_ENUM_VALUES: dict[str, frozenset[str]] = {
    "comparison": frozenset(
        {"object_id_match", "object_id_mismatch", "response_shape_mismatch"}
    ),
    "confidence": frozenset(confidence.value for confidence in OwnershipConfidence),
    "severity": frozenset({"critical", "high", "medium", "low", "info"}),
    "status": frozenset(verdict.value for verdict in Verdict),
}


class ErrorCode(StrEnum):
    """The bounded error classifications that may enter persistent JSON."""

    TIMEOUT = "timeout"
    TRANSPORT_ERROR = "transport_error"
    INVALID_RESPONSE = "invalid_response"
    SCOPE_DENIED = "scope_denied"
    RATE_LIMITED = "rate_limited"
    REDIRECT_BLOCKED = "redirect_blocked"


_JSON_ENUM_VALUES["error_code"] = frozenset(error_code.value for error_code in ErrorCode)


@dataclass(frozen=True)
class PendingCombination:
    """A known ownership relation that still needs an attacker probe."""

    endpoint_id: int
    owner_identity_id: int
    attacker_identity_id: int
    object_ref: str

    @property
    def object_id(self) -> str:
        """Compatibility alias for pre-v3 callers; the value is always opaque."""

        return self.object_ref


@dataclass(frozen=True)
class AuditEvent:
    """An immutable event recorded by the persistent state store."""

    id: int
    event_type: AuditEventType
    occurred_at: str
    run_id: int | None
    data: Mapping[str, Any]


_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY,
            template TEXT NOT NULL,
            method TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            UNIQUE(template, method)
        );

        CREATE TABLE IF NOT EXISTS identities (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            metadata_json TEXT NOT NULL,
            credential_ref_id TEXT,
            first_seen_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ownership_evidence (
            id INTEGER PRIMARY KEY,
            identity_id INTEGER NOT NULL REFERENCES identities(id),
            endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
            object_id TEXT NOT NULL,
            confidence TEXT NOT NULL,
            source TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(identity_id, endpoint_id, object_id, confidence, source)
        );

        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            label TEXT,
            metadata_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tested_combinations (
            id INTEGER PRIMARY KEY,
            endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
            owner_identity_id INTEGER NOT NULL REFERENCES identities(id),
            attacker_identity_id INTEGER NOT NULL REFERENCES identities(id),
            object_id TEXT NOT NULL,
            attempt_status TEXT NOT NULL,
            retryable INTEGER NOT NULL CHECK(retryable IN (0, 1)),
            attempted_at TEXT NOT NULL,
            run_id INTEGER REFERENCES runs(id)
        );

        CREATE INDEX IF NOT EXISTS tested_combination_lookup
            ON tested_combinations(
                endpoint_id, owner_identity_id, attacker_identity_id, object_id, id DESC
            );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            found_at TEXT NOT NULL,
            UNIQUE(endpoint_id, severity, title, description, evidence_hash)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            run_id INTEGER REFERENCES runs(id),
            data_json TEXT NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS no_update_runs
        BEFORE UPDATE ON runs BEGIN
            SELECT RAISE(ABORT, 'runs are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_delete_runs
        BEFORE DELETE ON runs BEGIN
            SELECT RAISE(ABORT, 'runs are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_update_tested_combinations
        BEFORE UPDATE ON tested_combinations BEGIN
            SELECT RAISE(ABORT, 'tested combinations are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_delete_tested_combinations
        BEFORE DELETE ON tested_combinations BEGIN
            SELECT RAISE(ABORT, 'tested combinations are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_update_findings
        BEFORE UPDATE ON findings BEGIN
            SELECT RAISE(ABORT, 'findings are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_delete_findings
        BEFORE DELETE ON findings BEGIN
            SELECT RAISE(ABORT, 'findings are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_update_audit_events
        BEFORE UPDATE ON audit_events BEGIN
            SELECT RAISE(ABORT, 'audit events are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS no_delete_audit_events
        BEFORE DELETE ON audit_events BEGIN
            SELECT RAISE(ABORT, 'audit events are append-only');
        END;
        """,
    ),
    (2, ""),
    (3, ""),
)


def _validate_credential_ref_id(credential_ref_id: str) -> str:
    """Accept only safe references, never a credential value or transport value."""

    reference_identifier = credential_ref_id.partition(":")[2]
    if (
        not _CREDENTIAL_REFERENCE.fullmatch(credential_ref_id)
        or any(character.isspace() or ord(character) < 32 for character in credential_ref_id)
        or _BEARER_VALUE.match(reference_identifier)
        or _JWT_LIKE_VALUE.fullmatch(reference_identifier)
        or _COOKIE_VALUE.search(reference_identifier)
    ):
        raise ValueError("credential reference is not an approved external reference")
    return credential_ref_id


def credential_ref_fingerprint(credential: CredentialRef) -> str:
    """Return the only credential identifier that may be persisted.

    The underlying reference stays process-local or externally resolved.  Its
    literal value never crosses the SQLite boundary.
    """

    _validate_credential_ref_id(credential.secret_ref)
    material = "|".join((credential.kind.value, credential.name, credential.secret_ref))
    return f"ref_{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def _validate_opaque_credential_ref_id(credential_ref_id: str) -> str:
    if not _OPAQUE_CREDENTIAL_REF_ID.fullmatch(credential_ref_id):
        raise ValueError("credential reference identifier is not an approved opaque fingerprint")
    return credential_ref_id


def object_ref_fingerprint(object_id: str) -> str:
    """Return the only object identifier representation allowed in SQLite.

    Callers may keep using concrete IDs at the public API. Already-opaque refs
    are accepted so values returned by pending-work and ownership queries can
    be passed back to the store without changing their lookup key.
    """

    if not isinstance(object_id, str) or not object_id:
        raise ValueError("object identifier must be a non-empty string")
    if len(object_id) > 4096:
        raise ValueError("object identifier is too long")
    if _OPAQUE_OBJECT_REF.fullmatch(object_id):
        return object_id
    return f"obj_{hashlib.sha256(object_id.encode('utf-8')).hexdigest()}"


def run_label_fingerprint(label: str) -> str:
    """Return the only run-label representation allowed in persistent state."""

    if not isinstance(label, str) or not label:
        raise ValueError("run label must be a non-empty string")
    if len(label) > 4096:
        raise ValueError("run label is too long")
    if _OPAQUE_RUN_LABEL_REF.fullmatch(label):
        return label
    return f"run_{hashlib.sha256(label.encode('utf-8')).hexdigest()}"


def _validate_audit_event_type(event_type: AuditEventType | str) -> AuditEventType:
    """Accept enum members and their exact legacy string values, but no free text."""

    try:
        return AuditEventType(event_type)
    except ValueError as error:
        raise ValueError("audit event type is not an approved event name") from error


def _validate_identifier(value: str, *, field: str) -> str:
    if not _SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} is not a safe identifier")
    return value


def _route_literal_entropy(value: str) -> float:
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in map(value.count, set(value))
    )


def _is_route_date(value: str) -> bool:
    try:
        if re.fullmatch(r"[0-9]{8}", value):
            date.fromisoformat(f"{value[:4]}-{value[4:6]}-{value[6:]}")
            return True
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            date.fromisoformat(value)
            return True
    except ValueError:
        return False
    return False


def _unsafe_route_literal(value: str, previous: str | None) -> bool:
    """Detect concrete object/credential material where route syntax is required."""

    if not value or _is_route_date(value):
        return False
    if value.isdecimal():
        if 1900 <= int(value) <= 2100:
            return False
        return not (previous is not None and previous.lower() in {"v", "version"})
    if (
        _UUID_LITERAL.fullmatch(value)
        or _HEX_LITERAL.fullmatch(value)
        or _JWT_LIKE_VALUE.fullmatch(value)
        or _BEARER_VALUE.match(value)
        or _COOKIE_VALUE.search(value)
        or _SECRET_PREFIX.match(value)
    ):
        return True
    if _BASE64_LITERAL.fullmatch(value) and _route_literal_entropy(value) >= 3.5:
        return True
    if not _URLSAFE_LITERAL.fullmatch(value):
        return False
    character_classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(character in "_-" for character in value),
        )
    )
    unseparated = re.fullmatch(r"[A-Za-z0-9]+", value) is not None
    return _route_literal_entropy(value) >= 3.5 and (character_classes >= 3 or unseparated)


def _validate_path(value: str) -> str:
    if "%" in value:
        raise ValueError("path templates may not contain percent escapes")
    if not _SAFE_PATH.fullmatch(value):
        raise ValueError("path is not a safe path template")
    previous: str | None = None
    for raw_segment in value.split("/"):
        if not raw_segment:
            continue
        segment = raw_segment
        if _ROUTE_PLACEHOLDER.fullmatch(segment):
            previous = segment
            continue
        if "{" in segment or "}" in segment or _unsafe_route_literal(segment, previous):
            raise ValueError("path template contains a concrete identifier-like segment")
        previous = segment
    return value


def _redacted_endpoint_template(value: str) -> str:
    """Convert a pre-v3 endpoint into a persistable route-only template."""

    if not _LEGACY_SAFE_PATH.fullmatch(value):
        return "/redacted/{id}"
    placeholder_count = 0
    previous: str | None = None
    safe_segments: list[str] = []
    for raw_segment in value.split("/"):
        if not raw_segment:
            safe_segments.append(raw_segment)
            continue
        segment = raw_segment
        is_placeholder = _ROUTE_PLACEHOLDER.fullmatch(segment) is not None
        is_unsafe = (
            "%" in raw_segment
            or "{" in segment
            or "}" in segment
            or _unsafe_route_literal(segment, previous)
        )
        if is_placeholder or is_unsafe:
            placeholder_count += 1
            suffix = "" if placeholder_count == 1 else str(placeholder_count)
            safe_segments.append(f"{{id{suffix}}}")
            previous = safe_segments[-1]
        else:
            safe_segments.append(raw_segment)
            previous = segment
    redacted = "/".join(safe_segments) or "/"
    return _validate_path(redacted)


def _validate_source(value: str) -> str:
    if not _SAFE_SOURCE.fullmatch(value):
        raise ValueError("source is not a safe provenance identifier")
    return value


def _validate_method(value: str) -> str:
    normalized = value.upper()
    if not _SAFE_METHOD.fullmatch(normalized):
        raise ValueError("method is not a safe HTTP method")
    return normalized


def redact_evidence(value: Any) -> Any:
    """Validate persistable JSON using a per-key type and value policy."""

    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise TypeError("persistent JSON mapping keys must be strings")
            persistent_key = "object_ref" if key == "object_id" else key
            if persistent_key in safe:
                raise ValueError("persistent JSON contains duplicate object reference fields")
            if key == "object_id":
                if not isinstance(nested_value, str):
                    raise ValueError("persistent JSON object field must be a string")
                safe[persistent_key] = object_ref_fingerprint(nested_value)
            else:
                safe[persistent_key] = _validate_json_field(key, nested_value)
        return safe

    raise TypeError("persistent JSON documents must be mappings")


def _validate_json_field(key: str, value: Any) -> Any:
    if key in _JSON_INTEGER_KEYS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("persistent JSON integer field has an invalid value")
        if key in {"attacker_status", "owner_status"} and not 100 <= value <= 599:
            raise ValueError("persistent JSON HTTP status is invalid")
        if key not in {"attacker_status", "owner_status"} and value < 0:
            raise ValueError("persistent JSON identifier is invalid")
        return value
    if key == "retryable":
        if not isinstance(value, bool):
            raise ValueError("persistent JSON retryable field must be boolean")
        return value
    if key == "object_ref":
        if not isinstance(value, str) or not _OPAQUE_OBJECT_REF.fullmatch(value):
            raise ValueError("persistent JSON object reference is not opaque")
        return value
    if key in _JSON_IDENTIFIER_KEYS:
        if not isinstance(value, str):
            raise ValueError("persistent JSON identifier field must be a string")
        return _validate_identifier(value, field="persistent JSON identifier")
    if key == "source":
        if not isinstance(value, str):
            raise ValueError("persistent JSON source field must be a string")
        return _validate_source(value)
    if key in _JSON_ENUM_VALUES:
        if not isinstance(value, str) or value not in _JSON_ENUM_VALUES[key]:
            raise ValueError("persistent JSON enum field has an invalid value")
        return value
    if key == "method":
        if not isinstance(value, str):
            raise ValueError("persistent JSON method field must be a string")
        return _validate_method(value)
    if key in {"template", "redirect_target"}:
        if not isinstance(value, str):
            raise ValueError("persistent JSON path field must be a string")
        return _validate_path(value)
    if key == "label":
        if value is None:
            return value
        if not isinstance(value, str):
            raise ValueError("persistent JSON label field must be a string")
        if not _OPAQUE_RUN_LABEL_REF.fullmatch(value):
            raise ValueError("persistent JSON run label is not an opaque reference")
        return value
    if key == "evidence":
        if not isinstance(value, Mapping):
            raise ValueError("persistent JSON evidence field must be a mapping")
        return redact_evidence(value)
    raise ValueError("persistent JSON contains a key outside the safe allowlist")


def _json_document(value: Mapping[str, Any]) -> str:
    """Serialize a validated mapping canonically."""

    redacted = redact_evidence(value)
    return json.dumps(redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _validate_finding_severity(severity: str) -> str:
    if severity not in _JSON_ENUM_VALUES["severity"]:
        raise ValueError("finding severity is not an approved value")
    return severity


def canonical_finding_text(
    *,
    severity: str,
    endpoint_template: str,
    method: str,
    evidence: Mapping[str, Any],
) -> tuple[str, str]:
    """Derive the only finding text that persistent state accepts.

    The concrete object ID becomes an opaque reference. No optional identity
    or other caller-controlled identifier is interpolated into report text.
    """

    severity = _validate_finding_severity(severity)
    endpoint_template = _validate_path(endpoint_template)
    method = _validate_method(method)
    safe_evidence = redact_evidence(evidence)
    object_ref = safe_evidence.get("object_ref")
    if not isinstance(object_ref, str):
        raise ValueError("finding evidence requires a validated object_ref")
    title = f"BOLA {severity.upper()} {method} {endpoint_template}"
    description = f"BOLA evidence for object ref {object_ref}"
    return title, description


def _inserted_id(cursor: sqlite3.Cursor) -> int:
    """Return an INSERT id, failing clearly if SQLite did not produce one."""

    if cursor.lastrowid is None:  # pragma: no cover - SQLite INSERT contract
        raise RuntimeError("SQLite did not return an inserted row id")
    return int(cursor.lastrowid)


class StateStore:
    """A local, migration-managed SQLite store with no credential material."""

    def __init__(self, db_path: str | Path = "bola_state.db") -> None:
        self.db_path = Path(os.path.abspath(os.fspath(db_path)))
        self._db_identity = self._prepare_database_path(self.db_path)
        self._initialise()

    @staticmethod
    def _current_uid() -> int | None:
        """Return the current owner where the platform exposes Unix UIDs."""

        getter = getattr(os, "getuid", None)
        return int(getter()) if getter is not None else None

    @classmethod
    def _validate_directory_stat(cls, metadata: os.stat_result, *, leaf: bool) -> None:
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("state database parent must be a regular directory")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            sticky = bool(metadata.st_mode & stat.S_ISVTX)
            uid = cls._current_uid()
            trusted_sticky_owner = uid is None or metadata.st_uid in {0, uid}
            if leaf or not sticky or not trusted_sticky_owner:
                raise RuntimeError("state database parent must not be group/world writable")
        uid = cls._current_uid()
        if leaf and uid is not None and metadata.st_uid != uid:
            raise RuntimeError("state database parent must be owned by the current user")

    @classmethod
    def _open_trusted_parent(cls, parent: Path) -> int:
        """Open every parent component without following a symlink.

        A private final parent is the trust boundary for SQLite's path-based
        open.  Python's sqlite3 API cannot receive the already-open leaf fd;
        keeping this descriptor open through each validation makes the path
        checks deterministic and prevents an untrusted parent substitution.
        """

        if not parent.is_absolute():  # pragma: no cover - __init__ normalises
            raise RuntimeError("state database parent must be absolute")
        parts = parent.parts
        if not parts:
            raise RuntimeError("state database parent is invalid")
        anchor = Path(parts[0])
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW
        try:
            descriptor = os.open(anchor, flags)
        except OSError as error:
            raise RuntimeError("state database parent could not be opened safely") from error
        try:
            for component in parts[1:]:
                if component in {"", ".", ".."}:
                    continue
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                cls._validate_directory_stat(metadata, leaf=False)
            cls._validate_directory_stat(os.fstat(descriptor), leaf=True)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def _validate_leaf_stat(cls, metadata: os.stat_result) -> tuple[int, int]:
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("state database must be a regular file")
        uid = cls._current_uid()
        if uid is not None and metadata.st_uid != uid:
            raise RuntimeError("state database must be owned by the current user")
        return int(metadata.st_dev), int(metadata.st_ino)

    @classmethod
    def _harden_existing_leaf(cls, descriptor: int) -> tuple[int, int]:
        metadata = os.fstat(descriptor)
        identity = cls._validate_leaf_stat(metadata)
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        return identity

    @classmethod
    def _harden_sidecars(cls, parent_fd: int, name: str) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = f"{name}{suffix}"
            try:
                descriptor = os.open(sidecar, os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RuntimeError("SQLite sidecar is not a safe regular file") from error
            try:
                metadata = os.fstat(descriptor)
                cls._validate_leaf_stat(metadata)
                os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            finally:
                os.close(descriptor)

    @classmethod
    def _prepare_database_path(cls, path: Path) -> tuple[int, int]:
        parent_fd = cls._open_trusted_parent(path.parent)
        descriptor = -1
        try:
            name = path.name
            if not name or name in {".", ".."}:
                raise RuntimeError("state database filename is invalid")
            create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW
            try:
                descriptor = os.open(
                    name, create_flags, _PRIVATE_FILE_MODE, dir_fd=parent_fd
                )
            except FileExistsError:
                try:
                    descriptor = os.open(name, os.O_RDWR | _NOFOLLOW, dir_fd=parent_fd)
                except PermissionError:
                    try:
                        descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
                    except OSError as error:
                        raise RuntimeError(
                            "state database path is not a safe regular file"
                        ) from error
                except OSError as error:
                    raise RuntimeError(
                        "state database path is not a safe regular file"
                    ) from error
                identity = cls._harden_existing_leaf(descriptor)
            else:
                identity = cls._harden_existing_leaf(descriptor)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if cls._validate_leaf_stat(current) != identity:
                raise RuntimeError("state database path changed during initialization")
            cls._harden_sidecars(parent_fd, name)
            return identity
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        finally:
            os.close(parent_fd)

    def _verify_database_identity(self) -> None:
        parent_fd = self._open_trusted_parent(self.db_path.parent)
        try:
            metadata = os.stat(self.db_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if self._validate_leaf_stat(metadata) != self._db_identity:
                raise RuntimeError("state database path changed during SQLite access")
            self._harden_sidecars(parent_fd, self.db_path.name)
        finally:
            os.close(parent_fd)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._verify_database_identity()
        connection = sqlite3.connect(self.db_path, timeout=5.0)
        try:
            self._verify_database_identity()
        except BaseException:
            connection.close()
            raise
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        with suppress(sqlite3.OperationalError):
            # WAL can be unavailable on a read-only or unusual filesystem.
            connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def _initialise(self) -> None:
        migrated_credential_refs = False
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_version "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL)"
            )
            applied = {
                int(row["version"])
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            for version, statements in _MIGRATIONS:
                if version == 3:
                    continue
                if version not in applied:
                    connection.executescript(statements)
                    if version == 2:
                        self._migrate_credential_reference_ids(connection)
                        migrated_credential_refs = True
                    connection.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (version, self._now()),
                    )
                    applied.add(version)
            recorded_version = max(applied, default=0)
            current = connection.execute(
                "SELECT version FROM schema_version WHERE singleton = 1"
            ).fetchone()
            if current is None:
                connection.execute(
                    "INSERT INTO schema_version(singleton, version) VALUES (1, ?)",
                    (recorded_version,),
                )
            elif int(current["version"]) != recorded_version:
                connection.execute(
                    "UPDATE schema_version SET version = ? WHERE singleton = 1",
                    (recorded_version,),
                )
            needs_object_migration = 3 not in applied
        if needs_object_migration:
            self._migrate_object_state_with_durable_scrub()
        elif migrated_credential_refs:
            self._scrub_sqlite_files_after_secret_migration()

    def _migrate_object_state_with_durable_scrub(self) -> None:
        """Gate v3 on an exclusive DELETE-mode migration and completed VACUUM.

        The migration ledger and ``schema_version`` remain at v2 until after
        transformed pages have committed and VACUUM has durably rebuilt the
        database.  Acquiring the exclusive conditions before the transform
        makes an active-reader failure leave the logical v2 state untouched.
        A crash after the transform but before the ledger write is retryable:
        the physical v3 columns are detected and only the scrub is repeated.
        """

        connection = sqlite3.connect(
            self.db_path, timeout=_MIGRATION_BUSY_TIMEOUT_MS / 1000
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {_MIGRATION_BUSY_TIMEOUT_MS}")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or int(checkpoint[0]) != 0:
                raise RuntimeError("object-state migration requires an idle SQLite reader set")
            journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                raise RuntimeError("object-state migration could not leave SQLite WAL mode")
            locking_mode = connection.execute("PRAGMA locking_mode = EXCLUSIVE").fetchone()
            if locking_mode is None or str(locking_mode[0]).lower() != "exclusive":
                raise RuntimeError("object-state migration could not request exclusive locking")

            connection.execute("BEGIN EXCLUSIVE")
            applied = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 3"
            ).fetchone()
            if applied is not None:
                connection.rollback()
                return
            physical_version = self._object_state_physical_version(connection)
            if physical_version == 2:
                self._migrate_object_state(connection)
            connection.commit()

            # VACUUM cannot run inside the preceding transaction. Exclusive
            # locking remains owned by this connection across both operations.
            self._vacuum_object_state(connection)

            connection.execute("BEGIN EXCLUSIVE")
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (3, ?)",
                (self._now(),),
            )
            connection.execute(
                "UPDATE schema_version SET version = 3 WHERE singleton = 1"
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _vacuum_object_state(connection: sqlite3.Connection) -> None:
        """Durably rebuild migrated pages outside the logical migration transaction."""

        connection.execute("VACUUM")

    @staticmethod
    def _object_state_physical_version(connection: sqlite3.Connection) -> int:
        ownership_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(ownership_evidence)")
        }
        attempt_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(tested_combinations)")
        }
        if "object_id" in ownership_columns and "object_id" in attempt_columns:
            return 2
        if "object_ref" in ownership_columns and "object_ref" in attempt_columns:
            return 3
        raise RuntimeError("object-state schema is inconsistent and cannot be migrated safely")

    def _scrub_sqlite_files_after_secret_migration(self) -> None:
        """Remove superseded secret-bearing pages from DB, WAL, and SHM artifacts."""

        connection = sqlite3.connect(self.db_path, timeout=5.0)
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result is None or int(result[0]) != 0:
                raise RuntimeError("secret migration could not clear SQLite WAL")
            connection.execute("VACUUM")
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            connection.close()
        if result is None or int(result[0]) != 0:
            raise RuntimeError("secret migration could not clear SQLite WAL after vacuum")

    @staticmethod
    def _migrate_credential_reference_ids(connection: sqlite3.Connection) -> None:
        """Replace pre-v2 literal credential references with irreversible identifiers."""

        rows = connection.execute(
            "SELECT id, credential_ref_id FROM identities WHERE credential_ref_id IS NOT NULL"
        ).fetchall()
        for row in rows:
            current = str(row["credential_ref_id"])
            if _OPAQUE_CREDENTIAL_REF_ID.fullmatch(current):
                continue
            fingerprint = hashlib.sha256(f"legacy|{current}".encode()).hexdigest()
            connection.execute(
                "UPDATE identities SET credential_ref_id = ? WHERE id = ?",
                (f"ref_{fingerprint}", int(row["id"])),
            )

    @staticmethod
    def _migrate_object_state(connection: sqlite3.Connection) -> None:
        """Replace every pre-v3 concrete object value with a deterministic ref."""

        if not connection.in_transaction:
            raise RuntimeError("object-state migration requires an existing transaction")
        append_only_tables = ("runs", "tested_combinations", "findings", "audit_events")
        for table in append_only_tables:
            connection.execute(f"DROP TRIGGER IF EXISTS no_update_{table}")
            connection.execute(f"DROP TRIGGER IF EXISTS no_delete_{table}")

        for statement in (
            "CREATE TABLE IF NOT EXISTS legacy_finding_events ("
            "id INTEGER PRIMARY KEY, legacy_finding_id INTEGER NOT NULL, "
            "legacy_endpoint_template TEXT NOT NULL, legacy_method TEXT NOT NULL, "
            "legacy_severity TEXT NOT NULL, legacy_object_ref TEXT NOT NULL, "
            "canonical_title TEXT NOT NULL, canonical_description TEXT NOT NULL, "
            "evidence_json TEXT NOT NULL, migration_marker TEXT NOT NULL, "
            "archived_at TEXT NOT NULL, UNIQUE(legacy_finding_id, migration_marker))",
            "CREATE TRIGGER IF NOT EXISTS no_update_legacy_finding_events "
            "BEFORE UPDATE ON legacy_finding_events BEGIN "
            "SELECT RAISE(ABORT, 'legacy finding events are append-only'); END",
            "CREATE TRIGGER IF NOT EXISTS no_delete_legacy_finding_events "
            "BEFORE DELETE ON legacy_finding_events BEGIN "
            "SELECT RAISE(ABORT, 'legacy finding events are append-only'); END",
        ):
            connection.execute(statement)

        # Snapshot before endpoint coalescing: the old endpoint row may be
        # removed below, but every legacy finding still needs an archive row.
        legacy_findings = connection.execute(
            "SELECT finding.id, finding.endpoint_id, finding.severity, "
            "finding.evidence_json, endpoint.template, endpoint.method "
            "FROM findings AS finding JOIN endpoints AS endpoint "
            "ON endpoint.id = finding.endpoint_id ORDER BY finding.id"
        ).fetchall()

        connection.execute(
            "ALTER TABLE ownership_evidence RENAME COLUMN object_id TO object_ref"
        )
        connection.execute(
            "ALTER TABLE tested_combinations RENAME COLUMN object_id TO object_ref"
        )
        object_tables = (
            (
                "SELECT id, object_ref FROM ownership_evidence",
                "UPDATE ownership_evidence SET object_ref = ? WHERE id = ?",
            ),
            (
                "SELECT id, object_ref FROM tested_combinations",
                "UPDATE tested_combinations SET object_ref = ? WHERE id = ?",
            ),
        )
        for select_sql, update_sql in object_tables:
            rows = connection.execute(select_sql).fetchall()
            for row in rows:
                connection.execute(
                    update_sql,
                    (object_ref_fingerprint(str(row["object_ref"])), int(row["id"])),
                )

        endpoint_id_map: dict[int, int] = {}
        endpoints = connection.execute(
            "SELECT id, template, method FROM endpoints ORDER BY id"
        ).fetchall()
        for endpoint in endpoints:
            endpoint_id = int(endpoint["id"])
            template = _redacted_endpoint_template(str(endpoint["template"]))
            method = _validate_method(str(endpoint["method"]))
            target = connection.execute(
                "SELECT id FROM endpoints WHERE template = ? AND method = ?",
                (template, method),
            ).fetchone()
            if target is None or int(target["id"]) == endpoint_id:
                connection.execute(
                    "UPDATE endpoints SET template = ?, method = ? WHERE id = ?",
                    (template, method, endpoint_id),
                )
                endpoint_id_map[endpoint_id] = endpoint_id
                continue

            target_id = int(target["id"])
            endpoint_id_map[endpoint_id] = target_id
            connection.execute(
                "INSERT OR IGNORE INTO ownership_evidence("
                "identity_id, endpoint_id, object_ref, confidence, source, recorded_at"
                ") SELECT identity_id, ?, object_ref, confidence, source, recorded_at "
                "FROM ownership_evidence WHERE endpoint_id = ?",
                (target_id, endpoint_id),
            )
            connection.execute(
                "DELETE FROM ownership_evidence WHERE endpoint_id = ?", (endpoint_id,)
            )
            connection.execute(
                "UPDATE tested_combinations SET endpoint_id = ? WHERE endpoint_id = ?",
                (target_id, endpoint_id),
            )
            connection.execute(
                "UPDATE OR IGNORE findings SET endpoint_id = ? WHERE endpoint_id = ?",
                (target_id, endpoint_id),
            )
            connection.execute("DELETE FROM findings WHERE endpoint_id = ?", (endpoint_id,))
            connection.execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))

        # Rebuild current findings from the complete snapshot. This allows
        # duplicate legacy rows and findings attached to coalesced endpoints
        # to remain represented canonically without losing their archive row.
        connection.execute("DELETE FROM findings")
        preserved_count = 0
        coalesced_count = 0
        migration_marker = "v3_findings_archive"
        for finding in legacy_findings:
            raw_evidence = json.loads(str(finding["evidence_json"]))
            if not isinstance(raw_evidence, Mapping):
                raw_evidence = {"object_ref": object_ref_fingerprint(str(finding["id"]))}
            try:
                evidence_json = _json_document(raw_evidence)
                safe_evidence = json.loads(evidence_json)
                object_ref = safe_evidence.get("object_ref")
                if not isinstance(object_ref, str):
                    object_ref = object_ref_fingerprint(f"legacy-finding:{finding['id']}")
                    safe_evidence = {"object_ref": object_ref}
                    evidence_json = _json_document(safe_evidence)
                severity = _validate_finding_severity(str(finding["severity"]))
                endpoint_id = endpoint_id_map.get(
                    int(finding["endpoint_id"]), int(finding["endpoint_id"])
                )
                endpoint = connection.execute(
                    "SELECT template, method FROM endpoints WHERE id = ?", (endpoint_id,)
                ).fetchone()
                if endpoint is None:
                    raise ValueError("migrated finding endpoint is missing")
                title, description = canonical_finding_text(
                    severity=severity,
                    endpoint_template=str(endpoint["template"]),
                    method=str(endpoint["method"]),
                    evidence=safe_evidence,
                )
            except (TypeError, ValueError):
                object_ref = object_ref_fingerprint(f"legacy-finding:{finding['id']}")
                safe_evidence = {"object_ref": object_ref}
                evidence_json = _json_document(safe_evidence)
                severity = "info"
                endpoint_id = endpoint_id_map.get(
                    int(finding["endpoint_id"]), int(finding["endpoint_id"])
                )
                endpoint = connection.execute(
                    "SELECT template, method FROM endpoints WHERE id = ?", (endpoint_id,)
                ).fetchone()
                if endpoint is None:
                    endpoint = {"template": "/redacted/{id}", "method": "GET"}
                title, description = canonical_finding_text(
                    severity=severity,
                    endpoint_template=str(endpoint["template"]),
                    method=str(endpoint["method"]),
                    evidence=safe_evidence,
                )
            evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
            connection.execute(
                "INSERT OR IGNORE INTO legacy_finding_events("
                "legacy_finding_id, legacy_endpoint_template, legacy_method, "
                "legacy_severity, legacy_object_ref, canonical_title, "
                "canonical_description, evidence_json, migration_marker, archived_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(finding["id"]),
                    _redacted_endpoint_template(str(finding["template"])),
                    _validate_method(str(finding["method"])),
                    severity,
                    object_ref,
                    title,
                    description,
                    evidence_json,
                    migration_marker,
                    datetime.now(UTC).isoformat(),
                ),
            )
            preserved_count += 1
            cursor = connection.execute(
                "INSERT OR IGNORE INTO findings("
                "endpoint_id, severity, title, description, evidence_json, evidence_hash, found_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    endpoint_id,
                    severity,
                    title,
                    description,
                    evidence_json,
                    evidence_hash,
                    datetime.now(UTC).isoformat(),
                ),
            )
            if cursor.rowcount == 0:
                coalesced_count += 1

        if legacy_findings:
            migration_audit = _json_document(
                {
                    "migration_marker": migration_marker,
                    "preserved_count": preserved_count,
                    "coalesced_count": coalesced_count,
                }
            )
            connection.execute(
                "INSERT INTO audit_events(event_type, occurred_at, run_id, data_json) "
                "VALUES (?, ?, NULL, ?)",
                (
                    AuditEventType.LEGACY_EVENT_REDACTED.value,
                    datetime.now(UTC).isoformat(),
                    migration_audit,
                ),
            )

        runs = connection.execute("SELECT id, label FROM runs ORDER BY id").fetchall()
        for run in runs:
            raw_label = run["label"]
            if raw_label is None:
                continue
            connection.execute(
                "UPDATE runs SET label = ? WHERE id = ?",
                (run_label_fingerprint(str(raw_label)), int(run["id"])),
            )

        events = connection.execute(
            "SELECT id, event_type, data_json FROM audit_events ORDER BY id"
        ).fetchall()
        for event in events:
            raw_data = json.loads(str(event["data_json"]))
            if isinstance(raw_data, dict):
                event_endpoint_id = raw_data.get("endpoint_id")
                if isinstance(event_endpoint_id, int):
                    raw_data["endpoint_id"] = endpoint_id_map.get(
                        event_endpoint_id, event_endpoint_id
                    )
                raw_label = raw_data.get("label")
                if isinstance(raw_label, str):
                    raw_data["label"] = run_label_fingerprint(raw_label)
                try:
                    data_json = _json_document(raw_data)
                except (TypeError, ValueError):
                    data_json = _json_document({"error_code": ErrorCode.INVALID_RESPONSE.value})
            else:
                data_json = _json_document({"error_code": ErrorCode.INVALID_RESPONSE.value})
            try:
                event_type = _validate_audit_event_type(str(event["event_type"]))
            except ValueError:
                event_type = AuditEventType.LEGACY_EVENT_REDACTED
            connection.execute(
                "UPDATE audit_events SET event_type = ?, data_json = ? WHERE id = ?",
                (event_type.value, data_json, int(event["id"])),
            )

        trigger_statements = (
            "CREATE TRIGGER no_update_runs BEFORE UPDATE ON runs BEGIN "
            "SELECT RAISE(ABORT, 'runs are append-only'); END",
            "CREATE TRIGGER no_delete_runs BEFORE DELETE ON runs BEGIN "
            "SELECT RAISE(ABORT, 'runs are append-only'); END",
            "CREATE TRIGGER no_update_tested_combinations "
            "BEFORE UPDATE ON tested_combinations BEGIN "
            "SELECT RAISE(ABORT, 'tested combinations are append-only'); END",
            "CREATE TRIGGER no_delete_tested_combinations "
            "BEFORE DELETE ON tested_combinations BEGIN "
            "SELECT RAISE(ABORT, 'tested combinations are append-only'); END",
            "CREATE TRIGGER no_update_findings BEFORE UPDATE ON findings BEGIN "
            "SELECT RAISE(ABORT, 'findings are append-only'); END",
            "CREATE TRIGGER no_delete_findings BEFORE DELETE ON findings BEGIN "
            "SELECT RAISE(ABORT, 'findings are append-only'); END",
            "CREATE TRIGGER no_update_audit_events BEFORE UPDATE ON audit_events BEGIN "
            "SELECT RAISE(ABORT, 'audit events are append-only'); END",
            "CREATE TRIGGER no_delete_audit_events BEFORE DELETE ON audit_events BEGIN "
            "SELECT RAISE(ABORT, 'audit events are append-only'); END",
        )
        for statement in trigger_statements:
            connection.execute(statement)

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def schema_version(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT version FROM schema_version WHERE singleton = 1"
            ).fetchone()
        if row is None:  # pragma: no cover - protected by initialisation
            raise RuntimeError("database schema version was not initialised")
        return int(row["version"])

    # Endpoints and identities -------------------------------------------------

    def add_endpoint(self, template: str, method: str) -> int:
        with self._connection() as connection:
            return self._add_endpoint(connection, template, method)

    def _add_endpoint(self, connection: sqlite3.Connection, template: str, method: str) -> int:
        template = _validate_path(template)
        normalized_method = _validate_method(method)
        connection.execute(
            "INSERT INTO endpoints(template, method, first_seen_at) VALUES (?, ?, ?) "
            "ON CONFLICT(template, method) DO NOTHING",
            (template, normalized_method, self._now()),
        )
        row = connection.execute(
            "SELECT id FROM endpoints WHERE template = ? AND method = ?",
            (template, normalized_method),
        ).fetchone()
        if row is None:  # pragma: no cover - INSERT/select occurs in one transaction
            raise RuntimeError("endpoint could not be read after insertion")
        return int(row["id"])

    def add_identity(
        self,
        name: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        credential: CredentialRef | None = None,
        credential_ref_id: str | None = None,
    ) -> int:
        """Register an identity with an opaque credential fingerprint only."""

        name = _validate_identifier(name, field="identity name")
        if credential is not None and credential_ref_id is not None:
            raise ValueError(
                "provide a credential or an opaque credential reference identifier, not both"
            )
        if credential is not None:
            if credential.identity != name:
                raise ValueError("credential reference identity does not match identity name")
            credential_ref_id = credential_ref_fingerprint(credential)
        elif credential_ref_id is not None:
            credential_ref_id = _validate_opaque_credential_ref_id(credential_ref_id)
        metadata_json = _json_document(metadata or {})
        with self._connection() as connection:
            return self._add_identity(connection, name, metadata_json, credential_ref_id)

    def _add_identity(
        self,
        connection: sqlite3.Connection,
        name: str,
        metadata_json: str,
        credential_ref_id: str | None,
    ) -> int:
        connection.execute(
            "INSERT INTO identities(name, metadata_json, credential_ref_id, first_seen_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
            "credential_ref_id = COALESCE(identities.credential_ref_id, "
            "excluded.credential_ref_id)",
            (name, metadata_json, credential_ref_id, self._now()),
        )
        row = connection.execute("SELECT id FROM identities WHERE name = ?", (name,)).fetchone()
        if row is None:  # pragma: no cover - INSERT/select occurs in one transaction
            raise RuntimeError("identity could not be read after insertion")
        return int(row["id"])

    def list_identities(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, name, metadata_json, credential_ref_id, first_seen_at "
                "FROM identities ORDER BY id"
            ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "name": str(row["name"]),
                "metadata": json.loads(str(row["metadata_json"])),
                "credential_ref_id": row["credential_ref_id"],
                "first_seen_at": str(row["first_seen_at"]),
            }
            for row in rows
        ]

    def list_endpoints(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, template, method, first_seen_at FROM endpoints ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    # Ownership ---------------------------------------------------------------

    def add_ownership_evidence(self, evidence: OwnershipEvidence) -> int:
        """Atomically persist evidence, rejecting conflicting strong ownership."""

        normalized = self._validated_ownership_evidence(evidence)
        with self._connection() as connection:
            if normalized.confidence in _STRONG_OWNERSHIP_CONFIDENCES:
                connection.execute("BEGIN IMMEDIATE")
            identity_id = self._add_identity(connection, normalized.identity, "{}", None)
            endpoint_id = self._add_endpoint(
                connection, normalized.endpoint_template, normalized.method
            )
            self._raise_for_strong_ownership_conflict(connection, normalized, endpoint_id)
            evidence_id = self._insert_ownership_evidence(
                connection,
                identity_id,
                endpoint_id,
                normalized.object_id,
                normalized.confidence,
                normalized.source,
            )
            audit_json = _json_document(
                {
                    "identity": normalized.identity,
                    "endpoint_id": endpoint_id,
                    "object_id": normalized.object_id,
                    "confidence": normalized.confidence.value,
                    "source": normalized.source,
                }
            )
            self._add_audit_event(
                connection, AuditEventType.OWNERSHIP_EVIDENCE_PERSISTED, audit_json, None
            )
            return evidence_id

    def persist_ownership_evidence(self, evidence: OwnershipEvidence) -> int:
        """Alias for phase integrations that name the atomic ownership operation explicitly."""

        return self.add_ownership_evidence(evidence)

    @staticmethod
    def _validated_ownership_evidence(evidence: OwnershipEvidence) -> OwnershipEvidence:
        object_ref_fingerprint(evidence.object_id)
        return OwnershipEvidence(
            identity=_validate_identifier(evidence.identity, field="ownership identity"),
            endpoint_template=_validate_path(evidence.endpoint_template),
            method=_validate_method(evidence.method),
            object_id=evidence.object_id,
            confidence=evidence.confidence,
            source=_validate_source(evidence.source),
        )

    def add_owned_object(
        self,
        identity_id: int,
        endpoint_id: int,
        object_id: str,
        *,
        confidence: OwnershipConfidence,
        source: str,
    ) -> int:
        """Store ownership by ids while applying the same strong-conflict rule."""

        with self._connection() as connection:
            if confidence in _STRONG_OWNERSHIP_CONFIDENCES:
                connection.execute("BEGIN IMMEDIATE")
            candidate = self._ownership_evidence_from_ids(
                connection, identity_id, endpoint_id, object_id, confidence, source
            )
            self._raise_for_strong_ownership_conflict(connection, candidate, endpoint_id)
            evidence_id = self._insert_ownership_evidence(
                connection, identity_id, endpoint_id, object_id, confidence, source
            )
            audit_json = _json_document(
                {
                    "identity": candidate.identity,
                    "endpoint_id": endpoint_id,
                    "object_id": candidate.object_id,
                    "confidence": confidence.value,
                    "source": candidate.source,
                }
            )
            self._add_audit_event(
                connection, AuditEventType.OWNERSHIP_EVIDENCE_PERSISTED, audit_json, None
            )
            return evidence_id

    def _ownership_evidence_from_ids(
        self,
        connection: sqlite3.Connection,
        identity_id: int,
        endpoint_id: int,
        object_id: str,
        confidence: OwnershipConfidence,
        source: str,
    ) -> OwnershipEvidence:
        object_ref_fingerprint(object_id)
        source = _validate_source(source)
        row = connection.execute(
            "SELECT identity.name, endpoint.template, endpoint.method "
            "FROM identities AS identity JOIN endpoints AS endpoint "
            "WHERE identity.id = ? AND endpoint.id = ?",
            (identity_id, endpoint_id),
        ).fetchone()
        if row is None:
            # The following insert gives callers the native FK failure they expect.
            return OwnershipEvidence(
                identity="missing",
                endpoint_template="/missing",
                method="GET",
                object_id=object_id,
                confidence=confidence,
                source=source,
            )
        return OwnershipEvidence(
            identity=str(row["name"]),
            endpoint_template=str(row["template"]),
            method=str(row["method"]),
            object_id=object_id,
            confidence=confidence,
            source=source,
        )

    def _raise_for_strong_ownership_conflict(
        self,
        connection: sqlite3.Connection,
        candidate: OwnershipEvidence,
        endpoint_id: int,
    ) -> None:
        if candidate.confidence not in _STRONG_OWNERSHIP_CONFIDENCES:
            return
        rows = connection.execute(
            "SELECT identity.name, endpoint.template, endpoint.method, ownership.object_ref, "
            "ownership.confidence, ownership.source "
            "FROM ownership_evidence AS ownership "
            "JOIN identities AS identity ON identity.id = ownership.identity_id "
            "JOIN endpoints AS endpoint ON endpoint.id = ownership.endpoint_id "
            "WHERE ownership.endpoint_id = ? AND ownership.object_ref = ? "
            "AND ownership.confidence IN (?, ?, ?) AND identity.name != ? "
            "ORDER BY ownership.id",
            (
                endpoint_id,
                object_ref_fingerprint(candidate.object_id),
                OwnershipConfidence.EXPLICIT.value,
                OwnershipConfidence.OBSERVED_CREATE.value,
                OwnershipConfidence.RESPONSE_MATCH.value,
                candidate.identity,
            ),
        ).fetchall()
        if rows:
            existing = tuple(
                OwnershipEvidence(
                    identity=str(row["name"]),
                    endpoint_template=str(row["template"]),
                    method=str(row["method"]),
                    object_id=str(row["object_ref"]),
                    confidence=OwnershipConfidence(str(row["confidence"])),
                    source=str(row["source"]),
                )
                for row in rows
            )
            raise OwnershipConflictError(candidate, existing)

    def _insert_ownership_evidence(
        self,
        connection: sqlite3.Connection,
        identity_id: int,
        endpoint_id: int,
        object_id: str,
        confidence: OwnershipConfidence,
        source: str,
    ) -> int:
        object_id = object_ref_fingerprint(object_id)
        connection.execute(
            "INSERT INTO ownership_evidence("
            "identity_id, endpoint_id, object_ref, confidence, source, recorded_at"
            ") VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(identity_id, endpoint_id, object_ref, confidence, source) DO NOTHING",
            (identity_id, endpoint_id, object_id, confidence.value, source, self._now()),
        )
        row = connection.execute(
            "SELECT id FROM ownership_evidence WHERE "
            "identity_id = ? AND endpoint_id = ? AND object_ref = ? "
            "AND confidence = ? AND source = ?",
            (identity_id, endpoint_id, object_id, confidence.value, source),
        ).fetchone()
        if row is None:  # pragma: no cover - INSERT/select occurs in one transaction
            raise RuntimeError("ownership evidence could not be read after insertion")
        return int(row["id"])

    def objects_owned_by(self, identity_id: int, endpoint_id: int) -> list[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT object_ref FROM ownership_evidence "
                "WHERE identity_id = ? AND endpoint_id = ? ORDER BY object_ref",
                (identity_id, endpoint_id),
            ).fetchall()
        return [str(row["object_ref"]) for row in rows]

    def ownership_evidence_for(
        self, endpoint_template: str, method: str, object_id: str
    ) -> list[OwnershipEvidence]:
        """Return persisted ownership evidence for one concrete endpoint object."""

        endpoint_template = _validate_path(endpoint_template)
        method = _validate_method(method)
        object_id = object_ref_fingerprint(object_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT identity.name, endpoint.template, endpoint.method, ownership.object_ref, "
                "ownership.confidence, ownership.source "
                "FROM ownership_evidence AS ownership "
                "JOIN identities AS identity ON identity.id = ownership.identity_id "
                "JOIN endpoints AS endpoint ON endpoint.id = ownership.endpoint_id "
                "WHERE endpoint.template = ? AND endpoint.method = ? AND ownership.object_ref = ? "
                "ORDER BY ownership.id",
                (endpoint_template, method, object_id),
            ).fetchall()
        return [
            OwnershipEvidence(
                identity=str(row["name"]),
                endpoint_template=str(row["template"]),
                method=str(row["method"]),
                object_id=str(row["object_ref"]),
                confidence=OwnershipConfidence(str(row["confidence"])),
                source=str(row["source"]),
            )
            for row in rows
        ]

    # Runs, attempts, and pending work ----------------------------------------

    def start_run(
        self, label: str | None = None, *, metadata: Mapping[str, Any] | None = None
    ) -> int:
        label_ref = run_label_fingerprint(label) if label is not None else None
        metadata_json = _json_document(metadata or {})
        event_json = _json_document({"label": label_ref})
        with self._connection() as connection:
            cursor = connection.execute(
                "INSERT INTO runs(started_at, label, metadata_json) VALUES (?, ?, ?)",
                (self._now(), label_ref, metadata_json),
            )
            run_id = _inserted_id(cursor)
            self._add_audit_event(connection, AuditEventType.RUN_STARTED, event_json, run_id)
            return run_id

    def record_probe_result(self, result: ProbeResult, *, run_id: int | None = None) -> int:
        """Append an attempt made by the deterministic executor.

        A retryable inconclusive attempt remains pending.  Only successful
        ``protected`` and ``bola`` attempts make the combination final.
        """

        target = result.target
        if target.owner_credential.identity != target.owner_identity:
            raise ValueError("credential reference identity does not match probe target identity")
        if target.attacker_credential.identity != target.attacker_identity:
            raise ValueError("credential reference identity does not match probe target identity")
        _validate_identifier(target.owner_identity, field="probe owner identity")
        _validate_identifier(target.attacker_identity, field="probe attacker identity")
        object_ref_fingerprint(target.object_id)
        owner_credential_ref_id = credential_ref_fingerprint(target.owner_credential)
        attacker_credential_ref_id = credential_ref_fingerprint(target.attacker_credential)
        evidence = redact_evidence(result.evidence)

        with self._connection() as connection:
            endpoint_id = self._add_endpoint(connection, target.endpoint_template, target.method)
            owner_id = self._add_identity(
                connection, target.owner_identity, "{}", owner_credential_ref_id
            )
            attacker_id = self._add_identity(
                connection, target.attacker_identity, "{}", attacker_credential_ref_id
            )
            attempt_id = self._record_attempt(
                connection,
                endpoint_id,
                owner_id,
                attacker_id,
                target.object_id,
                result.verdict.value,
                result.retryable,
                run_id,
            )
            audit_json = _json_document(
                {
                    "attempt_id": attempt_id,
                    "endpoint_id": endpoint_id,
                    "owner_identity_id": owner_id,
                    "attacker_identity_id": attacker_id,
                    "object_id": target.object_id,
                    "status": result.verdict.value,
                    "retryable": result.retryable,
                    "evidence": evidence,
                }
            )
            self._add_audit_event(
                connection, AuditEventType.PROBE_ATTEMPT_RECORDED, audit_json, run_id
            )
            return attempt_id

    def mark_tested(
        self,
        endpoint_id: int,
        owner_identity_id: int,
        attacker_identity_id: int,
        object_id: str,
        *,
        status: Literal["bola", "protected", "inconclusive", "skipped"],
        retryable: bool = False,
        run_id: int | None = None,
    ) -> int:
        """Append an explicit attempt for callers that have no ``ProbeResult``."""

        with self._connection() as connection:
            attempt_id = self._record_attempt(
                connection,
                endpoint_id,
                owner_identity_id,
                attacker_identity_id,
                object_id,
                status,
                retryable,
                run_id,
            )
            audit_json = _json_document(
                {"attempt_id": attempt_id, "status": status, "retryable": retryable}
            )
            self._add_audit_event(
                connection, AuditEventType.PROBE_ATTEMPT_RECORDED, audit_json, run_id
            )
            return attempt_id

    def _record_attempt(
        self,
        connection: sqlite3.Connection,
        endpoint_id: int,
        owner_identity_id: int,
        attacker_identity_id: int,
        object_id: str,
        status: str,
        retryable: bool,
        run_id: int | None,
    ) -> int:
        if status not in {verdict.value for verdict in Verdict}:
            raise ValueError(f"unknown probe status: {status}")
        object_id = object_ref_fingerprint(object_id)
        cursor = connection.execute(
            "INSERT INTO tested_combinations("
            "endpoint_id, owner_identity_id, attacker_identity_id, object_ref, "
            "attempt_status, retryable, attempted_at, run_id"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                endpoint_id,
                owner_identity_id,
                attacker_identity_id,
                object_id,
                status,
                int(retryable),
                self._now(),
                run_id,
            ),
        )
        return _inserted_id(cursor)

    def has_been_tested(
        self,
        endpoint_id: int,
        owner_identity_id: int,
        attacker_identity_id: int,
        object_id: str,
    ) -> bool:
        """Return whether a successful terminal attempt exists for this tuple."""

        object_id = object_ref_fingerprint(object_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM tested_combinations WHERE "
                "endpoint_id = ? AND owner_identity_id = ? AND attacker_identity_id = ? "
                "AND object_ref = ? AND retryable = 0 AND attempt_status IN (?, ?) LIMIT 1",
                (
                    endpoint_id,
                    owner_identity_id,
                    attacker_identity_id,
                    object_id,
                    *_FINAL_ATTEMPT_STATUSES,
                ),
            ).fetchone()
        return row is not None

    def untested_combinations(self) -> list[PendingCombination]:
        """Return strong-evidence pairs lacking a terminal attempt.

        Heuristic/requester-only evidence remains useful as provenance, but it
        must never enter the executable pending matrix.  Keeping this filter in
        the state boundary protects direct callers that bypass endpoint
        correlation's in-memory confidence gate.
        """

        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT ownership.endpoint_id, "
                "ownership.identity_id AS owner_identity_id, "
                "attacker.id AS attacker_identity_id, ownership.object_ref "
                "FROM ownership_evidence AS ownership "
                "JOIN identities AS attacker ON attacker.id != ownership.identity_id "
                "WHERE ownership.confidence IN (?, ?, ?) "
                "AND NOT EXISTS ("
                "SELECT 1 FROM tested_combinations AS attempt "
                "WHERE attempt.endpoint_id = ownership.endpoint_id "
                "AND attempt.owner_identity_id = ownership.identity_id "
                "AND attempt.attacker_identity_id = attacker.id "
                "AND attempt.object_ref = ownership.object_ref "
                "AND attempt.retryable = 0 "
                "AND attempt.attempt_status IN ('bola', 'protected')"
                ") ORDER BY ownership.endpoint_id, ownership.identity_id, attacker.id, "
                "ownership.object_ref",
                _EXECUTABLE_OWNERSHIP_VALUES,
            ).fetchall()
        return [
            PendingCombination(
                endpoint_id=int(row["endpoint_id"]),
                owner_identity_id=int(row["owner_identity_id"]),
                attacker_identity_id=int(row["attacker_identity_id"]),
                object_ref=str(row["object_ref"]),
            )
            for row in rows
        ]

    # Findings and audit trail -------------------------------------------------

    @overload
    def add_finding(self, finding: Finding, /) -> int: ...

    @overload
    def add_finding(
        self,
        endpoint_id: int,
        severity: str,
        description: str,
        evidence: Mapping[str, Any],
        /,
        *,
        title: str = "BOLA finding",
    ) -> int: ...

    def add_finding(
        self,
        finding: Finding | int,
        severity: str | None = None,
        description: str | None = None,
        evidence: Mapping[str, Any] | None = None,
        *,
        title: str = "BOLA finding",
    ) -> int:
        """Append a finding once without accepting caller-controlled report text."""

        if isinstance(finding, Finding):
            finding_severity = _validate_finding_severity(finding.severity)
            finding_evidence = finding.evidence
            finding_title, finding_description = canonical_finding_text(
                severity=finding_severity,
                endpoint_template=finding.endpoint_template,
                method=finding.method,
                evidence=finding_evidence,
            )
            if finding.title != finding_title or finding.description != finding_description:
                raise ValueError("finding title and description must use canonical state text")
            endpoint_id = self.add_endpoint(finding.endpoint_template, finding.method)
        else:
            if severity is None or description is None or evidence is None:
                raise TypeError("legacy add_finding requires severity, description, and evidence")
            endpoint_id = finding
            finding_severity = _validate_finding_severity(severity)
            finding_evidence = evidence
            with self._connection() as connection:
                endpoint = connection.execute(
                    "SELECT template, method FROM endpoints WHERE id = ?", (endpoint_id,)
                ).fetchone()
            if endpoint is None:
                raise ValueError("finding endpoint does not exist")
            finding_title, finding_description = canonical_finding_text(
                severity=finding_severity,
                endpoint_template=str(endpoint["template"]),
                method=str(endpoint["method"]),
                evidence=finding_evidence,
            )
            if title != finding_title or description != finding_description:
                raise ValueError("finding title and description must use canonical state text")

        evidence_json = _json_document(finding_evidence)
        evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO findings("
                "endpoint_id, severity, title, description, evidence_json, evidence_hash, found_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(endpoint_id, severity, title, description, evidence_hash) DO NOTHING",
                (
                    endpoint_id,
                    finding_severity,
                    finding_title,
                    finding_description,
                    evidence_json,
                    evidence_hash,
                    self._now(),
                ),
            )
            row = connection.execute(
                "SELECT id FROM findings WHERE "
                "endpoint_id = ? AND severity = ? AND title = ? AND description = ? "
                "AND evidence_hash = ?",
                (endpoint_id, finding_severity, finding_title, finding_description, evidence_hash),
            ).fetchone()
        if row is None:  # pragma: no cover - INSERT/select occurs in one transaction
            raise RuntimeError("finding could not be read after insertion")
        return int(row["id"])

    def list_findings(self) -> list[Finding]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT endpoint.template, endpoint.method, finding.severity, finding.title, "
                "finding.description, finding.evidence_json "
                "FROM findings AS finding "
                "JOIN endpoints AS endpoint ON endpoint.id = finding.endpoint_id "
                "ORDER BY finding.id"
            ).fetchall()
        return [
            Finding(
                endpoint_template=str(row["template"]),
                method=str(row["method"]),
                severity=str(row["severity"]),
                title=str(row["title"]),
                description=str(row["description"]),
                evidence=json.loads(str(row["evidence_json"])),
            )
            for row in rows
        ]

    def add_audit_event(
        self,
        event_type: AuditEventType,
        data: Mapping[str, Any],
        *,
        run_id: int | None = None,
    ) -> int:
        validated_event_type = _validate_audit_event_type(event_type)
        data_json = _json_document(data)
        with self._connection() as connection:
            return self._add_audit_event(connection, validated_event_type, data_json, run_id)

    def _add_audit_event(
        self,
        connection: sqlite3.Connection,
        event_type: AuditEventType,
        data_json: str,
        run_id: int | None,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO audit_events(event_type, occurred_at, run_id, data_json) "
            "VALUES (?, ?, ?, ?)",
            (event_type.value, self._now(), run_id, data_json),
        )
        return _inserted_id(cursor)

    def list_audit_events(self) -> list[AuditEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, event_type, occurred_at, run_id, data_json "
                "FROM audit_events ORDER BY id"
            ).fetchall()
        return [
            AuditEvent(
                id=int(row["id"]),
                event_type=self._listed_audit_event_type(str(row["event_type"])),
                occurred_at=str(row["occurred_at"]),
                run_id=int(row["run_id"]) if row["run_id"] is not None else None,
                data=json.loads(str(row["data_json"])),
            )
            for row in rows
        ]

    @staticmethod
    def _listed_audit_event_type(value: str) -> AuditEventType:
        """Redact unknown names left by pre-closed-enum databases on read."""

        try:
            return AuditEventType(value)
        except ValueError:
            return AuditEventType.LEGACY_EVENT_REDACTED
