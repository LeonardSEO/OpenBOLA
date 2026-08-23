"""In-memory credential handling for the execution boundary.

Credential values deliberately have no serialisation API.  Callers retain a
``CredentialRef`` in durable state and resolve it only immediately before an
authorised request is constructed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from threading import RLock
from typing import Final, NoReturn, SupportsIndex

from bola_checker.models import CredentialKind, CredentialRef

_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PROCESS_FINGERPRINT_KEY: Final = secrets.token_bytes(32)


class CredentialResolutionError(LookupError):
    """Raised without including credential material when a reference is unavailable."""


class _SecretValue:
    """A non-representable wrapper around a credential value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<redacted credential>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Credential value serialization is disabled.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("Credential value serialization is disabled.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Credential value serialization is disabled.")

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise TypeError("Credential value serialization is disabled.")


def fingerprint_secret(value: str | bytes) -> str:
    """Return a process-local HMAC-SHA-256 correlation fingerprint.

    The random key is created once per process and is neither exposed nor
    persisted, so the fingerprint cannot be used as a cross-run identifier or
    to recover the input value.
    """

    value_bytes = value.encode("utf-8") if isinstance(value, str) else value
    digest = hmac.new(_PROCESS_FINGERPRINT_KEY, value_bytes, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


class CredentialVault:
    """Holds credentials in memory and resolves only typed references.

    ``store`` keeps a raw value in this process and returns an opaque,
    fingerprint-backed reference. ``environment_reference`` makes no copy of
    an environment value; its ``env:NAME`` reference is resolved at use time.
    """

    __slots__ = ("_credentials", "_environment_references", "_lock")

    def __init__(self) -> None:
        self._credentials: dict[
            str, dict[tuple[str, CredentialKind, str], _SecretValue]
        ] = {}
        self._environment_references: set[CredentialRef] = set()
        self._lock = RLock()

    def __repr__(self) -> str:
        with self._lock:
            entry_count = sum(len(entries) for entries in self._credentials.values())
        return f"CredentialVault(entries={entry_count})"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Credential vault serialization is disabled.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("Credential vault serialization is disabled.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Credential vault serialization is disabled.")

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise TypeError("Credential vault serialization is disabled.")

    def store(
        self,
        *,
        identity: str,
        kind: CredentialKind,
        name: str,
        secret: str,
    ) -> CredentialRef:
        """Store one credential and return a safe reference to it."""

        if not identity or not name or not secret:
            raise ValueError("Credential identity, name, and value must be non-empty.")

        secret_ref = f"vault:{fingerprint_secret(secret)}"
        key = (identity, kind, name)
        with self._lock:
            self._credentials.setdefault(secret_ref, {})[key] = _SecretValue(secret)
        return CredentialRef(identity=identity, kind=kind, name=name, secret_ref=secret_ref)

    def environment_reference(
        self,
        *,
        identity: str,
        kind: CredentialKind,
        name: str,
        variable: str,
    ) -> CredentialRef:
        """Create a reference whose value will be read from an environment variable."""

        if not identity or not name or not _ENVIRONMENT_NAME.fullmatch(variable):
            raise ValueError("Credential identity, name, and environment variable are invalid.")
        reference = CredentialRef(
            identity=identity,
            kind=kind,
            name=name,
            secret_ref=f"env:{variable}",
        )
        return self.register_env_ref(reference)

    def register_env_ref(self, reference: CredentialRef) -> CredentialRef:
        """Register a validated environment reference with this vault instance."""

        variable = reference.secret_ref.removeprefix("env:")
        if (
            not reference.identity
            or not reference.name
            or not reference.secret_ref.startswith("env:")
            or not _ENVIRONMENT_NAME.fullmatch(variable)
        ):
            raise ValueError("Credential environment reference is invalid.")
        with self._lock:
            self._environment_references.add(reference)
        return reference

    def resolve(self, reference: CredentialRef) -> str:
        """Resolve a typed reference without logging or serialising its value."""

        if reference.secret_ref.startswith("env:"):
            variable = reference.secret_ref.removeprefix("env:")
            with self._lock:
                registered = reference in self._environment_references
            if not registered or not _ENVIRONMENT_NAME.fullmatch(variable):
                raise CredentialResolutionError("Credential reference cannot be resolved.")
            value = os.environ.get(variable)
            if not value:
                raise CredentialResolutionError("Credential reference cannot be resolved.")
            return value

        key = (reference.identity, reference.kind, reference.name)
        with self._lock:
            stored = self._credentials.get(reference.secret_ref, {}).get(key)
        if stored is None:
            raise CredentialResolutionError("Credential reference cannot be resolved.")
        return stored.reveal()
