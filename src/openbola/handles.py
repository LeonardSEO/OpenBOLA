"""Opaque, non-semantic handles for secrets and in-session values.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Handle ids are random (``secrets.token_urlsafe``), never derived from the
value or its purpose/kind, so a handle leaked into persisted state, a
report, or an AI provider payload carries no information about what it
refers to. Only the process holding the registry that minted a handle can
resolve it, and only immediately before a policy-approved operation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from threading import RLock
from typing import Literal, NoReturn, Protocol, SupportsIndex, runtime_checkable

ValueKind = Literal["record_id", "field_value", "body", "session_state"]
_VALUE_KINDS: frozenset[str] = frozenset({"record_id", "field_value", "body", "session_state"})


@dataclass(frozen=True)
class SecretHandle:
    id: str
    purpose: str


@dataclass(frozen=True)
class ValueHandle:
    id: str
    kind: ValueKind

    def __post_init__(self) -> None:
        if self.kind not in _VALUE_KINDS:
            raise ValueError(f"Unknown ValueHandle kind: {self.kind!r}")


class SessionValueRegistry(Protocol):
    def resolve_secret(self, handle: SecretHandle) -> str: ...
    def resolve_value(self, handle: ValueHandle) -> object: ...


@runtime_checkable
class SessionValueStore(SessionValueRegistry, Protocol):
    """Process-local registry capability required by full-fidelity capture."""

    def store_value(self, *, kind: ValueKind, value: object) -> ValueHandle: ...
    def close(self) -> None: ...


def _random_id() -> str:
    token = secrets.token_urlsafe(32)
    # ``token_urlsafe`` may begin with ``-`` or ``_``.  Handle bindings use a
    # conservative opaque-token grammar whose first character must be
    # alphanumeric, so normalize only that leading character without deriving
    # the identifier from its value, purpose, or kind.
    return token if token[0].isalnum() else f"h{token}"


class InMemorySessionValueRegistry:
    """Process-local registry minting random handles for secrets and values.

    Never serializable: state is destroyed when the process exits, matching
    the spec's requirement that full values are absent from every persisted
    artifact after the session ends.
    """

    __slots__ = ("_secrets", "_values", "_lock", "_closed")

    def __init__(self) -> None:
        self._secrets: dict[str, tuple[str, str]] = {}
        self._values: dict[str, tuple[ValueKind, object]] = {}
        self._lock = RLock()
        self._closed = False

    def __reduce__(self) -> NoReturn:
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise TypeError("SessionValueRegistry serialization is disabled.")

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("session value registry is closed")

    def close(self) -> None:
        with self._lock:
            self._secrets.clear()
            self._values.clear()
            self._closed = True

    def store_secret(self, *, purpose: str, value: str) -> SecretHandle:
        with self._lock:
            self._require_open()
            handle_id = _random_id()
            self._secrets[handle_id] = (purpose, value)
        return SecretHandle(id=handle_id, purpose=purpose)

    def store_value(self, *, kind: ValueKind, value: object) -> ValueHandle:
        with self._lock:
            self._require_open()
            handle_id = _random_id()
            self._values[handle_id] = (kind, value)
        return ValueHandle(id=handle_id, kind=kind)

    def resolve_secret(self, handle: SecretHandle) -> str:
        with self._lock:
            self._require_open()
            entry = self._secrets.get(handle.id)
        if entry is None or entry[0] != handle.purpose:
            raise LookupError("Secret handle cannot be resolved.")
        return entry[1]

    def resolve_value(self, handle: ValueHandle) -> object:
        with self._lock:
            self._require_open()
            entry = self._values.get(handle.id)
        if entry is None or entry[0] != handle.kind:
            raise LookupError("Value handle cannot be resolved.")
        return entry[1]
