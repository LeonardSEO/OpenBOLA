from __future__ import annotations

import pytest

from openbola.handles import (
    InMemorySessionValueRegistry,
    SecretHandle,
    ValueHandle,
)


def test_secret_handle_is_frozen_and_non_semantic() -> None:
    handle = SecretHandle(id="abc123", purpose="login_password")
    with pytest.raises(AttributeError):
        handle.id = "changed"  # type: ignore[misc]


def test_value_handle_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="kind"):
        ValueHandle(id="abc123", kind="not_a_real_kind")  # type: ignore[arg-type]


def test_registry_stores_secret_and_returns_random_handle() -> None:
    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="login_password", value="hunter2")
    assert isinstance(handle, SecretHandle)
    assert handle.purpose == "login_password"
    assert registry.resolve_secret(handle) == "hunter2"


def test_registry_secret_handle_ids_are_random_and_non_semantic() -> None:
    registry = InMemorySessionValueRegistry()
    first = registry.store_secret(purpose="login_password", value="hunter2")
    second = registry.store_secret(purpose="login_password", value="hunter2")
    assert first.id != second.id
    assert "hunter2" not in first.id
    assert "login_password" not in first.id


def test_registry_stores_value_and_returns_random_handle() -> None:
    registry = InMemorySessionValueRegistry()
    handle = registry.store_value(kind="record_id", value=42)
    assert isinstance(handle, ValueHandle)
    assert handle.kind == "record_id"
    assert registry.resolve_value(handle) == 42


def test_registry_resolve_secret_unknown_handle_raises() -> None:
    registry = InMemorySessionValueRegistry()
    stray = SecretHandle(id="never-stored", purpose="login_password")
    with pytest.raises(LookupError):
        registry.resolve_secret(stray)


def test_registry_resolve_value_unknown_handle_raises() -> None:
    registry = InMemorySessionValueRegistry()
    stray = ValueHandle(id="never-stored", kind="record_id")
    with pytest.raises(LookupError):
        registry.resolve_value(stray)


def test_registry_is_not_serializable() -> None:
    import pickle

    registry = InMemorySessionValueRegistry()
    registry.store_secret(purpose="login_password", value="hunter2")
    with pytest.raises(TypeError):
        pickle.dumps(registry)
