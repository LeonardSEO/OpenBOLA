from __future__ import annotations

import json
import pickle
from concurrent.futures import ThreadPoolExecutor

import pytest

from bola_checker.credentials import CredentialResolutionError, CredentialVault, _SecretValue
from bola_checker.models import CredentialKind, CredentialRef


def test_stores_and_resolves_typed_credentials_without_representing_secret() -> None:
    vault = CredentialVault()
    credential = vault.store(
        identity="alice",
        kind=CredentialKind.HEADER,
        name="X-API-Key",
        secret="private-api-value",  # noqa: S105, S106 - regression test credential material
    )

    assert vault.resolve(credential) == "private-api-value"
    assert "private-api-value" not in repr(vault)
    assert "private-api-value" not in repr(vault._credentials)  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        json.dumps(vault._credentials)  # type: ignore[attr-defined]
    assert credential.secret_ref.startswith("vault:hmac-sha256:")


def test_resolve_rejects_a_reference_retyped_as_another_transport() -> None:
    vault = CredentialVault()
    credential = vault.store(
        identity="alice",
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret="bearer-token-value",  # noqa: S105, S106 - regression test credential material
    )
    mismatched = CredentialRef(
        identity=credential.identity,
        kind=CredentialKind.COOKIE,
        name="session",
        secret_ref=credential.secret_ref,
    )

    with pytest.raises(CredentialResolutionError) as error:
        vault.resolve(mismatched)

    assert "bearer-token-value" not in str(error.value)


def test_same_value_can_be_stored_for_separate_identities() -> None:
    vault = CredentialVault()
    alice = vault.store(
        identity="alice",
        kind=CredentialKind.HEADER,
        name="X-API-Key",
        secret="shared-api-value",  # noqa: S105, S106 - regression test credential material
    )
    bob = vault.store(
        identity="bob",
        kind=CredentialKind.HEADER,
        name="X-API-Key",
        secret="shared-api-value",  # noqa: S105, S106 - regression test credential material
    )

    assert alice.secret_ref == bob.secret_ref
    assert vault.resolve(alice) == "shared-api-value"
    assert vault.resolve(bob) == "shared-api-value"


def test_resolves_environment_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOLA_ALICE_TOKEN", "environment-token-value")
    vault = CredentialVault()
    credential = vault.environment_reference(
        identity="alice",
        kind=CredentialKind.BEARER,
        name="Authorization",
        variable="BOLA_ALICE_TOKEN",
    )

    assert vault.resolve(credential) == "environment-token-value"
    assert "environment-token-value" not in repr(credential)


def test_rejects_unregistered_environment_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOLA_ARBITRARY_TOKEN", "arbitrary-environment-value")
    vault = CredentialVault()
    credential = CredentialRef(
        identity="alice",
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret_ref="env:BOLA_ARBITRARY_TOKEN",  # noqa: S106 - reference, not a value
    )

    with pytest.raises(CredentialResolutionError) as error:
        vault.resolve(credential)

    assert "arbitrary-environment-value" not in str(error.value)


def test_missing_environment_secret_has_a_generic_error() -> None:
    vault = CredentialVault()
    credential = CredentialRef(
        identity="alice",
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret_ref="env:BOLA_MISSING_SECRET",  # noqa: S106 - reference, not a value
    )

    with pytest.raises(CredentialResolutionError) as error:
        vault.resolve(credential)

    assert "BOLA_MISSING_SECRET" not in str(error.value)


def test_blocks_pickling_without_leaking_credential_material() -> None:
    sentinel = "pickle-sentinel-secret"
    vault = CredentialVault()
    vault.store(
        identity="alice",
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret=sentinel,  # noqa: S105, S106 - regression test credential material
    )

    for protected_value in (vault, _SecretValue(sentinel)):
        with pytest.raises(TypeError) as error:
            pickle.dumps(protected_value)
        assert sentinel not in str(error.value)

    with pytest.raises(TypeError) as error:
        vault.__getstate__()
    assert sentinel not in str(error.value)


def test_vault_store_and_resolve_are_safe_across_threads() -> None:
    vault = CredentialVault()

    def store_and_resolve(index: int) -> str:
        value = f"thread-value-{index}"
        reference = vault.store(
            identity=f"identity-{index}",
            kind=CredentialKind.HEADER,
            name="X-API-Key",
            secret=value,
        )
        return vault.resolve(reference)

    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(store_and_resolve, range(32)))

    assert values == [f"thread-value-{index}" for index in range(32)]
