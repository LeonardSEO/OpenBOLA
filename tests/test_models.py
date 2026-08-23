from bola_checker.models import CredentialKind, CredentialRef


def test_credential_ref_repr_does_not_contain_secret_value() -> None:
    credential = CredentialRef(
        identity="alice",
        kind=CredentialKind.BEARER,
        name="Authorization",
        secret_ref="env:BOLA_TOKEN_ALICE",  # noqa: S106 - reference, not a secret
    )

    assert "token-value" not in repr(credential)
    assert credential.secret_ref == "env:BOLA_TOKEN_ALICE"  # noqa: S105
