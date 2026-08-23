from __future__ import annotations

import base64
import json
from dataclasses import asdict

import pytest

from bola_checker.credentials import CredentialVault
from bola_checker.extract import decode_jwt_payload, extract_requests
from bola_checker.models import CredentialKind, RequestRecord


def _jwt(payload: dict[str, str]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{encoded}.signature"


def test_extracts_bearer_header_and_cookie_from_requests_only() -> None:
    token = _jwt({"sub": "alice-subject"})
    record = RequestRecord(
        identity="alice",
        method="GET",
        url="https://example.test/orders/1",
        headers={
            "Authorization": f"Bearer {token}",
            "X-API-Key": "request-api-value",  # noqa: S105 - regression test credential material
            "Cookie": "session=request-cookie-value; theme=light",
        },
        response_headers={"Authorization": "Bearer response-token-value"},
        response_body=b'{"access_token":"response-body-token-value"}',
    )
    vault = CredentialVault()

    result = extract_requests([record], vault)

    assert [(reference.kind, reference.name) for reference in result.credential_refs] == [
        (CredentialKind.BEARER, "Authorization"),
        (CredentialKind.HEADER, "X-API-Key"),
        (CredentialKind.COOKIE, "session"),
        (CredentialKind.COOKIE, "theme"),
    ]
    assert [vault.resolve(reference) for reference in result.credential_refs] == [
        token,
        "request-api-value",
        "request-cookie-value",
        "light",
    ]
    assert result.identity_hints[0].claim == "sub"
    assert result.identity_hints[0].value == "alice-subject"
    assert result.identity_hints[0].signature_verified is False
    assert len(result.body_secret_warnings) == 1
    assert result.body_secret_warnings[0].location == "response_body"


def test_bearer_normalization_removes_repeated_prefixes() -> None:
    record = RequestRecord(
        identity="alice",
        method="GET",
        url="https://example.test/me",
        headers={"Authorization": "Bearer Bearer opaque-token-value"},
    )
    vault = CredentialVault()

    result = extract_requests([record], vault)

    assert len(result.credential_refs) == 1
    assert vault.resolve(result.credential_refs[0]) == "opaque-token-value"


def test_malformed_jwt_is_not_a_hint_or_an_error() -> None:
    malformed = "eyJhbGciOiJub25lIn0.not-valid-json.signature"
    record = RequestRecord(
        identity="alice",
        method="GET",
        url="https://example.test/me",
        headers={"Authorization": f"Bearer {malformed}"},
    )

    result = extract_requests([record], CredentialVault())

    assert decode_jwt_payload(malformed) is None
    assert result.identity_hints == ()
    assert len(result.credential_refs) == 1


def test_persistent_result_never_contains_request_or_response_secret_values() -> None:
    value = "highly-sensitive-request-value"
    record = RequestRecord(
        identity="alice",
        method="POST",
        url=(
            "https://example.test/orders?access_token=url-access-token-sentinel&filter=active&"
            "api-key=url-api-key-sentinel&accessToken=url-camel-token-sentinel&"
            "X-API-Key=x-api-key-sentinel&X-Auth-Token=x-auth-token-sentinel&"
            "X-Access-Token=x-access-token-sentinel&X-Session-Token=x-session-token-sentinel&"
            "x_api_key=x-underscore-api-key-sentinel&"
            "x%2Dauth%2Dtoken=x-percent-auth-token-sentinel&"
            "X%5FACCESS%5FTOKEN=x-percent-access-token-sentinel&"
            "x_session_token=x-underscore-session-token-sentinel#url-fragment-sentinel"
        ),
        headers={"Authorization": f"Bearer {value}"},
        body=b'{"client_secret":"highly-sensitive-body-value"}',
        response_headers={"X-Access-Token": "highly-sensitive-response-value"},
        response_body=b'{"access_token":"highly-sensitive-response-body-value"}',
    )

    result = extract_requests([record], CredentialVault())
    serialised = json.dumps(asdict(result), sort_keys=True)

    for secret in (
        value,
        "highly-sensitive-body-value",
        "highly-sensitive-response-value",
        "highly-sensitive-response-body-value",
        "url-access-token-sentinel",
        "url-api-key-sentinel",
        "url-camel-token-sentinel",
        "x-api-key-sentinel",
        "x-auth-token-sentinel",
        "x-access-token-sentinel",
        "x-session-token-sentinel",
        "x-underscore-api-key-sentinel",
        "x-percent-auth-token-sentinel",
        "x-percent-access-token-sentinel",
        "x-underscore-session-token-sentinel",
        "url-fragment-sentinel",
    ):
        assert secret not in repr(result)
        assert secret not in serialised
    assert result.request_records[0].headers == {}
    assert result.request_records[0].body is None
    assert result.request_records[0].response_headers == {}
    assert result.request_records[0].response_body is None
    persistent_url = result.request_records[0].url
    assert "filter=active" in persistent_url
    assert "access_token=%5BREDACTED%5D" in persistent_url
    assert "api-key=%5BREDACTED%5D" in persistent_url
    assert "accessToken=%5BREDACTED%5D" in persistent_url
    assert all(
        warning.fingerprint.startswith("hmac-sha256:")
        for warning in result.body_secret_warnings
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://username:userinfo-sentinel@example.test/orders",
        "orders/1?token=relative-url-sentinel",
        "https://example.test:not-a-port/orders",
        "https://[invalid-host/orders",
    ],
)
def test_persistent_record_rejects_non_absolute_or_unsafe_urls(url: str) -> None:
    result = extract_requests(
        [RequestRecord(identity="alice", method="GET", url=url)],
        CredentialVault(),
    )

    serialised = json.dumps(asdict(result), sort_keys=True)
    assert result.request_records[0].url == "[INVALID_URL]"
    assert "sentinel" not in repr(result)
    assert "sentinel" not in serialised


@pytest.mark.parametrize(
    "url",
    [
        "https://example .test/path",
        "https://example.test\\internal/path",
        "https://example%ZZ.test/path",
        "https://-illegal-label.example/path",
        "https://empty..label.example/path",
    ],
)
def test_persistent_record_rejects_malformed_hosts_and_url_characters(url: str) -> None:
    result = extract_requests(
        [RequestRecord(identity="alice", method="GET", url=url)],
        CredentialVault(),
    )

    assert result.request_records[0].url == "[INVALID_URL]"


def test_persistent_record_keeps_a_safe_url_in_canonical_form() -> None:
    result = extract_requests(
        [
            RequestRecord(
                identity="alice",
                method="GET",
                url="HTTPS://Example.TEST:8443/orders?filter=open",
            )
        ],
        CredentialVault(),
    )

    assert result.request_records[0].url == "https://example.test:8443/orders?filter=open"
