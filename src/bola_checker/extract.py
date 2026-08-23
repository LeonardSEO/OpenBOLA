"""Deterministic, request-only credential and identity extraction.

Response credentials are deliberately ignored: a credential is replayable only
when it was present on the request made by that identity. JWT payloads are
decoded only for unverified identity hints and never grant identity ownership.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from bola_checker.credentials import CredentialVault, fingerprint_secret
from bola_checker.models import CredentialKind, CredentialRef, RequestRecord

_API_KEY_HEADERS = frozenset(
    {
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-access-token",
        "x-session-token",
    }
)
_SECRET_BODY_FIELD = re.compile(
    r"[\"']?(api[_-]?key|access[_-]?token|secret|bearer|auth[_-]?token|client[_-]?secret)"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"';,}\]]{8,})",
    re.IGNORECASE,
)
_IDENTITY_CLAIMS = ("sub", "user_id", "uid", "tenant_id")
_SENSITIVE_QUERY_NAME_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "authorization",
    "apikey",
    "accesskey",
    "session",
    "cookie",
    "bearer",
    "credential",
    "code",
    "key",
)
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@dataclass(frozen=True)
class IdentityHint:
    """An explicitly unverified identity clue decoded from a JWT payload."""

    identity: str
    claim: str
    value: str
    signature_verified: bool = False


@dataclass(frozen=True)
class BodySecretWarning:
    """A body secret indication without retaining the detected value."""

    location: str
    field_name: str
    fingerprint: str


@dataclass(frozen=True)
class ExtractionResult:
    """Secret-safe phase-2 output suitable for passing to persistent phases."""

    credential_refs: tuple[CredentialRef, ...]
    identity_hints: tuple[IdentityHint, ...]
    request_records: tuple[RequestRecord, ...]
    body_secret_warnings: tuple[BodySecretWarning, ...]


def decode_jwt_payload(token: str) -> Mapping[str, object] | None:
    """Decode a JWT payload for hints only; this does not verify a signature."""

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return None

    try:
        payload = parts[1]
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def extract_requests(records: Iterable[RequestRecord], vault: CredentialVault) -> ExtractionResult:
    """Extract request credentials and return only redacted persistence records."""

    references: list[CredentialRef] = []
    hints: list[IdentityHint] = []
    persistence_records: list[RequestRecord] = []
    warnings: list[BodySecretWarning] = []
    seen_references: set[CredentialRef] = set()

    for record in records:
        for name, value in record.headers.items():
            _extract_header(record.identity, name, value, vault, references, seen_references, hints)

        warnings.extend(_scan_body(record.body, "request_body"))
        warnings.extend(_scan_body(record.response_body, "response_body"))
        persistence_records.append(_redacted_request_record(record))

    return ExtractionResult(
        credential_refs=tuple(references),
        identity_hints=tuple(hints),
        request_records=tuple(persistence_records),
        body_secret_warnings=tuple(warnings),
    )


def _extract_header(
    identity: str,
    name: str,
    value: str,
    vault: CredentialVault,
    references: list[CredentialRef],
    seen_references: set[CredentialRef],
    hints: list[IdentityHint],
) -> None:
    normalized_name = name.casefold()
    if normalized_name == "authorization":
        bearer = _normalize_bearer(value)
        if bearer is not None:
            reference = vault.store(
                identity=identity,
                kind=CredentialKind.BEARER,
                name=name,
                secret=bearer,
            )
            _add_reference(reference, references, seen_references)
            _add_jwt_hints(identity, bearer, hints)
        elif value.strip():
            _add_reference(
                vault.store(
                    identity=identity,
                    kind=CredentialKind.HEADER,
                    name=name,
                    secret=value,
                ),
                references,
                seen_references,
            )
        return

    if normalized_name == "cookie":
        for cookie_name, cookie_value in _cookies(value):
            _add_reference(
                vault.store(
                    identity=identity,
                    kind=CredentialKind.COOKIE,
                    name=cookie_name,
                    secret=cookie_value,
                ),
                references,
                seen_references,
            )
        return

    if normalized_name in _API_KEY_HEADERS and value.strip():
        _add_reference(
            vault.store(
                identity=identity,
                kind=CredentialKind.HEADER,
                name=name,
                secret=value,
            ),
            references,
            seen_references,
        )


def _normalize_bearer(value: str) -> str | None:
    parts = value.split()
    while parts and parts[0].casefold() == "bearer":
        parts.pop(0)
    return parts[0] if len(parts) == 1 else None


def _cookies(value: str) -> Iterable[tuple[str, str]]:
    for part in value.split(";"):
        name, separator, cookie_value = part.strip().partition("=")
        if separator and name and cookie_value:
            yield name, cookie_value


def _add_reference(
    reference: CredentialRef,
    references: list[CredentialRef],
    seen_references: set[CredentialRef],
) -> None:
    if reference not in seen_references:
        references.append(reference)
        seen_references.add(reference)


def _add_jwt_hints(identity: str, token: str, hints: list[IdentityHint]) -> None:
    payload = decode_jwt_payload(token)
    if payload is None:
        return
    for claim in _IDENTITY_CLAIMS:
        value = payload.get(claim)
        if isinstance(value, str) and value:
            hints.append(IdentityHint(identity=identity, claim=claim, value=value))


def _scan_body(body: bytes | None, location: str) -> list[BodySecretWarning]:
    if body is None:
        return []
    text = body.decode("utf-8", errors="replace")
    return [
        BodySecretWarning(
            location=location,
            field_name=match.group(1),
            fingerprint=fingerprint_secret(match.group(2)),
        )
        for match in _SECRET_BODY_FIELD.finditer(text)
    ]


def _redacted_request_record(record: RequestRecord) -> RequestRecord:
    """Keep replay metadata while removing every header and body value."""

    return RequestRecord(
        identity=record.identity,
        method=record.method,
        url=_redact_url(record.url),
        headers={},
        body=None,
        response_status=record.response_status,
        response_headers={},
        response_body=None,
    )


def _redact_url(url: str) -> str:
    """Return a safe persistent URL or a fixed placeholder for invalid input."""

    if _contains_invalid_url_characters(url) or _INVALID_PERCENT_ESCAPE.search(url):
        return "[INVALID_URL]"
    try:
        split_url = urlsplit(url)
        if (
            split_url.scheme.casefold() not in {"http", "https"}
            or split_url.hostname is None
            or split_url.username is not None
            or split_url.password is not None
        ):
            return "[INVALID_URL]"
        hostname = _canonical_hostname(split_url.hostname)
        port = split_url.port
    except ValueError:
        return "[INVALID_URL]"
    if hostname is None or (port is not None and not 1 <= port <= 65535):
        return "[INVALID_URL]"

    host_for_netloc = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host_for_netloc}:{port}" if port is not None else host_for_netloc
    query = urlencode(
        [
            (key, "[REDACTED]" if _is_sensitive_query_key(key) else value)
            for key, value in parse_qsl(
                split_url.query.replace(";", "&"), keep_blank_values=True
            )
        ],
        doseq=True,
    )
    return urlunsplit((split_url.scheme.casefold(), netloc, split_url.path, query, ""))


def _is_sensitive_query_key(key: str) -> bool:
    normalised = re.sub(r"[^a-z0-9]", "", unquote_plus(key).casefold())
    normalised = normalised.removeprefix("x")
    return any(part in normalised for part in _SENSITIVE_QUERY_NAME_PARTS)


def _contains_invalid_url_characters(url: str) -> bool:
    return any(
        character.isspace() or unicodedata.category(character) == "Cc" or character == "\\"
        for character in url
    )


def _canonical_hostname(hostname: str) -> str | None:
    """Return a strict lowercase IDNA/IP hostname, preserving only a root dot."""

    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        pass

    trailing_root = hostname.endswith(".")
    dns_hostname = hostname[:-1] if trailing_root else hostname
    if not dns_hostname:
        return None
    try:
        normalised = dns_hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None
    if len(normalised) > 253:
        return None
    labels = normalised.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return None
    return f"{normalised}." if trailing_root else normalised
