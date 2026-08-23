"""Shared, dependency-light contracts between BOLACheck phases."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CredentialKind(StrEnum):
    BEARER = "bearer"
    HEADER = "header"
    COOKIE = "cookie"


class OwnershipConfidence(StrEnum):
    EXPLICIT = "explicit"
    OBSERVED_CREATE = "observed_create"
    RESPONSE_MATCH = "response_match"
    HEURISTIC = "heuristic"


class ProbeMode(StrEnum):
    READ = "read"
    MUTATION = "mutation"


class Verdict(StrEnum):
    BOLA = "bola"
    PROTECTED = "protected"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class CredentialRef:
    """Reference to a credential held outside persistent state."""

    identity: str
    kind: CredentialKind
    name: str
    secret_ref: str


@dataclass(frozen=True)
class RequestRecord:
    identity: str
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    body: bytes | None = field(default=None, repr=False)
    response_status: int | None = None
    response_headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    response_body: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class OwnershipEvidence:
    identity: str
    endpoint_template: str
    method: str
    object_id: str
    confidence: OwnershipConfidence
    source: str


@dataclass(frozen=True)
class ProbeTarget:
    base_url: str
    endpoint_template: str
    method: str
    object_id: str
    owner_identity: str
    attacker_identity: str
    owner_credential: CredentialRef
    attacker_credential: CredentialRef
    mode: ProbeMode = ProbeMode.READ
    id_field: str = "id"


@dataclass(frozen=True)
class ProbeResult:
    target: ProbeTarget
    verdict: Verdict
    owner_status: int | None
    attacker_status: int | None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    retryable: bool = False


@dataclass(frozen=True)
class Finding:
    endpoint_template: str
    method: str
    severity: str
    title: str
    description: str
    evidence: Mapping[str, Any]
