"""Provider-agnostic and provider-specific resource inventory contracts.

Spec: docs/superpowers/specs/2026-08-24-openbola-v1-design.md #5.

Adapters consume already-captured ``RequestRecord`` evidence and never send
a request themselves. Every field this module reports comes from data
``RequestRecord`` already carries; it never assumes richer fidelity than
that (see the roadmap's P4 entry for why field *value types* are
deliberately not part of ``FieldInventory``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from openbola.handles import ValueHandle
from openbola.models import RequestRecord


class ProviderConfidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FieldInventory:
    name: str


@dataclass(frozen=True)
class ResourceInventory:
    provider: str
    provider_confidence: ProviderConfidence
    resource_name: str
    endpoint_template: str
    fields: tuple[FieldInventory, ...]
    record_handles: tuple[ValueHandle, ...]
    observed_methods: frozenset[str]


@dataclass(frozen=True)
class ProviderDetection:
    provider: str
    confidence: ProviderConfidence


class ProviderAdapter(Protocol):
    name: str

    def detect(self, records: Sequence[RequestRecord]) -> ProviderDetection: ...
    def inventory(self, records: Sequence[RequestRecord]) -> tuple[ResourceInventory, ...]: ...
