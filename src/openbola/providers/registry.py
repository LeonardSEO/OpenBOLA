"""Typed provider-adapter registration and discovery orchestration.

Provider adapters are deliberately small, evidence-only consumers.  This module
is the one place that assembles the v1 adapters and gives callers a single,
typed path from an ephemeral :class:`AdapterRecordView` sequence to provider
detections and normalized inventories.  It does not own a transport, resolve
handles, or persist the values behind handles.

The generic adapter is always present.  Supabase and PostgREST share one wire
format and one adapter (``SupabaseAdapter``); ``PostgRESTAdapter`` is exported
as a compatibility alias rather than registering a second adapter that would
duplicate every inventory entry.  Firebase is scoped to Realtime Database.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from openbola.capture import AdapterRecordView
from openbola.discovery import (
    FieldInventory,
    GenericAdapter,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
)
from openbola.handles import InMemorySessionValueRegistry, ValueHandle
from openbola.providers.firebase import FirebaseRealtimeDatabaseAdapter
from openbola.providers.hasura import HasuraAdapter
from openbola.providers.supabase import PostgRESTAdapter

_SAFE_PROVIDER_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class ProviderDiscoveryError(RuntimeError):
    """A bounded error raised when an adapter violates its local contract."""


class ProviderAdapterFactory(Protocol):
    """Factory for one adapter sharing the session's handle registry."""

    def __call__(self, registry: InMemorySessionValueRegistry) -> ProviderAdapter: ...


@dataclass(frozen=True)
class ProviderRegistration:
    """One stable provider name and its constructor.

    Registrations are data, not import-time plugin hooks.  Keeping the list
    explicit makes the supported providers auditable and prevents arbitrary
    third-party code from running during a discovery pass.
    """

    name: str
    factory: ProviderAdapterFactory

    def __post_init__(self) -> None:
        if type(self.name) is not str or _SAFE_PROVIDER_NAME.fullmatch(self.name) is None:
            raise ValueError("provider registration name is invalid")
        if not callable(self.factory):
            raise TypeError("provider registration factory is not callable")


@dataclass(frozen=True)
class ProviderDiscoveryResult:
    """Complete read-only result from one ordered adapter pass."""

    detections: tuple[ProviderDetection, ...]
    inventories: tuple[ResourceInventory, ...]

    def __post_init__(self) -> None:
        if type(self.detections) is not tuple or not all(
            type(item) is ProviderDetection for item in self.detections
        ):
            raise TypeError("provider detections must be an exact tuple")
        if type(self.inventories) is not tuple or not all(
            type(item) is ResourceInventory for item in self.inventories
        ):
            raise TypeError("provider inventories must be an exact tuple")

    @property
    def confirmed(self) -> tuple[ProviderDetection, ...]:
        """Return only confirmed provider signals, preserving registration order."""

        return tuple(
            detection
            for detection in self.detections
            if detection.confidence is ProviderConfidence.CONFIRMED
        )


def _default_registrations() -> tuple[ProviderRegistration, ...]:
    """Construct the explicit v1 registration list.

    The function (rather than a mutable module-level list) makes it impossible
    for a caller to alter the process-wide registration order accidentally.
    """

    return (
        ProviderRegistration("generic", GenericAdapter),
        ProviderRegistration("supabase", PostgRESTAdapter),
        ProviderRegistration("firebase-rtdb", FirebaseRealtimeDatabaseAdapter),
        ProviderRegistration("hasura", HasuraAdapter),
    )


def provider_adapters(
    registry: InMemorySessionValueRegistry,
    *,
    registrations: Sequence[ProviderRegistration] | None = None,
) -> tuple[ProviderAdapter, ...]:
    """Build the ordered v1 adapter set against one process-local registry.

    ``registry`` is intentionally required: every record handle returned by an
    adapter must belong to the active session and must not silently move to a
    second registry.  No adapter created here has network access.
    """

    if not isinstance(registry, InMemorySessionValueRegistry):
        raise TypeError("provider adapter registry must be an in-memory session registry")
    selected = tuple(_default_registrations() if registrations is None else registrations)
    _validate_registrations(selected)
    adapters: list[ProviderAdapter] = []
    for registration in selected:
        try:
            adapter = registration.factory(registry)
        except Exception:
            raise ProviderDiscoveryError("provider adapter could not be constructed") from None
        if not _is_provider_adapter(adapter, expected_name=registration.name):
            raise ProviderDiscoveryError("provider adapter violates its registration contract")
        adapters.append(adapter)
    return tuple(adapters)


class ProviderRegistry:
    """Ordered factory plus safe inventory bridge for captured evidence."""

    def __init__(
        self,
        registry: InMemorySessionValueRegistry,
        *,
        registrations: Sequence[ProviderRegistration] | None = None,
    ) -> None:
        self._registry = registry
        selected = tuple(_default_registrations() if registrations is None else registrations)
        _validate_registrations(selected)
        self._registrations = selected
        self._adapters = provider_adapters(registry, registrations=selected)

    @property
    def adapters(self) -> tuple[ProviderAdapter, ...]:
        """Return the immutable ordered adapter inventory."""

        return self._adapters

    @property
    def registrations(self) -> tuple[ProviderRegistration, ...]:
        return self._registrations

    def detect(self, records: Sequence[AdapterRecordView]) -> tuple[ProviderDetection, ...]:
        """Run detection for every registered adapter without sending requests."""

        views = _validated_views(records)
        return tuple(self._safe_detect(adapter, views) for adapter in self._adapters)

    def inventory(self, records: Sequence[AdapterRecordView]) -> tuple[ResourceInventory, ...]:
        """Flatten ordered adapter inventories into a safe tuple.

        This method is suitable as the callback passed to
        ``InSessionCapture.with_adapter_records``.  It returns only the typed
        inventory contract; ephemeral views and the registry remain local to
        the active session.
        """

        views = _validated_views(records)
        inventories: list[ResourceInventory] = []
        for adapter in self._adapters:
            inventories.extend(self._safe_inventory(adapter, views))
        return tuple(inventories)

    def discover(self, records: Sequence[AdapterRecordView]) -> ProviderDiscoveryResult:
        """Run detection and inventory once, retaining both typed results."""

        views = _validated_views(records)
        detections: list[ProviderDetection] = []
        inventories: list[ResourceInventory] = []
        for adapter in self._adapters:
            detections.append(self._safe_detect(adapter, views))
            inventories.extend(self._safe_inventory(adapter, views))
        return ProviderDiscoveryResult(tuple(detections), tuple(inventories))

    def _safe_detect(
        self, adapter: ProviderAdapter, records: Sequence[AdapterRecordView]
    ) -> ProviderDetection:
        try:
            detection = adapter.detect(records)
        except Exception:
            raise ProviderDiscoveryError("provider detection failed") from None
        if type(detection) is not ProviderDetection or detection.provider != adapter.name:
            raise ProviderDiscoveryError("provider detection violates its adapter contract")
        return detection

    def _safe_inventory(
        self, adapter: ProviderAdapter, records: Sequence[AdapterRecordView]
    ) -> tuple[ResourceInventory, ...]:
        try:
            result = adapter.inventory(records)
        except Exception:
            raise ProviderDiscoveryError("provider inventory failed") from None
        if type(result) is not tuple:
            raise ProviderDiscoveryError("provider inventory must be an exact tuple")
        for item in result:
            if not _is_safe_inventory(item, expected_provider=adapter.name):
                raise ProviderDiscoveryError("provider inventory violates its adapter contract")
        return result


def discover_provider_inventory(
    records: Sequence[AdapterRecordView],
    registry: InMemorySessionValueRegistry,
    *,
    registrations: Sequence[ProviderRegistration] | None = None,
) -> ProviderDiscoveryResult:
    """Convenience entry point for one complete provider discovery pass."""

    return ProviderRegistry(registry, registrations=registrations).discover(records)


def _validate_registrations(registrations: Sequence[ProviderRegistration]) -> None:
    if type(registrations) is not tuple:
        raise TypeError("provider registrations must be an exact tuple")
    if not all(type(item) is ProviderRegistration for item in registrations):
        raise TypeError("provider registrations contain an invalid item")
    names = [item.name for item in registrations]
    if len(names) != len(set(names)):
        raise ValueError("provider registration names must be unique")


def _is_provider_adapter(value: object, *, expected_name: str) -> bool:
    return (
        callable(getattr(value, "detect", None))
        and callable(getattr(value, "inventory", None))
        and type(getattr(value, "name", None)) is str
        and value.name == expected_name  # type: ignore[attr-defined]
    )


def _validated_views(records: Sequence[AdapterRecordView]) -> tuple[AdapterRecordView, ...]:
    if not isinstance(records, Sequence):
        raise TypeError("provider records must be a sequence of adapter views")
    views = tuple(records)
    if any(type(view) is not AdapterRecordView for view in views):
        raise TypeError("provider records must contain only ephemeral adapter views")
    return views


def _is_safe_inventory(value: object, *, expected_provider: str) -> bool:
    if type(value) is not ResourceInventory:
        return False
    if value.provider != expected_provider:
        return False
    if type(value.provider_confidence) is not ProviderConfidence:
        return False
    if type(value.fields) is not tuple or not all(
        type(field) is FieldInventory and type(field.name) is str for field in value.fields
    ):
        return False
    if type(value.record_handles) is not tuple or not all(
        type(handle) is ValueHandle and handle.kind == "record_id"
        for handle in value.record_handles
    ):
        return False
    return type(value.observed_methods) is frozenset and all(
        type(method) is str for method in value.observed_methods
    )


__all__ = [
    "ProviderAdapterFactory",
    "ProviderDiscoveryError",
    "ProviderDiscoveryResult",
    "ProviderRegistration",
    "ProviderRegistry",
    "PostgRESTAdapter",
    "discover_provider_inventory",
    "provider_adapters",
]
