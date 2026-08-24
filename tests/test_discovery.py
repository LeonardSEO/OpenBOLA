from __future__ import annotations

from openbola.discovery import (
    FieldInventory,
    ProviderAdapter,
    ProviderConfidence,
    ProviderDetection,
    ResourceInventory,
)
from openbola.handles import ValueHandle


def test_provider_confidence_has_three_members() -> None:
    assert {member.value for member in ProviderConfidence} == {
        "confirmed",
        "inferred",
        "unknown",
    }


def test_field_inventory_is_frozen_and_name_only() -> None:
    field = FieldInventory(name="email")
    assert field.name == "email"
    assert not hasattr(field, "type")
    assert not hasattr(field, "observed_types")


def test_provider_detection_pairs_provider_and_confidence() -> None:
    detection = ProviderDetection(provider="generic", confidence=ProviderConfidence.UNKNOWN)
    assert detection.provider == "generic"
    assert detection.confidence is ProviderConfidence.UNKNOWN


def test_resource_inventory_holds_value_handles_not_raw_ids() -> None:
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_value(kind="record_id", value="42")
    inventory = ResourceInventory(
        provider="generic",
        provider_confidence=ProviderConfidence.UNKNOWN,
        resource_name="users",
        endpoint_template="/v1/users/{id}",
        fields=(FieldInventory(name="email"),),
        record_handles=(handle,),
        observed_methods=frozenset({"GET", "PATCH"}),
    )
    assert inventory.record_handles == (handle,)
    assert isinstance(inventory.record_handles[0], ValueHandle)
    assert inventory.observed_methods == frozenset({"GET", "PATCH"})


def test_provider_adapter_is_a_protocol_with_expected_members() -> None:
    # A structural check that a minimal conforming class satisfies the Protocol
    # at the attribute/method level - Protocol membership is duck-typed, so
    # this test exercises that shape rather than calling isinstance().
    class MinimalAdapter:
        name = "minimal"

        def detect(self, records: object) -> ProviderDetection:
            return ProviderDetection(provider="minimal", confidence=ProviderConfidence.UNKNOWN)

        def inventory(self, records: object) -> tuple[ResourceInventory, ...]:
            return ()

    adapter: ProviderAdapter = MinimalAdapter()
    assert adapter.name == "minimal"
    assert adapter.detect(()).provider == "minimal"
    assert adapter.inventory(()) == ()
