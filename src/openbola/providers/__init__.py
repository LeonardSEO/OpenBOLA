"""Built-in evidence-only provider adapters and their ordered registry.

Imports are lazy on purpose.  The adapter modules import the shared discovery
contracts, and eagerly importing the registry from this package initializer
would create a cycle when callers import one adapter directly.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openbola.providers.firebase import FirebaseRealtimeDatabaseAdapter
    from openbola.providers.hasura import HasuraAdapter
    from openbola.providers.registry import (
        ProviderAdapterFactory,
        ProviderDiscoveryError,
        ProviderDiscoveryResult,
        ProviderRegistration,
        ProviderRegistry,
        discover_provider_inventory,
        provider_adapters,
    )
    from openbola.providers.supabase import PostGRESTAdapter, PostgRESTAdapter, SupabaseAdapter


def __getattr__(name: str) -> object:
    if name == "FirebaseRealtimeDatabaseAdapter":
        from openbola.providers.firebase import FirebaseRealtimeDatabaseAdapter

        return FirebaseRealtimeDatabaseAdapter
    if name == "HasuraAdapter":
        from openbola.providers.hasura import HasuraAdapter

        return HasuraAdapter
    if name in {"PostGRESTAdapter", "PostgRESTAdapter", "SupabaseAdapter"}:
        from openbola.providers.supabase import PostGRESTAdapter, PostgRESTAdapter, SupabaseAdapter

        if name == "PostGRESTAdapter":
            return PostGRESTAdapter
        return PostgRESTAdapter if name == "PostgRESTAdapter" else SupabaseAdapter
    if name in {
        "ProviderAdapterFactory",
        "ProviderDiscoveryError",
        "ProviderDiscoveryResult",
        "ProviderRegistration",
        "ProviderRegistry",
        "discover_provider_inventory",
        "provider_adapters",
    }:
        from openbola.providers import registry

        return getattr(registry, name)
    raise AttributeError(name)

__all__ = [
    "FirebaseRealtimeDatabaseAdapter",
    "HasuraAdapter",
    "PostGRESTAdapter",
    "PostgRESTAdapter",
    "ProviderAdapterFactory",
    "ProviderDiscoveryError",
    "ProviderDiscoveryResult",
    "ProviderRegistration",
    "ProviderRegistry",
    "SupabaseAdapter",
    "discover_provider_inventory",
    "provider_adapters",
]
