"""Typed, fail-closed mutation sweep preflight contracts.

This module deliberately contains no transport or journal implementation.
Preflight is a pure authorization and budgeting boundary: it freezes the
complete candidate set, validates the mutation grant and scope for every
concrete request shape, and only then returns a plan that a later executor may
dispatch.  Raw object IDs and original values remain runtime-only fields on
the candidate and are never copied into error messages or serialized metadata.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any, Literal, NoReturn, SupportsIndex, TypeAlias
from urllib.parse import quote, urlsplit, urlunsplit

from openbola.executor import ProbeExecutor, ScopedExchange
from openbola.handles import ValueHandle
from openbola.models import ProbeMode, ProbeTarget
from openbola.scope import (
    MutationGrant,
    MutationRecordScope,
    ScopeError,
    ScopeGuard,
)

MAX_MUTATION_REQUESTS = 100_000
_EXISTING_RECORD_REQUESTS = 5
_SAFE_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_SAFE_CANARY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ALLOWED_EXISTING_METHODS = frozenset({"PATCH", "PUT"})
_RELATIVE_PATH_FORBIDDEN = frozenset({"?", "#"})


class MutationPreflightError(ValueError):
    """Raised when a mutation sweep cannot be authorized before dispatch."""


@dataclass(frozen=True)
class MutationOperation:
    """The bounded, grant-bound operation used for an existing record."""

    method: str
    endpoint_template: str
    field: str
    allowed_path: str

    def __post_init__(self) -> None:
        method = _normalise_method(self.method)
        if method not in _ALLOWED_EXISTING_METHODS:
            raise MutationPreflightError("mutation operation method is not supported")
        object.__setattr__(self, "method", method)
        _validate_relative_template(self.endpoint_template, "endpoint template")
        _validate_relative_template(self.allowed_path, "allowed path")
        if (
            not isinstance(self.field, str)
            or not self.field.strip()
            or self.field != self.field.strip()
            or len(self.field) > 256
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in self.field)
        ):
            raise MutationPreflightError("mutation field must be non-empty")


@dataclass(frozen=True)
class MutationCandidate:
    """One existing record and its in-process restore material."""

    endpoint_handle: str
    record_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    target: ProbeTarget = dataclass_field(repr=False)
    field: str
    original_value: ValueHandle = dataclass_field(repr=False)
    canary_value: str = dataclass_field(repr=False)
    mutation: MutationOperation

    def __reduce__(self) -> NoReturn:
        raise TypeError("Mutation candidates are process-local and cannot be serialized.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("Mutation candidates are process-local and cannot be serialized.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Mutation candidates are process-local and cannot be serialized.")

    def __post_init__(self) -> None:
        for value, label in (
            (self.endpoint_handle, "endpoint handle"),
            (self.record_handle, "record handle"),
            (self.owner_identity_handle, "owner identity handle"),
            (self.attacker_identity_handle, "attacker identity handle"),
        ):
            if not isinstance(value, str) or not _SAFE_HANDLE.fullmatch(value):
                raise MutationPreflightError(f"{label} is invalid")
        if self.owner_identity_handle == self.attacker_identity_handle:
            raise MutationPreflightError("owner and attacker handles must differ")
        if type(self.target) is not ProbeTarget:
            raise MutationPreflightError("candidate target is invalid")
        if self.target.owner_identity == self.target.attacker_identity:
            raise MutationPreflightError("owner and attacker identities must differ")
        if self.target.owner_credential.identity != self.target.owner_identity:
            raise MutationPreflightError("owner credential identity does not match target")
        if self.target.attacker_credential.identity != self.target.attacker_identity:
            raise MutationPreflightError("attacker credential identity does not match target")
        if self.target.mode is not ProbeMode.MUTATION:
            raise MutationPreflightError("candidate target must be a mutation target")
        if self.target.method.upper() != self.mutation.method:
            raise MutationPreflightError("candidate target method does not match operation")
        if self.target.endpoint_template != self.mutation.endpoint_template:
            raise MutationPreflightError("candidate target endpoint does not match operation")
        if not isinstance(self.original_value, ValueHandle):
            raise MutationPreflightError("original value must be a value handle")
        if self.original_value.kind != "field_value" or not _SAFE_HANDLE.fullmatch(
            self.original_value.id
        ):
            raise MutationPreflightError("original value handle is invalid")
        if not isinstance(self.canary_value, str) or not _SAFE_CANARY.fullmatch(self.canary_value):
            raise MutationPreflightError("canary value is invalid")
        if self.field != self.mutation.field:
            raise MutationPreflightError("candidate field does not match operation")


@dataclass(frozen=True)
class MutationCandidateInventory:
    """Explicitly complete discovery output for ``all_discovered`` sweeps."""

    candidates: tuple[MutationCandidate, ...]
    discovery_complete: bool

    def __post_init__(self) -> None:
        if type(self.discovery_complete) is not bool:
            raise MutationPreflightError("discovery completeness marker is invalid")
        if not isinstance(self.candidates, tuple):
            raise MutationPreflightError("discovery candidates must be an immutable tuple")


# Friendly aliases for integrations whose discovery layer calls this result a
# discovery set rather than an inventory.  They remain the same typed contract.
MutationDiscoveryResult: TypeAlias = MutationCandidateInventory
MutationCandidateSet: TypeAlias = MutationCandidateInventory


@dataclass(frozen=True)
class MutationSweepPlan:
    candidates: tuple[MutationCandidate, ...]
    grant: MutationGrant
    scope_digest: str
    request_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.candidates, tuple):
            raise MutationPreflightError("mutation plan candidates must be immutable")
        if not self.candidates:
            raise MutationPreflightError("mutation plan requires at least one candidate")
        if not isinstance(self.grant, MutationGrant):
            raise MutationPreflightError("mutation plan grant is invalid")
        if not isinstance(self.scope_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.scope_digest
        ):
            raise MutationPreflightError("mutation plan scope digest is invalid")
        if self.request_count != len(self.candidates) * _EXISTING_RECORD_REQUESTS:
            raise MutationPreflightError("mutation plan request count is invalid")


@dataclass(frozen=True)
class MutationOutcome:
    record_handle: str
    status: Literal["verified", "inconclusive", "skipped"]
    mutation_verified: bool
    restore_verified: bool
    error_code: str | None = None


@dataclass(frozen=True)
class RecoveryStatus:
    state: Literal["clear", "required", "escalated", "blocked"]
    journal_present: bool
    reason_code: str | None = None


def preflight_sweep(
    candidates: Sequence[MutationCandidate] | MutationCandidateInventory,
    scope_guard: ScopeGuard,
    grant: MutationGrant | None = None,
    *,
    discovery_complete: bool | None = None,
    now: datetime | None = None,
) -> MutationSweepPlan:
    """Validate and freeze a mutation sweep before opening any transport.

    ``all_discovered`` requires :class:`MutationCandidateInventory` (or the
    explicit ``discovery_complete=True`` keyword).  A plain sequence is
    intentionally insufficient so a partial discovery cannot be mistaken for
    the complete set.
    """
    if not isinstance(scope_guard, ScopeGuard):
        raise MutationPreflightError("scope guard is invalid")
    source, complete_marker = _normalise_source(candidates, discovery_complete)
    frozen = tuple(source)
    if not frozen:
        raise MutationPreflightError("mutation sweep requires at least one candidate")
    if not all(type(candidate) is MutationCandidate for candidate in frozen):
        raise MutationPreflightError("mutation candidate set is invalid")
    # Re-run the immutable contract validation at the trust boundary.  The
    # dataclass is frozen for normal callers, but a hostile integration can
    # still mutate it through ``object.__setattr__``; preflight must not trust
    # such an object merely because its original constructor succeeded.
    for candidate in frozen:
        try:
            candidate.mutation.__post_init__()
            candidate.__post_init__()
        except (AttributeError, TypeError, MutationPreflightError) as error:
            raise MutationPreflightError("mutation candidate set is invalid") from error

    selected = _select_grant(scope_guard, frozen, grant)
    if selected.record_scope is MutationRecordScope.ALL_DISCOVERED and complete_marker is not True:
        raise MutationPreflightError("all_discovered requires a complete discovery result")
    if len(frozen) > selected.max_records:
        raise MutationPreflightError("mutation record budget exceeded")

    _reject_duplicates(frozen)
    ordered = tuple(
        sorted(
            frozen,
            key=lambda item: (
                item.endpoint_handle,
                item.record_handle,
                item.field,
                item.mutation.method,
                item.mutation.endpoint_template,
            ),
        )
    )
    request_count = len(ordered) * _EXISTING_RECORD_REQUESTS
    if request_count > selected.max_requests or request_count > MAX_MUTATION_REQUESTS:
        raise MutationPreflightError("mutation request budget exceeded")

    for candidate in ordered:
        if candidate.field not in selected.allowed_fields:
            raise MutationPreflightError("mutation field is not granted")
        _validate_candidate_scope(candidate, selected, scope_guard, now=now)

    return MutationSweepPlan(
        candidates=ordered,
        grant=selected,
        scope_digest=scope_guard.scope_digest,
        request_count=request_count,
    )


class MutationSweepExecutor:
    """Preflight and execute a deterministic, reversible mutation sweep."""

    def __init__(
        self,
        scope_guard_or_executor: ScopeGuard | ProbeExecutor,
        value_registry: Any | None = None,
        *,
        journal: Any | None = None,
    ) -> None:
        if isinstance(scope_guard_or_executor, ProbeExecutor):
            self.executor: ProbeExecutor | None = scope_guard_or_executor
            self.scope_guard = scope_guard_or_executor.scope_guard
        elif isinstance(scope_guard_or_executor, ScopeGuard):
            self.executor = None
            self.scope_guard = scope_guard_or_executor
        else:
            raise TypeError("scope guard or probe executor is invalid")
        self.value_registry = value_registry
        self.journal = journal

    def preflight(
        self,
        candidates: Sequence[MutationCandidate] | MutationCandidateInventory,
        grant: MutationGrant | None = None,
        *,
        discovery_complete: bool | None = None,
        now: datetime | None = None,
    ) -> MutationSweepPlan:
        return preflight_sweep(
            candidates,
            self.scope_guard,
            grant,
            discovery_complete=discovery_complete,
            now=now,
        )

    def sweep(
        self,
        plan: MutationSweepPlan,
        *,
        executor: ProbeExecutor | None = None,
        value_registry: Any | None = None,
        journal: Any | None = None,
    ) -> tuple[MutationOutcome, ...]:
        """Run the five requests for each preflighted existing-record candidate.

        A failed or uncertain cleanup is a global stop condition.  Later
        records are returned as ``skipped`` and no write is dispatched for
        them.  No response body or restore value is copied into outcomes.
        """

        if type(plan) is not MutationSweepPlan:
            raise TypeError("sweep requires a MutationSweepPlan")
        active_executor = executor or self.executor
        if not isinstance(active_executor, ProbeExecutor):
            raise TypeError("sweep requires a ProbeExecutor")
        registry = value_registry or self.value_registry
        if registry is None or not hasattr(registry, "resolve_value"):
            raise TypeError("sweep requires an in-memory value registry")
        active_journal = journal if journal is not None else self.journal

        outcomes: list[MutationOutcome] = []
        blocked = False
        for candidate in plan.candidates:
            if blocked:
                outcomes.append(
                    MutationOutcome(
                        record_handle=candidate.record_handle,
                        status="skipped",
                        mutation_verified=False,
                        restore_verified=False,
                        error_code="cleanup_unverified",
                    )
                )
                continue
            outcome, must_stop = self._run_candidate(
                candidate,
                active_executor,
                registry,
                active_journal,
            )
            outcomes.append(outcome)
            blocked = must_stop
        return tuple(outcomes)

    # ``run_sweep`` and ``run`` are intentionally small aliases for callers
    # that treat this class as an executor rather than a phase facade.
    run_sweep = sweep
    run = sweep

    @staticmethod
    def _successful(exchange: ScopedExchange) -> bool:
        return (
            exchange.error_code is None
            and exchange.status is not None
            and 200 <= exchange.status < 300
        )

    @staticmethod
    def _body(field: str, value: object) -> bytes:
        import json

        if not isinstance(field, str) or not field or len(field) > 256:
            raise MutationPreflightError("mutation field is invalid")
        try:
            encoded = json.dumps(
                {field: value}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError) as error:
            raise MutationPreflightError(
                "mutation restore value is not JSON serializable"
            ) from error
        if len(encoded) > 256 * 1024:
            raise MutationPreflightError("mutation restore body exceeds the safety limit")
        return encoded

    @staticmethod
    def _journal_commit(
        journal: Any | None,
        candidate: MutationCandidate,
        snapshot: ScopedExchange,
    ) -> None:
        if journal is None:
            return
        # Task 3 supplies the concrete encrypted journal.  Keep this adapter
        # deliberately metadata-only so an older/no-op journal cannot receive
        # the raw object id or original value.
        commit = getattr(journal, "commit", None)
        if commit is None:
            commit = getattr(journal, "begin", None)
        if commit is None:
            raise RuntimeError("mutation journal does not provide a commit operation")
        try:
            commit(
                record_handle=candidate.record_handle,
                endpoint_handle=candidate.endpoint_handle,
                field=candidate.field,
                snapshot_fingerprint=snapshot.body_fingerprint,
            )
        except TypeError:
            # A typed Task 3 implementation may accept a single journal
            # record object instead; the caller owns that adaptation.
            commit(candidate.record_handle, snapshot.body_fingerprint)

    def _run_candidate(
        self,
        candidate: MutationCandidate,
        executor: ProbeExecutor,
        registry: Any,
        journal: Any | None,
    ) -> tuple[MutationOutcome, bool]:
        target = candidate.target
        operation = candidate.mutation
        request_kwargs = {
            "endpoint_template": operation.endpoint_template,
            "content_type": "application/json",
            "id_field": candidate.field,
        }
        snapshot_kwargs = {
            "method": "GET",
            "endpoint_template": operation.endpoint_template,
            "content_type": "application/json",
            "id_field": candidate.field,
        }
        snapshot = executor.request_scoped(
            target,
            target.owner_credential,
            body=None,
            **snapshot_kwargs,
        )
        if not self._successful(snapshot) or not snapshot.object_values:
            return (
                MutationOutcome(
                    candidate.record_handle,
                    "inconclusive",
                    False,
                    False,
                    "snapshot_failed",
                ),
                False,
            )
        try:
            self._journal_commit(journal, candidate, snapshot)
        except BaseException:
            return (
                MutationOutcome(
                    candidate.record_handle,
                    "inconclusive",
                    False,
                    False,
                    "journal_failed",
                ),
                True,
            )

        canary = candidate.canary_value
        canary_exchange: ScopedExchange | None = None
        canary_error: str | None = None
        try:
            canary_exchange = executor.request_scoped(
                target,
                target.owner_credential,
                body=self._body(candidate.field, canary),
                method=operation.method,
                **request_kwargs,
            )
        except BaseException:
            canary_error = "mutation_dispatch_failed"

        mutation_verified = False
        if (
            canary_error is None
            and canary_exchange is not None
            and self._successful(canary_exchange)
        ):
            try:
                attacker = executor.request_scoped(
                    target,
                    target.attacker_credential,
                    body=None,
                    method="GET",
                    **request_kwargs,
                )
                mutation_verified = self._successful(attacker) and canary in attacker.object_values
                if not mutation_verified:
                    canary_error = "attacker_verification_failed"
            except BaseException:
                canary_error = "attacker_verification_failed"
        elif canary_error is None:
            canary_error = "mutation_failed"

        restore_verified = False
        restore_error: str | None = None
        try:
            original = registry.resolve_value(candidate.original_value)
            restore = executor.request_scoped(
                target,
                target.owner_credential,
                body=self._body(candidate.field, original),
                method=operation.method,
                **request_kwargs,
            )
            if not self._successful(restore):
                restore_error = "cleanup_unverified"
            else:
                try:
                    verification = executor.request_scoped(
                        target,
                        target.owner_credential,
                        body=None,
                        method="GET",
                        **request_kwargs,
                    )
                    restore_verified = self._successful(verification) and str(
                        original
                    ) in verification.object_values
                except BaseException:
                    restore_verified = False
                if not restore_verified:
                    restore_error = "cleanup_unverified"
        except BaseException:
            restore_error = "cleanup_unverified"

        if restore_error is not None:
            return (
                MutationOutcome(
                    candidate.record_handle,
                    "inconclusive",
                    mutation_verified,
                    False,
                    restore_error,
                ),
                True,
            )
        if not mutation_verified:
            return (
                MutationOutcome(
                    candidate.record_handle,
                    "inconclusive",
                    False,
                    True,
                    canary_error or "attacker_verification_failed",
                ),
                True,
            )
        return (
            MutationOutcome(candidate.record_handle, "verified", True, True),
            False,
        )


def _normalise_source(
    source: Sequence[MutationCandidate] | MutationCandidateInventory,
    marker: bool | None,
) -> tuple[Sequence[MutationCandidate], bool | None]:
    if isinstance(source, MutationCandidateInventory):
        if marker is not None and marker is not source.discovery_complete:
            raise MutationPreflightError("discovery completeness markers conflict")
        return source.candidates, source.discovery_complete
    if marker is not None and type(marker) is not bool:
        raise MutationPreflightError("discovery completeness marker is invalid")
    if not isinstance(source, Sequence) or isinstance(source, (str, bytes, bytearray)):
        raise MutationPreflightError("mutation candidates must be a sequence")
    return source, marker


def _select_grant(
    scope_guard: ScopeGuard,
    candidates: tuple[MutationCandidate, ...],
    requested: MutationGrant | None,
) -> MutationGrant:
    grants = scope_guard.config.mutation_grants
    if requested is not None:
        if type(requested) is not MutationGrant or requested not in grants:
            raise MutationPreflightError("mutation grant is not part of the confirmed scope")
        selected_candidates = candidates
    else:
        selected_candidates = candidates
        matching = []
        for candidate_grant in grants:
            try:
                covers_all = all(
                    candidate.field in candidate_grant.allowed_fields
                    and candidate_grant.permits(
                        candidate.mutation.method,
                        _concrete_path(
                            candidate.mutation.endpoint_template,
                            candidate.target.object_id,
                        ),
                    )
                    for candidate in selected_candidates
                )
            except MutationPreflightError:
                covers_all = False
            if covers_all:
                matching.append(candidate_grant)
        if not matching:
            raise MutationPreflightError("no confirmed mutation grant covers the candidates")
        if len(matching) > 1:
            # Deterministic selection is safe only when grants are equivalent;
            # otherwise an operator must make the authorization explicit.
            unique = {repr(item) for item in matching}
            if len(unique) > 1:
                raise MutationPreflightError("multiple mutation grants match the candidates")
        return matching[0]
    return requested


def _reject_duplicates(candidates: tuple[MutationCandidate, ...]) -> None:
    seen_candidates: set[tuple[str, str, str, str, str]] = set()
    seen_fields: set[tuple[str, str]] = set()
    seen_value_handles: set[str] = set()
    for candidate in candidates:
        key = (
            candidate.endpoint_handle,
            candidate.record_handle,
            candidate.field,
            candidate.mutation.method,
            candidate.mutation.endpoint_template,
        )
        if key in seen_candidates:
            raise MutationPreflightError("duplicate mutation candidate")
        seen_candidates.add(key)
        field_key = (candidate.record_handle, candidate.field)
        if field_key in seen_fields:
            raise MutationPreflightError("duplicate mutation field binding")
        seen_fields.add(field_key)
        value_handle_id = candidate.original_value.id
        if value_handle_id in seen_value_handles:
            raise MutationPreflightError("duplicate original value handle")
        seen_value_handles.add(value_handle_id)


def _validate_candidate_scope(
    candidate: MutationCandidate,
    grant: MutationGrant,
    scope_guard: ScopeGuard,
    *,
    now: datetime | None,
) -> None:
    concrete_path = _concrete_path(candidate.mutation.endpoint_template, candidate.target.object_id)
    allowed_path = candidate.mutation.allowed_path
    if (
        "{" not in allowed_path
        and allowed_path != concrete_path
        and not any(character in allowed_path for character in "*+([\\")
    ):
        # An explicit allowed path must bind the same concrete endpoint.  A
        # wildcard/template path remains a grant-only declaration.
        raise MutationPreflightError("mutation path binding is invalid")
    if not grant.permits(candidate.mutation.method, concrete_path):
        raise MutationPreflightError("mutation method or path is not granted")
    base = _base_origin(candidate.target.base_url)
    request_url = urlunsplit((base[0], base[1], concrete_path, "", ""))
    request_shapes = (
        ("GET", request_url),
        (candidate.mutation.method, request_url),
        ("GET", request_url),
        (candidate.mutation.method, request_url),
        ("GET", request_url),
    )
    for method, url in request_shapes:
        try:
            scope_guard.require_allowed(url, method, now=now)
        except ScopeError as error:
            raise MutationPreflightError(
                "scope does not authorize the complete mutation sweep"
            ) from error


def _normalise_method(method: str) -> str:
    if not isinstance(method, str):
        raise MutationPreflightError("mutation method is invalid")
    normalized = method.upper()
    if not re.fullmatch(r"[A-Z]{1,10}", normalized):
        raise MutationPreflightError("mutation method is invalid")
    return normalized


def _validate_relative_template(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or len(value) > 2048
        or not value.isascii()
    ):
        raise MutationPreflightError(f"{label} must be a safe relative path")
    if (
        any(char in value for char in _RELATIVE_PATH_FORBIDDEN)
        or "%" in value
        or "\\" in value
        or "//" in value
    ):
        raise MutationPreflightError(f"{label} must be a safe relative path")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise MutationPreflightError(f"{label} must be a safe relative path")
    if any(segment in {"", ".", ".."} for segment in value.split("/")):
        # The first segment is empty because the path starts with '/'.
        segments = value.split("/")[1:]
        if any(segment in {".", ".."} for segment in segments):
            raise MutationPreflightError(f"{label} contains unsafe traversal")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise MutationPreflightError(f"{label} contains control characters")


def _concrete_path(template: str, object_id: str) -> str:
    if not isinstance(object_id, str) or not object_id or len(object_id) > 512:
        raise MutationPreflightError("candidate target identifier is invalid")
    if any(ord(char) < 0x20 or char in "/?#{}%\\" for char in object_id):
        raise MutationPreflightError("candidate target identifier is invalid")
    encoded = quote(object_id, safe="._:-~")
    concrete = template.replace("{id}", encoded).replace("{object_id}", encoded)
    if "{" in concrete or "}" in concrete:
        raise MutationPreflightError("mutation endpoint template has an unresolved placeholder")
    return concrete


def _base_origin(base_url: str) -> tuple[str, str]:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
        raise MutationPreflightError("candidate target base URL is invalid")
    return parsed.scheme, parsed.netloc


__all__ = [
    "MAX_MUTATION_REQUESTS",
    "MutationCandidate",
    "MutationCandidateInventory",
    "MutationCandidateSet",
    "MutationDiscoveryResult",
    "MutationOperation",
    "MutationOutcome",
    "MutationPreflightError",
    "MutationSweepExecutor",
    "MutationSweepPlan",
    "RecoveryStatus",
    "ScopedExchange",
    "preflight_sweep",
]
