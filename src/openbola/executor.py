"""Authorization-enforced deterministic HTTP probes.

The executor is the only phase that is allowed to perform network I/O.  It
does not use the optional AI planner and it never follows a redirect through
the HTTP client's implicit redirect machinery.  Every hop is checked by the
same :class:`~openbola.scope.ScopeGuard` that checked the initial target.

The default operation is a bounded read probe.  Mutation probes are a
separate, deliberately narrow API: a caller must provide a canary and a
cleanup request, and the scope must grant the exact methods and paths.  A
mutation is never retried automatically.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from typing import Any, NoReturn, SupportsIndex
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from openbola.credentials import CredentialResolutionError, CredentialVault
from openbola.models import CredentialKind, ProbeMode, ProbeResult, ProbeTarget, Verdict
from openbola.scope import ScopeDecision, ScopeError, ScopeGuard

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH"})
_HTTP_METHOD = re.compile(r"[A-Z]{1,10}\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OBJECT_REF = re.compile(r"obj_[0-9a-f]{64}\Z")
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 10_000
_ERROR_CODES = frozenset(
    {
        "timeout",
        "transport_error",
        "invalid_response",
        "scope_denied",
        "rate_limited",
        "redirect_blocked",
    }
)


class ExecutorError(RuntimeError):
    """Raised when a probe cannot be safely constructed or executed."""


class MutationSafetyError(ExecutorError):
    """Raised for an incomplete or potentially destructive mutation spec."""


@dataclass(frozen=True)
class MutationSpec:
    """A reversible, canary-scoped write request.

    ``path`` and ``cleanup_path`` are optional relative templates.  When
    omitted, the target's concrete path is used.  The cleanup request runs in
    a ``finally`` block, even when the mutation response is a transport error.
    The canary is an explicit operator-supplied label; it is never sent as an
    implicit field and is never included in evidence.
    """

    method: str
    canary: str
    cleanup_method: str
    body: bytes | str | Mapping[str, Any] | None = None
    cleanup_body: bytes | str | Mapping[str, Any] | None = None
    path: str | None = None
    cleanup_path: str | None = None
    content_type: str | None = "application/json"
    cleanup_success_statuses: frozenset[int] = frozenset({200, 201, 202, 204})

    def __post_init__(self) -> None:
        method = self.method.upper()
        cleanup_method = self.cleanup_method.upper()
        if method not in _MUTATION_METHODS:
            raise MutationSafetyError("mutation method must be POST, PUT, or PATCH")
        if cleanup_method not in _MUTATION_METHODS | {"DELETE"}:
            raise MutationSafetyError("cleanup method must be a supported mutation method")
        if not self.canary or not _IDENTIFIER.fullmatch(self.canary):
            raise MutationSafetyError("mutation canary must be a non-empty safe identifier")
        if self.path is not None and not self.path.startswith("/"):
            raise MutationSafetyError("mutation path must be relative")
        if self.cleanup_path is not None and not self.cleanup_path.startswith("/"):
            raise MutationSafetyError("cleanup path must be relative")
        if cleanup_method == "DELETE" and self.cleanup_path is None:
            raise MutationSafetyError("cleanup DELETE requires an explicit canary path")
        if cleanup_method == "DELETE" and self.cleanup_path == self.path:
            raise MutationSafetyError("cleanup DELETE must target a distinct canary path")
        if not self.cleanup_success_statuses or any(
            status < 200 or status >= 300 for status in self.cleanup_success_statuses
        ):
            raise MutationSafetyError("cleanup success statuses must be non-empty 2xx values")
        if self.content_type is not None and (
            not self.content_type
            or any(ord(character) < 32 for character in self.content_type)
        ):
            raise MutationSafetyError("mutation content type is invalid")


@dataclass(frozen=True)
class ExecutorLimits:
    """Hard per-executor resource limits."""

    timeout_seconds: float = 15.0
    max_response_bytes: int = 1_048_576
    max_redirects: int = 5
    max_retries: int = 2
    requests_per_second: float = 10.0
    max_requests: int = 100
    max_concurrency: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 300
        ):
            raise ValueError("timeout_seconds must be between 0 and 300")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or self.max_response_bytes < 1
            or self.max_response_bytes > 100 * 1024 * 1024
        ):
            raise ValueError("max_response_bytes is outside the safe range")
        if (
            isinstance(self.max_redirects, bool)
            or not isinstance(self.max_redirects, int)
            or not 0 <= self.max_redirects <= 20
        ):
            raise ValueError("max_redirects is outside the safe range")
        if (
            isinstance(self.max_retries, bool)
            or not isinstance(self.max_retries, int)
            or not 0 <= self.max_retries <= 5
        ):
            raise ValueError("max_retries is outside the safe range")
        if (
            isinstance(self.requests_per_second, bool)
            or not isinstance(self.requests_per_second, (int, float))
            or not math.isfinite(float(self.requests_per_second))
            or self.requests_per_second <= 0
            or self.requests_per_second > 1000
        ):
            raise ValueError("requests_per_second is outside the safe range")
        if (
            isinstance(self.max_requests, bool)
            or not isinstance(self.max_requests, int)
            or not 1 <= self.max_requests <= 100_000
        ):
            raise ValueError("max_requests is outside the safe range")
        if (
            isinstance(self.max_concurrency, bool)
            or not isinstance(self.max_concurrency, int)
            or not 1 <= self.max_concurrency <= 32
        ):
            raise ValueError("max_concurrency is outside the safe range")


@dataclass(frozen=True)
class _ResponseSnapshot:
    status: int
    content_type: str
    object_values: tuple[str, ...]
    body_fingerprint: str
    field_present: bool
    field_scalar: bool
    field_value: str | int | float | None


@dataclass(frozen=True)
class _Exchange:
    response: _ResponseSnapshot | None
    error_code: str | None = None
    retryable: bool = False
    redirect_target: str | None = None
    sent: bool = False
    cleanup_failed: bool = False


@dataclass(frozen=True)
class ScopedExchange:
    """Redacted result of one policy-approved request.

    Response bodies are deliberately not part of this contract.  Callers get
    only the bounded object-field values and a fingerprint calculated while
    the response stream is still open.
    """

    status: int | None
    body_fingerprint: str | None
    object_values: tuple[str, ...] = dataclass_field(repr=False)
    error_code: str | None = None
    sent: bool = False
    field_present: bool = False
    field_scalar: bool = False
    field_value: str | int | float | None = dataclass_field(default=None, repr=False)

    def __reduce__(self) -> NoReturn:
        # A live snapshot can contain the exact value of a sensitive field.
        # It is intentionally process-local and must never cross a pickle or
        # other serialization boundary.
        raise TypeError("Scoped exchanges cannot be serialized.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("Scoped exchanges cannot be serialized.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Scoped exchanges cannot be serialized.")


class _ResponseTooLarge(Exception):
    pass


class _RequestFailure(Exception):
    def __init__(self, code: str, *, retryable: bool, sent: bool) -> None:
        self.code = code
        self.retryable = retryable
        self.sent = sent
        super().__init__(code)


def _object_values(value: Any, field_name: str) -> tuple[str, ...]:
    values: list[str] = []
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON response exceeds comparison limits")
        if isinstance(current, Mapping):
            for key, child in current.items():
                if (
                    str(key) == field_name
                    and isinstance(child, (str, int, float))
                    and not isinstance(child, bool)
                ):
                    values.append(str(child))
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return tuple(values)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _object_ref(object_id: str) -> str:
    """Return the opaque object reference used by state and reporting."""

    if _OBJECT_REF.fullmatch(object_id):
        return object_id
    return "obj_" + hashlib.sha256(object_id.encode("utf-8")).hexdigest()


def _field_material(
    value: Any, field_name: str
) -> tuple[bool, bool, str | int | float | None]:
    """Read only the requested top-level JSON field.

    Nested values are deliberately ignored: selecting the first matching leaf
    from an arbitrary response tree can snapshot an unrelated field.  The
    scalar marker keeps a present ``null``/object/array distinguishable from a
    supported scalar while keeping the redacted exchange contract bounded.
    """

    if not isinstance(value, Mapping) or field_name not in value:
        return False, False, None
    child = value[field_name]
    if isinstance(child, str):
        return True, True, child
    if type(child) is int:
        return True, True, child
    if type(child) is float and math.isfinite(child):
        return True, True, child
    # bool, null, arrays, objects, and non-finite numbers are intentionally
    # present-but-unsupported and must fail closed at the mutation boundary.
    return True, False, None


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys rather than choosing one silently."""

    result: dict[str, Any] = {}
    for key, child in pairs:
        if key in result:
            raise ValueError("duplicate JSON object field")
        result[key] = child
    return result


def _parse_body(
    body: bytes, content_type: str, id_field: str
) -> tuple[tuple[str, ...], str, bool, bool, str | int | float | None]:
    fingerprint = hashlib.sha256(body).hexdigest()
    if "json" not in content_type.lower():
        return (), fingerprint, False, False, None
    try:
        decoded = json.loads(body.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return (), fingerprint, False, False, None
    try:
        canonical = _canonical_json(decoded).encode("utf-8")
    except (RecursionError, TypeError, ValueError):
        return (), fingerprint, False, False, None
    try:
        object_values = _object_values(decoded, id_field)
    except (RecursionError, TypeError, ValueError):
        return (), fingerprint, False, False, None
    field_present, field_scalar, field_value = _field_material(decoded, id_field)
    return (
        object_values,
        hashlib.sha256(canonical).hexdigest(),
        field_present,
        field_scalar,
        field_value,
    )


def _safe_body(value: bytes | str | Mapping[str, Any] | None) -> tuple[bytes | None, str | None]:
    if value is None:
        return None, None
    if isinstance(value, bytes):
        body = value
    elif isinstance(value, str):
        body = value.encode("utf-8")
    else:
        try:
            _object_values(value, "__never_match__")
            body = _canonical_json(value).encode("utf-8")
        except (RecursionError, TypeError, ValueError) as error:
            raise MutationSafetyError("mutation body is not JSON serializable") from error
    if len(body) > 256 * 1024:
        raise MutationSafetyError("mutation body exceeds the safety limit")
    return body, "application/json"


def _fill_url(base_url: str, endpoint_template: str, object_id: str) -> str:
    if not base_url or not endpoint_template or not object_id:
        raise ExecutorError("probe URL components must be non-empty")
    if any(
        ord(character) < 32
        or character.isspace()
        or character in "/\\#?%&="
        for character in object_id
    ):
        raise ExecutorError("object identifier contains unsafe characters")
    base = urlsplit(base_url)
    if base.scheme not in {"http", "https"} or not base.netloc or base.query or base.fragment:
        raise ExecutorError("base URL must be an HTTP(S) origin")
    endpoint = endpoint_template.replace("{id}", object_id, 1)
    if "{" in endpoint or "}" in endpoint:
        raise ExecutorError("endpoint template contains an unresolved placeholder")
    parsed_endpoint = urlsplit(endpoint)
    if parsed_endpoint.scheme or parsed_endpoint.netloc or parsed_endpoint.fragment:
        raise ExecutorError("endpoint template must be a relative path")
    path = parsed_endpoint.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((base.scheme, base.netloc, path, parsed_endpoint.query, ""))


def _origin_key(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("redirect target is not an HTTP(S) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower(), port


class ProbeExecutor:
    """Run one owner-vs-attacker probe through an enforced scope boundary."""

    def __init__(
        self,
        scope_guard: ScopeGuard,
        credential_vault: CredentialVault,
        *,
        limits: ExecutorLimits | None = None,
        transport: httpx.BaseTransport | None = None,
        state_store: Any | None = None,
        run_id: int | None = None,
        now: datetime | Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(scope_guard, ScopeGuard):
            raise TypeError("scope_guard must be a ScopeGuard")
        if not isinstance(credential_vault, CredentialVault):
            raise TypeError("credential_vault must be a CredentialVault")
        self.scope_guard = scope_guard
        self.credential_vault = credential_vault
        self.limits = limits or ExecutorLimits()
        self.transport = transport
        self.state_store = state_store
        self.run_id = run_id
        if callable(now):
            self._clock = now
        elif now is not None:
            self._clock = lambda: now
        else:
            self._clock = lambda: datetime.now(UTC)
        self._semaphore = threading.BoundedSemaphore(self.limits.max_concurrency)
        self._request_lock = threading.Lock()
        self._request_count = 0
        self._reserved_requests = 0
        self._last_request_at = 0.0

    def run(self, target: ProbeTarget, *, mutation: MutationSpec | None = None) -> ProbeResult:
        """Execute and optionally persist one deterministic probe result."""
        self._validate_target(target, mutation)
        if not self._semaphore.acquire(timeout=self.limits.timeout_seconds):
            return self._finish(
                ProbeResult(
                    target=target,
                    verdict=Verdict.INCONCLUSIVE,
                    owner_status=None,
                    attacker_status=None,
                    evidence={"error_code": "rate_limited", "retryable": True},
                    retryable=True,
                )
            )
        try:
            return self._run_locked(target, mutation)
        finally:
            self._semaphore.release()

    def request_scoped(
        self,
        target: ProbeTarget,
        credential: Any,
        *,
        method: str,
        endpoint_template: str,
        body: bytes | str | Mapping[str, Any] | None,
        content_type: str | None,
        id_field: str,
    ) -> ScopedExchange:
        """Dispatch exactly one request through this executor's policy boundary.

        This is intentionally package-visible API for mutation and recovery
        phases.  It is not a second HTTP client: URL construction, redirect
        handling, peer checks, credential resolution, rate limiting and
        response bounds all remain in the executor's existing path.
        """

        if type(target) is not ProbeTarget:
            raise ExecutorError("scoped request target is invalid")
        if not isinstance(method, str) or not _HTTP_METHOD.fullmatch(method):
            raise ExecutorError("scoped request method is invalid")
        if method != method.upper():
            raise ExecutorError("scoped request method must be uppercase")
        if not isinstance(id_field, str) or not id_field or len(id_field) > 256:
            raise ExecutorError("scoped request field is invalid")
        if "?" in endpoint_template or "#" in endpoint_template:
            # ScopeGuard authorizes URL paths, not query-string policy.  A
            # scoped mutation/recovery request therefore cannot smuggle an
            # unbound query or fragment through this primitive.
            raise ExecutorError("scoped request endpoint must be path-only")
        if credential not in (target.owner_credential, target.attacker_credential):
            raise ExecutorError("scoped request credential is not bound to target")
        if credential.identity not in {target.owner_identity, target.attacker_identity}:
            raise ExecutorError("scoped request credential identity is invalid")
        request_url = _fill_url(target.base_url, endpoint_template, target.object_id)
        request_body, default_content_type = _safe_body(body)
        request_content_type = content_type or default_content_type
        exchange = self._request_with_redirects(
            method,
            request_url,
            credential,
            id_field,
            body=request_body,
            content_type=request_content_type,
            # Redirects are never delegated to httpx.  Safe reads may be
            # followed by our explicit per-hop guard; writes stop at the
            # first redirect and therefore cannot be replayed.
            allow_redirects=method in _SAFE_METHODS,
        )
        return ScopedExchange(
            status=exchange.response.status if exchange.response is not None else None,
            body_fingerprint=(
                exchange.response.body_fingerprint if exchange.response is not None else None
            ),
            object_values=(
                exchange.response.object_values if exchange.response is not None else ()
            ),
            error_code=exchange.error_code,
            sent=exchange.sent,
            field_present=(
                exchange.response.field_present if exchange.response is not None else False
            ),
            field_scalar=(
                exchange.response.field_scalar if exchange.response is not None else False
            ),
            field_value=(exchange.response.field_value if exchange.response is not None else None),
        )

    def _run_locked(self, target: ProbeTarget, mutation: MutationSpec | None) -> ProbeResult:
        try:
            owner_url = _fill_url(target.base_url, target.endpoint_template, target.object_id)
        except ExecutorError:
            return self._finish(self._failed(target, "invalid_response", retryable=False))
        owner = self._identity_exchange(target, target.owner_credential, owner_url, mutation)
        if mutation is not None and (owner.cleanup_failed or owner.error_code is not None):
            attacker = _Exchange(None, "invalid_response", False)
        else:
            attacker = self._identity_exchange(
                target, target.attacker_credential, owner_url, mutation
            )
        verdict, comparison = self._compare(target, owner, attacker)
        evidence: dict[str, Any] = {
            "object_ref": _object_ref(target.object_id),
            "comparison": comparison,
        }
        if owner.response is not None:
            evidence["owner_status"] = owner.response.status
        if attacker.response is not None:
            evidence["attacker_status"] = attacker.response.status
        error_code = attacker.error_code or owner.error_code
        if error_code is not None:
            evidence["error_code"] = error_code
        retryable = owner.retryable or attacker.retryable
        evidence["retryable"] = retryable
        return self._finish(
            ProbeResult(
                target=target,
                verdict=verdict,
                owner_status=owner.response.status if owner.response else None,
                attacker_status=attacker.response.status if attacker.response else None,
                evidence=evidence,
                retryable=retryable,
            )
        )

    def _finish(self, result: ProbeResult) -> ProbeResult:
        if self.state_store is not None:
            self.state_store.record_probe_result(result, run_id=self.run_id)
        return result

    @staticmethod
    def _failed(target: ProbeTarget, code: str, *, retryable: bool) -> ProbeResult:
        if code not in _ERROR_CODES:
            code = "invalid_response"
        return ProbeResult(
            target=target,
            verdict=Verdict.INCONCLUSIVE,
            owner_status=None,
            attacker_status=None,
            evidence={"error_code": code, "retryable": retryable},
            retryable=retryable,
        )

    @staticmethod
    def _validate_target(target: ProbeTarget, mutation: MutationSpec | None) -> None:
        if target.owner_identity == target.attacker_identity:
            raise ExecutorError("owner and attacker identities must differ")
        if target.owner_credential.identity != target.owner_identity:
            raise ExecutorError("owner credential identity does not match target")
        if target.attacker_credential.identity != target.attacker_identity:
            raise ExecutorError("attacker credential identity does not match target")
        if not _HTTP_METHOD.fullmatch(target.method) or target.method != target.method.upper():
            raise ExecutorError("probe method must be uppercase")
        if target.mode is ProbeMode.READ and mutation is not None:
            raise MutationSafetyError("a read target cannot carry a mutation spec")
        if target.mode is ProbeMode.MUTATION and mutation is None:
            raise MutationSafetyError("mutation target requires an explicit reversible spec")
        if target.mode is ProbeMode.READ and target.method not in _SAFE_METHODS:
            raise ExecutorError("read probes are limited to safe HTTP methods")
        if target.mode is ProbeMode.MUTATION and target.method not in _MUTATION_METHODS:
            raise MutationSafetyError("mutation target method is not reversible")
        if mutation is not None and mutation.method.upper() != target.method:
            raise MutationSafetyError("mutation spec method must match the probe target method")
        if mutation is not None:
            if mutation.cleanup_method.upper() == "DELETE" and mutation.cleanup_path in {
                target.endpoint_template,
                mutation.path,
            }:
                raise MutationSafetyError("cleanup DELETE must target a distinct canary path")
            mutation_body, _ = _safe_body(mutation.body)
            if mutation_body is None or mutation.canary.encode("utf-8") not in mutation_body:
                raise MutationSafetyError("mutation body must carry the declared canary")
            cleanup_body, _ = _safe_body(mutation.cleanup_body)
            cleanup_template = mutation.cleanup_path or mutation.path or target.endpoint_template
            if (
                (cleanup_body is None or mutation.canary.encode("utf-8") not in cleanup_body)
                and mutation.canary not in cleanup_template
            ):
                raise MutationSafetyError("cleanup must be bound to the declared canary")

    def _identity_exchange(
        self,
        target: ProbeTarget,
        credential: Any,
        url: str,
        mutation: MutationSpec | None,
    ) -> _Exchange:
        method = target.method
        body: bytes | None = None
        content_type: str | None = None
        request_url = url
        cleanup: tuple[str, str, bytes | None, str | None, frozenset[int]] | None = None
        if mutation is not None:
            body, default_content_type = _safe_body(mutation.body)
            content_type = mutation.content_type or default_content_type
            request_url = _fill_url(
                target.base_url,
                mutation.path or target.endpoint_template,
                target.object_id,
            )
            cleanup_path = mutation.cleanup_path or mutation.path or target.endpoint_template
            cleanup_url = _fill_url(target.base_url, cleanup_path, target.object_id)
            cleanup_body, cleanup_default_type = _safe_body(mutation.cleanup_body)
            cleanup_type = mutation.content_type or cleanup_default_type
            cleanup = (
                mutation.cleanup_method.upper(),
                cleanup_url,
                cleanup_body,
                cleanup_type,
                mutation.cleanup_success_statuses,
            )
            method = mutation.method.upper()
            reservation = [2]
            dispatch_started = [False]
            if not self._reserve_budget(2):
                return _Exchange(None, "rate_limited", False)
        if cleanup is None:
            return self._request_with_redirects(
                method,
                request_url,
                credential,
                target.id_field,
                body=body,
                content_type=content_type,
                allow_redirects=True,
                reservation=None,
            )

        exchange: _Exchange | None = None
        primary_exception: BaseException | None = None
        cleanup_result: _Exchange | None = None
        cleanup_exception: BaseException | None = None
        try:
            exchange = self._request_with_redirects(
                method,
                request_url,
                credential,
                target.id_field,
                body=body,
                content_type=content_type,
                allow_redirects=False,
                reservation=reservation,
                dispatch_started=dispatch_started,
            )
        except BaseException as error:
            primary_exception = error
        finally:
            if (exchange is not None and exchange.sent) or dispatch_started[0]:
                try:
                    cleanup_result = self._request_with_redirects(
                        cleanup[0],
                        cleanup[1],
                        credential,
                        target.id_field,
                        body=cleanup[2],
                        content_type=cleanup[3],
                        allow_redirects=False,
                        reservation=reservation,
                    )
                except BaseException as error:
                    cleanup_exception = error

        try:
            if primary_exception is not None and not isinstance(primary_exception, Exception):
                exchange = _Exchange(None, "transport_error", False, sent=True)
            if exchange is None:
                exchange = _Exchange(None, "invalid_response", False)
            if not exchange.sent:
                return _Exchange(
                    response=exchange.response,
                    error_code=exchange.error_code or "invalid_response",
                    retryable=exchange.retryable,
                )
            if cleanup_exception is not None or cleanup_result is None:
                return _Exchange(
                    response=exchange.response,
                    error_code="invalid_response",
                    retryable=exchange.retryable,
                    cleanup_failed=True,
                )
            if (
                cleanup_result.error_code is not None
                or cleanup_result.response is None
                or cleanup_result.response.status not in cleanup[4]
            ):
                return _Exchange(
                    response=exchange.response,
                    error_code="invalid_response",
                    retryable=exchange.retryable or cleanup_result.retryable,
                    cleanup_failed=True,
                )
            return exchange
        finally:
            self._release_budget(reservation[0])

    def _request_with_redirects(
        self,
        method: str,
        url: str,
        credential: Any,
        id_field: str,
        *,
        body: bytes | None,
        content_type: str | None,
        allow_redirects: bool,
        reservation: list[int] | None = None,
        dispatch_started: list[bool] | None = None,
    ) -> _Exchange:
        current_method = method
        current_url = url
        try:
            origin = _origin_key(url)
        except ValueError:
            return _Exchange(None, "scope_denied", False)
        redirects = 0
        retries = 0
        while True:
            try:
                exchange = self._request_once(
                    current_method,
                    current_url,
                    credential,
                    id_field,
                    body=body,
                    content_type=content_type,
                    reservation=reservation,
                    dispatch_started=dispatch_started,
                )
            except ScopeError:
                if redirects:
                    return _Exchange(None, "redirect_blocked", False, current_url, True)
                return _Exchange(None, "scope_denied", False)
            except _RequestFailure as failure:
                if (
                    current_method in _SAFE_METHODS
                    and failure.retryable
                    and retries < self.limits.max_retries
                ):
                    retries += 1
                    continue
                return _Exchange(
                    None,
                    failure.code,
                    failure.retryable,
                    sent=failure.sent,
                )
            except _ResponseTooLarge:
                return _Exchange(None, "invalid_response", False)
            except httpx.TimeoutException:
                if current_method in _SAFE_METHODS and retries < self.limits.max_retries:
                    retries += 1
                    continue
                return _Exchange(None, "timeout", current_method in _SAFE_METHODS)
            except httpx.TransportError:
                if current_method in _SAFE_METHODS and retries < self.limits.max_retries:
                    retries += 1
                    continue
                return _Exchange(None, "transport_error", current_method in _SAFE_METHODS)
            response = exchange.response
            if response is None:
                return exchange
            if response.status == 429:
                if current_method in _SAFE_METHODS and retries < self.limits.max_retries:
                    retries += 1
                    continue
                return _Exchange(
                    response,
                    "rate_limited",
                    current_method in _SAFE_METHODS,
                    sent=True,
                )
            if response.status not in {301, 302, 303, 307, 308}:
                return exchange
            location = exchange.redirect_target
            if not location:
                return _Exchange(response, "redirect_blocked", False, sent=True)
            if not allow_redirects or redirects >= self.limits.max_redirects:
                return _Exchange(response, "redirect_blocked", False, location, True)
            next_url = urljoin(current_url, location)
            next_method = (
                "GET" if response.status in {301, 302, 303} else current_method
            )
            try:
                # Check policy before the origin boundary so every redirect
                # target receives an explicit ScopeGuard decision, even when
                # credentials will be withheld due to a cross-origin hop.
                self.scope_guard.require_allowed(next_url, next_method, now=self._clock())
            except ScopeError:
                return _Exchange(response, "redirect_blocked", False, next_url, True)
            try:
                if _origin_key(next_url) != origin:
                    return _Exchange(response, "redirect_blocked", False, next_url, True)
            except ValueError:
                return _Exchange(response, "redirect_blocked", False, next_url, True)
            if response.status in {301, 302, 303}:
                if current_method not in _SAFE_METHODS:
                    return _Exchange(response, "redirect_blocked", False, next_url, True)
                current_method = "GET"
                body = None
                content_type = None
            current_url = next_url
            redirects += 1

    def _request_once(
        self,
        method: str,
        url: str,
        credential: Any,
        id_field: str,
        *,
        body: bytes | None,
        content_type: str | None,
        reservation: list[int] | None = None,
        dispatch_started: list[bool] | None = None,
    ) -> _Exchange:
        decision = self.scope_guard.require_allowed(url, method, now=self._clock())
        self._ensure_peer_policy(decision)
        try:
            headers = self._credential_headers(credential)
        except httpx.TransportError as error:
            raise _RequestFailure("transport_error", retryable=False, sent=False) from error
        if content_type is not None:
            headers["Content-Type"] = content_type
        with self._request_lock:
            if reservation is not None and reservation[0] > 0:
                reservation[0] -= 1
                self._reserved_requests -= 1
            elif self._request_count >= self.limits.max_requests:
                return _Exchange(None, "rate_limited", True)
            now = time.monotonic()
            interval = 1.0 / self.limits.requests_per_second
            wait = interval - (now - self._last_request_at)
            if wait > 0:
                time.sleep(wait)
            self._request_count += 1
            self._last_request_at = time.monotonic()
        sent = True
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            if dispatch_started is not None:
                dispatch_started[0] = True
            try:
                return asyncio.run(
                    self._async_request(
                        method,
                        decision.canonical_url,
                        headers,
                        body,
                        id_field,
                    )
                )
            except TimeoutError as error:
                raise _RequestFailure(
                    "timeout", retryable=method in _SAFE_METHODS, sent=sent
                ) from error
            except httpx.TimeoutException as error:
                raise _RequestFailure(
                    "timeout", retryable=method in _SAFE_METHODS, sent=sent
                ) from error
            except httpx.TransportError as error:
                raise _RequestFailure(
                    "transport_error", retryable=method in _SAFE_METHODS, sent=sent
                ) from error
            except _ResponseTooLarge as error:
                raise _RequestFailure("invalid_response", retryable=False, sent=sent) from error
            except Exception as error:
                raise _RequestFailure(
                    "transport_error", retryable=False, sent=sent
                ) from error
            except BaseException as error:
                # A cancellation/interrupt after dispatch may have reached the
                # target. Preserve that fact so mutation cleanup is attempted.
                raise _RequestFailure(
                    "transport_error", retryable=False, sent=sent
                ) from error
        raise _RequestFailure(
            "transport_error", retryable=False, sent=False
        )

    async def _async_request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        id_field: str,
    ) -> _Exchange:
        timeout = httpx.Timeout(self.limits.timeout_seconds)
        client_kwargs: dict[str, Any] = {
            "follow_redirects": False,
            "timeout": timeout,
            "trust_env": False,
        }
        if self.transport is not None:
            client_kwargs["transport"] = self.transport
        async with asyncio.timeout(self.limits.timeout_seconds):
            async with httpx.AsyncClient(**client_kwargs) as client:
                async with client.stream(method, url, headers=headers, content=body) as response:
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > self.limits.max_response_bytes:
                            raise _ResponseTooLarge
                    response_body = bytes(data)
                    content_type_header = response.headers.get("content-type", "")
                    (
                        object_values,
                        body_fingerprint,
                        field_present,
                        field_scalar,
                        field_value,
                    ) = _parse_body(
                        response_body, content_type_header, id_field
                    )
                    return _Exchange(
                        _ResponseSnapshot(
                            status=response.status_code,
                            content_type=content_type_header.split(";", 1)[0].strip().lower(),
                            object_values=object_values,
                            body_fingerprint=body_fingerprint,
                            field_present=field_present,
                            field_scalar=field_scalar,
                            field_value=field_value,
                        ),
                        redirect_target=response.headers.get("location"),
                        sent=True,
                    )

    def _reserve_budget(self, count: int) -> bool:
        with self._request_lock:
            if self._request_count + self._reserved_requests + count > self.limits.max_requests:
                return False
            self._reserved_requests += count
            return True

    def _release_budget(self, count: int) -> None:
        with self._request_lock:
            self._reserved_requests = max(0, self._reserved_requests - count)

    @staticmethod
    def _ensure_peer_policy(decision: ScopeDecision) -> None:
        try:
            ipaddress.ip_address(decision.hostname)
        except ValueError:
            if decision.connect_ips:
                raise ScopeError(
                    "hostname CIDR targets require a proven peer-pinning transport"
                ) from None

    def _credential_headers(self, credential: Any) -> dict[str, str]:
        try:
            value = self.credential_vault.resolve(credential)
        except CredentialResolutionError as error:
            raise httpx.TransportError("credential reference could not be resolved") from error
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise httpx.TransportError("credential contains unsafe control characters")
        if credential.kind is CredentialKind.BEARER:
            return {"Authorization": f"Bearer {value}"}
        if not _HEADER_NAME.fullmatch(credential.name):
            raise httpx.TransportError("credential header name is invalid")
        if credential.kind is CredentialKind.HEADER:
            return {credential.name: value}
        if credential.kind is CredentialKind.COOKIE:
            if ";" in value or "=" in credential.name:
                raise httpx.TransportError("credential cookie is invalid")
            return {"Cookie": f"{credential.name}={value}"}
        raise httpx.TransportError("unsupported credential kind")

    @staticmethod
    def _compare(target: ProbeTarget, owner: _Exchange, attacker: _Exchange) -> tuple[Verdict, str]:
        if owner.error_code is not None or attacker.error_code is not None:
            return Verdict.INCONCLUSIVE, "response_shape_mismatch"
        if owner.response is None or owner.response.status < 200 or owner.response.status >= 300:
            return Verdict.INCONCLUSIVE, "response_shape_mismatch"
        if attacker.response is None:
            return Verdict.INCONCLUSIVE, "response_shape_mismatch"
        if attacker.response.status in {401, 403, 404}:
            return Verdict.PROTECTED, "response_shape_mismatch"
        if not 200 <= attacker.response.status < 300:
            return Verdict.INCONCLUSIVE, "response_shape_mismatch"
        same = (
            bool(owner.response.object_values)
            and bool(attacker.response.object_values)
            and target.object_id in owner.response.object_values
            and target.object_id in attacker.response.object_values
            and set(owner.response.object_values) == set(attacker.response.object_values)
        )
        return (
            (Verdict.BOLA, "object_id_match")
            if same
            else (Verdict.INCONCLUSIVE, "object_id_mismatch")
        )


def run_test(
    target: ProbeTarget,
    *,
    scope_guard: ScopeGuard,
    credential_vault: CredentialVault,
    limits: ExecutorLimits | None = None,
    transport: httpx.BaseTransport | None = None,
    state_store: Any | None = None,
    run_id: int | None = None,
    mutation: MutationSpec | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> ProbeResult:
    """Convenience wrapper retained for callers of the original plan API."""

    return ProbeExecutor(
        scope_guard,
        credential_vault,
        limits=limits,
        transport=transport,
        state_store=state_store,
        run_id=run_id,
        now=now,
    ).run(target, mutation=mutation)


# Descriptive aliases make the execution boundary discoverable to integrations
# while keeping the shared dataclass contracts in ``models.py`` authoritative.
DeterministicExecutor = ProbeExecutor
TestTarget = ProbeTarget
TestResult = ProbeResult
run_probe = run_test


__all__ = [
    "ExecutorError",
    "ExecutorLimits",
    "DeterministicExecutor",
    "MutationSafetyError",
    "MutationSpec",
    "ProbeExecutor",
    "ScopedExchange",
    "TestResult",
    "TestTarget",
    "run_probe",
    "run_test",
]
