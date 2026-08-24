"""Fail-closed structural browser capture and bounded HAR import for phase 1."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import stat
import struct
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Literal, NoReturn, Protocol, TypeVar, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from openbola.discovery import FieldInventory, ProviderConfidence, ResourceInventory
from openbola.handles import SecretHandle, SessionValueStore, ValueHandle
from openbola.models import RequestRecord
from openbola.scope import ScopeDecision, ScopeError, ScopeGuard

DEFAULT_MAX_HAR_BYTES = 25 * 1024 * 1024
_REDACTED = "[REDACTED]"
_MAX_CAPTURE_ENTRIES = 10_000
_MAX_FULL_BODY_BYTES = 1024 * 1024
_MAX_FULL_STATE_BYTES = 1024 * 1024
_MAX_FULL_SESSION_BYTES = 25 * 1024 * 1024
_SAFE_FULL_CAPTURE_ERRORS = frozenset(
    {
        "full capture body exceeds the safe limit",
        "full capture event stream is incomplete",
        "full capture session material exceeds the safe limit",
    }
)
_MAX_URL_CHARS = 16_384
_MAX_QUERY_FIELDS = 256
_MAX_HEADER_COUNT = 256
_MAX_HEADER_NAME_CHARS = 256
_MAX_HEADER_VALUE_CHARS = 16_384
_MAX_BODY_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 4_096
_MAX_JSON_KEY_CHARS = 256
_HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z")
_URL_HEADERS = frozenset({"location", "content-location"})


class _StructuralLimitExceeded(ValueError):
    """Raised internally when structural JSON retention exceeds safe bounds."""


class CaptureError(ValueError):
    """Raised when capture configuration or HAR input is unsafe or invalid."""


@dataclass(frozen=True)
class CaptureConfig:
    target_url: str = field(repr=False)
    capture_root: Path
    output_path: Path
    identity: str
    headless: bool = True
    interactive_login: bool = False
    max_har_bytes: int = DEFAULT_MAX_HAR_BYTES
    login_recipe: LoginRecipe | None = None

    def __post_init__(self) -> None:
        _validate_target_url(self.target_url)
        _validated_output_path(self.capture_root, self.output_path)
        if not self.identity.strip():
            raise CaptureError("identity must not be empty")
        if self.interactive_login and self.headless:
            raise CaptureError("interactive_login requires headless=False")
        if self.max_har_bytes <= 0:
            raise CaptureError("max_har_bytes must be greater than zero")
        if self.login_recipe is not None and self.interactive_login:
            raise CaptureError("login_recipe and interactive_login are mutually exclusive")
        if self.login_recipe is not None and not isinstance(self.login_recipe, LoginRecipe):
            raise CaptureError("login_recipe must be a LoginRecipe")


_LOGIN_SECRET_FIELD_KINDS = frozenset({"static", "totp"})


@dataclass(frozen=True)
class LoginSecretField:
    """One extra credential-bearing field a login recipe fills, e.g. a TOTP code."""

    selector: str
    secret: SecretHandle
    kind: Literal["static", "totp"] = "static"

    def __post_init__(self) -> None:
        if not self.selector.strip():
            raise CaptureError("LoginSecretField selector must not be empty")
        if not isinstance(self.secret, SecretHandle):
            raise CaptureError("LoginSecretField secret must be a SecretHandle")
        if self.kind not in _LOGIN_SECRET_FIELD_KINDS:
            allowed = sorted(_LOGIN_SECRET_FIELD_KINDS)
            raise CaptureError(f"LoginSecretField kind must be one of {allowed}")


@dataclass(frozen=True)
class LoginRecipe:
    """Selectors, URL patterns, and secret handles for one automated login flow."""

    name: str
    start_url: str = field(repr=False)
    username_selector: str
    password_selector: str
    submit_selector: str
    success_url_pattern: str
    username_secret: SecretHandle
    password_secret: SecretHandle
    extra_secret_fields: tuple[LoginSecretField, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise CaptureError("LoginRecipe name must not be empty")
        try:
            _validate_target_url(self.start_url)
        except CaptureError as exc:
            raise CaptureError("LoginRecipe start_url is unsafe") from exc
        for field_name in ("username_selector", "password_selector", "submit_selector"):
            if not getattr(self, field_name).strip():
                raise CaptureError(f"LoginRecipe {field_name} must not be empty")
        if not self.success_url_pattern.strip():
            raise CaptureError("LoginRecipe success_url_pattern must not be empty")
        for secret_field_name in ("username_secret", "password_secret"):
            if not isinstance(getattr(self, secret_field_name), SecretHandle):
                raise CaptureError(f"LoginRecipe {secret_field_name} must be a SecretHandle")
        if not isinstance(self.extra_secret_fields, tuple) or not all(
            isinstance(item, LoginSecretField) for item in self.extra_secret_fields
        ):
            raise CaptureError(
                "LoginRecipe extra_secret_fields must be a tuple of LoginSecretField"
            )


@dataclass(frozen=True)
class SessionRequestMaterial:
    """Raw request data retained only in an active session value store."""

    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None = field(repr=False)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Session request material serialization is disabled.")


@dataclass(frozen=True)
class SessionResponseMaterial:
    """Raw response data retained only in an active session value store."""

    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None = field(repr=False)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Session response material serialization is disabled.")


@dataclass(frozen=True)
class SessionExchange:
    """A sanitized record and opaque handles to its full-fidelity material."""

    record: RequestRecord
    request_material_handle: ValueHandle
    response_material_handle: ValueHandle


@dataclass(frozen=True, slots=True, repr=False)
class AdapterRecordView:
    """Ephemeral adapter input with raw bodies valid only in one callback."""

    record: RequestRecord
    request_body: bytes | None = field(repr=False)
    response_body: bytes | None = field(repr=False)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Adapter record view serialization is disabled.")


_SessionMaterial = TypeVar("_SessionMaterial", SessionRequestMaterial, SessionResponseMaterial)


@dataclass(frozen=True, init=False)
class InSessionCapture:
    """Handle-only view of full-fidelity capture data for one active session."""

    har_path: Path
    exchanges: tuple[SessionExchange, ...]
    browser_state_handle: ValueHandle
    _registry: SessionValueStore = field(init=False, repr=False, compare=False)
    _closed: bool = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        har_path: Path,
        exchanges: tuple[SessionExchange, ...],
        browser_state_handle: ValueHandle,
        registry: SessionValueStore,
    ) -> None:
        if not isinstance(har_path, Path) or not har_path.is_file() or har_path.is_symlink():
            raise CaptureError("capture HAR path must be a regular non-symlink file")
        if not isinstance(exchanges, tuple) or not exchanges:
            raise CaptureError("capture exchanges must be a non-empty tuple")
        if not isinstance(registry, SessionValueStore):
            raise CaptureError("capture registry must be a SessionValueStore")
        for exchange in exchanges:
            if not isinstance(exchange, SessionExchange) or not isinstance(
                exchange.record, RequestRecord
            ):
                raise CaptureError("capture exchanges must contain SessionExchange records")
            self._require_session_handle(exchange.request_material_handle, "request material")
            self._require_session_handle(exchange.response_material_handle, "response material")
        self._require_session_handle(browser_state_handle, "browser state")

        object.__setattr__(self, "har_path", har_path)
        object.__setattr__(self, "exchanges", exchanges)
        object.__setattr__(self, "browser_state_handle", browser_state_handle)
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "_closed", False)

    def __reduce__(self) -> NoReturn:
        raise TypeError("InSessionCapture serialization is disabled.")

    def request_material(self, exchange: SessionExchange) -> SessionRequestMaterial:
        self._require_open()
        owned_exchange = self._require_owned_exchange(exchange)
        return self._resolve_material(
            owned_exchange.request_material_handle,
            SessionRequestMaterial,
            "request material",
        )

    def response_material(self, exchange: SessionExchange) -> SessionResponseMaterial:
        self._require_open()
        owned_exchange = self._require_owned_exchange(exchange)
        return self._resolve_material(
            owned_exchange.response_material_handle,
            SessionResponseMaterial,
            "response material",
        )

    def browser_state(self) -> Mapping[str, object]:
        self._require_open()
        value = self._resolve_value(self.browser_state_handle, "browser state")
        if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
            raise CaptureError("browser state is malformed")
        return value

    def with_adapter_records(
        self,
        consumer: Callable[[Sequence[AdapterRecordView]], tuple[ResourceInventory, ...]],
    ) -> tuple[ResourceInventory, ...]:
        self._require_open()
        adapter_views: tuple[AdapterRecordView, ...] = ()
        try:
            adapter_views = tuple(
                AdapterRecordView(
                    record=exchange.record,
                    request_body=self.request_material(exchange).body,
                    response_body=self.response_material(exchange).body,
                )
                for exchange in self.exchanges
            )
            try:
                result = consumer(adapter_views)
            except Exception:
                raise CaptureError("session adapter failed") from None
            if not self._is_safe_adapter_result(result):
                raise CaptureError("session adapter result must be a ResourceInventory tuple")
            return result
        finally:
            adapter_views = ()

    def close(self) -> None:
        if not self._closed:
            object.__setattr__(self, "_closed", True)
            self._registry.close()

    def _require_open(self) -> None:
        if self._closed:
            raise CaptureError("in-session capture is closed")

    def _require_owned_exchange(self, exchange: SessionExchange) -> SessionExchange:
        if not isinstance(exchange, SessionExchange) or not any(
            exchange is owned_exchange for owned_exchange in self.exchanges
        ):
            raise CaptureError("exchange does not belong to this capture")
        return exchange

    @staticmethod
    def _require_session_handle(handle: ValueHandle, label: str) -> None:
        if not isinstance(handle, ValueHandle) or handle.kind != "session_state":
            raise CaptureError(f"{label} handle must be a session_state handle")

    def _resolve_value(self, handle: ValueHandle, label: str) -> object:
        self._require_session_handle(handle, label)
        try:
            return self._registry.resolve_value(handle)
        except Exception:
            raise CaptureError(f"{label} is unavailable") from None

    def _resolve_material(
        self,
        handle: ValueHandle,
        expected_type: type[_SessionMaterial],
        label: str,
    ) -> _SessionMaterial:
        value = self._resolve_value(handle, label)
        if not isinstance(value, expected_type) or not self._is_well_formed_material(value):
            raise CaptureError(f"{label} is malformed")
        return value

    @staticmethod
    def _is_well_formed_material(
        value: SessionRequestMaterial | SessionResponseMaterial,
    ) -> bool:
        try:
            headers_are_valid = isinstance(value.headers, Mapping) and all(
                isinstance(name, str) and isinstance(header_value, str)
                for name, header_value in value.headers.items()
            )
            body_is_valid = value.body is None or isinstance(value.body, bytes)
            if isinstance(value, SessionRequestMaterial):
                return isinstance(value.url, str) and headers_are_valid and body_is_valid
            return (
                isinstance(value.status, int)
                and not isinstance(value.status, bool)
                and 0 <= value.status <= 999
                and headers_are_valid
                and body_is_valid
            )
        except Exception:
            return False

    @staticmethod
    def _is_safe_adapter_result(value: object) -> bool:
        return type(value) is tuple and all(
            InSessionCapture._is_safe_resource_inventory(item) for item in value
        )

    @staticmethod
    def _is_safe_resource_inventory(value: object) -> bool:
        if type(value) is not ResourceInventory or set(vars(value)) != {
            "provider",
            "provider_confidence",
            "resource_name",
            "endpoint_template",
            "fields",
            "record_handles",
            "observed_methods",
        }:
            return False
        return (
            type(value.provider) is str
            and type(value.provider_confidence) is ProviderConfidence
            and type(value.resource_name) is str
            and type(value.endpoint_template) is str
            and type(value.fields) is tuple
            and all(InSessionCapture._is_safe_field_inventory(field) for field in value.fields)
            and type(value.record_handles) is tuple
            and all(
                InSessionCapture._is_safe_value_handle(handle)
                for handle in value.record_handles
            )
            and type(value.observed_methods) is frozenset
            and all(type(method) is str for method in value.observed_methods)
        )

    @staticmethod
    def _is_safe_field_inventory(value: object) -> bool:
        return (
            type(value) is FieldInventory
            and set(vars(value)) == {"name"}
            and type(value.name) is str
        )

    @staticmethod
    def _is_safe_value_handle(value: object) -> bool:
        return (
            type(value) is ValueHandle
            and set(vars(value)) == {"id", "kind"}
            and type(value.id) is str
            and type(value.kind) is str
            and value.kind in {"record_id", "field_value", "body", "session_state"}
        )


class CaptureCollector(Protocol):
    def attach(self, context: Any) -> None: ...
    async def entries(self) -> list[dict[str, Any]]: ...


@dataclass
class InMemoryEventCollector:
    """Retain only sanitized event metadata; never a raw HAR or response body."""

    _entries: dict[int, dict[str, Any]] = field(default_factory=dict)
    _limit_exceeded: bool = False

    def attach(self, context: Any) -> None:
        context.on("request", self._on_request)
        context.on("response", self._on_response)

    def _on_request(self, request: Any) -> None:
        request_id = id(request)
        if request_id not in self._entries and len(self._entries) >= _MAX_CAPTURE_ENTRIES:
            self._limit_exceeded = True
            return
        headers = dict(request.headers)
        request_data: dict[str, Any] = {
            "method": str(request.method),
            "url": _sanitize_url(str(request.url)),
            "headers": _headers_to_har(headers),
        }
        raw_post_data = getattr(request, "post_data", None)
        post_data = _sanitize_body(raw_post_data, headers)
        if post_data is not None:
            request_data["postData"] = {
                "mimeType": _request_mime_type(headers, raw_post_data),
                "text": post_data.decode("utf-8", errors="replace"),
            }
        self._entries[request_id] = {
            "request": request_data,
            "response": {"status": 0, "headers": [], "content": {}},
        }

    def _on_response(self, response: Any) -> None:
        entry = self._entries.get(id(response.request))
        if entry is not None:
            entry["response"] = {
                "status": int(response.status),
                "headers": _headers_to_har(dict(response.headers)),
                "content": {},
            }

    async def entries(self) -> list[dict[str, Any]]:
        if self._limit_exceeded:
            raise CaptureError("capture exceeds the safe entry count limit")
        return list(self._entries.values())


class _FullFidelityEventCollector:
    """Collect raw browser material behind opaque, process-local handles."""

    def __init__(self, registry: SessionValueStore) -> None:
        self._registry = registry
        self._requests: dict[int, tuple[SessionRequestMaterial, ValueHandle]] = {}
        self._request_order: list[int] = []
        self._responses: dict[int, tuple[SessionResponseMaterial, ValueHandle]] = {}
        self._response_tasks: dict[int, asyncio.Task[None]] = {}
        self._task_errors: list[BaseException] = []
        self._stream_incomplete = False
        self._total_bytes = 0
        self._lock = RLock()
        self._sanitized_entries: list[dict[str, Any]] | None = None
        self._identity: str | None = None

    def attach(self, context: Any) -> None:
        context.on("request", self._on_request)
        context.on("response", self._on_response)

    def set_sanitized_entries(self, entries: list[dict[str, Any]], identity: str) -> None:
        self._sanitized_entries = entries
        self._identity = identity

    def _on_request(self, request: Any) -> None:
        request_id = id(request)
        with self._lock:
            if request_id in self._requests:
                self._stream_incomplete = True
                return
            if len(self._requests) >= _MAX_CAPTURE_ENTRIES:
                self._stream_incomplete = True
                return
        try:
            url = request.url
            headers = request.headers
            body = self._request_body(request)
            if not isinstance(url, str) or not isinstance(headers, Mapping):
                raise CaptureError("full capture event stream is incomplete")
            normalized_headers = self._raw_headers(headers)
            if body is not None and not isinstance(body, bytes):
                raise CaptureError("full capture event stream is incomplete")
            if body is not None and len(body) > _MAX_FULL_BODY_BYTES:
                raise CaptureError("full capture body exceeds the safe limit")
            material_size = len(url.encode()) + self._header_bytes(normalized_headers)
            if body is not None:
                material_size += len(body)
            self._reserve(material_size)
            material = SessionRequestMaterial(url, normalized_headers, body)
            handle = self._registry.store_value(kind="session_state", value=material)
        except CaptureError as exc:
            raise _safe_full_capture_error(exc) from None
        except Exception:
            raise CaptureError("full capture event stream is incomplete") from None
        with self._lock:
            self._requests[request_id] = (material, handle)
            self._request_order.append(request_id)

    def _on_response(self, response: Any) -> None:
        request = getattr(response, "request", None)
        request_id = id(request)
        with self._lock:
            if (
                request_id not in self._requests
                or request_id in self._responses
                or request_id in self._response_tasks
            ):
                self._stream_incomplete = True
                return
            body_method = getattr(response, "body", None)
            if not callable(body_method):
                self._stream_incomplete = True
                return
            task = asyncio.create_task(self._read_response(request_id, response))
            self._response_tasks[request_id] = task

    async def _read_response(self, request_id: int, response: Any) -> None:
        try:
            body = await response.body()
            status = response.status
            headers = response.headers
            if (
                not isinstance(body, bytes)
                or not isinstance(status, int)
                or isinstance(status, bool)
                or not 0 <= status <= 999
                or not isinstance(headers, Mapping)
            ):
                raise CaptureError("full capture event stream is incomplete")
            if len(body) > _MAX_FULL_BODY_BYTES:
                raise CaptureError("full capture body exceeds the safe limit")
            normalized_headers = self._raw_headers(headers)
            self._reserve(self._header_bytes(normalized_headers) + len(body))
            material = SessionResponseMaterial(status, normalized_headers, body)
            handle = self._registry.store_value(kind="session_state", value=material)
            with self._lock:
                self._responses[request_id] = (material, handle)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            safe_error = _safe_full_capture_error(exc)
            with self._lock:
                self._task_errors.append(safe_error)

    @staticmethod
    def _request_body(request: Any) -> bytes | None:
        sentinel = object()
        try:
            value = getattr(request, "post_data_buffer", sentinel)
        except Exception:
            value = sentinel
        if value is sentinel or value is None:
            value = getattr(request, "post_data", None)
            if isinstance(value, str):
                return value.encode()
        return cast(bytes | None, value)

    @staticmethod
    def _raw_headers(headers: Mapping[Any, Any]) -> dict[str, str]:
        output: dict[str, str] = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise CaptureError("full capture event stream is incomplete")
            output[name] = value
        return output

    @staticmethod
    def _header_bytes(headers: Mapping[str, str]) -> int:
        return sum(len(name.encode()) + len(value.encode()) for name, value in headers.items())

    def _reserve(self, amount: int) -> None:
        with self._lock:
            if self._total_bytes + amount > _MAX_FULL_SESSION_BYTES:
                raise CaptureError("full capture session material exceeds the safe limit")
            self._total_bytes += amount

    async def _await_response_tasks(self) -> None:
        with self._lock:
            tasks = tuple(self._response_tasks.values())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def cancel(self) -> None:
        with self._lock:
            tasks = tuple(self._response_tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def finalize(self, context: Any) -> tuple[tuple[SessionExchange, ...], ValueHandle]:
        await self._await_response_tasks()
        with self._lock:
            errors = tuple(self._task_errors)
            incomplete = self._stream_incomplete
            request_order = tuple(self._request_order)
            requests = dict(self._requests)
            responses = dict(self._responses)
            entries = self._sanitized_entries
            identity = self._identity
        for error in errors:
            if isinstance(error, CaptureError):
                raise error
        if incomplete or not request_order or entries is None or identity is None:
            raise CaptureError("full capture event stream is incomplete")
        if len(request_order) != len(entries) or len(request_order) != len(responses):
            raise CaptureError("full capture event stream is incomplete")
        try:
            state = await context.storage_state()
            if not isinstance(state, Mapping) or not all(
                isinstance(key, str) for key in state
            ):
                raise CaptureError("full capture event stream is incomplete")
            serialized_state = json.dumps(state, separators=(",", ":")).encode()
        except Exception:
            raise CaptureError("full capture event stream is incomplete") from None
        if len(serialized_state) > _MAX_FULL_STATE_BYTES:
            raise CaptureError("full capture state exceeds the safe limit")
        self._reserve(len(serialized_state))
        try:
            state_handle = self._registry.store_value(kind="session_state", value=state)
        except Exception:
            raise CaptureError("full capture event stream is incomplete") from None
        exchanges: list[SessionExchange] = []
        try:
            records = tuple(_entry_to_record(entry, identity) for entry in entries)
        except CaptureError:
            raise
        for request_id, record in zip(request_order, records, strict=True):
            request_item = requests.get(request_id)
            response_item = responses.get(request_id)
            if request_item is None or response_item is None:
                raise CaptureError("full capture event stream is incomplete")
            exchanges.append(
                SessionExchange(record, request_item[1], response_item[1])
            )
        return tuple(exchanges), state_handle


def _safe_full_capture_error(error: BaseException) -> CaptureError:
    if isinstance(error, CaptureError) and str(error) in _SAFE_FULL_CAPTURE_ERRORS:
        return error
    return CaptureError("full capture event stream is incomplete")


async def capture_har(
    config: CaptureConfig,
    scope_guard: ScopeGuard,
    *,
    collector: CaptureCollector | None = None,
    registry: Any | None = None,
) -> Path:
    """Write a sanitized HAR after a session, never navigating config.target_url itself."""
    if not isinstance(scope_guard, ScopeGuard):
        raise CaptureError("scope_guard must be a ScopeGuard")
    if config.login_recipe is not None and registry is None:
        raise CaptureError("registry is required when config.login_recipe is set")
    active_collector = collector or InMemoryEventCollector()
    entries, _ = await _run_scoped_capture(
        config,
        scope_guard,
        active_collector,
        full_collector=None,
        registry=registry,
    )
    output_path = _validated_output_path(config.capture_root, config.output_path)
    _write_sanitized_har(
        config.capture_root,
        config.output_path,
        entries,
        max_bytes=config.max_har_bytes,
    )
    return output_path


async def capture_session(
    config: CaptureConfig,
    scope_guard: ScopeGuard,
    *,
    registry: SessionValueStore,
) -> InSessionCapture:
    """Capture one scoped browser session with raw material held by handles."""
    if not isinstance(scope_guard, ScopeGuard):
        raise CaptureError("scope_guard must be a ScopeGuard")
    if not isinstance(registry, SessionValueStore):
        raise CaptureError("registry must be a SessionValueStore")
    sanitized_collector = InMemoryEventCollector()
    full_collector = _FullFidelityEventCollector(registry)
    try:
        entries, full_result = await _run_scoped_capture(
            config,
            scope_guard,
            sanitized_collector,
            full_collector=full_collector,
            registry=registry,
        )
        if full_result is None:
            raise CaptureError("full capture event stream is incomplete")
        exchanges, state_handle = full_result
        output_path = _validated_output_path(config.capture_root, config.output_path)
        _write_sanitized_har(
            config.capture_root,
            config.output_path,
            entries,
            max_bytes=config.max_har_bytes,
        )
        return InSessionCapture(output_path, exchanges, state_handle, registry)
    except BaseException:
        registry.close()
        raise


async def _run_scoped_capture(
    config: CaptureConfig,
    scope_guard: ScopeGuard,
    sanitized_collector: CaptureCollector,
    *,
    full_collector: _FullFidelityEventCollector | None,
    registry: SessionValueStore | None,
) -> tuple[list[dict[str, Any]], tuple[tuple[SessionExchange, ...], ValueHandle] | None]:
    """Run the one routed browser session shared by both capture entrypoints."""
    if full_collector is not None and registry is None:
        raise CaptureError("registry is required for full capture")
    try:
        async_api = importlib.import_module("playwright.async_api")
        async_playwright = async_api.async_playwright
    except (ImportError, AttributeError) as exc:
        if full_collector is not None and registry is not None:
            registry.close()
        raise CaptureError("Playwright unavailable. Install openbola[capture].") from exc

    policy_failures: list[ScopeError] = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=config.headless,
                args=["--no-proxy-server"],
            )
            try:
                context = await browser.new_context(service_workers="block")
                try:
                    await context.route("**/*", _scoped_route(scope_guard, policy_failures))
                    _attach_collectors(context, sanitized_collector, full_collector)
                    if config.login_recipe is not None:
                        page = await context.new_page()
                        try:
                            await _perform_login(page, config.login_recipe, registry)
                        except (async_api.Error, LookupError) as exc:
                            raise CaptureError(
                                "automated login did not reach success_url_pattern"
                            ) from exc
                        finally:
                            await page.close()
                    elif config.interactive_login:
                        page = await context.new_page()
                        try:
                            await page.wait_for_event("close")
                        finally:
                            await page.close()
                    entries = await sanitized_collector.entries()
                    if full_collector is not None:
                        full_collector.set_sanitized_entries(entries, config.identity)
                        await full_collector._await_response_tasks()
                    if policy_failures:
                        raise CaptureError("a browser request was denied by the confirmed scope")
                    full_result = (
                        await full_collector.finalize(context)
                        if full_collector is not None
                        else None
                    )
                finally:
                    await context.close()
            finally:
                await browser.close()
    except BaseException:
        if full_collector is not None:
            await full_collector.cancel()
            assert registry is not None
            registry.close()
        raise
    return entries, full_result


def _attach_collectors(
    context: Any,
    sanitized_collector: CaptureCollector,
    full_collector: _FullFidelityEventCollector | None,
) -> None:
    """Attach both collectors while remaining compatible with simple event doubles."""
    if full_collector is None:
        sanitized_collector.attach(context)
        return

    callbacks: dict[str, list[Callable[..., None]]] = {}

    class CallbackContext:
        def on(self, event: str, callback: Callable[..., None]) -> None:
            callbacks.setdefault(event, []).append(callback)

    proxy = CallbackContext()
    sanitized_collector.attach(proxy)
    full_collector.attach(proxy)
    for event, handlers in callbacks.items():
        def dispatch(
            *args: Any,
            _handlers: tuple[Callable[..., None], ...] = tuple(handlers),
        ) -> None:
            for handler in _handlers:
                handler(*args)

        context.on(event, dispatch)


def parse_har_records(
    path: Path, identity: str, *, max_bytes: int = DEFAULT_MAX_HAR_BYTES
) -> list[RequestRecord]:
    """Import a bounded HAR into the structural redaction contract."""
    if not identity.strip() or max_bytes <= 0:
        raise CaptureError("identity must not be empty and max_bytes must be positive")
    if not path.is_file() or path.is_symlink():
        raise CaptureError("HAR input must be a regular file")
    try:
        with path.open("rb") as source:
            raw = source.read(max_bytes + 1)
    except OSError as exc:
        raise CaptureError("HAR file cannot be read") from exc
    if len(raw) > max_bytes:
        raise CaptureError("HAR file exceeds the configured size limit")
    try:
        document: Any = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CaptureError("HAR file is not valid JSON") from exc
    if not isinstance(document, Mapping) or not isinstance(document.get("log"), Mapping):
        raise CaptureError("HAR log must be an object")
    entries = document["log"].get("entries")
    if not isinstance(entries, list):
        raise CaptureError("HAR log.entries must be a list")
    if len(entries) > _MAX_CAPTURE_ENTRIES:
        raise CaptureError("HAR log.entries exceeds the safe count limit")
    return [_entry_to_record(entry, identity) for entry in entries]


def _validate_target_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CaptureError("target_url must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise CaptureError("target_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise CaptureError("target_url must not contain query parameters or fragments")


def _validated_output_path(root: Path, relative: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise CaptureError("capture_root must be an existing non-symlink directory")
    if relative.is_absolute() or ".." in relative.parts or relative.name in {"", "."}:
        raise CaptureError("output_path must be a relative path inside capture_root")
    if relative.suffix.lower() != ".har":
        raise CaptureError("output_path must use the .har extension")
    resolved_root = root.resolve(strict=True)
    candidate = resolved_root / relative
    current = resolved_root
    for part in relative.parent.parts:
        current /= part
        if not current.exists():
            break
        if current.is_symlink() or not current.is_dir():
            raise CaptureError("output_path parent must not be a symlink")
    if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
        raise CaptureError("output_path must be a regular non-symlink file")
    return candidate


def _write_sanitized_har(
    root: Path,
    relative: Path,
    entries: list[dict[str, Any]],
    *,
    max_bytes: int = DEFAULT_MAX_HAR_BYTES,
) -> None:
    """Atomically write below an anchored root without traversing a writable path."""
    if max_bytes <= 0:
        raise CaptureError("sanitized HAR size limit must be positive")
    serialized = json.dumps(_har_document(entries), separators=(",", ":"))
    if len(serialized.encode("utf-8")) > max_bytes:
        raise CaptureError("sanitized HAR exceeds the configured size limit")

    directory_fds: list[int] = []
    parent_fd: int | None = None
    temp_fd: int | None = None
    temp_name: str | None = None
    try:
        parent_fd = os.open(root, _directory_open_flags())
        directory_fds.append(parent_fd)
        for component in relative.parent.parts:
            parent_fd = _open_or_create_directory(parent_fd, component)
            directory_fds.append(parent_fd)

        _require_replaceable_target(parent_fd, relative.name)
        temp_name, temp_fd = _open_temporary_file(parent_fd, relative.name)
        output = os.fdopen(temp_fd, "w", encoding="utf-8")
        temp_fd = None
        with output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())

        os.replace(
            temp_name,
            relative.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temp_name = None
        os.fsync(parent_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise CaptureError("sanitized HAR output cannot be written") from exc
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_name is not None and parent_fd is not None:
            with suppress(FileNotFoundError):
                os.unlink(temp_name, dir_fd=parent_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


def _directory_open_flags() -> int:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    no_follow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not no_follow_flag:
        raise CaptureError("secure capture output is unsupported on this platform")
    return os.O_RDONLY | directory_flag | no_follow_flag


def _open_or_create_directory(parent_fd: int, component: str) -> int:
    try:
        return os.open(component, _directory_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        with suppress(FileExistsError):
            os.mkdir(component, mode=0o700, dir_fd=parent_fd)
        return os.open(component, _directory_open_flags(), dir_fd=parent_fd)


def _require_replaceable_target(parent_fd: int, name: str) -> None:
    try:
        target_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(target_stat.st_mode):
        raise CaptureError("output_path must be a regular non-symlink file")


def _open_temporary_file(parent_fd: int, target_name: str) -> tuple[str, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for _ in range(128):
        name = f".{target_name}.{secrets.token_hex(8)}.tmp"
        try:
            return name, os.open(name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            continue
    raise CaptureError("sanitized HAR output temporary file cannot be created")


def _entry_to_record(entry: Any, identity: str) -> RequestRecord:
    if not isinstance(entry, Mapping):
        raise CaptureError("each HAR entry must be an object")
    request, response = entry.get("request"), entry.get("response")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        raise CaptureError("each HAR entry requires request and response objects")
    method, url, status = request.get("method"), request.get("url"), response.get("status")
    if not isinstance(method, str) or not method or not isinstance(url, str):
        raise CaptureError("HAR request requires method and URL strings")
    _validate_har_url(url)
    if not isinstance(status, int) or isinstance(status, bool) or not 0 <= status <= 999:
        raise CaptureError("HAR response.status must be an integer between 0 and 999")
    request_headers = _headers_from_har(request.get("headers"), "request")
    response_headers = _headers_from_har(response.get("headers"), "response")
    body_headers = _headers_with_post_data_mime(request_headers, request.get("postData"))
    return RequestRecord(
        identity,
        method,
        _sanitize_url(url),
        _sanitize_header_mapping(request_headers),
        _sanitize_body(_post_data(request.get("postData")), body_headers),
        status,
        _sanitize_header_mapping(response_headers),
        None,
    )


def _validate_har_url(url: str) -> None:
    try:
        _sanitize_url(url)
    except CaptureError as exc:
        raise CaptureError(
            "HAR request.url must be an absolute HTTP(S) URL without credentials"
        ) from exc
    else:
        return


def _headers_from_har(value: Any, location: str) -> dict[str, str]:
    if not isinstance(value, list):
        raise CaptureError(f"HAR {location}.headers must be a list")
    if len(value) > _MAX_HEADER_COUNT:
        raise CaptureError(f"HAR {location}.headers exceeds the safe count limit")
    headers: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise CaptureError(f"HAR {location}.headers entries require string name and value")
        name, item_value = item["name"], item["value"]
        assert isinstance(name, str) and isinstance(item_value, str)
        _validate_header_name(name)
        headers[name] = item_value
    return headers


def _headers_with_post_data_mime(
    headers: Mapping[str, str], post_data: Any
) -> dict[str, str]:
    """Include a safe HAR ``postData.mimeType`` as Content-Type metadata.

    HAR stores the request body MIME separately from request headers.  The
    sanitizer uses the merged view when deciding whether a body can be
    retained structurally; only a validated media type is copied.
    """
    merged = dict(headers)
    if isinstance(post_data, Mapping):
        mime_type = post_data.get("mimeType")
        if isinstance(mime_type, str):
            safe_mime = _safe_content_type(mime_type)
            if safe_mime is not None and not any(
                name.casefold() == "content-type" for name in merged
            ):
                merged["Content-Type"] = safe_mime
    return merged


def _headers_to_har(headers: Mapping[str, str]) -> list[dict[str, str]]:
    if len(headers) > _MAX_HEADER_COUNT:
        raise CaptureError("headers exceed the safe count limit")
    output: list[dict[str, str]] = []
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise CaptureError("headers require string names and values")
        _validate_header_name(name)
        output.append({"name": name, "value": _sanitize_header_value(name, value)})
    return output


def _sanitize_har_headers(value: Any, location: str) -> list[dict[str, str]]:
    return _headers_to_har(_headers_from_har(value, location))


def _request_mime_type(headers: Mapping[str, str], body: bytes | str | None) -> str:
    content_type = _content_type(headers)
    if content_type is not None:
        return content_type
    if isinstance(body, bytes):
        return "application/octet-stream"
    return "text/plain"


def _sanitize_header_mapping(headers: Mapping[str, str]) -> dict[str, str]:
    if len(headers) > _MAX_HEADER_COUNT:
        raise CaptureError("headers exceed the safe count limit")
    return {name: _sanitize_header_value(name, value) for name, value in headers.items()}


def _sanitize_url(url: str, *, allow_relative: bool = False) -> str:
    if len(url) > _MAX_URL_CHARS or any(
        character == "\\" or character.isspace() or ord(character) < 32 for character in url
    ):
        raise CaptureError("URL exceeds safe structural bounds")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CaptureError("URL is not structurally valid") from exc

    scheme = parsed.scheme.casefold()
    if parsed.username is not None or parsed.password is not None:
        raise CaptureError("URL userinfo is not retained")
    if scheme:
        if scheme not in {"http", "https"} or parsed.hostname is None:
            raise CaptureError("URL must use HTTP(S)")
    elif not allow_relative or (parsed.netloc == "" and not parsed.path.startswith("/")):
        raise CaptureError("URL must be absolute or origin-relative")

    query_source = parsed.query.replace(";", "&")
    if query_source and query_source.count("&") + 1 > _MAX_QUERY_FIELDS:
        raise CaptureError("URL query exceeds the safe field count limit")
    query_items = parse_qsl(query_source, keep_blank_values=True)
    if any(len(key) > _MAX_JSON_KEY_CHARS for key, _ in query_items):
        raise CaptureError("URL query name exceeds the safe length limit")
    query = urlencode([(key, _REDACTED) for key, _ in query_items], doseq=True)

    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parsed.path, query, ""))


def _sanitize_header_value(name: str, value: str) -> str:
    _validate_header_name(name)
    normalized_name = name.casefold()
    if normalized_name == "content-type":
        return _safe_content_type(value) or _REDACTED
    if normalized_name in _URL_HEADERS and len(value) <= _MAX_HEADER_VALUE_CHARS:
        try:
            return _sanitize_url(value, allow_relative=True)
        except CaptureError:
            return _REDACTED
    return _REDACTED


def _validate_header_name(name: str) -> None:
    if (
        not name
        or len(name) > _MAX_HEADER_NAME_CHARS
        or _HTTP_TOKEN.fullmatch(name) is None
    ):
        raise CaptureError("header name is not a bounded HTTP token")


def _safe_content_type(value: str) -> str | None:
    if len(value) > _MAX_HEADER_VALUE_CHARS:
        return None
    media_type = value.partition(";")[0].strip().casefold()
    return media_type if _MEDIA_TYPE.fullmatch(media_type) is not None else None


def _content_type(headers: Mapping[str, str]) -> str | None:
    for name, value in headers.items():
        if name.casefold() == "content-type":
            return _safe_content_type(value)
    return None


def _scoped_route(scope_guard: ScopeGuard, failures: list[ScopeError]) -> Any:
    async def route_handler(route: Any, request: Any) -> None:
        url = str(request.url)
        scheme = urlsplit(url).scheme.lower()
        if scheme in {"about", "data", "blob"}:
            await route.continue_()
            return
        if scheme not in {"http", "https"}:
            await route.abort()
            return
        try:
            decision: ScopeDecision = scope_guard.require_allowed(url, str(request.method))
        except ScopeError as exc:
            failures.append(exc)
            await route.abort("blockedbyclient")
            return
        if decision.connect_ips:
            hostname = urlsplit(decision.canonical_url).hostname
            if hostname not in {str(address) for address in decision.connect_ips}:
                failures.append(
                    ScopeError("Browser DNS pinning is unavailable for this scope decision.")
                )
                await route.abort("blockedbyclient")
                return
        await route.continue_(url=decision.canonical_url)

    return route_handler


def _har_document(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if len(entries) > _MAX_CAPTURE_ENTRIES:
        raise CaptureError("capture exceeds the safe entry count limit")
    complete_entries: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise CaptureError("capture entry must be an object")
        request_source, response_source = entry.get("request"), entry.get("response")
        if not isinstance(request_source, Mapping) or not isinstance(response_source, Mapping):
            raise CaptureError("capture entry requires request and response objects")

        method, url = request_source.get("method"), request_source.get("url")
        if (
            not isinstance(method, str)
            or len(method) > 32
            or _HTTP_TOKEN.fullmatch(method) is None
            or not isinstance(url, str)
        ):
            raise CaptureError("capture request requires a bounded method and URL")
        safe_url = _sanitize_url(url)

        raw_request_headers = request_source.get("headers", [])
        request_header_mapping = _headers_from_har(raw_request_headers, "request")
        request_headers = _headers_to_har(request_header_mapping)
        post_data = request_source.get("postData")
        body_headers = _headers_with_post_data_mime(request_header_mapping, post_data)
        raw_body = _post_data(post_data)
        body = _sanitize_body(raw_body, body_headers)
        request: dict[str, Any] = {
            "method": method.upper(),
            "url": safe_url,
            "httpVersion": "HTTP/1.1",
            "headers": request_headers,
            "queryString": _query_string_to_har(safe_url),
            "cookies": [],
            "headersSize": -1,
            "bodySize": -1,
        }
        if body is not None:
            request["postData"] = {
                "mimeType": _request_mime_type(body_headers, raw_body),
                "text": body.decode("utf-8", errors="replace"),
            }

        status = response_source.get("status", 0)
        if not isinstance(status, int) or isinstance(status, bool) or not 0 <= status <= 999:
            raise CaptureError("capture response status must be an integer from 0 to 999")
        response: dict[str, Any] = {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": _sanitize_har_headers(response_source.get("headers", []), "response"),
            "cookies": [],
            "content": {"size": 0, "mimeType": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        }
        complete_entries.append(
            {
                "startedDateTime": "1970-01-01T00:00:00Z",
                "time": 0,
                "request": request,
                "response": response,
                "cache": {},
                "timings": {
                    "blocked": 0,
                    "dns": 0,
                    "connect": 0,
                    "send": 0,
                    "wait": 0,
                    "receive": 0,
                    "ssl": 0,
                },
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "OpenBOLA", "version": "0.1.0"},
            "entries": complete_entries,
        }
    }


def _post_data(value: Any) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or not isinstance(value.get("text"), str):
        raise CaptureError("HAR request.postData.text must be a string")
    text = value["text"]
    assert isinstance(text, str)
    return text.encode()


def _query_string_to_har(url: str) -> list[dict[str, str]]:
    return [
        {"name": key, "value": _REDACTED}
        for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ]


def _sanitize_body(value: bytes | str | None, headers: Mapping[str, str]) -> bytes | None:
    if value is None:
        return None
    body = value.encode() if isinstance(value, str) else value
    if len(body) > _MAX_BODY_BYTES:
        return _REDACTED.encode()
    content_type = _content_type(headers)
    if content_type is None or not (
        content_type.endswith("/json") or content_type.endswith("+json")
    ):
        return _REDACTED.encode()
    try:
        decoded = json.loads(body)
        redacted = _redact_json(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, _StructuralLimitExceeded):
        return _REDACTED.encode()
    return json.dumps(redacted, separators=(",", ":")).encode()


_TOTP_PERIOD_SECONDS = 30
_TOTP_DIGITS = 6


def _totp_code(
    secret_base32: str,
    *,
    now: float | None = None,
    period: int = _TOTP_PERIOD_SECONDS,
    digits: int = _TOTP_DIGITS,
) -> str:
    """Compute the current RFC 6238 TOTP code for a base32-encoded seed."""
    padded = secret_base32.strip().upper().replace(" ", "")
    padded += "=" * (-len(padded) % 8)
    try:
        key = base64.b32decode(padded)
    except ValueError as exc:
        raise CaptureError("TOTP secret must be valid base32") from exc
    counter = int((now if now is not None else time.time()) // period)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()  # noqa: S324 - RFC 6238 HMAC-SHA1, not a security digest
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = truncated % (10**digits)
    return str(code).zfill(digits)


_LOGIN_TIMEOUT_MS = 15_000


async def _perform_login(page: Any, recipe: LoginRecipe, registry: Any) -> None:
    """Fill and submit a login recipe; the caller translates failures to CaptureError."""
    await page.goto(recipe.start_url, timeout=_LOGIN_TIMEOUT_MS)
    await page.fill(
        recipe.username_selector,
        registry.resolve_secret(recipe.username_secret),
        timeout=_LOGIN_TIMEOUT_MS,
    )
    await page.fill(
        recipe.password_selector,
        registry.resolve_secret(recipe.password_secret),
        timeout=_LOGIN_TIMEOUT_MS,
    )
    for extra in recipe.extra_secret_fields:
        value = registry.resolve_secret(extra.secret)
        if extra.kind == "totp":
            value = _totp_code(value)
        await page.fill(extra.selector, value, timeout=_LOGIN_TIMEOUT_MS)
    await page.click(recipe.submit_selector, timeout=_LOGIN_TIMEOUT_MS)
    await page.wait_for_url(recipe.success_url_pattern, timeout=_LOGIN_TIMEOUT_MS)


def _redact_json(value: Any) -> Any:
    nodes = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise _StructuralLimitExceeded
        if isinstance(item, Mapping):
            output: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > _MAX_JSON_KEY_CHARS:
                    raise _StructuralLimitExceeded
                output[key] = visit(child, depth + 1)
            return output
        if isinstance(item, list):
            return [visit(child, depth + 1) for child in item]
        return _REDACTED

    return visit(value, 0)
