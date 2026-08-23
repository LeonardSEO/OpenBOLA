"""Secret-safe browser capture and bounded HAR import for phase 1."""

from __future__ import annotations

import importlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bola_checker.models import RequestRecord
from bola_checker.scope import ScopeDecision, ScopeError, ScopeGuard

DEFAULT_MAX_HAR_BYTES = 25 * 1024 * 1024
_REDACTED = "[REDACTED]"
_SENSITIVE_NAME = re.compile(
    r"(?:authorization|cookie|token|api[-_]?key|secret|password|code|signature|credential|x-amz-)",
    re.I,
)
_URL_HEADERS = frozenset({"location", "referer", "content-location"})


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

    def __post_init__(self) -> None:
        _validate_target_url(self.target_url)
        _validated_output_path(self.capture_root, self.output_path)
        if not self.identity.strip():
            raise CaptureError("identity must not be empty")
        if self.interactive_login and self.headless:
            raise CaptureError("interactive_login requires headless=False")
        if self.max_har_bytes <= 0:
            raise CaptureError("max_har_bytes must be greater than zero")


class CaptureCollector(Protocol):
    def attach(self, context: Any) -> None: ...
    async def entries(self) -> list[dict[str, Any]]: ...


@dataclass
class InMemoryEventCollector:
    """Retain only sanitized event metadata; never a raw HAR or response body."""

    _entries: dict[int, dict[str, Any]] = field(default_factory=dict)

    def attach(self, context: Any) -> None:
        context.on("request", self._on_request)
        context.on("response", self._on_response)

    def _on_request(self, request: Any) -> None:
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
        self._entries[id(request)] = {
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
        return list(self._entries.values())


async def capture_har(
    config: CaptureConfig, scope_guard: ScopeGuard, *, collector: CaptureCollector | None = None
) -> Path:
    """Write a sanitized HAR after a session without navigating the target URL."""
    try:
        async_api = importlib.import_module("playwright.async_api")
        async_playwright = async_api.async_playwright
    except (ImportError, AttributeError) as exc:
        raise CaptureError("Playwright unavailable. Install bolacheck[capture].") from exc

    if not isinstance(scope_guard, ScopeGuard):
        raise CaptureError("scope_guard must be a ScopeGuard")
    active_collector = collector or InMemoryEventCollector()
    policy_failures: list[ScopeError] = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=config.headless)
        try:
            context = await browser.new_context()
            try:
                await context.route("**/*", _scoped_route(scope_guard, policy_failures))
                active_collector.attach(context)
                if config.interactive_login:
                    page = await context.new_page()
                    await page.wait_for_event("close")
            finally:
                await context.close()
        finally:
            await browser.close()
    entries = await active_collector.entries()
    if policy_failures:
        raise CaptureError("a browser request was denied by the confirmed scope")
    output_path = _validated_output_path(config.capture_root, config.output_path)
    _write_sanitized_har(config.capture_root, config.output_path, entries)
    return output_path


def parse_har_records(
    path: Path, identity: str, *, max_bytes: int = DEFAULT_MAX_HAR_BYTES
) -> list[RequestRecord]:
    """Import a bounded HAR, redacting all secret material before retention."""
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
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError("HAR file is not valid JSON") from exc
    if not isinstance(document, Mapping) or not isinstance(document.get("log"), Mapping):
        raise CaptureError("HAR log must be an object")
    entries = document["log"].get("entries")
    if not isinstance(entries, list):
        raise CaptureError("HAR log.entries must be a list")
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
    root: Path, relative: Path, entries: list[dict[str, Any]]
) -> None:
    """Atomically write below an anchored root without traversing a writable path."""
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
            json.dump(_har_document(entries), output, separators=(",", ":"))
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
    return RequestRecord(
        identity,
        method,
        _sanitize_url(url),
        _sanitize_header_mapping(request_headers),
        _sanitize_body(_post_data(request.get("postData")), request_headers),
        status,
        _sanitize_header_mapping(response_headers),
        None,
    )


def _validate_har_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
        raise CaptureError("HAR request.url must be an absolute HTTP(S) URL without credentials")


def _headers_from_har(value: Any, location: str) -> dict[str, str]:
    if not isinstance(value, list):
        raise CaptureError(f"HAR {location}.headers must be a list")
    headers: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise CaptureError(f"HAR {location}.headers entries require string name and value")
        headers[item["name"]] = item["value"]
    return headers


def _headers_to_har(headers: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {"name": name, "value": _sanitize_header_value(name, value)}
        for name, value in headers.items()
    ]


def _request_mime_type(headers: Mapping[str, str], body: bytes | str | None) -> str:
    content_type = next(
        (value.strip() for name, value in headers.items() if name.lower() == "content-type"),
        "",
    )
    if content_type:
        return content_type
    if isinstance(body, bytes):
        return "application/octet-stream"
    return "text/plain"


def _sanitize_header_mapping(headers: Mapping[str, str]) -> dict[str, str]:
    return {name: _sanitize_header_value(name, value) for name, value in headers.items()}


def _sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    query_source = parsed.query.replace(";", "&")
    query = urlencode(
        [
            (key, _REDACTED if _SENSITIVE_NAME.search(key) else value)
            for key, value in parse_qsl(query_source, keep_blank_values=True)
        ],
        doseq=True,
    )
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, query, ""))


def _sanitize_header_value(name: str, value: str) -> str:
    if _SENSITIVE_NAME.search(name):
        return _REDACTED
    if name.lower() in _URL_HEADERS:
        return _sanitize_url(value)
    if name.lower() == "link":
        return re.sub(r"<([^>]*)>", lambda match: f"<{_sanitize_url(match.group(1))}>", value)
    if name.lower() == "refresh":
        return re.sub(
            r"(?i)(\burl\s*=\s*)([^;]+)",
            lambda match: match.group(1) + _sanitize_url(match.group(2).strip()),
            value,
        )
    return value


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
    complete_entries: list[dict[str, Any]] = []
    for entry in entries:
        request = dict(entry.get("request", {}))
        response = dict(entry.get("response", {}))
        request.setdefault("method", "GET")
        request.setdefault("url", "about:blank")
        request.setdefault("httpVersion", "HTTP/1.1")
        request.setdefault("headers", [])
        request.setdefault("queryString", [])
        request.setdefault("cookies", [])
        request.setdefault("headersSize", -1)
        request.setdefault("bodySize", -1)
        response.setdefault("status", 0)
        response.setdefault("statusText", "")
        response.setdefault("httpVersion", "HTTP/1.1")
        response.setdefault("headers", [])
        response.setdefault("cookies", [])
        content = dict(response.get("content", {}))
        content.setdefault("size", 0)
        content.setdefault("mimeType", "")
        response["content"] = content
        response.setdefault("redirectURL", "")
        response.setdefault("headersSize", -1)
        response.setdefault("bodySize", -1)
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
            "creator": {"name": "BOLACheck", "version": "0.1.0"},
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


def _sanitize_body(value: bytes | str | None, headers: Mapping[str, str]) -> bytes | None:
    if value is None:
        return None
    body = value.encode() if isinstance(value, str) else value
    content_type = next(
        (item for name, item in headers.items() if name.lower() == "content-type"), ""
    )
    if "json" not in content_type.lower():
        return _REDACTED.encode()
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _REDACTED.encode()
    return json.dumps(_redact_json(decoded), separators=(",", ":")).encode()


def _redact_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _REDACTED if _SENSITIVE_NAME.search(str(key)) else _redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    return value
