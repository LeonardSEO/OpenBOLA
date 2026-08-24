import asyncio
import json
import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from openbola.capture import CaptureConfig, CaptureError, parse_har_records
from openbola.models import RequestRecord
from openbola.scope import ScopeGuard


def make_config(tmp_path: Path, **changes: object) -> CaptureConfig:
    values: dict[str, object] = {
        "target_url": "https://api.example.test",
        "capture_root": tmp_path,
        "output_path": Path("nested/a.har"),
        "identity": "alice",
    }
    values.update(changes)
    return CaptureConfig(**values)  # type: ignore[arg-type]


class Guard(ScopeGuard):
    def __init__(self) -> None:
        pass

    def require_allowed(self, url: str, method: str) -> object:
        return SimpleNamespace(canonical_url=url, connect_ips=frozenset())


def make_scope_guard(
    tmp_path: Path,
    *,
    allowed_hosts: list[str],
    allowed_cidrs: list[str],
    resolver: Callable[[str], list[str]] | None = None,
) -> ScopeGuard:
    scope_path = tmp_path / "route-scope.yaml"
    scope_path.write_text(
        json.dumps(
            {
                "client_name": "Example B.V.",
                "authorization_reference": "PT-ROUTE-TEST",
                "confirmed": True,
                "starts_at": "2020-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "allowed_hosts": allowed_hosts,
                "allowed_cidrs": allowed_cidrs,
                "allowed_paths": ["glob:/v1/**"],
            }
        ),
        encoding="utf-8",
    )
    return ScopeGuard.from_file(scope_path, resolver=resolver)


def test_config_rejects_leaky_urls_and_unsafe_paths(tmp_path: Path) -> None:
    assert "api.example.test" not in repr(make_config(tmp_path))
    for value in ("https://a:x@example.test", "https://e.test/?token=x", "https://e.test/#x"):
        with pytest.raises(CaptureError):
            make_config(tmp_path, target_url=value)
    for value in (Path("../a.har"), tmp_path / "absolute.har", Path("a.json")):
        with pytest.raises(CaptureError):
            make_config(tmp_path, output_path=value)


def test_import_sanitizes_and_bounds(tmp_path: Path) -> None:
    secret = "private-value"  # noqa: S105
    doc = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": f"https://e.test/x?keep=1&token={secret}",
                        "headers": [
                            {"name": "Authorization", "value": secret},
                            {"name": "X-Auth", "value": "custom-auth-sentinel"},
                            {"name": "X-Session", "value": "custom-session-sentinel"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {
                            "text": (
                                '{"id":"1","auth":"json-auth-sentinel",'
                                '"session":"json-session-sentinel","neutral":"json-value-sentinel"}'
                            )
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Set-Cookie", "value": secret},
                            {
                                "name": "Link",
                                "value": f'<https://e.test/next?token={secret}>; rel="next"',
                            },
                            {
                                "name": "Refresh",
                                "value": f"0; url=https://e.test/login?code={secret}",
                            },
                        ],
                        "content": {"text": secret},
                    },
                }
            ]
        }
    }
    path = tmp_path / "x.har"
    path.write_text(json.dumps(doc))
    [record] = parse_har_records(path, "alice")
    assert (
        record.url.endswith("keep=%5BREDACTED%5D&token=%5BREDACTED%5D")
        and record.headers["Authorization"] == "[REDACTED]"
    )
    assert record.headers["X-Auth"] == "[REDACTED]"
    assert record.headers["X-Session"] == "[REDACTED]"
    assert record.body == (
        b'{"id":"[REDACTED]","auth":"[REDACTED]","session":"[REDACTED]",'
        b'"neutral":"[REDACTED]"}'
    )
    assert record.response_body is None
    assert record.response_headers["Link"] == "[REDACTED]"
    assert record.response_headers["Refresh"] == "[REDACTED]"
    assert all(
        marker not in repr(record)
        and marker not in json.dumps(
            {
                "url": record.url,
                "headers": record.headers,
                "body": record.body.decode() if record.body else None,
            }
        )
        for marker in (
            "custom-auth-sentinel",
            "custom-session-sentinel",
            "json-auth-sentinel",
            "json-session-sentinel",
            "json-value-sentinel",
        )
    )
    assert secret not in repr(record)
    path.write_bytes(b"{" + b" " * 20 + b"}")
    with pytest.raises(CaptureError):
        parse_har_records(path, "alice", max_bytes=10)
    with pytest.raises(CaptureError):
        parse_har_records(tmp_path, "alice")


def test_default_collector_captures_sanitized_body_and_response_metadata() -> None:
    from openbola import capture

    callbacks: dict[str, Any] = {}

    class Context:
        def on(self, event: str, callback: object) -> None:
            callbacks[event] = callback

    secret = "private-value"  # noqa: S105
    request = SimpleNamespace(
        method="POST",
        url=f"https://api.example.test/v1/items?token={secret}",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {secret}",
        },
        post_data=f'{{"id":"1","password":"{secret}"}}',
    )
    response = SimpleNamespace(
        request=request,
        status=201,
        headers={"Location": f"https://api.example.test/v1/items/1?code={secret}"},
    )
    collector = capture.InMemoryEventCollector()
    collector.attach(Context())
    callbacks["request"](request)
    callbacks["response"](response)

    [entry] = asyncio.run(collector.entries())
    assert entry["request"]["url"].endswith("token=%5BREDACTED%5D")
    assert entry["request"]["headers"] == [
        {"name": "Content-Type", "value": "application/json"},
        {"name": "Authorization", "value": "[REDACTED]"},
    ]
    assert entry["request"]["postData"] == {
        "mimeType": "application/json",
        "text": '{"id":"[REDACTED]","password":"[REDACTED]"}',
    }
    assert entry["response"] == {
        "status": 201,
        "headers": [
            {
                "name": "Location",
                "value": "https://api.example.test/v1/items/1?code=%5BREDACTED%5D",
            }
        ],
        "content": {},
    }


@pytest.mark.parametrize(
    ("body", "expected_mime_type"),
    [("plain text", "text/plain"), (b"\xff\x00", "application/octet-stream")],
)
def test_default_collector_assigns_safe_post_data_mime_fallbacks(
    body: str | bytes, expected_mime_type: str
) -> None:
    from openbola import capture

    callbacks: dict[str, Any] = {}
    context = SimpleNamespace(on=lambda event, callback: callbacks.__setitem__(event, callback))
    request = SimpleNamespace(
        method="POST",
        url="https://api.example.test/v1/items",
        headers={},
        post_data=body,
    )
    collector = capture.InMemoryEventCollector()
    collector.attach(context)
    callbacks["request"](request)

    [entry] = asyncio.run(collector.entries())
    assert entry["request"]["postData"] == {
        "mimeType": expected_mime_type,
        "text": "[REDACTED]",
    }


def test_default_collector_bounds_entries_during_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from openbola import capture

    callbacks: dict[str, Any] = {}
    context = SimpleNamespace(on=lambda event, callback: callbacks.__setitem__(event, callback))
    collector = capture.InMemoryEventCollector()
    collector.attach(context)
    monkeypatch.setattr(capture, "_MAX_CAPTURE_ENTRIES", 2)
    requests = [
        SimpleNamespace(
            method="GET",
            url=f"https://api.example.test/v1/items/{index}",
            headers={},
            post_data=None,
        )
        for index in range(3)
    ]

    for request in requests:
        callbacks["request"](request)

    assert len(collector._entries) == 2
    with pytest.raises(CaptureError, match="safe entry count limit"):
        asyncio.run(collector.entries())


@pytest.mark.parametrize("failure", [None, "new_context", "collector", "interrupt"])
def test_capture_cleanup_and_safe_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    from openbola import capture

    closed: list[str] = []

    class Context:
        async def route(self, pattern: str, handler: object) -> None:
            return None

        async def close(self) -> None:
            closed.append("context")

    class Browser:
        async def new_context(self, *, service_workers: str) -> Context:
            assert service_workers == "block"
            if failure == "new_context":
                raise RuntimeError()
            return Context()

        async def close(self) -> None:
            closed.append("browser")

    class Chromium:
        async def launch(self, **kwargs: object) -> Browser:
            assert kwargs == {"headless": True, "args": ["--no-proxy-server"]}
            return Browser()

    class Manager:
        async def __aenter__(self) -> object:
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *args: object) -> None:
            return None

    class Collector:
        def attach(self, context: object) -> None:
            if failure == "collector":
                raise RuntimeError()
            if failure == "interrupt":
                raise asyncio.CancelledError()

        async def entries(self) -> list[dict[str, object]]:
            return []

    monkeypatch.setattr(
        capture.importlib,
        "import_module",
        lambda _: SimpleNamespace(async_playwright=lambda: Manager()),
    )
    if failure is None:
        output = asyncio.run(
            capture.capture_har(make_config(tmp_path), Guard(), collector=Collector())
        )
        document = json.loads(output.read_text())
        assert document["log"]["version"] == "1.2"
        assert document["log"]["creator"]["name"] == "OpenBOLA"
        assert document["log"]["entries"] == []
    else:
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            asyncio.run(capture.capture_har(make_config(tmp_path), Guard(), collector=Collector()))
        assert not (tmp_path / "nested/a.har").exists()
    assert closed == (["browser"] if failure == "new_context" else ["context", "browser"])


def test_capture_writes_a_complete_har_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola import capture

    class Context:
        async def route(self, pattern: str, handler: object) -> None:
            return None

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self, *, service_workers: str) -> Context:
            assert service_workers == "block"
            return Context()

        async def close(self) -> None:
            return None

    class Chromium:
        async def launch(self, **kwargs: object) -> Browser:
            assert kwargs == {"headless": True, "args": ["--no-proxy-server"]}
            return Browser()

    class Manager:
        async def __aenter__(self) -> object:
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *args: object) -> None:
            return None

    class Collector:
        def attach(self, context: object) -> None:
            return None

        async def entries(self) -> list[dict[str, Any]]:
            return [
                {
                    "collectorExtension": "collector-extension-sentinel",
                    "request": {
                        "method": "POST",
                        "url": (
                            "https://api.example.test/v1/items?opaque=query-value-sentinel"
                        ),
                        "headers": [
                            {
                                "name": "Content-Type",
                                "value": (
                                    "application/problem+json; charset=utf-8;"
                                    " boundary=mime-parameter-value-sentinel"
                                ),
                            },
                            {"name": "X-Auth", "value": "x-auth-value-sentinel"},
                            {"name": "X-Session", "value": "x-session-value-sentinel"},
                        ],
                        "postData": {
                            "mimeType": (
                                "application/problem+json; charset=utf-8;"
                                " boundary=mime-parameter-value-sentinel"
                            ),
                            "text": (
                                '{"id":"1","auth":"json-auth-value-sentinel",'
                                '"session":"json-session-value-sentinel",'
                                '"neutral":"json-neutral-value-sentinel",'
                                '"active":true,"items":[7,null]}'
                            ),
                        },
                    },
                    "response": {
                        "status": 201,
                        "headers": [
                            {
                                "name": "Location",
                                "value": (
                                    "/v1/items/1?opaque=location-query-value-sentinel"
                                ),
                            },
                            {
                                "name": "Content-Location",
                                "value": (
                                    "https://api.example.test/v1/items/1"
                                    "?opaque=content-location-query-value-sentinel"
                                ),
                            },
                            {"name": "Link", "value": "link-value-sentinel"},
                            {"name": "Refresh", "value": "refresh-value-sentinel"},
                        ],
                        "content": {"text": "response-body-value-sentinel"},
                    },
                }
            ]

    monkeypatch.setattr(
        capture.importlib,
        "import_module",
        lambda _: SimpleNamespace(async_playwright=lambda: Manager()),
    )
    output = asyncio.run(
        capture.capture_har(make_config(tmp_path), Guard(), collector=Collector())
    )

    output_bytes = output.read_bytes()
    for marker in (
        b"collector-extension-sentinel",
        b"query-value-sentinel",
        b"x-auth-value-sentinel",
        b"x-session-value-sentinel",
        b"mime-parameter-value-sentinel",
        b"json-auth-value-sentinel",
        b"json-session-value-sentinel",
        b"json-neutral-value-sentinel",
        b"location-query-value-sentinel",
        b"content-location-query-value-sentinel",
        b"link-value-sentinel",
        b"refresh-value-sentinel",
        b"response-body-value-sentinel",
    ):
        assert marker not in output_bytes

    document = json.loads(output_bytes)
    [entry] = document["log"]["entries"]
    assert set(entry) == {
        "startedDateTime",
        "time",
        "request",
        "response",
        "cache",
        "timings",
    }
    assert set(entry["request"]) == {
        "method",
        "url",
        "httpVersion",
        "headers",
        "queryString",
        "cookies",
        "headersSize",
        "bodySize",
        "postData",
    }
    assert entry["request"]["postData"] == {
        "mimeType": "application/problem+json",
        "text": (
            '{"id":"[REDACTED]","auth":"[REDACTED]",'
            '"session":"[REDACTED]","neutral":"[REDACTED]",'
            '"active":"[REDACTED]","items":["[REDACTED]","[REDACTED]"]}'
        ),
    }
    assert entry["request"]["queryString"] == [
        {"name": "opaque", "value": "[REDACTED]"}
    ]
    assert entry["request"]["headers"] == [
        {"name": "Content-Type", "value": "application/problem+json"},
        {"name": "X-Auth", "value": "[REDACTED]"},
        {"name": "X-Session", "value": "[REDACTED]"},
    ]
    assert set(entry["response"]) == {
        "status",
        "statusText",
        "httpVersion",
        "headers",
        "cookies",
        "content",
        "redirectURL",
        "headersSize",
        "bodySize",
    }
    assert entry["response"]["content"] == {"size": 0, "mimeType": ""}
    assert entry["response"]["headers"] == [
        {
            "name": "Location",
            "value": "/v1/items/1?opaque=%5BREDACTED%5D",
        },
        {
            "name": "Content-Location",
            "value": (
                "https://api.example.test/v1/items/1?opaque=%5BREDACTED%5D"
            ),
        },
        {"name": "Link", "value": "[REDACTED]"},
        {"name": "Refresh", "value": "[REDACTED]"},
    ]
    assert set(entry["timings"]) == {
        "blocked",
        "dns",
        "connect",
        "send",
        "wait",
        "receive",
        "ssl",
    }
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("case", ["depth", "nodes", "bytes"])
def test_json_structural_limits_fail_closed(case: str) -> None:
    from openbola import capture

    if case == "depth":
        value: object = "value"
        for _ in range(34):
            value = [value]
        body = json.dumps({"nested": value})
    elif case == "nodes":
        body = json.dumps([0] * 4_096)
    else:
        body = '{"value":"' + ("x" * (1024 * 1024)) + '"}'

    assert capture._sanitize_body(body, {"Content-Type": "application/json"}) == b"[REDACTED]"


def test_writer_rejects_output_over_configured_size_before_creating_file(
    tmp_path: Path,
) -> None:
    from openbola import capture

    with pytest.raises(CaptureError, match="exceeds the configured size limit"):
        capture._write_sanitized_har(tmp_path, Path("oversized.har"), [], max_bytes=10)

    assert not (tmp_path / "oversized.har").exists()


@pytest.mark.parametrize(
    ("case", "request_url", "allowed_hosts", "allowed_cidrs", "should_continue"),
    [
        (
            "denied",
            "https://outside.example.test/v1/items",
            ["api.example.test"],
            [],
            False,
        ),
        (
            "cidr-hostname",
            "https://api.example.test/v1/items",
            ["api.example.test"],
            ["192.0.2.0/24"],
            False,
        ),
        (
            "direct-ip",
            "https://192.0.2.10/v1/items",
            [],
            ["192.0.2.0/24"],
            True,
        ),
    ],
)
def test_capture_uses_real_route_handler_for_denial_cidr_and_direct_ip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    request_url: str,
    allowed_hosts: list[str],
    allowed_cidrs: list[str],
    should_continue: bool,
) -> None:
    from openbola import capture

    actions: list[tuple[str, str | None]] = []

    class Route:
        async def abort(self, error_code: str | None = None) -> None:
            actions.append(("abort", error_code))

        async def continue_(self, *, url: str | None = None) -> None:
            actions.append(("continue", url))

    class Context:
        async def route(self, pattern: str, handler: Any) -> None:
            assert pattern == "**/*"
            await handler(Route(), SimpleNamespace(url=request_url, method="GET"))

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self, *, service_workers: str) -> Context:
            assert service_workers == "block"
            return Context()

        async def close(self) -> None:
            return None

    class Chromium:
        async def launch(self, **kwargs: object) -> Browser:
            assert kwargs == {"headless": True, "args": ["--no-proxy-server"]}
            return Browser()

    class Manager:
        async def __aenter__(self) -> object:
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *args: object) -> None:
            return None

    class Collector:
        def attach(self, context: object) -> None:
            return None

        async def entries(self) -> list[dict[str, Any]]:
            return []

    monkeypatch.setattr(
        capture.importlib,
        "import_module",
        lambda _: SimpleNamespace(async_playwright=lambda: Manager()),
    )
    resolver = (lambda _: ["192.0.2.10"]) if allowed_cidrs else None
    guard = make_scope_guard(
        tmp_path,
        allowed_hosts=allowed_hosts,
        allowed_cidrs=allowed_cidrs,
        resolver=resolver,
    )

    if should_continue:
        output = asyncio.run(
            capture.capture_har(make_config(tmp_path), guard, collector=Collector())
        )
        assert output.is_file()
        assert actions == [("continue", request_url)]
    else:
        with pytest.raises(CaptureError, match="denied by the confirmed scope"):
            asyncio.run(capture.capture_har(make_config(tmp_path), guard, collector=Collector()))
        assert actions == [("abort", "blockedbyclient")], case
        assert not (tmp_path / "nested/a.har").exists()


def test_writer_rejects_a_symlink_parent(tmp_path: Path) -> None:
    from openbola import capture

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(CaptureError, match="cannot be written"):
        capture._write_sanitized_har(root, Path("nested/a.har"), [])

    assert not (outside / "a.har").exists()


def test_writer_remains_anchored_when_parent_is_swapped_for_a_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola import capture

    root = tmp_path / "root"
    nested = root / "nested"
    moved = root / "moved"
    outside = tmp_path / "outside"
    nested.mkdir(parents=True)
    outside.mkdir()
    real_open = os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if isinstance(path, str) and path.startswith(".a.har.") and not swapped:
            nested.rename(moved)
            nested.symlink_to(outside, target_is_directory=True)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(capture.os, "open", swapping_open)
    capture._write_sanitized_har(root, Path("nested/a.har"), [])

    assert swapped
    assert (moved / "a.har").is_file()
    assert not (outside / "a.har").exists()


def test_writer_failure_cleans_temp_and_preserves_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola import capture

    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    target = nested / "a.har"
    target.write_text("existing", encoding="utf-8")

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(capture.os, "replace", fail_replace)
    with pytest.raises(CaptureError, match="cannot be written"):
        capture._write_sanitized_har(root, Path("nested/a.har"), [])

    assert target.read_text(encoding="utf-8") == "existing"
    assert list(nested.iterdir()) == [target]


def test_playwright_import_is_lazy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openbola import capture

    monkeypatch.setattr(
        capture.importlib, "import_module", lambda _: (_ for _ in ()).throw(ImportError())
    )
    with pytest.raises(CaptureError):
        asyncio.run(capture.capture_har(make_config(tmp_path), Guard()))


def test_login_secret_field_requires_non_empty_selector() -> None:
    from openbola.capture import LoginSecretField
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="totp_seed", value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

    with pytest.raises(CaptureError, match="selector"):
        LoginSecretField(selector="", secret=handle, kind="totp")


def test_login_secret_field_rejects_unknown_kind() -> None:
    from openbola.capture import LoginSecretField
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="totp_seed", value="seed")

    with pytest.raises(CaptureError, match="kind"):
        LoginSecretField(selector="#otp", secret=handle, kind="sms")  # type: ignore[arg-type]


def test_login_secret_field_rejects_non_secret_handle() -> None:
    from openbola.capture import LoginSecretField

    not_a_handle: Any = "not-a-handle"  # noqa: S105 - not a real secret
    with pytest.raises(CaptureError, match="SecretHandle"):
        LoginSecretField(selector="#otp", secret=not_a_handle)


def _valid_login_recipe() -> Any:
    from openbola.capture import LoginRecipe
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    return LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    ), registry


def test_login_recipe_accepts_a_minimal_valid_recipe() -> None:
    recipe, _ = _valid_login_recipe()
    assert recipe.name == "staging-portal"
    assert recipe.extra_secret_fields == ()


def test_login_recipe_rejects_empty_name() -> None:
    from openbola.capture import LoginRecipe

    recipe, _ = _valid_login_recipe()
    with pytest.raises(CaptureError, match="name"):
        LoginRecipe(
            name="  ",
            start_url=recipe.start_url,
            username_selector=recipe.username_selector,
            password_selector=recipe.password_selector,
            submit_selector=recipe.submit_selector,
            success_url_pattern=recipe.success_url_pattern,
            username_secret=recipe.username_secret,
            password_secret=recipe.password_secret,
        )


@pytest.mark.parametrize(
    "bad_start_url",
    [
        "not-a-url",
        "ftp://app.example.test/login",
        "https://user:pass@app.example.test/login",
        "https://app.example.test/login?next=/x",
    ],
)
def test_login_recipe_rejects_unsafe_start_url(bad_start_url: str) -> None:
    from openbola.capture import LoginRecipe

    recipe, _ = _valid_login_recipe()
    with pytest.raises(CaptureError, match="start_url"):
        LoginRecipe(
            name=recipe.name,
            start_url=bad_start_url,
            username_selector=recipe.username_selector,
            password_selector=recipe.password_selector,
            submit_selector=recipe.submit_selector,
            success_url_pattern=recipe.success_url_pattern,
            username_secret=recipe.username_secret,
            password_secret=recipe.password_secret,
        )


def test_login_recipe_rejects_empty_success_url_pattern() -> None:
    from openbola.capture import LoginRecipe

    recipe, _ = _valid_login_recipe()
    with pytest.raises(CaptureError, match="success_url_pattern"):
        LoginRecipe(
            name=recipe.name,
            start_url=recipe.start_url,
            username_selector=recipe.username_selector,
            password_selector=recipe.password_selector,
            submit_selector=recipe.submit_selector,
            success_url_pattern="   ",
            username_secret=recipe.username_secret,
            password_secret=recipe.password_secret,
        )


def test_login_recipe_accepts_extra_totp_field() -> None:
    from openbola.capture import LoginRecipe, LoginSecretField
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
        extra_secret_fields=(
            LoginSecretField(
                selector="#otp",
                secret=registry.store_secret(
                    purpose="totp_seed", value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                ),
                kind="totp",
            ),
        ),
    )
    assert recipe.extra_secret_fields[0].kind == "totp"


_TOTP_TEST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # noqa: S105 - RFC 6238 reference vector, not a secret


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1234567890, "005924"),
    ],
)
def test_totp_code_matches_known_vectors(now: int, expected: str) -> None:
    from openbola.capture import _totp_code

    assert _totp_code(_TOTP_TEST_SECRET, now=now) == expected


def test_totp_code_is_six_digits_and_zero_padded() -> None:
    from openbola.capture import _totp_code

    code = _totp_code(_TOTP_TEST_SECRET, now=59)
    assert len(code) == 6
    assert code.isdigit()


def test_totp_code_accepts_lowercase_and_unpadded_secret() -> None:
    from openbola.capture import _totp_code

    lowercase = _TOTP_TEST_SECRET.lower().rstrip("=")
    assert _totp_code(lowercase, now=59) == _totp_code(_TOTP_TEST_SECRET, now=59)


def test_totp_code_rejects_invalid_base32_secret() -> None:
    from openbola.capture import _totp_code

    with pytest.raises(CaptureError, match="base32"):
        _totp_code("not-valid-base32!!!", now=59)


def _login_harness(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_at: str | None = None,
) -> tuple[list[tuple[str, tuple[Any, ...]]], type]:
    from openbola import capture

    calls: list[tuple[str, tuple[Any, ...]]] = []

    class FakePlaywrightError(Exception):
        pass

    class Page:
        async def goto(self, url: str, **kwargs: object) -> None:
            calls.append(("goto", (url,)))
            if fail_at == "goto":
                raise FakePlaywrightError("goto failed")

        async def fill(self, selector: str, value: str, **kwargs: object) -> None:
            calls.append(("fill", (selector, value)))
            if fail_at == f"fill:{selector}":
                raise FakePlaywrightError("fill failed")

        async def click(self, selector: str, **kwargs: object) -> None:
            calls.append(("click", (selector,)))
            if fail_at == "click":
                raise FakePlaywrightError("click failed")

        async def wait_for_url(self, pattern: str, **kwargs: object) -> None:
            calls.append(("wait_for_url", (pattern,)))
            if fail_at == "wait_for_url":
                raise FakePlaywrightError("timed out")

        async def close(self) -> None:
            calls.append(("close", ()))

    class Context:
        async def route(self, pattern: str, handler: object) -> None:
            return None

        async def new_page(self) -> Page:
            return Page()

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self, *, service_workers: str) -> Context:
            return Context()

        async def close(self) -> None:
            return None

    class Chromium:
        async def launch(self, **kwargs: object) -> Browser:
            return Browser()

    class Manager:
        async def __aenter__(self) -> object:
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *args: object) -> None:
            return None

    class Collector:
        def attach(self, context: object) -> None:
            return None

        async def entries(self) -> list[dict[str, object]]:
            return []

    monkeypatch.setattr(
        capture.importlib,
        "import_module",
        lambda _: SimpleNamespace(
            async_playwright=lambda: Manager(),
            Error=FakePlaywrightError,
        ),
    )
    return calls, Collector


def _login_config(tmp_path: Path, recipe: Any) -> Any:
    from openbola.capture import CaptureConfig

    return CaptureConfig(
        target_url="https://app.example.test/",
        capture_root=tmp_path,
        output_path=Path("out.har"),
        identity="alice",
        login_recipe=recipe,
    )


def test_capture_har_performs_automated_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.capture import LoginRecipe, LoginSecretField, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
        extra_secret_fields=(
            LoginSecretField(
                selector="#otp",
                secret=registry.store_secret(
                    purpose="totp_seed", value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                ),
                kind="totp",
            ),
        ),
    )
    calls, Collector = _login_harness(monkeypatch)

    output = asyncio.run(
        capture_har(
            _login_config(tmp_path, recipe),
            Guard(),
            collector=Collector(),
            registry=registry,
        )
    )

    assert output.exists()
    kinds = [name for name, _ in calls]
    assert kinds == ["goto", "fill", "fill", "fill", "click", "wait_for_url", "close"]
    assert calls[0] == ("goto", ("https://app.example.test/login",))
    assert calls[1] == ("fill", ("#email", "alice"))
    assert calls[2] == ("fill", ("#password", "hunter2"))
    assert calls[3][1][0] == "#otp"
    assert calls[3][1][1] != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # TOTP seed never filled verbatim
    assert calls[3][1][1].isdigit() and len(calls[3][1][1]) == 6
    assert calls[4] == ("click", ("#submit",))
    assert calls[5] == ("wait_for_url", ("**/dashboard",))


def test_capture_har_wraps_login_failure_as_capture_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.capture import LoginRecipe, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )
    _, Collector = _login_harness(monkeypatch, fail_at="wait_for_url")

    with pytest.raises(CaptureError, match="login"):
        asyncio.run(
            capture_har(
                _login_config(tmp_path, recipe),
                Guard(),
                collector=Collector(),
                registry=registry,
            )
        )


def test_capture_config_rejects_login_recipe_with_interactive_login(tmp_path: Path) -> None:
    from openbola.capture import CaptureConfig, LoginRecipe
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )
    with pytest.raises(CaptureError, match="mutually exclusive"):
        CaptureConfig(
            target_url="https://app.example.test/",
            capture_root=tmp_path,
            output_path=Path("out.har"),
            identity="alice",
            headless=False,
            interactive_login=True,
            login_recipe=recipe,
        )


def test_capture_config_rejects_non_login_recipe_login_recipe(tmp_path: Path) -> None:
    from openbola.capture import CaptureConfig

    fake_recipe = SimpleNamespace(start_url="https://app.example.test/login")
    with pytest.raises(CaptureError, match="LoginRecipe"):
        CaptureConfig(
            target_url="https://app.example.test/",
            capture_root=tmp_path,
            output_path=Path("out.har"),
            identity="alice",
            login_recipe=fake_recipe,  # type: ignore[arg-type]
        )


def test_capture_har_requires_registry_when_login_recipe_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.capture import LoginRecipe, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )
    _, Collector = _login_harness(monkeypatch)

    with pytest.raises(CaptureError, match="registry"):
        asyncio.run(
            capture_har(_login_config(tmp_path, recipe), Guard(), collector=Collector())
        )


def test_capture_har_translates_lookup_error_from_mismatched_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.capture import LoginRecipe, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    minting_registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=minting_registry.store_secret(purpose="username", value="alice"),
        password_secret=minting_registry.store_secret(purpose="password", value="hunter2"),
    )
    mismatched_registry = InMemorySessionValueRegistry()
    _, Collector = _login_harness(monkeypatch)

    with pytest.raises(CaptureError, match="login") as excinfo:
        asyncio.run(
            capture_har(
                _login_config(tmp_path, recipe),
                Guard(),
                collector=Collector(),
                registry=mismatched_registry,
            )
        )
    assert isinstance(excinfo.value.__cause__, LookupError)


def test_capture_har_login_post_body_is_sanitized_in_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola import capture
    from openbola.capture import InMemoryEventCollector, LoginRecipe, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",  # noqa: S106 - CSS selector, not a secret
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )

    class FakePlaywrightError(Exception):
        pass

    class FakeRequest:
        def __init__(self) -> None:
            self.method = "POST"
            self.url = "https://app.example.test/login"
            self.headers = {"content-type": "application/x-www-form-urlencoded"}
            self.post_data = "email=alice&password=hunter2"

    class FakeResponse:
        def __init__(self, request: "FakeRequest") -> None:
            self.request = request
            self.status = 302
            self.headers = {"location": "https://app.example.test/dashboard"}

    class Context:
        def __init__(self) -> None:
            self._handlers: dict[str, Any] = {}

        def on(self, event: str, handler: object) -> None:
            self._handlers[event] = handler

        async def route(self, pattern: str, handler: object) -> None:
            return None

        async def new_page(self) -> "Page":
            return Page(self)

        async def close(self) -> None:
            return None

    class Page:
        def __init__(self, context: Context) -> None:
            self._context = context

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def fill(self, selector: str, value: str, **kwargs: object) -> None:
            return None

        async def click(self, selector: str, **kwargs: object) -> None:
            request = FakeRequest()
            self._context._handlers["request"](request)
            self._context._handlers["response"](FakeResponse(request))

        async def wait_for_url(self, pattern: str, **kwargs: object) -> None:
            return None

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self, *, service_workers: str) -> Context:
            return Context()

        async def close(self) -> None:
            return None

    class Chromium:
        async def launch(self, **kwargs: object) -> Browser:
            return Browser()

    class Manager:
        async def __aenter__(self) -> object:
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(
        capture.importlib,
        "import_module",
        lambda _: SimpleNamespace(
            async_playwright=lambda: Manager(),
            Error=FakePlaywrightError,
        ),
    )

    output = asyncio.run(
        capture_har(
            _login_config(tmp_path, recipe),
            Guard(),
            collector=InMemoryEventCollector(),
            registry=registry,
        )
    )

    output_bytes = output.read_bytes()
    assert b"hunter2" not in output_bytes

    document = json.loads(output_bytes)
    [entry] = document["log"]["entries"]
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["postData"]["text"] == "[REDACTED]"
    assert entry["response"]["status"] == 302


def test_in_session_capture_exposes_raw_material_only_via_session_handles(tmp_path: Path) -> None:
    from openbola.capture import InSessionCapture, SessionExchange
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    har_path = tmp_path / "capture.har"
    har_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
    safe = RequestRecord("alice", "GET", "https://api.example.test/v1/items/[REDACTED]")
    request_handle = registry.store_value(kind="session_state", value=object())
    response_handle = registry.store_value(kind="session_state", value=object())
    state_handle = registry.store_value(kind="session_state", value={"cookies": []})
    exchange = SessionExchange(safe, request_handle, response_handle)

    capture = InSessionCapture(har_path, (exchange,), state_handle, registry)

    assert "FULL_VALUE_SENTINEL" not in repr(capture)
    assert capture.exchanges[0].record.url.endswith("[REDACTED]")
    with pytest.raises(CaptureError, match="request material"):
        capture.request_material(exchange)
    with pytest.raises(TypeError, match="serialization"):
        import pickle

        pickle.dumps(capture)


def test_in_session_capture_close_revokes_every_handle(tmp_path: Path) -> None:
    from openbola.capture import (
        InSessionCapture,
        SessionExchange,
        SessionRequestMaterial,
        SessionResponseMaterial,
    )
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    har_path = tmp_path / "capture.har"
    har_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
    request_handle = registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial("https://api.example.test/v1/items/42", {}, None),
    )
    response_handle = registry.store_value(
        kind="session_state", value=SessionResponseMaterial(200, {}, b"FULL_VALUE_SENTINEL")
    )
    state_handle = registry.store_value(kind="session_state", value={"cookies": []})
    exchange = SessionExchange(
        RequestRecord("alice", "GET", "https://api.example.test/v1/items/42"),
        request_handle,
        response_handle,
    )
    capture = InSessionCapture(har_path, (exchange,), state_handle, registry)

    assert capture.response_material(exchange).body == b"FULL_VALUE_SENTINEL"
    capture.close()
    with pytest.raises(CaptureError, match="closed"):
        capture.response_material(exchange)
    with pytest.raises(RuntimeError, match="registry is closed"):
        registry.resolve_value(response_handle)


def test_in_session_capture_rejects_malformed_resolved_material(tmp_path: Path) -> None:
    from openbola.capture import (
        InSessionCapture,
        SessionExchange,
        SessionRequestMaterial,
        SessionResponseMaterial,
    )
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    har_path = tmp_path / "capture.har"
    har_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
    request_handle = registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial(42, {}, None),  # type: ignore[arg-type]
    )
    response_handle = registry.store_value(
        kind="session_state",
        value=SessionResponseMaterial(200, {}, None),
    )
    state_handle = registry.store_value(kind="session_state", value={"cookies": []})
    exchange = SessionExchange(
        RequestRecord("alice", "GET", "https://api.example.test/v1/items/[REDACTED]"),
        request_handle,
        response_handle,
    )
    capture = InSessionCapture(har_path, (exchange,), state_handle, registry)

    with pytest.raises(CaptureError, match="request material"):
        capture.request_material(exchange)


def test_session_material_rejects_serialization() -> None:
    import pickle

    from openbola.capture import SessionRequestMaterial, SessionResponseMaterial

    materials = (
        SessionRequestMaterial(
            "https://api.example.test/v1/items/FULL_VALUE_SENTINEL",
            {"Authorization": "FULL_VALUE_SENTINEL"},
            b"FULL_VALUE_SENTINEL",
        ),
        SessionResponseMaterial(
            200,
            {"Set-Cookie": "FULL_VALUE_SENTINEL"},
            b"FULL_VALUE_SENTINEL",
        ),
    )

    for material in materials:
        assert "FULL_VALUE_SENTINEL" not in repr(material)
        with pytest.raises(TypeError, match="serialization"):
            pickle.dumps(material)


def test_in_session_capture_adapter_bridge_rejects_unsafe_results(tmp_path: Path) -> None:
    from openbola.capture import (
        InSessionCapture,
        SessionExchange,
        SessionRequestMaterial,
        SessionResponseMaterial,
    )
    from openbola.discovery import FieldInventory, ProviderConfidence, ResourceInventory
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    har_path = tmp_path / "capture.har"
    har_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
    request_handle = registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial("https://api.example.test/v1/items/42", {}, None),
    )
    response_handle = registry.store_value(
        kind="session_state",
        value=SessionResponseMaterial(200, {}, None),
    )
    state_handle = registry.store_value(kind="session_state", value={"cookies": []})
    exchange = SessionExchange(
        RequestRecord("alice", "GET", "https://api.example.test/v1/items/[REDACTED]"),
        request_handle,
        response_handle,
    )
    capture = InSessionCapture(har_path, (exchange,), state_handle, registry)
    raw_record = RequestRecord(
        "alice",
        "GET",
        "https://api.example.test/v1/items/FULL_VALUE_SENTINEL",
    )
    safe_inventory = ResourceInventory(
        provider="generic",
        provider_confidence=ProviderConfidence.UNKNOWN,
        resource_name="items",
        endpoint_template="/v1/items/{id}",
        fields=(FieldInventory("name"),),
        record_handles=(registry.store_value(kind="record_id", value="42"),),
        observed_methods=frozenset({"GET"}),
    )
    unsafe_inventory = ResourceInventory(
        provider="generic",
        provider_confidence=ProviderConfidence.UNKNOWN,
        resource_name="items",
        endpoint_template="/v1/items/{id}",
        fields=(raw_record,),
        record_handles=(),
        observed_methods=frozenset({"GET"}),
    )

    assert capture.with_adapter_records(lambda _records: (safe_inventory,)) == (safe_inventory,)
    for result in (
        raw_record,
        [raw_record],
        {"record": raw_record},
        (raw_record,),
        (unsafe_inventory,),
    ):
        with pytest.raises(CaptureError, match="ResourceInventory tuple"):
            capture.with_adapter_records(lambda _records, result=result: result)

    def failing_consumer(_records: object) -> tuple[ResourceInventory, ...]:
        raise RuntimeError("FULL_VALUE_SENTINEL")

    with pytest.raises(CaptureError, match="session adapter failed") as excinfo:
        capture.with_adapter_records(failing_consumer)  # type: ignore[arg-type]
    assert "FULL_VALUE_SENTINEL" not in str(excinfo.value)
