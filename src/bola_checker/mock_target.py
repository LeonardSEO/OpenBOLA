"""A deterministic, localhost-only target for BOLACheck development tests."""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import ClassVar

DOCUMENT = {"id": "812", "owner_id": "alice", "content": "alice-only fixture"}
DEMO_OBJECT_ID = "e2e-object-7c31f0a9"
DEMO_DOCUMENT = {
    "id": DEMO_OBJECT_ID,
    "owner_id": "alice",
    "content": "alice-only fixture",
}


class _Handler(BaseHTTPRequestHandler):
    server_version = "BOLACheckMock/1"
    sys_version = ""
    documents: ClassVar[dict[str, dict[str, str]]] = {
        "812": DOCUMENT,
        DEMO_OBJECT_ID: DEMO_DOCUMENT,
    }
    token_users: ClassVar[dict[str, str]] = {}
    request_counter: ClassVar[list[int] | None] = None

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args

    def do_GET(self) -> None:  # noqa: N802
        if self.request_counter is not None:
            self.request_counter[0] += 1
        match = re.fullmatch(r"/api/(documents|secure)/([A-Za-z0-9_-]+)", self.path)
        if match is None:
            self.send_error(404)
            return
        kind, object_id = match.groups()
        document = self.documents.get(object_id)
        if document is None:
            self.send_error(404)
            return
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        user = self.token_users.get(token)
        if kind == "secure" and user != document["owner_id"]:
            self.send_response(403)
            self.end_headers()
            return
        payload = json.dumps(document, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@dataclass
class MockTarget:
    """Threaded localhost server; use as a context manager in tests."""

    server: ThreadingHTTPServer | None = None
    thread: Thread | None = None
    alice_token: str = ""
    bob_token: str = ""
    _request_counter: list[int] = field(default_factory=lambda: [0], repr=False)

    def __post_init__(self) -> None:
        if self.server is not None or self.thread is not None:
            if self.server is None or self.thread is None:
                raise ValueError("mock target server and thread must be supplied together")
            return
        self.alice_token = "mock-alice-" + secrets.token_hex(16)
        self.bob_token = "mock-bob-" + secrets.token_hex(16)
        handler = type(
            "LocalMockHandler",
            (_Handler,),
            {
                "token_users": {self.alice_token: "alice", self.bob_token: "bob"},
                "request_counter": self._request_counter,
            },
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = Thread(target=self.server.serve_forever, name="bolacheck-mock", daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        if self.server is None:
            raise RuntimeError("mock target is not running")
        return f"http://127.0.0.1:{self.server.server_port}"

    @classmethod
    def start(cls) -> MockTarget:
        return cls()

    def close(self) -> None:
        if self.server is None or self.thread is None:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("local mock target thread did not stop")

    @property
    def request_count(self) -> int:
        return self._request_counter[0]

    def __enter__(self) -> MockTarget:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.close()


__all__ = ["DEMO_OBJECT_ID", "DOCUMENT", "MockTarget"]
