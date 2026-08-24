from __future__ import annotations

import json
from pathlib import Path

import pytest

from openbola.capture import (
    InSessionCapture,
    SessionExchange,
    SessionRequestMaterial,
    SessionResponseMaterial,
)
from openbola.handles import InMemorySessionValueRegistry
from openbola.models import RequestRecord


@pytest.fixture
def captured_session_with_sentinels(tmp_path: Path) -> InSessionCapture:
    har_path = tmp_path / "session.har"
    har_path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://api.example.test/v1/items/[REDACTED]",
                                "headers": [],
                                "postData": {"mimeType": "application/json", "text": "[REDACTED]"},
                            },
                            "response": {"status": 200, "headers": [], "content": {}},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    registry = InMemorySessionValueRegistry()
    request_handle = registry.store_value(
        kind="session_state",
        value=SessionRequestMaterial(
            "https://api.example.test/v1/items/RAW_ID_4eC39HqLyjWDarjtT1zdp7dc",
            {"Authorization": "Bearer REQUEST_SECRET_SENTINEL"},
            b'{"id":"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc"}',
        ),
    )
    response_handle = registry.store_value(
        kind="session_state",
        value=SessionResponseMaterial(
            200,
            {"Set-Cookie": "sid=COOKIE_SECRET_SENTINEL"},
            b'{"id":"RAW_ID_4eC39HqLyjWDarjtT1zdp7dc","name":"FULL_VALUE_SENTINEL"}',
        ),
    )
    browser_state_handle = registry.store_value(
        kind="session_state",
        value={"cookies": [{"name": "sid", "value": "COOKIE_SECRET_SENTINEL"}], "origins": []},
    )
    exchange = SessionExchange(
        RequestRecord("alice", "POST", "https://api.example.test/v1/items/[REDACTED]"),
        request_handle,
        response_handle,
    )
    capture = InSessionCapture(har_path, (exchange,), browser_state_handle, registry)
    yield capture
    capture.close()
