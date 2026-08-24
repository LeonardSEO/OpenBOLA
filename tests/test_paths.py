from __future__ import annotations

import sys

import pytest

from openbola.paths import data_root


def test_macos_data_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("HOME", "/Users/testuser")
    assert str(data_root()) == "/Users/testuser/Library/Application Support/OpenBOLA"


def test_windows_data_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\testuser\AppData\Local")
    from pathlib import PureWindowsPath
    assert PureWindowsPath(str(data_root())) == PureWindowsPath(
        r"C:\Users\testuser\AppData\Local\OpenBOLA"
    )


def test_windows_data_root_requires_localappdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    with pytest.raises(RuntimeError, match="LOCALAPPDATA"):
        data_root()


def test_unsupported_platform_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="linux"):
        data_root()
