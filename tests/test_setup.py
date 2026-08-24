from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from openbola import __version__
from openbola.setup import (
    SETUP_MARKER_SCHEMA,
    SetupResult,
    marker_path,
    read_marker,
    run_setup,
)


class FakeVault:
    def __init__(self, key: bytes = b"k" * 32) -> None:
        self.key = key
        self.calls = 0

    def get_or_create_key(self) -> bytes:
        self.calls += 1
        return self.key


class FakeInstaller:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.install_calls: list[bool] = []
        self.ready_calls = 0

    def is_ready(self) -> bool:
        self.ready_calls += 1
        return self.ready

    def install(self, *, force: bool = False) -> None:
        self.install_calls.append(force)
        self.ready = True


class FakeSelfTest:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.calls = 0

    def run(self) -> bool:
        self.calls += 1
        return self.result


def _setup(
    root: Path,
    *,
    installer: FakeInstaller | None = None,
    self_test: FakeSelfTest | None = None,
    vault: FakeVault | None = None,
    force_browser: bool = False,
) -> SetupResult:
    return run_setup(
        root=root,
        installer=installer or FakeInstaller(),
        browser_self_test=self_test or FakeSelfTest(),
        vault=vault or FakeVault(),
        force_browser=force_browser,
    )


def test_ready_browser_runs_local_self_test_and_publishes_private_marker(tmp_path: Path) -> None:
    installer = FakeInstaller(ready=True)
    browser_test = FakeSelfTest()
    vault = FakeVault()

    result = _setup(tmp_path / "OpenBOLA", installer=installer, self_test=browser_test, vault=vault)

    assert result == SetupResult("already_ready", "ready", "passed")
    assert installer.install_calls == []
    assert browser_test.calls == 1
    assert vault.calls == 2
    marker = marker_path(tmp_path / "OpenBOLA")
    assert marker.is_file()
    assert os.stat(marker).st_mode & 0o777 == 0o600
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "browser": "already_ready",
        "schema": SETUP_MARKER_SCHEMA,
        "self_test": "passed",
        "vault": "ready",
        "version": __version__,
    }


def test_force_browser_installs_once_even_when_already_ready(tmp_path: Path) -> None:
    installer = FakeInstaller(ready=True)
    result = _setup(
        tmp_path / "OpenBOLA",
        installer=installer,
        force_browser=True,
    )

    assert result.ok
    assert installer.install_calls == [True]


def test_missing_browser_is_installed_and_checked_again(tmp_path: Path) -> None:
    installer = FakeInstaller(ready=False)
    result = _setup(tmp_path / "OpenBOLA", installer=installer)

    assert result.ok
    assert installer.install_calls == [False]
    assert installer.ready_calls == 2


def test_missing_vault_fails_closed_without_install_or_marker(tmp_path: Path) -> None:
    root = tmp_path / "OpenBOLA"
    installer = FakeInstaller(ready=False)

    result = run_setup(root=root, installer=installer, browser_self_test=FakeSelfTest())

    assert result == SetupResult("unavailable", "unavailable", "failed", "vault_unavailable")
    assert installer.install_calls == []
    assert not root.exists() or not marker_path(root).exists()


def test_invalid_vault_key_never_leaks_material_and_blocks_browser(tmp_path: Path) -> None:
    root = tmp_path / "OpenBOLA"
    installer = FakeInstaller(ready=False)
    sentinel = b"VAULT_SECRET_SENTINEL"
    result = _setup(root, installer=installer, vault=FakeVault(sentinel))

    assert result.reason_code == "vault_unavailable"
    assert result.vault == "unavailable"
    assert installer.install_calls == []
    assert sentinel.decode() not in repr(result)
    assert not marker_path(root).exists()


def test_self_test_failure_does_not_publish_partial_marker(tmp_path: Path) -> None:
    root = tmp_path / "OpenBOLA"
    result = _setup(root, self_test=FakeSelfTest(False))

    assert result.ok is False
    assert result.reason_code == "browser_self_test_failed"
    assert not marker_path(root).exists()


def test_installer_failure_is_generic_and_does_not_expose_exception(tmp_path: Path) -> None:
    class FailingInstaller(FakeInstaller):
        def install(self, *, force: bool = False) -> None:
            del force
            raise RuntimeError("PLAYWRIGHT_SECRET / Users/private-user")

    root = tmp_path / "OpenBOLA"
    result = _setup(root, installer=FailingInstaller(ready=False))

    assert result.reason_code == "browser_unavailable"
    assert "PLAYWRIGHT_SECRET" not in repr(result)
    assert "private-user" not in repr(result)
    assert not marker_path(root).exists()


def test_marker_reader_rejects_symlink(tmp_path: Path) -> None:
    root = tmp_path / "OpenBOLA"
    result = _setup(root)
    assert result.ok
    marker = marker_path(root)
    replacement = tmp_path / "replacement.json"
    replacement.write_text(marker.read_text(encoding="utf-8"), encoding="utf-8")
    marker.unlink()
    marker.symlink_to(replacement)

    with pytest.raises(Exception) as error:
        read_marker(root)
    assert "private-user" not in str(error.value)
    assert "replacement" not in str(error.value)


def test_self_test_callable_is_local_and_receives_no_target(tmp_path: Path) -> None:
    calls: list[object] = []

    def local_test() -> bool:
        calls.append("about:blank")
        return True

    result = run_setup(
        root=tmp_path / "OpenBOLA",
        installer=FakeInstaller(),
        browser_self_test=local_test,
        vault=FakeVault(),
    )

    assert result.ok
    assert calls == ["about:blank"]
