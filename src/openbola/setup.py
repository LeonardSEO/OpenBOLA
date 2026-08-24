"""Safe, explicit setup of local OpenBOLA prerequisites.

The setup command is deliberately kept separate from the assessment engine.  It
may install the Playwright browser selected by the installed Playwright
package, and it may check the P6 recovery-key boundary, but it never receives a
target URL and never constructs an HTTP client.  All external operations are
behind small protocols so the command can be tested without a browser,
subprocess, network, or operating-system vault.
"""

from __future__ import annotations

import hmac
import importlib
import importlib.util
import inspect
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

from openbola import __version__
from openbola.paths import data_root

BrowserStatus = Literal["installed", "already_ready", "unavailable"]
VaultStatus = Literal["ready", "unavailable"]
SelfTestStatus = Literal["passed", "failed"]

SETUP_MARKER_NAME: Final = "setup-status.json"
SETUP_MARKER_SCHEMA: Final = "openbola-setup-v1"
_MARKER_MODE: Final = 0o600
_DIRECTORY_MODE: Final = 0o700
_MAX_MARKER_BYTES: Final = 16_384
_INSTALL_TIMEOUT_SECONDS: Final = 300.0
_RECOVERY_KEY_BYTES: Final = 32


class BrowserInstaller(Protocol):
    """The bounded browser install/readiness boundary used by ``run_setup``."""

    def is_ready(self) -> bool:
        """Return whether the pinned Chromium browser is available locally."""

    def install(self, *, force: bool = False) -> None:
        """Install the browser selected by the installed Playwright package."""


class BrowserSelfTest(Protocol):
    """A local-only browser launch check.

    Implementations must use ``about:blank`` (or an equivalent local page) and
    must not navigate to a target, localhost service, or remote URL.
    """

    def run(self) -> bool | None:
        """Launch, open a local blank page, and close the browser."""


class RecoveryKeyStore(Protocol):
    """P6's OS-vault key boundary as consumed by setup.

    The returned key is used only during the immediate self-test and is never
    returned by ``run_setup`` or written to the setup marker.  P6 adapters may
    expose a more specific implementation; ``run_setup`` also accepts the
    compatible ``ensure_key``/``get_key`` forms while the recovery module is
    optional during installation.
    """

    def get_or_create_key(self) -> bytes:
        """Read an existing key or create it in the approved OS vault."""


@dataclass(frozen=True)
class SetupResult:
    """Secret-free outcome of one explicit setup attempt."""

    browser: BrowserStatus
    vault: VaultStatus
    self_test: SelfTestStatus
    reason_code: str | None = None

    @property
    def ok(self) -> bool:
        """Whether all prerequisites completed successfully."""

        return (
            self.browser in {"installed", "already_ready"}
            and self.vault == "ready"
            and self.self_test == "passed"
        )

    def public_summary(self) -> dict[str, str | bool]:
        """Return the bounded shape suitable for CLI JSON output."""

        result: dict[str, str | bool] = {
            "ok": self.ok,
            "browser": self.browser,
            "vault": self.vault,
            "self_test": self.self_test,
        }
        if self.reason_code is not None:
            result["reason_code"] = self.reason_code
        return result


class SetupError(RuntimeError):
    """Internal setup refusal carrying only a stable public reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def marker_path(root: Path | None = None) -> Path:
    """Return the setup marker path without creating the data root."""

    return (root if root is not None else data_root()) / SETUP_MARKER_NAME


def _check_private_directory(path: Path) -> None:
    try:
        if path.is_symlink() or not path.is_dir():
            raise SetupError("data_root_untrusted")
        info = path.stat()
    except (OSError, ValueError) as error:
        raise SetupError("data_root_unavailable") from error
    if os.name != "nt":
        uid = getattr(os, "getuid", lambda: info.st_uid)()
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
            raise SetupError("data_root_untrusted")


def _ensure_private_root(root: Path) -> None:
    """Create only missing path components with private permissions.

    Existing parents are not made private by this function: the standard
    macOS application-support parent is commonly user-readable.  The actual
    OpenBOLA directory and every newly created component are private.
    """

    if root == root.parent:
        raise SetupError("data_root_unavailable")
    missing: list[Path] = []
    current = root
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            raise SetupError("data_root_unavailable")
        current = parent
    if current.is_symlink() or not current.is_dir():
        raise SetupError("data_root_untrusted")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=_DIRECTORY_MODE)
        except FileExistsError:
            pass
        except OSError as error:
            raise SetupError("data_root_unavailable") from error
        _check_private_directory(directory)
    _check_private_directory(root)


def _write_marker(root: Path, *, browser: BrowserStatus) -> None:
    """Atomically publish a marker only after every prerequisite passed."""

    marker = marker_path(root)
    payload = {
        "schema": SETUP_MARKER_SCHEMA,
        "version": __version__,
        "browser": browser,
        "vault": "ready",
        "self_test": "passed",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = root / f".{SETUP_MARKER_NAME}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    file_descriptor: int | None = None
    try:
        file_descriptor = os.open(temporary, flags, _MARKER_MODE)
        with os.fdopen(file_descriptor, "wb", closefd=True) as stream:
            file_descriptor = None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, _MARKER_MODE)
        os.replace(temporary, marker)
        # Directory fsync is supported on POSIX and harmlessly skipped on
        # platforms where opening a directory is not available.
        if os.name != "nt":
            try:
                directory_fd = os.open(root, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
    except (OSError, ValueError) as error:
        raise SetupError("marker_write_failed") from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # The successful marker is still valid; a failed cleanup must not
            # be rendered as an exception containing a local path.
            pass


def read_marker(root: Path | None = None) -> Mapping[str, str]:
    """Read and validate a setup marker for local diagnostic consumers.

    This helper returns only the fixed marker fields.  It refuses symlinks,
    malformed JSON, unknown keys, and values outside the bounded enum; it does
    not return the path or any filesystem exception text.
    """

    directory = root if root is not None else data_root()
    _check_private_directory(directory)
    marker = marker_path(directory)
    try:
        if marker.is_symlink() or not marker.is_file():
            raise SetupError("setup_marker_missing")
        info = marker.stat()
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise SetupError("setup_marker_untrusted")
        if info.st_size > _MAX_MARKER_BYTES:
            raise SetupError("setup_marker_invalid")
        raw = marker.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
    except SetupError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SetupError("setup_marker_invalid") from error
    if not isinstance(parsed, dict):
        raise SetupError("setup_marker_invalid")
    expected_keys = {"schema", "version", "browser", "vault", "self_test"}
    if set(parsed) != expected_keys or any(not isinstance(value, str) for value in parsed.values()):
        raise SetupError("setup_marker_invalid")
    values = cast(dict[str, str], parsed)
    if values["schema"] != SETUP_MARKER_SCHEMA:
        raise SetupError("setup_marker_invalid")
    if values["browser"] not in {"installed", "already_ready"}:
        raise SetupError("setup_marker_invalid")
    if values["vault"] != "ready" or values["self_test"] != "passed":
        raise SetupError("setup_marker_invalid")
    return values


def _playwright_available() -> bool:
    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


class PlaywrightInstaller:
    """Default installer for the browser pinned by the installed package."""

    def is_ready(self) -> bool:
        if not _playwright_available():
            return False
        try:
            sync_api = importlib.import_module("playwright.sync_api")
            with sync_api.sync_playwright() as playwright:
                executable = Path(playwright.chromium.executable_path)
            return executable.is_file()
        except (OSError, ImportError, RuntimeError, AttributeError, TypeError):
            return False

    def install(self, *, force: bool = False) -> None:
        del force  # Playwright's command is idempotent; the caller controls when it runs.
        if not _playwright_available():
            raise SetupError("browser_unavailable")
        command = [sys.executable, "-m", "playwright", "install", "chromium"]
        try:
            completed = subprocess.run(  # noqa: S603
                command,
                check=False,
                capture_output=True,
                timeout=_INSTALL_TIMEOUT_SECONDS,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise SetupError("browser_install_failed") from error
        # Never include stdout/stderr in an exception or result.  It may contain
        # local paths or environment-dependent values.
        del completed.stdout, completed.stderr
        if completed.returncode != 0:
            raise SetupError("browser_install_failed")


class PlaywrightSelfTest:
    """Default local browser self-test; it opens only ``about:blank``."""

    def run(self) -> bool:
        if not _playwright_available():
            return False
        browser: Any = None
        try:
            sync_api = importlib.import_module("playwright.sync_api")
            with sync_api.sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto("about:blank", wait_until="load")
                return cast(str, page.url) == "about:blank"
        except (OSError, ImportError, RuntimeError, AttributeError, TypeError):
            return False
        finally:
            if browser is not None:
                with suppress(Exception):
                    browser.close()


def _invoke_install(installer: BrowserInstaller, *, force: bool) -> None:
    install = cast(Any, installer).install
    parameters: Mapping[str, inspect.Parameter]
    try:
        parameters = inspect.signature(install).parameters
    except (TypeError, ValueError):
        parameters = {}
    accepts_force = "force" in parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    )
    if accepts_force:
        install(force=force)
    else:
        install()


def _run_vault_self_test(vault: object) -> None:
    """Exercise the P6 vault without returning or persisting its key."""

    candidate: Any = None
    method: Any = getattr(vault, "get_or_create_key", None)
    if callable(method):
        candidate = method()
        if isinstance(candidate, bytes) and len(candidate) != _RECOVERY_KEY_BYTES:
            raise SetupError("vault_unavailable")
        # Read once more through the same boundary to prove an existing key is
        # accessible after creation.  Do not compare or expose the key.
        second: Any = method()
        if isinstance(second, bytes) and len(second) != _RECOVERY_KEY_BYTES:
            raise SetupError("vault_unavailable")
        if (
            isinstance(candidate, bytes)
            and isinstance(second, bytes)
            and not hmac.compare_digest(candidate, second)
        ):
            raise SetupError("vault_unavailable")
        del second
    else:
        for method_name in ("ensure_key", "get_key"):
            method = getattr(vault, method_name, None)
            if callable(method):
                candidate = method()
                break
        else:
            raise SetupError("vault_unavailable")
        if isinstance(candidate, bytes) and len(candidate) != _RECOVERY_KEY_BYTES:
            raise SetupError("vault_unavailable")
    # An approved key provider may intentionally return None from ensure_key;
    # a provider that returns a value must return bytes of the AES-256 size.
    if candidate is not None and not isinstance(candidate, bytes):
        raise SetupError("vault_unavailable")
    del candidate


def _run_self_test(self_test: BrowserSelfTest | Any) -> bool:
    if callable(self_test) and not hasattr(self_test, "run"):
        result = self_test()
    else:
        result = cast(Any, self_test).run()
    return result is not False


def _result(
    browser: BrowserStatus,
    vault: VaultStatus,
    self_test: SelfTestStatus,
    reason: str,
) -> SetupResult:
    return SetupResult(browser, vault, self_test, reason)


def run_setup(
    *,
    force_browser: bool = False,
    installer: BrowserInstaller | None = None,
    browser_self_test: BrowserSelfTest | Any | None = None,
    self_test: BrowserSelfTest | Any | None = None,
    vault: RecoveryKeyStore | object | None = None,
    root: Path | None = None,
) -> SetupResult:
    """Install/check local prerequisites and publish a success marker.

    ``installer``, ``browser_self_test``, and ``vault`` are injectable for
    deterministic tests.  No default vault is synthesized: until P6 exposes an
    approved OS-vault implementation, setup fails closed with
    ``vault_unavailable``.  ``root`` is a test-only data-root override; normal
    callers use :func:`openbola.paths.data_root`.
    """

    if browser_self_test is not None and self_test is not None:
        return _result("unavailable", "unavailable", "failed", "invalid_arguments")
    selected_self_test = browser_self_test if browser_self_test is not None else self_test
    try:
        selected_root = root if root is not None else data_root()
    except (OSError, RuntimeError, ValueError):
        return _result("unavailable", "unavailable", "failed", "data_root_unavailable")

    try:
        _ensure_private_root(selected_root)
    except SetupError as error:
        return _result("unavailable", "unavailable", "failed", error.code)
    except (OSError, RuntimeError, ValueError):
        return _result("unavailable", "unavailable", "failed", "data_root_unavailable")

    # Do not install a browser when the recovery-key boundary is unavailable.
    # This avoids a partial setup that could launch capture but cannot support
    # the crash-recovery guarantees required by P6.
    if vault is None:
        return _result("unavailable", "unavailable", "failed", "vault_unavailable")
    try:
        _run_vault_self_test(vault)
    except SetupError as error:
        return _result("unavailable", "unavailable", "failed", error.code)
    except Exception:
        return _result("unavailable", "unavailable", "failed", "vault_unavailable")

    selected_installer: BrowserInstaller = (
        installer if installer is not None else PlaywrightInstaller()
    )
    browser_status: BrowserStatus
    try:
        if force_browser:
            _invoke_install(selected_installer, force=True)
            browser_status = "installed"
        elif selected_installer.is_ready():
            browser_status = "already_ready"
        else:
            _invoke_install(selected_installer, force=False)
            if not selected_installer.is_ready():
                return _result("unavailable", "ready", "failed", "browser_install_failed")
            browser_status = "installed"
    except SetupError as error:
        return _result("unavailable", "ready", "failed", error.code)
    except Exception:
        return _result("unavailable", "ready", "failed", "browser_unavailable")

    if selected_self_test is None:
        selected_self_test = PlaywrightSelfTest()
    try:
        passed = _run_self_test(selected_self_test)
    except Exception:
        passed = False
    if not passed:
        return _result(browser_status, "ready", "failed", "browser_self_test_failed")

    try:
        _write_marker(selected_root, browser=browser_status)
    except SetupError as error:
        return _result(browser_status, "ready", "failed", error.code)
    except Exception:
        return _result(browser_status, "ready", "failed", "marker_write_failed")
    return SetupResult(browser_status, "ready", "passed")


__all__ = [
    "BrowserInstaller",
    "BrowserSelfTest",
    "PlaywrightInstaller",
    "PlaywrightSelfTest",
    "RecoveryKeyStore",
    "SETUP_MARKER_NAME",
    "SETUP_MARKER_SCHEMA",
    "SetupError",
    "SetupResult",
    "marker_path",
    "read_marker",
    "run_setup",
]
