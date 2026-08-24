"""Bounded, read-only diagnostics for the local OpenBOLA installation.

The doctor command is deliberately independent from the target execution
pipeline.  It does not initialise a database, attempt recovery, launch a
browser, or resolve a credential.  Checks are small and injectable so the CLI
can be exercised without optional packages or an operating-system vault.
Only stable status codes leave this module; exception text and filesystem
locations are intentionally discarded.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

from openbola import __version__
from openbola.paths import data_root

DiagnosticStatus = Literal["ok", "warning", "blocked"]
RecoveryState = Literal["clear", "required", "escalated", "blocked"]

_SUPPORTED_PLATFORMS = frozenset({"darwin", "win32"})
_SETUP_SCHEMA = "openbola-setup-v1"
_MARKER_NAME = "setup-status.json"
_MAX_MARKER_BYTES = 4096
_MAX_VERSION_LENGTH = 64
_MAX_CODE_LENGTH = 64
_EXPECTED_STATE_SCHEMA = 3


@dataclass(frozen=True)
class Diagnostic:
    """One stable local check result.

    ``name`` and ``code`` are an allowlisted, bounded protocol rather than an
    exception or path transport.  The constructor rejects arbitrary values so
    a future probe cannot accidentally place a secret in JSON output.
    """

    name: str
    status: DiagnosticStatus
    code: str

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name or len(self.name) > 48:
            raise ValueError("diagnostic name is invalid")
        if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in self.name):
            raise ValueError("diagnostic name is invalid")
        if self.status not in ("ok", "warning", "blocked"):
            raise ValueError("diagnostic status is invalid")
        if type(self.code) is not str or not self.code or len(self.code) > _MAX_CODE_LENGTH:
            raise ValueError("diagnostic code is invalid")
        if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in self.code):
            raise ValueError("diagnostic code is invalid")

    def public_dict(self) -> dict[str, str]:
        """Return the only representation safe for JSON/Rich adapters."""

        return {"name": self.name, "status": self.status, "code": self.code}


@dataclass(frozen=True)
class DiagnosticReport:
    """Deterministic aggregate of local diagnostics."""

    diagnostics: tuple[Diagnostic, ...]
    recovery_state: RecoveryState

    def __post_init__(self) -> None:
        if not isinstance(self.diagnostics, tuple):
            raise ValueError("diagnostics must be immutable")
        if self.recovery_state not in ("clear", "required", "escalated", "blocked"):
            raise ValueError("recovery state is invalid")
        if any(type(item) is not Diagnostic for item in self.diagnostics):
            raise ValueError("diagnostic value is invalid")
        if tuple(item.name for item in self.diagnostics) != tuple(
            sorted(item.name for item in self.diagnostics)
        ):
            raise ValueError("diagnostics must be sorted")

    @property
    def blocked(self) -> bool:
        """Whether the local command should return its bounded error exit."""

        return self.recovery_state == "blocked" or any(
            item.status == "blocked" for item in self.diagnostics
        )

    @property
    def ok(self) -> bool:
        return not self.blocked

    @property
    def exit_code(self) -> int:
        return 2 if self.blocked else 0

    def public_dict(self) -> dict[str, object]:
        """Return a stable, path- and secret-free JSON-compatible mapping."""

        return {
            "diagnostics": [item.public_dict() for item in self.diagnostics],
            "recovery_state": self.recovery_state,
            "ok": self.ok,
        }

    def to_dict(self) -> dict[str, object]:
        """Compatibility alias used by command adapters."""

        return self.public_dict()

    def to_json(self) -> str:
        return json.dumps(self.public_dict(), sort_keys=True, separators=(",", ":"))


class RecoveryProbe(Protocol):
    def status(self) -> object: ...


Probe = Callable[..., object]


@dataclass(frozen=True)
class _Marker:
    browser: str
    vault: str
    self_test: str


@dataclass(frozen=True)
class _ProbeResult:
    status: DiagnosticStatus
    code: str


def _result(status: DiagnosticStatus, code: str) -> _ProbeResult:
    # Never permit a hostile injected probe to expand the public protocol.
    try:
        Diagnostic("probe", status, code)
    except (TypeError, ValueError):
        return _ProbeResult("warning", "probe_unavailable")
    return _ProbeResult(status, code)


def _normalise_probe(value: object, *, ok_code: str, fail_code: str) -> _ProbeResult:
    """Map test adapters to the bounded diagnostic protocol."""

    if type(value) is bool:
        return _result("ok" if value else "warning", ok_code if value else fail_code)
    if isinstance(value, str):
        # Codes are deliberately accepted only if they are safe protocol names.
        if value in {ok_code, fail_code}:
            return _result("ok" if value == ok_code else "warning", value)
        return _result("warning", fail_code)
    if isinstance(value, tuple) and len(value) == 2:
        status, code = value
        if status in ("ok", "warning", "blocked") and isinstance(code, str):
            return _result(cast(DiagnosticStatus, status), code)
    if isinstance(value, Mapping):
        try:
            ready = value.get("ready")
        except Exception:
            return _result("warning", fail_code)
        if type(ready) is bool:
            return _result("ok" if ready else "warning", ok_code if ready else fail_code)
    return _result("warning", fail_code)


def _invoke_probe(
    probe: Probe,
    *,
    ok_code: str,
    fail_code: str,
    argument: object = None,
    with_argument: bool = False,
) -> _ProbeResult:
    """Invoke a local adapter while keeping all failures inside the protocol."""

    try:
        value = probe(argument) if with_argument else probe()
    except Exception:
        return _result("warning", fail_code)
    return _normalise_probe(value, ok_code=ok_code, fail_code=fail_code)


def _safe_path_components(path: Path) -> tuple[bool, bool]:
    """Return ``(exists_and_regular_directory, contains_symlink)`` safely."""

    try:
        absolute = path.absolute()
        current = Path(absolute.anchor or Path.cwd().anchor or ".")
        for component in absolute.parts[1:] if absolute.anchor else absolute.parts:
            current /= component
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                return False, True
        metadata = os.lstat(absolute)
    except (OSError, ValueError, RuntimeError):
        return False, False
    return stat.S_ISDIR(metadata.st_mode), False


def _private_directory(path: Path) -> _ProbeResult:
    exists, symlink = _safe_path_components(path)
    if symlink:
        return _result("blocked", "data_root_symlink")
    if not exists:
        return _result("warning", "data_root_missing")
    try:
        metadata = os.lstat(path)
        uid = getattr(os, "getuid", lambda: metadata.st_uid)()
        if metadata.st_uid != uid or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return _result("blocked", "data_root_not_private")
    except (OSError, ValueError, AttributeError):
        return _result("blocked", "data_root_unreadable")
    return _result("ok", "data_root_ready")


def _read_marker(root: Path) -> tuple[_Marker | None, str | None]:
    marker = root / _MARKER_NAME
    try:
        metadata = os.lstat(marker)
        uid = getattr(os, "getuid", lambda: metadata.st_uid)()
        if stat.S_ISLNK(metadata.st_mode):
            return None, "setup_marker_symlink"
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_MARKER_BYTES:
            return None, "setup_marker_invalid"
        if metadata.st_uid != uid or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None, "setup_marker_not_private"
        with marker.open("rb") as stream:
            payload = stream.read(_MAX_MARKER_BYTES + 1)
        if len(payload) > _MAX_MARKER_BYTES:
            return None, "setup_marker_invalid"
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_marker_pairs)
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "version",
            "browser",
            "vault",
            "self_test",
        } or value.get("schema") != _SETUP_SCHEMA:
            return None, "setup_marker_invalid"
        browser = value.get("browser")
        vault = value.get("vault")
        self_test = value.get("self_test")
        if browser not in {"installed", "already_ready"}:
            return None, "setup_marker_invalid"
        if vault != "ready" or self_test != "passed":
            return None, "setup_marker_incomplete"
        version = value.get("version")
        if not isinstance(version, str) or not version or len(version) > _MAX_VERSION_LENGTH:
            return None, "setup_marker_invalid"
    except FileNotFoundError:
        return None, "setup_marker_missing"
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None, "setup_marker_invalid"
    return _Marker(browser=browser, vault=vault, self_test=self_test), None


def _default_browser_probe(root: Path | None) -> _ProbeResult:
    try:
        if importlib.util.find_spec("playwright") is None:
            return _result("warning", "browser_dependency_missing")
    except Exception:
        return _result("warning", "browser_dependency_missing")
    if root is None:
        return _result("warning", "setup_marker_missing")
    marker, error = _read_marker(root)
    if marker is not None:
        return _result("ok", "browser_ready")
    return _result("warning", error or "browser_not_ready")


def _default_vault_probe(root: Path | None) -> _ProbeResult:
    if root is None:
        return _result("warning", "setup_marker_missing")
    marker, error = _read_marker(root)
    if marker is not None:
        return _result("ok", "vault_ready")
    return _result("warning", error or "vault_not_ready")


def _default_package_probe() -> _ProbeResult:
    version = __version__
    if not isinstance(version, str) or not version or len(version) > _MAX_VERSION_LENGTH:
        return _result("blocked", "package_version_missing")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in version):
        return _result("blocked", "package_version_invalid")
    return _result("ok", "package_ready")


def _default_state_probe(path: Path | None) -> _ProbeResult:
    if path is None:
        return _result("warning", "state_path_unavailable")
    try:
        absolute = path.absolute()
        parent_exists, parent_symlink = _safe_path_components(absolute.parent)
        if parent_symlink:
            return _result("blocked", "state_parent_symlink")
        if not parent_exists:
            return _result("warning", "state_missing")
        metadata = os.lstat(absolute)
        uid = getattr(os, "getuid", lambda: metadata.st_uid)()
        if stat.S_ISLNK(metadata.st_mode):
            return _result("blocked", "state_symlink")
        if not stat.S_ISREG(metadata.st_mode):
            return _result("warning", "state_missing")
        if metadata.st_uid != uid or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return _result("blocked", "state_not_private")
        # URI mode=ro guarantees that diagnostics cannot create/migrate state.
        uri = absolute.as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=0.5) as connection:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT version FROM schema_version WHERE singleton = 1"
            ).fetchone()
        if row is None or type(row[0]) is not int:
            return _result("warning", "state_schema_invalid")
        if row[0] != _EXPECTED_STATE_SCHEMA:
            return _result("warning", "state_schema_mismatch")
    except FileNotFoundError:
        return _result("warning", "state_missing")
    except (OSError, sqlite3.Error, ValueError):
        return _result("warning", "state_unreadable")
    return _result("ok", "state_ready")


def _normalise_recovery(value: object) -> RecoveryState:
    state: object = value
    if isinstance(value, Mapping):
        state = value.get("state")
    elif not isinstance(value, str):
        state = getattr(value, "state", None)
    if state in ("clear", "required", "escalated", "blocked"):
        return state
    return "blocked"


def _marker_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate marker keys rather than allowing last-value wins."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate setup marker key")
        result[key] = value
    return result


def _recovery_diagnostic(gate: RecoveryProbe | Probe | None) -> tuple[Diagnostic, RecoveryState]:
    if gate is None:
        return Diagnostic("recovery", "blocked", "recovery_unavailable"), "blocked"
    try:
        value = gate.status() if hasattr(gate, "status") else gate()
        state = _normalise_recovery(value)
    except Exception:
        return Diagnostic("recovery", "blocked", "recovery_unavailable"), "blocked"
    status: DiagnosticStatus = (
        "ok" if state == "clear" else "blocked" if state == "blocked" else "warning"
    )
    return Diagnostic("recovery", status, f"recovery_{state}"), state


def run_doctor(
    *,
    db_path: Path | None = None,
    json_output: bool = False,
    data_root_path: Path | None = None,
    root_path: Path | None = None,
    platform: str | None = None,
    browser_probe: Probe | None = None,
    vault_probe: Probe | None = None,
    package_probe: Probe | None = None,
    state_probe: Probe | None = None,
    recovery_gate: RecoveryProbe | Probe | None = None,
) -> DiagnosticReport:
    """Run deterministic local checks without changing local or target state.

    The optional probe arguments are intentionally dependency-injection hooks
    for tests and platform adapters.  They may return ``bool``, a bounded code,
    ``(status, code)``, or ``{"ready": bool}``; all other values fail closed.
    ``json_output`` is accepted by the service contract but serialization is
    performed by :meth:`DiagnosticReport.to_json` so callers cannot get an
    accidental print side effect.
    """

    del json_output
    active_platform = sys.platform if platform is None else platform
    diagnostics: list[Diagnostic] = []
    if not isinstance(active_platform, str):
        diagnostics.append(Diagnostic("platform", "blocked", "platform_unsupported"))
    elif active_platform == "win32" and not os.environ.get("LOCALAPPDATA"):
        diagnostics.append(Diagnostic("platform", "blocked", "localappdata_missing"))
    elif active_platform in _SUPPORTED_PLATFORMS:
        diagnostics.append(Diagnostic("platform", "ok", "platform_supported"))
    else:
        diagnostics.append(Diagnostic("platform", "blocked", "platform_unsupported"))

    selected_root = data_root_path if data_root_path is not None else root_path
    if selected_root is None:
        try:
            selected_root = data_root()
        except Exception:
            selected_root = None
    if selected_root is not None:
        try:
            selected_root = Path(selected_root)
        except (TypeError, ValueError, OSError):
            selected_root = None
    root_result = (
        _private_directory(selected_root)
        if selected_root is not None
        else _result("blocked", "data_root_unavailable")
    )
    diagnostics.append(Diagnostic("data_root", root_result.status, root_result.code))

    package_result = (
        _invoke_probe(
            package_probe,
            ok_code="package_ready",
            fail_code="package_version_missing",
        )
        if package_probe is not None
        else _default_package_probe()
    )
    diagnostics.append(Diagnostic("package", package_result.status, package_result.code))

    browser_result = (
        _invoke_probe(
            browser_probe,
            ok_code="browser_ready",
            fail_code="browser_unavailable",
        )
        if browser_probe is not None
        else _default_browser_probe(selected_root)
    )
    diagnostics.append(Diagnostic("browser", browser_result.status, browser_result.code))

    vault_result = (
        _invoke_probe(
            vault_probe,
            ok_code="vault_ready",
            fail_code="vault_unavailable",
        )
        if vault_probe is not None
        else _default_vault_probe(selected_root)
    )
    diagnostics.append(Diagnostic("vault", vault_result.status, vault_result.code))

    if db_path is not None:
        try:
            selected_db = Path(db_path)
        except (TypeError, ValueError, OSError):
            selected_db = None
    else:
        selected_db = selected_root / "state.db" if selected_root is not None else None
    state_result = (
        _invoke_probe(
            state_probe,
            ok_code="state_ready",
            fail_code="state_unreadable",
            argument=selected_db,
            with_argument=True,
        )
        if state_probe is not None
        else _default_state_probe(selected_db)
    )
    diagnostics.append(Diagnostic("state", state_result.status, state_result.code))

    recovery, recovery_state = _recovery_diagnostic(recovery_gate)
    diagnostics.append(recovery)
    diagnostics.sort(key=lambda item: item.name)
    return DiagnosticReport(tuple(diagnostics), recovery_state)


__all__ = [
    "Diagnostic",
    "DiagnosticReport",
    "RecoveryState",
    "run_doctor",
]
