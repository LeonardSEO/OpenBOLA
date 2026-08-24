"""Platform-specific data root for persisted sanitized OpenBOLA state."""

from __future__ import annotations

import os
import sys
from pathlib import Path, PureWindowsPath

_APP_DIR_NAME = "OpenBOLA"


def data_root() -> Path:
    """Return the platform data root, creating no directories itself.

    macOS: ``~/Library/Application Support/OpenBOLA/``
    Windows: ``%LOCALAPPDATA%\\OpenBOLA\\``

    Callers are responsible for creating the directory (and any parents)
    before writing into it; this function only computes the path.
    """

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / _APP_DIR_NAME

    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise RuntimeError("LOCALAPPDATA is not set; cannot resolve the OpenBOLA data root.")
        return PureWindowsPath(local_app_data) / _APP_DIR_NAME  # type: ignore[return-value]

    raise RuntimeError(
        f"Unsupported platform {sys.platform!r}: OpenBOLA v1 supports macOS and Windows only."
    )
