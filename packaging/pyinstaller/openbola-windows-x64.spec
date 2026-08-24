"""Native Windows x64 PyInstaller specification for OpenBOLA."""

from pathlib import Path
import platform
import sys

TARGET = "windows-x64"
EXECUTABLE = "openbola.exe"
if sys.platform != "win32" or platform.machine().casefold() not in {"amd64", "x86_64"}:
    raise SystemExit(f"{TARGET} requires a native Windows x64 build host")

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

import openbola.cli

ENTRYPOINT = "openbola.cli:app"
SCRIPT = str(Path(openbola.cli.__file__).resolve())
hiddenimports = collect_submodules("openbola") + collect_submodules("playwright")
datas = collect_data_files("openbola") + collect_data_files("playwright")

a = Analysis(
    [SCRIPT],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="openbola",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
