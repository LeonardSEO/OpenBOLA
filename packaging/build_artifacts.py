"""Create deterministic, offline OpenBOLA release archives.

This module intentionally has no import-time dependency on the application.  It
is used by native build runners after PyInstaller has produced one executable.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

TARGETS = ("windows-x64", "macos-arm64", "macos-x64")
TargetName = Literal["windows-x64", "macos-arm64", "macos-x64"]
_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}"
    r"(?:(?:a|b|rc)[0-9]+|\.post[0-9]+|\.dev[0-9]+)?$"
)
_FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_MAC_MODES = 0o100755
_DATA_MODES = 0o100644


@dataclass(frozen=True)
class TargetArtifact:
    target: TargetName
    version: str
    archive: Path
    executable_digest: str
    archive_digest: str


def _validate_version(version: str) -> str:
    if (
        not isinstance(version, str)
        or version != version.strip()
        or not _VERSION_RE.fullmatch(version)
    ):
        raise ValueError("project version is not a supported PEP 440 release")
    return version


def read_project_version(pyproject: Path) -> str:
    """Read and validate the release version without importing the project."""

    try:
        with pyproject.open("rb") as stream:
            document = tomllib.load(stream)
        version = document["project"]["version"]
    except (KeyError, OSError, TypeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("project version is unavailable") from error
    return _validate_version(version)


def _regular_file(path: Path, label: str) -> Path:
    """Return a regular, non-symlink file.

    Parent directories may be operating-system aliases (for example macOS
    ``/var``), so containment is checked by callers through explicit paths and
    the final source member is the only symlink accepted nowhere.
    """

    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} is unavailable") from error
    if not resolved.is_file() or not candidate.is_file():
        raise ValueError(f"{label} must be a regular file")
    return resolved


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _archive_name(target: str, version: str) -> str:
    if target == "windows-x64":
        return f"openbola-{version}-windows-x64.zip"
    if target == "macos-arm64":
        return f"openbola-{version}-macos-arm64.tar.gz"
    if target == "macos-x64":
        return f"openbola-{version}-macos-x64.tar.gz"
    raise ValueError("unsupported target")


def _atomic_bytes(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    stream = __import__("io").BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, _FIXED_TIMESTAMP)
            info.create_system = 3
            mode = 0o100755 if name == "openbola.exe" else _DATA_MODES
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, members[name])
    return stream.getvalue()


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    import gzip
    import io

    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressed, tarfile.open(
        fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT
    ) as archive:
        for name in sorted(members):
            data = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = _MAC_MODES if name == "openbola" else _DATA_MODES
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def archive_target(
    *,
    target: str,
    version: str,
    executable: Path,
    output_dir: Path,
    license_file: Path,
    readme_file: Path,
    installer_file: Path,
) -> TargetArtifact:
    """Create one allowlisted deterministic target archive."""

    if target not in TARGETS:
        raise ValueError("unsupported target")
    version = _validate_version(version)
    executable_path = _regular_file(executable, "executable")
    license_path = _regular_file(license_file, "license")
    readme_path = _regular_file(readme_file, "readme")
    installer_path = _regular_file(installer_file, "installer")
    expected_executable = "openbola.exe" if target == "windows-x64" else "openbola"
    expected_installer = "install.ps1" if target == "windows-x64" else "install.sh"
    if executable_path.name != expected_executable:
        raise ValueError("executable name does not match target")
    if installer_path.name != expected_installer:
        raise ValueError("installer name does not match target")
    archive_path = Path(output_dir) / _archive_name(target, version)
    if archive_path.is_symlink():
        raise ValueError("archive destination must not be a symlink")

    executable_digest = _digest(executable_path)
    manifest = f"{executable_digest}  {expected_executable}\n".encode("ascii")
    members = {
        expected_executable: executable_path.read_bytes(),
        expected_installer: installer_path.read_bytes(),
        "openbola.sha256": manifest,
        "LICENSE": license_path.read_bytes(),
        "README.md": readme_path.read_bytes(),
    }
    content = _zip_bytes(members) if target == "windows-x64" else _tar_bytes(members)
    _atomic_bytes(archive_path, content)
    return TargetArtifact(target, version, archive_path, executable_digest, _digest(archive_path))


def write_sha256sums(artifacts: Sequence[TargetArtifact], output: Path) -> None:
    """Write sorted GNU-format checksums for exactly one archive per target."""

    if len(artifacts) != len(TARGETS) or {item.target for item in artifacts} != set(TARGETS):
        raise ValueError("checksums require exactly one artifact for every target")
    names = [item.archive.name for item in artifacts]
    if len(set(names)) != len(names):
        raise ValueError("duplicate archive names")
    lines = [f"{item.archive_digest}  {item.archive.name}" for item in artifacts]
    content = "\n".join(sorted(lines, key=lambda line: line.split("  ", 1)[1])) + "\n"
    _atomic_bytes(Path(output), content.encode())


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    archive_parser = subparsers.add_parser("archive")
    archive_parser.add_argument("--project-root", type=Path, required=True)
    archive_parser.add_argument("--target", choices=TARGETS, required=True)
    archive_parser.add_argument("--version", required=True)
    archive_parser.add_argument("--tag")
    archive_parser.add_argument("--executable", type=Path, required=True)
    archive_parser.add_argument("--output-dir", type=Path, required=True)
    checksums_parser = subparsers.add_parser("checksums")
    checksums_parser.add_argument("--output-dir", type=Path, required=True)
    checksums_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "archive":
            version = _validate_version(args.version)
            if args.tag is not None and args.tag != f"v{version}":
                raise ValueError("tag does not match project version")
            root = args.project_root.resolve()
            archive_target(
                target=args.target,
                version=version,
                executable=args.executable,
                output_dir=args.output_dir,
                license_file=root / "LICENSE",
                readme_file=root / "README.md",
                installer_file=root / "packaging" / (
                    "install.ps1" if args.target == "windows-x64" else "install.sh"
                ),
            )
        else:
            archives = sorted(args.output_dir.glob("openbola-*.zip")) + sorted(
                args.output_dir.glob("openbola-*.tar.gz")
            )
            if len(archives) != 3:
                raise ValueError("checksums require all three target archives")
            artifacts = []
            for archive in archives:
                name = archive.name
                target = next((item for item in TARGETS if f"-{item}." in name), None)
                if target is None:
                    raise ValueError("unexpected archive name")
                match = re.match(r"openbola-(.+)-(?:windows-x64|macos-arm64|macos-x64)\.", name)
                if match is None:
                    raise ValueError("invalid archive name")
                artifacts.append(
                    TargetArtifact(target, match.group(1), archive, "", _digest(archive))
                )
            write_sha256sums(artifacts, args.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
