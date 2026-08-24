from __future__ import annotations

import hashlib
import sys
import tarfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
_SPEC = spec_from_file_location(
    "openbola_build_artifacts", ROOT / "packaging" / "build_artifacts.py"
)
assert _SPEC and _SPEC.loader
_MODULE = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
TARGETS = _MODULE.TARGETS
TargetArtifact = _MODULE.TargetArtifact
archive_target = _MODULE.archive_target
read_project_version = _MODULE.read_project_version
write_sha256sums = _MODULE.write_sha256sums


@pytest.mark.parametrize(
    ("target", "spec_name", "executable"),
    [
        ("windows-x64", "openbola-windows-x64.spec", "openbola.exe"),
        ("macos-arm64", "openbola-macos-arm64.spec", "openbola"),
        ("macos-x64", "openbola-macos-x64.spec", "openbola"),
    ],
)
def test_spec_declares_native_target_and_safe_entrypoint(
    target: str, spec_name: str, executable: str
) -> None:
    source = (ROOT / "packaging" / "pyinstaller" / spec_name).read_text()
    assert f'TARGET = "{target}"' in source
    assert 'name="openbola"' in source
    assert "console=True" in source
    assert "openbola.cli:app" in source
    assert "playwright" in source
    assert "chromium" not in source.casefold()
    assert executable in source


def test_archive_and_checksum_are_deterministic(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "packaging").mkdir(parents=True)
    (project / "LICENSE").write_text("license\n")
    (project / "README.md").write_text("readme\n")
    (project / "packaging" / "install.sh").write_text("#!/bin/sh\n")
    executable = tmp_path / "openbola"
    executable.write_bytes(b"executable")
    first = archive_target(
        target="macos-arm64",
        version="0.1.0",
        executable=executable,
        output_dir=tmp_path / "one",
        license_file=project / "LICENSE",
        readme_file=project / "README.md",
        installer_file=project / "packaging" / "install.sh",
    )
    second = archive_target(
        target="macos-arm64",
        version="0.1.0",
        executable=executable,
        output_dir=tmp_path / "two",
        license_file=project / "LICENSE",
        readme_file=project / "README.md",
        installer_file=project / "packaging" / "install.sh",
    )
    assert first.archive.read_bytes() == second.archive.read_bytes()
    with tarfile.open(first.archive, "r:gz") as archive:
        assert archive.getnames() == [
            "LICENSE",
            "README.md",
            "install.sh",
            "openbola",
            "openbola.sha256",
        ]
        assert archive.extractfile("openbola.sha256").read().endswith(b"  openbola\n")
    sums = tmp_path / "SHA256SUMS"
    checksum_artifacts = []
    for target in TARGETS:
        suffix = ".zip" if target == "windows-x64" else ".tar.gz"
        archive = tmp_path / f"openbola-0.1.0-{target}{suffix}"
        archive.write_bytes(target.encode())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum_artifacts.append(TargetArtifact(target, "0.1.0", archive, "", digest))
    write_sha256sums(checksum_artifacts, sums)
    lines = sums.read_text().splitlines()
    assert lines == sorted(lines, key=lambda line: line.split("  ", 1)[1])


def test_project_version_rejects_tag_and_whitespace(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = " 0.1.0"\n')
    with pytest.raises(ValueError):
        read_project_version(pyproject)
