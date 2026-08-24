from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from openbola.updates import (
    CACHE_FILENAME,
    GITHUB_API_RELEASE_URL,
    MAX_ARTIFACT_BYTES,
    UpdateService,
    apply_update,
    artifact_name,
    check_for_update,
    detect_platform,
)

CURRENT = "0.1.0"
CANDIDATE = "0.1.1"
ARTIFACT = b"openbola-native-test-executable"
ARTIFACT_DIGEST = hashlib.sha256(ARTIFACT).hexdigest()
ARTIFACT_NAME = artifact_name(CANDIDATE, "macos-arm64")
CHECKSUMS = f"{ARTIFACT_DIGEST}  {ARTIFACT_NAME}\n".encode()


def _release_payload(
    *,
    tag: str = "v0.1.1",
    artifact_url: str | None = None,
    size: int = len(ARTIFACT),
    extra_assets: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    version = tag[1:] if tag[:1].casefold() == "v" else tag
    release_artifact_name = artifact_name(version, "macos-arm64")
    artifact_url = artifact_url or (
        "https://github.com/LeonardSEO/openbola/releases/download/"
        + tag
        + "/"
        + release_artifact_name
    )
    release_checksums = f"{ARTIFACT_DIGEST}  {release_artifact_name}\n".encode()
    assets: list[dict[str, object]] = [
        {
            "name": release_artifact_name,
            "browser_download_url": artifact_url,
            "size": size,
        },
        {
            "name": "SHA256SUMS",
            "browser_download_url": (
                "https://github.com/LeonardSEO/openbola/releases/download/" + tag + "/SHA256SUMS"
            ),
            "size": len(release_checksums),
        },
    ]
    if extra_assets:
        assets.extend(extra_assets)
    return {"tag_name": tag, "assets": assets}


def _transport(
    payload: object,
    *,
    checksums: bytes = CHECKSUMS,
    artifact: bytes = ARTIFACT,
    api_status: int = 200,
    checksum_status: int = 200,
    artifact_status: int = 200,
    locations: dict[str, str] | None = None,
) -> tuple[httpx.MockTransport, list[str]]:
    calls: list[str] = []
    locations = locations or {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url == GITHUB_API_RELEASE_URL:
            if api_status != 200:
                return httpx.Response(
                    api_status,
                    headers={"location": locations.get(url, "https://evil.example/")},
                    request=request,
                )
            return httpx.Response(200, content=json.dumps(payload).encode(), request=request)
        if url.endswith("/SHA256SUMS"):
            if checksum_status != 200:
                return httpx.Response(
                    checksum_status,
                    headers={"location": locations.get(url, "https://evil.example/")},
                    request=request,
                )
            return httpx.Response(200, content=checksums, request=request)
        if url.endswith(ARTIFACT_NAME):
            if artifact_status != 200:
                return httpx.Response(
                    artifact_status,
                    headers={"location": locations.get(url, "https://evil.example/")},
                    request=request,
                )
            return httpx.Response(200, content=artifact, request=request)
        return httpx.Response(404, request=request)

    return httpx.MockTransport(handler), calls


def _clock(hour: int = 12) -> datetime:
    return datetime(2026, 8, 24, hour, tzinfo=UTC)


def _executable(root: Path, content: bytes = b"old executable") -> Path:
    path = root / "openbola"
    path.write_bytes(content)
    path.chmod(0o751)
    return path


def test_current_release_is_a_safe_noop_and_cache_suppresses_second_check(tmp_path: Path) -> None:
    payload = _release_payload(tag="v0.1.0")
    transport, calls = _transport(payload)
    service = UpdateService(
        current_version=CURRENT,
        root=tmp_path / "state",
        transport=transport,
        system="darwin",
        machine="arm64",
        clock=lambda: _clock(),
    )

    first = service.check(force_check=True)
    second = service.check()

    assert first.status == "current"
    assert first.candidate_version == CURRENT
    assert second == first
    assert calls == [GITHUB_API_RELEASE_URL]
    cache = tmp_path / "state" / CACHE_FILENAME
    assert cache.exists()
    assert "https://" not in cache.read_text()


def test_newer_release_is_available_and_force_check_bypasses_cache(tmp_path: Path) -> None:
    transport, calls = _transport(_release_payload())
    service = UpdateService(
        current_version=CURRENT,
        root=tmp_path / "state",
        transport=transport,
        system="darwin",
        machine="arm64",
        clock=lambda: _clock(),
    )

    result = service.check(force_check=True)
    forced = service.check(force_check=True)

    assert result.status == "available"
    assert result.candidate_version == CANDIDATE
    assert forced.status == "available"
    assert calls == [GITHUB_API_RELEASE_URL, GITHUB_API_RELEASE_URL]


@pytest.mark.parametrize(
    ("system", "machine"),
    [("linux", "x86_64"), ("darwin", "s390x"), ("win32", "arm64")],
)
def test_unsupported_platform_does_not_make_a_request(
    tmp_path: Path, system: str, machine: str
) -> None:
    transport, calls = _transport(_release_payload())
    result = check_for_update(
        force_check=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        transport=transport,
        system=system,
        machine=machine,
    )
    assert result.status == "unavailable"
    assert result.reason_code == "unsupported_platform"
    assert calls == []


def test_every_redirect_response_is_rejected_without_following_it(tmp_path: Path) -> None:
    transport, calls = _transport(_release_payload(), api_status=302)
    result = check_for_update(
        force_check=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.reason_code == "redirect_denied"
    assert calls == [GITHUB_API_RELEASE_URL]


def test_non_github_asset_url_is_rejected_before_download(tmp_path: Path) -> None:
    payload = _release_payload(artifact_url="https://evil.example/openbola.zip")
    transport, calls = _transport(payload)
    result = check_for_update(
        force_check=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.status == "unavailable"
    assert result.reason_code == "url_denied"
    assert calls == [GITHUB_API_RELEASE_URL]


def test_duplicate_release_json_keys_fail_closed_without_echoing_body(tmp_path: Path) -> None:
    duplicate = b'{"tag_name":"v0.1.1","tag_name":"v9.9.9","assets":[]}'

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == GITHUB_API_RELEASE_URL
        return httpx.Response(200, content=duplicate, request=request)

    result = check_for_update(
        force_check=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        transport=httpx.MockTransport(handler),
        system="darwin",
        machine="arm64",
    )
    assert result.reason_code == "malformed_release"
    assert b"9.9.9" not in json.dumps(result.__dict__).encode()


def test_missing_checksum_is_refused_and_old_executable_is_untouched(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    payload = _release_payload(extra_assets=[])
    # Remove the checksum asset while retaining the artifact.
    assets = payload["assets"]
    assert isinstance(assets, list)
    payload["assets"] = [assets[0]]
    transport, _ = _transport(payload)
    before = executable.read_bytes()
    result = apply_update(
        confirm=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        executable=executable,
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.status == "unavailable"
    assert result.reason_code == "checksum_missing"
    assert executable.read_bytes() == before


def test_checksum_mismatch_leaves_executable_byte_for_byte_unchanged(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    bad_checksum = b"0" * 64 + b"  " + ARTIFACT_NAME.encode() + b"\n"
    transport, _ = _transport(_release_payload(), checksums=bad_checksum)
    before = executable.read_bytes()
    result = apply_update(
        confirm=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        executable=executable,
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.reason_code == "digest_mismatch"
    assert executable.read_bytes() == before


def test_declined_confirmation_does_not_replace_executable(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    transport, _ = _transport(_release_payload())
    before = executable.read_bytes()
    result = apply_update(
        confirm=False,
        confirmation=lambda _artifact: False,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        executable=executable,
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.status == "denied"
    assert result.reason_code == "confirmation_required"
    assert executable.read_bytes() == before
    assert (tmp_path / "state").exists() is False


def test_yes_replaces_atomically_and_preserves_executable_mode(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    transport, calls = _transport(_release_payload())
    result = apply_update(
        confirm=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        executable=executable,
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.status == "updated"
    assert result.candidate_version == CANDIDATE
    assert executable.read_bytes() == ARTIFACT
    assert os.stat(executable).st_mode & 0o777 == 0o751
    assert calls[0] == GITHUB_API_RELEASE_URL
    assert calls[-1].endswith(ARTIFACT_NAME)


def test_replacement_failure_preserves_old_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path)
    transport, _ = _transport(_release_payload())
    before = executable.read_bytes()

    def refuse_replace(_source: str | os.PathLike[str], _target: str | os.PathLike[str]) -> None:
        raise PermissionError("SECRET_PATH_SENTINEL")

    monkeypatch.setattr("openbola.updates.os.replace", refuse_replace)
    result = apply_update(
        confirm=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        executable=executable,
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.reason_code == "replacement_failed"
    assert executable.read_bytes() == before
    assert "SECRET_PATH_SENTINEL" not in repr(result)


def test_symlink_executable_is_refused(tmp_path: Path) -> None:
    real = _executable(tmp_path, b"real")
    link = tmp_path / "openbola-link"
    link.symlink_to(real)
    transport, _ = _transport(_release_payload())
    result = apply_update(
        confirm=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        executable=link,
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.reason_code == "executable_invalid"
    assert real.read_bytes() == b"real"


def test_oversized_artifact_is_rejected_from_declared_size(tmp_path: Path) -> None:
    payload = _release_payload(size=MAX_ARTIFACT_BYTES + 1)
    transport, calls = _transport(payload)
    result = check_for_update(
        force_check=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert result.reason_code == "artifact_too_large"
    assert calls == [GITHUB_API_RELEASE_URL]


def test_detect_platform_covers_three_release_targets() -> None:
    assert detect_platform(system="win32", machine="AMD64") == "windows-x64"
    assert detect_platform(system="darwin", machine="arm64") == "macos-arm64"
    assert detect_platform(system="darwin", machine="x86_64") == "macos-x64"


def test_cache_is_not_followed_when_stale(tmp_path: Path) -> None:
    transport, calls = _transport(_release_payload())
    root = tmp_path / "state"
    service = UpdateService(
        current_version=CURRENT,
        root=root,
        transport=transport,
        system="darwin",
        machine="arm64",
        clock=lambda: _clock(12),
    )
    assert service.check(force_check=True).status == "available"
    stale = json.loads((root / CACHE_FILENAME).read_text())
    stale["checked_at"] = (_clock(12) - timedelta(hours=25)).isoformat()
    (root / CACHE_FILENAME).write_text(json.dumps(stale))
    assert service.check().status == "available"
    assert calls == [GITHUB_API_RELEASE_URL, GITHUB_API_RELEASE_URL]


def test_result_does_not_contain_release_body_or_local_secret(tmp_path: Path) -> None:
    body_sentinel = "LOCAL_SECRET_SENTINEL"
    payload = _release_payload(tag="v0.1.1")
    payload["body"] = body_sentinel
    transport, _ = _transport(payload)
    result = check_for_update(
        force_check=True,
        current_version=CURRENT,
        data_root=tmp_path / "state",
        transport=transport,
        system="darwin",
        machine="arm64",
    )
    assert body_sentinel not in repr(result)
