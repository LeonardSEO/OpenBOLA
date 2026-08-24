"""Checksum-verified, explicitly confirmed OpenBOLA release updates.

The updater is deliberately a small boundary around ``httpx`` and the local
filesystem.  It knows only the fixed OpenBOLA GitHub release endpoints and
never executes downloaded bytes.  All I/O dependencies can be injected so
that callers and tests can prove the refusal paths without contacting the
internet or replacing a real executable.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as _platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, cast
from urllib.parse import SplitResult, urlsplit

import httpx

from openbola import __version__
from openbola.paths import data_root as _default_data_root
from openbola.scope import ScopeDecision, ScopeError, ScopeGuard

Platform = Literal["windows-x64", "macos-arm64", "macos-x64"]
UpdateStatus = Literal["current", "available", "updated", "denied", "unavailable"]

GITHUB_API_RELEASE_URL: Final = (
    "https://api.github.com/repos/LeonardSEO/openbola/releases/latest"
)
GITHUB_API_ORIGIN: Final = "api.github.com"
GITHUB_WEB_ORIGIN: Final = "github.com"
REPOSITORY_PATH: Final = "/LeonardSEO/openbola"
CHECKSUMS_NAME: Final = "SHA256SUMS"
CACHE_FILENAME: Final = "update-check.json"
MAX_RELEASE_BYTES: Final = 1_048_576
MAX_CHECKSUM_BYTES: Final = 1_048_576
MAX_ARTIFACT_BYTES: Final = 256 * 1024 * 1024
MAX_EXTRACTED_BYTES: Final = 256 * 1024 * 1024
CACHE_TTL: Final = timedelta(hours=24)
HTTP_TIMEOUT: Final = 15.0
USER_AGENT: Final = "OpenBOLA/0.1 (+https://github.com/LeonardSEO/openbola)"

_SEMVER_RE: Final = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?P<suffix>-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SHA256_RE: Final = re.compile(r"^[0-9a-fA-F]{64}$")
_REASON_RE: Final = re.compile(r"^[a-z0-9_]{1,64}$")
_RELEASE_KEYS: Final = frozenset(
    {
        "url",
        "assets_url",
        "upload_url",
        "html_url",
        "id",
        "author",
        "node_id",
        "tag_name",
        "target_commitish",
        "name",
        "draft",
        "immutable",
        "prerelease",
        "created_at",
        "updated_at",
        "published_at",
        "assets",
        "tarball_url",
        "zipball_url",
        "body",
        "mentions",
        "discussion_url",
        "generate_release_notes",
    }
)
_REQUIRED_RELEASE_KEYS: Final = frozenset({"tag_name", "assets"})
_ASSET_KEYS: Final = frozenset(
    {
        "url",
        "id",
        "node_id",
        "name",
        "label",
        "uploader",
        "content_type",
        "state",
        "size",
        "download_count",
        "created_at",
        "updated_at",
        "digest",
        "browser_download_url",
    }
)
_REQUIRED_ASSET_KEYS: Final = frozenset({"name", "browser_download_url", "size"})


@dataclass(frozen=True)
class ReleaseArtifact:
    """A release asset after all metadata has been validated."""

    version: str
    platform: Platform
    download_url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class UpdateResult:
    """Bounded, secret-free updater result exposed to the CLI."""

    status: UpdateStatus
    current_version: str
    candidate_version: str | None = None
    reason_code: str | None = None


@dataclass(frozen=True)
class _Release:
    version: str
    artifact: ReleaseArtifact
    checksums_url: str


class UpdateError(Exception):
    """Internal refusal carrying a stable public reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _duplicate_free_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(value)


def _parse_json(data: bytes, *, max_bytes: int) -> object:
    if len(data) > max_bytes:
        raise UpdateError("response_too_large")
    try:
        text = data.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_duplicate_free_pairs,
            parse_constant=_reject_constant,
        )
    except (RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise UpdateError("malformed_release") from error
    _check_json_shape(parsed, depth=0)
    return parsed


def _check_json_shape(value: object, *, depth: int) -> None:
    if depth > 32:
        raise UpdateError("malformed_release")
    if isinstance(value, dict):
        if len(value) > 256:
            raise UpdateError("malformed_release")
        for key, nested in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise UpdateError("malformed_release")
            _check_json_shape(nested, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 512:
            raise UpdateError("malformed_release")
        for nested in value:
            _check_json_shape(nested, depth=depth + 1)
    elif isinstance(value, str) and len(value) > 16_384:
        raise UpdateError("malformed_release")


def normalize_version(value: str) -> str:
    """Return a strict release version without an optional leading ``v``."""

    if not isinstance(value, str):
        raise UpdateError("invalid_version")
    normalized = value[1:] if value.startswith(("v", "V")) else value
    match = _SEMVER_RE.fullmatch(normalized)
    if match is None:
        raise UpdateError("invalid_version")
    suffix = match.group("suffix")
    if suffix:
        for identifier in suffix[1:].split("."):
            if identifier.isdecimal() and len(identifier) > 1 and identifier.startswith("0"):
                raise UpdateError("invalid_version")
    return normalized


def _version_parts(value: str) -> tuple[int, int, int, tuple[str, ...]]:
    normalized = normalize_version(value)
    match = _SEMVER_RE.fullmatch(normalized)
    assert match is not None
    suffix = match.group("suffix")
    identifiers = tuple(suffix[1:].split(".")) if suffix else ()
    for identifier in identifiers:
        if identifier.isdecimal() and len(identifier) > 1 and identifier.startswith("0"):
            raise UpdateError("invalid_version")
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        identifiers,
    )


def _compare_versions(left: str, right: str) -> int:
    left_major, left_minor, left_patch, left_pre = _version_parts(left)
    right_major, right_minor, right_patch, right_pre = _version_parts(right)
    left_core = (left_major, left_minor, left_patch)
    right_core = (right_major, right_minor, right_patch)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    if not left_pre and not right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1
    for left_identifier, right_identifier in zip(left_pre, right_pre, strict=False):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdecimal()
        right_numeric = right_identifier.isdecimal()
        if left_numeric and right_numeric:
            return 1 if int(left_identifier) > int(right_identifier) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_identifier > right_identifier else -1
    if len(left_pre) == len(right_pre):
        return 0
    return 1 if len(left_pre) > len(right_pre) else -1


def detect_platform(*, system: str | None = None, machine: str | None = None) -> Platform:
    """Map a native host to one of the P10 release targets."""

    host = (system or sys.platform).casefold()
    architecture = (machine or _platform.machine()).casefold().replace("-", "_")
    if host in {"win32", "windows"} and architecture in {"amd64", "x86_64", "x64"}:
        return "windows-x64"
    if host in {"darwin", "macos", "mac"} and architecture in {"arm64", "aarch64"}:
        return "macos-arm64"
    if host in {"darwin", "macos", "mac"} and architecture in {"x86_64", "amd64", "x64"}:
        return "macos-x64"
    raise UpdateError("unsupported_platform")


def artifact_name(version: str, target: Platform) -> str:
    normalized = normalize_version(version)
    suffix = ".zip" if target == "windows-x64" else ".tar.gz"
    return f"openbola-{normalized}-{target}{suffix}"


def _port(parts: SplitResult) -> int | None:
    try:
        return parts.port
    except ValueError as error:
        raise UpdateError("url_denied") from error


def _allowed_url(url: str, *, kind: Literal["api", "release"]) -> str:
    if not isinstance(url, str) or len(url) > 2048:
        raise UpdateError("url_denied")
    parts = urlsplit(url)
    if parts.scheme.casefold() != "https" or parts.username or parts.password:
        raise UpdateError("url_denied")
    if _port(parts) not in {None, 443}:
        raise UpdateError("url_denied")
    hostname = (parts.hostname or "").casefold()
    expected_host = GITHUB_API_ORIGIN if kind == "api" else GITHUB_WEB_ORIGIN
    if parts.netloc.casefold() != expected_host:
        raise UpdateError("url_denied")
    if kind == "api":
        expected_path = f"/repos{REPOSITORY_PATH}/releases/latest"
        if hostname != expected_host or parts.path != expected_path:
            raise UpdateError("url_denied")
    else:
        prefix = f"{REPOSITORY_PATH}/releases/download/"
        if hostname != expected_host or not parts.path.startswith(prefix):
            raise UpdateError("url_denied")
        suffix = parts.path[len(prefix) :]
        segments = suffix.split("/")
        if (
            len(segments) != 2
            or not all(segments)
            or any(segment in {".", ".."} for segment in segments)
            or any(marker in parts.path.casefold() for marker in ("%2e", "%2f", "%5c"))
            or any(marker in suffix for marker in ("\\", "/./", "/../"))
        ):
            raise UpdateError("url_denied")
    if parts.query or parts.fragment:
        raise UpdateError("url_denied")
    return parts.geturl()


def _asset_url(url: object, *, expected_path: str) -> str:
    if not isinstance(url, str):
        raise UpdateError("malformed_release")
    try:
        validated = _allowed_url(url, kind="release")
        if urlsplit(validated).path != expected_path:
            raise UpdateError("url_denied")
        return validated
    except UpdateError as error:
        if error.code == "url_denied":
            raise UpdateError("url_denied") from error
        raise


def _json_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise UpdateError("malformed_release")
    return value


def _json_size(mapping: Mapping[str, object]) -> int:
    value = mapping.get("size")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise UpdateError("malformed_release")
    if value > MAX_ARTIFACT_BYTES:
        raise UpdateError("artifact_too_large")
    return value


def _parse_release(payload: object, *, target: Platform, current_version: str) -> _Release:
    if not isinstance(payload, dict):
        raise UpdateError("malformed_release")
    if not frozenset(payload).issubset(_RELEASE_KEYS) or not _REQUIRED_RELEASE_KEYS.issubset(
        payload
    ):
        raise UpdateError("malformed_release")
    tag = _json_string(payload, "tag_name")
    version = normalize_version(tag)
    assets_value = payload.get("assets")
    if not isinstance(assets_value, list) or not assets_value:
        raise UpdateError("malformed_release")
    expected_name = artifact_name(version, target)
    selected: dict[str, object] | None = None
    checksums: dict[str, object] | None = None
    seen_names: set[str] = set()
    for item in assets_value:
        if not isinstance(item, dict):
            raise UpdateError("malformed_release")
        if not frozenset(item).issubset(_ASSET_KEYS) or not _REQUIRED_ASSET_KEYS.issubset(item):
            raise UpdateError("malformed_release")
        name_value = item.get("name")
        if not isinstance(name_value, str) or not name_value or name_value in seen_names:
            raise UpdateError("malformed_release")
        seen_names.add(name_value)
        if name_value == expected_name:
            selected = item
        if name_value == CHECKSUMS_NAME:
            checksums = item
    if selected is None:
        raise UpdateError("artifact_missing")
    if checksums is None:
        raise UpdateError("checksum_missing")
    release_prefix = f"{REPOSITORY_PATH}/releases/download/{tag}"
    expected_artifact_path = f"{release_prefix}/{expected_name}"
    expected_checksums_path = f"{release_prefix}/{CHECKSUMS_NAME}"
    selected_url = _asset_url(
        selected.get("browser_download_url"),
        expected_path=expected_artifact_path,
    )
    checksums_url = _asset_url(
        checksums.get("browser_download_url"),
        expected_path=expected_checksums_path,
    )
    size = _json_size(selected)
    # Do not carry URLs or arbitrary metadata beyond this typed boundary.
    if _compare_versions(version, current_version) <= 0:
        # The artifact is still parsed so malformed current releases fail
        # closed, but callers can return ``current`` without downloading it.
        pass
    return _Release(
        version=version,
        artifact=ReleaseArtifact(version, target, selected_url, "", size),
        checksums_url=checksums_url,
    )


def _parse_checksum(data: bytes, *, filename: str) -> str:
    if len(data) > MAX_CHECKSUM_BYTES:
        raise UpdateError("checksum_too_large")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise UpdateError("checksum_malformed") from error
    matches: list[str] = []
    for line in text.splitlines():
        if not line:
            continue
        digest, separator, name = line.partition("  ")
        if not separator or not _SHA256_RE.fullmatch(digest) or not name:
            raise UpdateError("checksum_malformed")
        if name.startswith("*"):
            name = name[1:]
        if name == filename:
            matches.append(digest.casefold())
    if len(matches) != 1:
        raise UpdateError("checksum_missing" if not matches else "checksum_duplicate")
    return matches[0]


def _scoped_url(scope_guard: ScopeGuard | None, url: str) -> str:
    """Return the canonical URL only after a concrete scope decision."""

    if type(scope_guard) is not ScopeGuard:
        raise UpdateError("scope_required")
    try:
        decision = scope_guard.require_allowed(url, "GET")
    except ScopeError as error:
        raise UpdateError("scope_denied") from error
    if type(decision) is not ScopeDecision:
        raise UpdateError("scope_denied")
    if decision.connect_ips:
        # The updater has no transport adapter that can enforce a resolved
        # peer set.  Never silently downgrade a pinned scope to hostname-only.
        raise UpdateError("scope_peer_pinning_unsupported")
    return decision.canonical_url


def _reject_redirect(response: httpx.Response, scope_guard: ScopeGuard | None) -> None:
    if response.status_code not in {301, 302, 303, 307, 308}:
        return
    location = response.headers.get("location")
    if location:
        try:
            _scoped_url(scope_guard, location)
        except UpdateError as error:
            raise UpdateError("redirect_denied") from error
    raise UpdateError("redirect_denied")


def _response_bytes(
    response: httpx.Response,
    *,
    max_bytes: int,
    too_large_code: str = "response_too_large",
    scope_guard: ScopeGuard | None = None,
) -> bytes:
    _reject_redirect(response, scope_guard)
    if response.status_code != 200:
        raise UpdateError("release_unavailable")
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise UpdateError("response_malformed") from error
        if declared < 0 or declared > max_bytes:
            raise UpdateError(too_large_code)
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise UpdateError(too_large_code)
        chunks.append(chunk)
    return b"".join(chunks)


def _safe_cache_path(root: Path) -> Path:
    if _path_contains_symlink(root):
        raise UpdateError("cache_untrusted")
    return root / CACHE_FILENAME


def _path_contains_symlink(path: Path) -> bool:
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor or Path.cwd().anchor or ".")
        parts = absolute.parts[1:] if absolute.anchor else absolute.parts
        for component in parts:
            current /= component
            if current.is_symlink():
                return True
    except (OSError, RuntimeError, ValueError):
        return True
    return False


def _read_cache(root: Path, *, current_version: str, now: datetime) -> UpdateResult | None:
    try:
        cache_path = _safe_cache_path(root)
        if not cache_path.exists() or cache_path.is_symlink() or not cache_path.is_file():
            return None
        raw = cache_path.read_bytes()
        payload = _parse_json(raw, max_bytes=8_192)
        if not isinstance(payload, dict) or set(payload) != {
            "checked_at",
            "status",
            "current_version",
            "candidate_version",
            "reason_code",
        }:
            return None
        checked_at = payload.get("checked_at")
        if not isinstance(checked_at, str):
            return None
        timestamp = datetime.fromisoformat(checked_at)
        if timestamp.tzinfo is None:
            return None
        if now - timestamp.astimezone(UTC) >= CACHE_TTL:
            return None
        if timestamp.astimezone(UTC) > now:
            return None
        cached_current = payload.get("current_version")
        if cached_current != current_version:
            return None
        status = payload.get("status")
        if status not in {"current", "available", "unavailable"}:
            return None
        candidate = payload.get("candidate_version")
        reason = payload.get("reason_code")
        if candidate is not None and not isinstance(candidate, str):
            return None
        if reason is not None and not isinstance(reason, str):
            return None
        if candidate is not None:
            try:
                normalize_version(candidate)
            except UpdateError:
                return None
        if reason is not None and _REASON_RE.fullmatch(reason) is None:
            return None
        if status == "current" and candidate != current_version:
            return None
        if status == "available" and (
            candidate is None or _compare_versions(candidate, current_version) <= 0
        ):
            return None
        if status == "unavailable" and candidate is not None:
            return None
        return UpdateResult(cast(UpdateStatus, status), current_version, candidate, reason)
    except (OSError, TypeError, ValueError, UpdateError):
        return None


def _write_cache(root: Path, result: UpdateResult, *, now: datetime) -> None:
    if result.status not in {"current", "available", "unavailable"}:
        return
    try:
        if _path_contains_symlink(root):
            return
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        cache_path = _safe_cache_path(root)
        if _path_contains_symlink(cache_path):
            return
        payload = {
            "checked_at": now.astimezone(UTC).isoformat(),
            "status": result.status,
            "current_version": result.current_version,
            "candidate_version": result.candidate_version,
            "reason_code": result.reason_code,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".update-", dir=root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, cache_path)
            _fsync_parent(root)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError:
        # A cache is an optimization.  It must never turn a safe check into
        # a user-visible failure or disclose an OS exception.
        return


def _fsync_parent(parent: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _current_executable(path: Path | None) -> Path:
    candidate = path if path is not None else Path(sys.argv[0])
    try:
        resolved = candidate.absolute()
    except OSError as error:
        raise UpdateError("executable_invalid") from error
    if resolved.is_symlink() or not resolved.is_file() or _path_contains_symlink(resolved.parent):
        raise UpdateError("executable_invalid")
    return resolved


def _download_to_temp(
    client: httpx.Client,
    url: str,
    *,
    directory: Path,
    expected_size: int,
    scope_guard: ScopeGuard | None = None,
) -> tuple[Path, str, int]:
    temporary: Path | None = None
    try:
        with client.stream("GET", url) as response:
            _reject_redirect(response, scope_guard)
            if response.status_code != 200:
                raise UpdateError("download_failed")
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as error:
                    raise UpdateError("download_malformed") from error
                if declared < 0 or declared > MAX_ARTIFACT_BYTES:
                    raise UpdateError("artifact_too_large")
                if declared != expected_size:
                    raise UpdateError("size_mismatch")
            descriptor, temporary_name = tempfile.mkstemp(prefix=".openbola-update-", dir=directory)
            temporary = Path(temporary_name)
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(descriptor, "wb") as stream:
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_ARTIFACT_BYTES:
                        raise UpdateError("artifact_too_large")
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if total != expected_size:
                raise UpdateError("size_mismatch")
            return temporary, digest.hexdigest(), total
    except (httpx.HTTPError, OSError) as error:
        _remove_temporary(temporary)
        raise UpdateError("download_failed") from error
    except UpdateError:
        _remove_temporary(temporary)
        raise
    finally:
        # The successful path transfers ownership to the caller.
        if temporary is not None and not temporary.exists():
            temporary = None


def _remove_temporary(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def _archive_members(target: Platform) -> tuple[str, ...]:
    executable = "openbola.exe" if target == "windows-x64" else "openbola"
    installer = "install.ps1" if target == "windows-x64" else "install.sh"
    return (executable, installer, "openbola.sha256", "LICENSE", "README.md")


def _safe_member_name(name: str) -> bool:
    path = Path(name)
    return (
        bool(name)
        and "\\" not in name
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and len(name) <= 256
    )


def _extract_verified_archive(
    archive: Path,
    *,
    target: Platform,
    directory: Path,
) -> tuple[Path, Path]:
    """Extract one P10 archive after validating members and its executable manifest."""

    expected_members = set(_archive_members(target))
    extraction = Path(tempfile.mkdtemp(prefix=".openbola-extract-", dir=directory))
    total = 0
    try:
        names: list[str]
        if target == "windows-x64":
            with zipfile.ZipFile(archive, "r") as bundle:
                infos = bundle.infolist()
                names = [info.filename for info in infos]
                if len(names) != len(set(names)) or set(names) != expected_members:
                    raise UpdateError("archive_members_invalid")
                for info in infos:
                    if not _safe_member_name(info.filename) or info.is_dir():
                        raise UpdateError("archive_members_invalid")
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK or info.file_size > MAX_EXTRACTED_BYTES:
                        raise UpdateError("archive_members_invalid")
                    total += info.file_size
                    if total > MAX_EXTRACTED_BYTES:
                        raise UpdateError("archive_too_large")
                    destination = extraction / info.filename
                    with bundle.open(info, "r") as source, destination.open("xb") as output:
                        shutil.copyfileobj(source, output, length=64 * 1024)
        else:
            with tarfile.open(archive, mode="r:gz") as bundle:
                members = bundle.getmembers()
                names = [member.name for member in members]
                if len(names) != len(set(names)) or set(names) != expected_members:
                    raise UpdateError("archive_members_invalid")
                for member in members:
                    if (
                        not _safe_member_name(member.name)
                        or not member.isreg()
                        or member.size > MAX_EXTRACTED_BYTES
                    ):
                        raise UpdateError("archive_members_invalid")
                    total += member.size
                    if total > MAX_EXTRACTED_BYTES:
                        raise UpdateError("archive_too_large")
                    tar_source = bundle.extractfile(member)
                    if tar_source is None:
                        raise UpdateError("archive_members_invalid")
                    destination = extraction / member.name
                    with tar_source, destination.open("xb") as output:
                        shutil.copyfileobj(tar_source, output, length=64 * 1024)
        executable_name = "openbola.exe" if target == "windows-x64" else "openbola"
        manifest = extraction / "openbola.sha256"
        expected_digest = _parse_checksum(manifest.read_bytes(), filename=executable_name)
        executable = extraction / executable_name
        if executable.is_symlink() or not executable.is_file():
            raise UpdateError("archive_members_invalid")
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if digest.casefold() != expected_digest.casefold():
            raise UpdateError("manifest_mismatch")
        return extraction, executable
    except UpdateError:
        shutil.rmtree(extraction, ignore_errors=True)
        raise
    except (
        OSError,
        EOFError,
        RuntimeError,
        tarfile.TarError,
        zipfile.BadZipFile,
        ValueError,
    ) as error:
        shutil.rmtree(extraction, ignore_errors=True)
        raise UpdateError("archive_invalid") from error
def _replace_from_temp(temporary: Path, executable: Path) -> None:
    try:
        mode = stat.S_IMODE(executable.stat().st_mode)
        if not stat.S_ISREG(executable.stat().st_mode) or executable.is_symlink():
            raise UpdateError("executable_invalid")
        os.chmod(temporary, mode)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, executable)
        _fsync_parent(executable.parent)
    except UpdateError:
        raise
    except OSError as error:
        raise UpdateError("replacement_failed") from error


class UpdateService:
    """Dependency-injected release checker and atomic updater."""

    def __init__(
        self,
        *,
        current_version: str = __version__,
        root: Path | None = None,
        executable: Path | None = None,
        transport: httpx.BaseTransport | None = None,
        scope_guard: ScopeGuard | None = None,
        system: str | None = None,
        machine: str | None = None,
        clock: Callable[[], datetime] | None = None,
        confirmation: Callable[[ReleaseArtifact], bool] | None = None,
    ) -> None:
        self.current_version = normalize_version(current_version)
        self.root = root
        self.executable = executable
        self.transport = transport
        self.scope_guard = scope_guard
        self.system = system
        self.machine = machine
        self.clock = clock or (lambda: datetime.now(UTC))
        self.confirmation = confirmation

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        try:
            return _default_data_root()
        except (OSError, RuntimeError) as error:
            raise UpdateError("data_root_unavailable") from error

    def _client(self) -> httpx.Client:
        return httpx.Client(
            transport=self.transport,
            follow_redirects=False,
            trust_env=False,
            timeout=HTTP_TIMEOUT,
            headers={"accept": "application/json", "user-agent": USER_AGENT},
        )

    def _fetch_release(self, target: Platform) -> _Release:
        request_url = _allowed_url(GITHUB_API_RELEASE_URL, kind="api")
        request_url = _scoped_url(self.scope_guard, request_url)
        try:
            with self._client() as client:
                with client.stream("GET", request_url) as response:
                    payload = _parse_json(
                        _response_bytes(
                            response,
                            max_bytes=MAX_RELEASE_BYTES,
                            scope_guard=self.scope_guard,
                        ),
                        max_bytes=MAX_RELEASE_BYTES,
                    )
                release = _parse_release(
                    payload,
                    target=target,
                    current_version=self.current_version,
                )
        except UpdateError:
            raise
        except (httpx.HTTPError, OSError) as error:
            raise UpdateError("release_unavailable") from error
        return release

    def _check_uncached(self) -> UpdateResult:
        try:
            target = detect_platform(system=self.system, machine=self.machine)
            release = self._fetch_release(target)
            status: UpdateStatus
            reason: str | None = None
            if _compare_versions(release.version, self.current_version) > 0:
                status = "available"
            else:
                status = "current"
            return UpdateResult(status, self.current_version, release.version, reason)
        except UpdateError as error:
            return UpdateResult("unavailable", self.current_version, None, error.code)

    def check(self, *, force_check: bool = False) -> UpdateResult:
        try:
            now = self.clock().astimezone(UTC)
            root = self._root()
        except UpdateError as error:
            return UpdateResult("unavailable", self.current_version, None, error.code)
        if not force_check:
            cached = _read_cache(root, current_version=self.current_version, now=now)
            if cached is not None:
                return cached
        result = self._check_uncached()
        _write_cache(root, result, now=now)
        return result

    def apply(self, *, confirm: bool = False) -> UpdateResult:
        try:
            target = detect_platform(system=self.system, machine=self.machine)
            release = self._fetch_release(target)
            if _compare_versions(release.version, self.current_version) <= 0:
                result = UpdateResult("current", self.current_version, release.version)
                _write_cache(self._root(), result, now=self.clock().astimezone(UTC))
                return result
            executable = _current_executable(self.executable)
            root = self._root()
            # Validate and download the checksum file before touching the
            # executable.  The two assets are fetched from the same release.
            with self._client() as client:
                checksum_url = _scoped_url(self.scope_guard, release.checksums_url)
                with client.stream("GET", checksum_url) as response:
                    checksum_data = _response_bytes(
                        response,
                        max_bytes=MAX_CHECKSUM_BYTES,
                        too_large_code="checksum_too_large",
                        scope_guard=self.scope_guard,
                    )
                checksum = _parse_checksum(
                    checksum_data,
                    filename=artifact_name(release.version, target),
                )
                release = _Release(
                    release.version,
                    ReleaseArtifact(
                        release.version,
                        target,
                        release.artifact.download_url,
                        checksum,
                        release.artifact.size,
                    ),
                    release.checksums_url,
                )
                archive, digest, _ = _download_to_temp(
                    client,
                    _scoped_url(self.scope_guard, release.artifact.download_url),
                    directory=executable.parent,
                    expected_size=release.artifact.size,
                    scope_guard=self.scope_guard,
                )
            if digest.casefold() != release.artifact.sha256.casefold():
                _remove_temporary(archive)
                return UpdateResult(
                    "unavailable",
                    self.current_version,
                    release.version,
                    "digest_mismatch",
                )
            try:
                extraction, replacement = _extract_verified_archive(
                    archive,
                    target=target,
                    directory=executable.parent,
                )
            except UpdateError:
                _remove_temporary(archive)
                raise
            _remove_temporary(archive)
            approved = confirm
            if not approved and self.confirmation is not None:
                try:
                    approved = bool(self.confirmation(release.artifact))
                except Exception:
                    approved = False
            if not approved:
                shutil.rmtree(extraction, ignore_errors=True)
                return UpdateResult(
                    "denied", self.current_version, release.version, "confirmation_required"
                )
            try:
                _replace_from_temp(replacement, executable)
            except UpdateError:
                shutil.rmtree(extraction, ignore_errors=True)
                raise
            shutil.rmtree(extraction, ignore_errors=True)
            result = UpdateResult("updated", self.current_version, release.version)
            _write_cache(root, result, now=self.clock().astimezone(UTC))
            return result
        except UpdateError as error:
            return UpdateResult("unavailable", self.current_version, None, error.code)
        except (httpx.HTTPError, OSError):
            return UpdateResult("unavailable", self.current_version, None, "update_failed")


def check_for_update(
    force_check: bool = False,
    *,
    current_version: str = __version__,
    data_root: Path | None = None,
    executable: Path | None = None,
    transport: httpx.BaseTransport | None = None,
    scope_guard: ScopeGuard | None = None,
    system: str | None = None,
    machine: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> UpdateResult:
    """Check the fixed GitHub release endpoint, respecting the cache policy."""

    return UpdateService(
        current_version=current_version,
        root=data_root,
        executable=executable,
        transport=transport,
        scope_guard=scope_guard,
        system=system,
        machine=machine,
        clock=clock,
    ).check(force_check=force_check)


def apply_update(
    *,
    confirm: bool = False,
    current_version: str = __version__,
    data_root: Path | None = None,
    executable: Path | None = None,
    transport: httpx.BaseTransport | None = None,
    scope_guard: ScopeGuard | None = None,
    system: str | None = None,
    machine: str | None = None,
    clock: Callable[[], datetime] | None = None,
    confirmation: Callable[[ReleaseArtifact], bool] | None = None,
) -> UpdateResult:
    """Verify and optionally atomically replace the current executable."""

    return UpdateService(
        current_version=current_version,
        root=data_root,
        executable=executable,
        transport=transport,
        scope_guard=scope_guard,
        system=system,
        machine=machine,
        clock=clock,
        confirmation=confirmation,
    ).apply(confirm=confirm)


__all__ = [
    "CACHE_FILENAME",
    "CHECKSUMS_NAME",
    "GITHUB_API_RELEASE_URL",
    "MAX_ARTIFACT_BYTES",
    "MAX_RELEASE_BYTES",
    "ReleaseArtifact",
    "UpdateError",
    "UpdateResult",
    "UpdateService",
    "apply_update",
    "artifact_name",
    "check_for_update",
    "detect_platform",
    "normalize_version",
]
