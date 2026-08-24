"""Read-only reopening of the sanitized OpenBOLA report bundle.

This module is intentionally separate from :mod:`openbola.reporting`.  The
reporting module creates a bundle from live, typed values; this module accepts
only an already published bundle and treats its directory as untrusted input.
It never opens the session registry, credentials, HAR files, or an executor.
The SQLite lookup used for numeric run references is opened in read-only mode
and is limited to checking that the run exists.
"""

from __future__ import annotations

import csv
import html.parser
import json
import os
import re
import sqlite3
import stat
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any, Final, NoReturn, cast
from urllib.parse import quote

from openbola.reporting import _ARTIFACT_FILENAMES, _CSV_HEADER

REPORT_SCHEMA: Final = "openbola-report-v1"
MANIFEST_SCHEMA: Final = "openbola-report-run-v1"
MANIFEST_FILENAME: Final = "manifest.json"
ARTIFACT_FILENAMES: Final[dict[str, str]] = dict(_ARTIFACT_FILENAMES)
ARTIFACT_FORMATS: Final[frozenset[str]] = frozenset(ARTIFACT_FILENAMES)
_RUN_RE: Final = re.compile(r"[1-9][0-9]{0,8}\Z")
_SAFE_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MAX_MANIFEST_BYTES: Final = 16 * 1024
_MAX_JSON_BYTES: Final = 8 * 1024 * 1024
_MAX_TEXT_BYTES: Final = 16 * 1024 * 1024
_MAX_DEPTH: Final = 32
_MAX_NODES: Final = 100_000
# Tests and callers use these exact uppercase sentinels to prove that raw
# material never crosses the report boundary.  Do not match ordinary prose
# such as the P7 limitations' ``tokens``/``bodies`` or HTML's ``<body>`` tag.
_SENTINEL_RE: Final = re.compile(r"\b(?:RAW_ID|TOKEN|BODY)\b")
_SENSITIVE_FIELD_NAMES: Final = frozenset(
    {
        "api_key",
        "authorization_value",
        "body",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "headers",
        "password",
        "raw_id",
        "secret",
        "session",
        "token",
    }
)


class ReportError(RuntimeError):
    """A stable, non-sensitive report-command refusal."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> NoReturn:
    raise ReportError(code)


def _lstat_path(path: Path) -> os.stat_result:
    try:
        return os.lstat(path)
    except (OSError, ValueError):
        _fail("path_denied")


def _private_stat(path: Path, *, directory: bool) -> os.stat_result:
    """Validate one existing path component without following symlinks."""

    metadata = _lstat_path(path)
    if stat.S_ISLNK(metadata.st_mode):
        _fail("path_symlink")
    if directory and not stat.S_ISDIR(metadata.st_mode):
        _fail("path_denied")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        _fail("path_denied")
    # Report directories/files are created 0700/0600 by P7.  Refuse a
    # user-readable artifact rather than silently reopening an unsafe copy.
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        _fail("path_not_private")
    uid_getter = getattr(os, "getuid", None)
    if uid_getter is not None and metadata.st_uid != int(uid_getter()):
        _fail("path_not_private")
    return metadata


def _assert_no_symlink_components(path: Path, *, stop: Path | None = None) -> None:
    """Check every component between ``stop`` and ``path`` using lstat."""

    absolute = Path(os.path.abspath(path))
    stop_absolute = Path(os.path.abspath(stop)) if stop is not None else None
    if stop_absolute is not None:
        try:
            absolute.relative_to(stop_absolute)
        except ValueError:
            _fail("path_denied")
    parts = absolute.parts
    current = Path(parts[0])
    start_index = 1
    if stop_absolute is not None:
        stop_parts = stop_absolute.parts
        if len(stop_parts) <= len(parts) and parts[: len(stop_parts)] == stop_parts:
            current = Path(*stop_parts)
            start_index = len(stop_parts)
    for component in parts[start_index:]:
        if component in {"", ".", ".."}:
            _fail("path_traversal")
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            _fail("path_not_found")
        except (OSError, ValueError):
            _fail("path_denied")
        if stat.S_ISLNK(metadata.st_mode):
            _fail("path_symlink")


def _trusted_root(root: Path) -> Path:
    if not isinstance(root, Path):
        root = Path(root)
    if not root.is_absolute():
        root = Path(os.path.abspath(root))
    _assert_no_symlink_components(root)
    _private_stat(root, directory=True)
    return root


def _trusted_file(path: Path, *, root: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.relative_to(root)
    except ValueError:
        _fail("path_denied")
    if any(item in {"", ".", ".."} for item in relative.parts):
        _fail("path_traversal")
    _assert_no_symlink_components(path, stop=root)
    _private_stat(path, directory=False)
    return path


def _read_bounded(path: Path, *, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (OSError, ValueError):
        _fail("path_denied")
    try:
        output = bytearray()
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                _fail("report_too_large")
        return bytes(output)
    except ReportError:
        raise
    except OSError:
        _fail("report_unavailable")
    finally:
        os.close(descriptor)


def _reject_constant(value: str) -> Any:
    del value
    _fail("report_malformed")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("report_malformed")
        result[key] = value
    return result


def _shape(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > _MAX_DEPTH or nodes[0] > _MAX_NODES:
        _fail("report_malformed")
    if isinstance(value, Mapping):
        if len(value) > _MAX_NODES:
            _fail("report_malformed")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 512:
                _fail("report_malformed")
            if key.casefold() in _SENSITIVE_FIELD_NAMES:
                _fail("report_unsafe")
            _shape(child, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        if len(value) > _MAX_NODES:
            _fail("report_malformed")
        for child in value:
            _shape(child, depth=depth + 1, nodes=nodes)
    elif isinstance(value, str):
        if len(value) > 16_384 or _SENTINEL_RE.search(value):
            _fail("report_unsafe")


def _decode_json(payload: bytes, *, limit: int) -> object:
    if len(payload) > limit:
        _fail("report_too_large")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except ReportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        _fail("report_malformed")
    _shape(value)
    return value


def _validate_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("manifest_invalid")
    value = cast(Mapping[str, Any], value)
    expected = {"schema", "run_id", "artifacts", "created_at"}
    if set(value) != expected or value.get("schema") != MANIFEST_SCHEMA:
        _fail("manifest_invalid")
    run_id = value.get("run_id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or not 1 <= run_id <= 999_999_999:
        _fail("manifest_invalid")
    created = value.get("created_at")
    if not isinstance(created, str) or len(created) > 64:
        _fail("manifest_invalid")
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        _fail("manifest_invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != ARTIFACT_FORMATS:
        _fail("manifest_invalid")
    for format_name, filename in artifacts.items():
        if format_name not in ARTIFACT_FORMATS or not isinstance(filename, str):
            _fail("manifest_invalid")
        if filename != ARTIFACT_FILENAMES[format_name] or not _SAFE_NAME_RE.fullmatch(filename):
            _fail("manifest_invalid")
    return dict(value)


def _validate_report_document(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("report_schema_mismatch")
    value = cast(Mapping[str, Any], value)
    expected = {
        "authorization",
        "findings",
        "format",
        "limitations",
        "outcomes",
        "resources",
        "schema_version",
        "scope",
        "summary",
    }
    if (
        set(value) != expected
        or value.get("format") != REPORT_SCHEMA
        or value.get("schema_version") != 1
    ):
        _fail("report_schema_mismatch")
    # Keep the loader closed over P7's canonical shape.  Detailed semantic
    # validation remains in P7's immutable constructors; here we refuse
    # unknown fields, non-container values, and any unsafe text before CLI
    # presentation.
    if not isinstance(value.get("authorization"), Mapping):
        _fail("report_schema_mismatch")
    authorization = cast(Mapping[str, Any], value["authorization"])
    if set(authorization) != {"reference_fingerprint"}:
        _fail("report_schema_mismatch")
    fingerprint = authorization.get("reference_fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint):
        _fail("report_schema_mismatch")
    if not isinstance(value.get("scope"), Mapping):
        _fail("report_schema_mismatch")
    scope = cast(Mapping[str, Any], value["scope"])
    if set(scope) != {"target_label"}:
        _fail("report_schema_mismatch")
    if not isinstance(scope.get("target_label"), str):
        _fail("report_schema_mismatch")
    for field in ("findings", "outcomes", "resources", "limitations"):
        if not isinstance(value.get(field), list):
            _fail("report_schema_mismatch")
    summary_value = value.get("summary")
    if not isinstance(summary_value, Mapping):
        _fail("report_schema_mismatch")
    summary = cast(Mapping[str, Any], summary_value)
    if set(summary) != {
        "bola",
        "coverage",
        "executed",
        "inconclusive",
        "protected",
        "skipped",
    }:
        _fail("report_schema_mismatch")
    coverage_value = summary.get("coverage")
    if not isinstance(coverage_value, Mapping):
        _fail("report_schema_mismatch")
    coverage = cast(Mapping[str, Any], coverage_value)
    if set(coverage) != {
        "completed",
        "ratio",
        "total_combinations",
    }:
        _fail("report_schema_mismatch")
    for name in ("bola", "executed", "inconclusive", "protected", "skipped"):
        if (
            isinstance(summary.get(name), bool)
            or not isinstance(summary.get(name), int)
            or summary[name] < 0
        ):
            _fail("report_schema_mismatch")
    for name in ("completed", "total_combinations"):
        if (
            isinstance(coverage.get(name), bool)
            or not isinstance(coverage.get(name), int)
            or coverage[name] < 0
        ):
            _fail("report_schema_mismatch")
    ratio = coverage.get("ratio")
    if ratio is not None and (isinstance(ratio, bool) or not isinstance(ratio, (int, float))):
        _fail("report_schema_mismatch")
    return dict(value)


class _HTMLValidator(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.seen_html = False
        self.seen_body = False
        self.seen_script = False
        self.error = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag.lower() == "html":
            self.seen_html = True
        elif tag.lower() == "body":
            self.seen_body = True
        elif tag.lower() in {"iframe", "object", "embed", "form"}:
            self.error = True
        elif tag.lower() == "script":
            self.seen_script = True

    def handle_decl(self, declaration: str) -> None:
        if not declaration.lower().startswith("doctype html"):
            self.error = True


def _validate_text_artifact(path: Path, format_name: str) -> Mapping[str, object]:
    payload = _read_bounded(path, limit=_MAX_TEXT_BYTES)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _fail("report_malformed")
    if _SENTINEL_RE.search(text):
        _fail("report_unsafe")
    if format_name == "markdown":
        if not text.startswith("# BOLA/IDOR assessment report\n"):
            _fail("report_malformed")
    elif format_name == "html":
        parser = _HTMLValidator()
        try:
            parser.feed(text)
            parser.close()
        except (ValueError, AssertionError):
            _fail("report_malformed")
        if parser.error or not parser.seen_html or not parser.seen_body:
            _fail("report_malformed")
    elif format_name == "csv":
        try:
            rows = list(csv.reader(text.splitlines()))
        except csv.Error:
            _fail("report_malformed")
        if not rows or tuple(rows[0]) != _CSV_HEADER:
            _fail("report_schema_mismatch")
        if any(len(row) != len(_CSV_HEADER) for row in rows[1:]):
            _fail("report_schema_mismatch")
    elif format_name == "junit":
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            _fail("report_malformed")
        try:
            root = ET.fromstring(text)  # noqa: S314 - DTD/entity declarations rejected above
        except (ET.ParseError, ValueError):
            _fail("report_malformed")
        if root.tag != "testsuite" or root.attrib.keys() - {
            "name",
            "tests",
            "failures",
            "errors",
            "skipped",
        }:
            _fail("report_schema_mismatch")
    return {"format": format_name, "filename": path.name, "size": len(payload)}


def _validate_artifacts(directory: Path, manifest: Mapping[str, Any]) -> None:
    expected = {MANIFEST_FILENAME, *ARTIFACT_FILENAMES.values()}
    try:
        names = {item.name for item in directory.iterdir()}
    except OSError:
        _fail("report_unavailable")
    if names != expected:
        _fail("report_partial")
    for filename in ARTIFACT_FILENAMES.values():
        _trusted_file(directory / filename, root=directory)
    _trusted_file(directory / MANIFEST_FILENAME, root=directory)


def _load_directory(directory: Path) -> dict[str, Any]:
    _private_stat(directory, directory=True)
    manifest_path = directory / MANIFEST_FILENAME
    _trusted_file(manifest_path, root=directory)
    manifest_value = _decode_json(
        _read_bounded(manifest_path, limit=_MAX_MANIFEST_BYTES), limit=_MAX_MANIFEST_BYTES
    )
    manifest = _validate_manifest(manifest_value)
    _validate_artifacts(directory, manifest)
    json_path = directory / ARTIFACT_FILENAMES["json"]
    document_value = _decode_json(
        _read_bounded(json_path, limit=_MAX_JSON_BYTES), limit=_MAX_JSON_BYTES
    )
    document = _validate_report_document(document_value)
    if int(manifest["run_id"]) < 1:
        _fail("manifest_invalid")
    return document


def load_published_report(path: Path) -> Mapping[str, object]:
    """Load and validate a published report directory or one artifact.

    A directory always requires the complete six-artifact bundle and its
    manifest.  ``report.json`` and ``report.sarif`` return their validated JSON
    document; the remaining formats return bounded metadata after syntax and
    schema checks.  No raw artifact text is returned by this boundary.
    """

    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(os.path.abspath(candidate))
    _assert_no_symlink_components(candidate)
    try:
        metadata = os.lstat(candidate)
    except OSError:
        _fail("path_not_found")
    if stat.S_ISDIR(metadata.st_mode):
        return _load_directory(candidate)
    if not stat.S_ISREG(metadata.st_mode):
        _fail("path_denied")
    _private_stat(candidate, directory=False)
    suffix = candidate.name
    format_name = next(
        (name for name, filename in ARTIFACT_FILENAMES.items() if filename == suffix),
        None,
    )
    if format_name is None:
        _fail("report_format_denied")
    # An artifact is meaningful only as part of the complete atomically
    # published bundle.  Refuse a copied/lone report that has no manifest or
    # sibling artifacts; callers that need the canonical JSON receive it
    # after this bundle validation below.
    _load_directory(candidate.parent)
    if format_name == "json":
        value = _decode_json(_read_bounded(candidate, limit=_MAX_JSON_BYTES), limit=_MAX_JSON_BYTES)
        return _validate_report_document(value)
    if format_name == "sarif":
        value = _decode_json(
            _read_bounded(candidate, limit=_MAX_JSON_BYTES), limit=_MAX_JSON_BYTES
        )
        if (
            not isinstance(value, Mapping)
            or value.get("version") != "2.1.0"
            or not isinstance(value.get("runs"), list)
        ):
            _fail("report_schema_mismatch")
        return dict(cast(Mapping[str, object], value))
    return _validate_text_artifact(candidate, format_name)


class ReportLocator:
    """Resolve numeric run IDs and explicit report paths without writes."""

    def resolve(self, run_ref: str, *, db_path: Path, data_root: Path) -> Path:
        if not isinstance(run_ref, str) or not run_ref or len(run_ref) > 2048:
            _fail("run_not_found")
        root = _trusted_root(Path(data_root))
        if _RUN_RE.fullmatch(run_ref):
            run_id = int(run_ref)
            self._require_run(db_path, run_id)
            candidates = (
                root / "runs" / str(run_id),
                root / "runs" / f"run-{run_id}",
                root / f"run-{run_id}",
                root / str(run_id),
            )
            for directory in candidates:
                if directory.exists() and not directory.is_symlink():
                    try:
                        _assert_no_symlink_components(directory, stop=root)
                        _load_directory(directory)
                    except ReportError as error:
                        if error.code in {"path_not_found", "run_not_found"}:
                            continue
                        raise
                    manifest = _decode_json(
                        _read_bounded(directory / MANIFEST_FILENAME, limit=_MAX_MANIFEST_BYTES),
                        limit=_MAX_MANIFEST_BYTES,
                    )
                    if not isinstance(manifest, Mapping) or manifest.get("run_id") != run_id:
                        _fail("manifest_invalid")
                    return directory
            _fail("run_not_found")
        if any(part in {"", ".", ".."} for part in Path(run_ref).parts):
            _fail("path_traversal")
        path = Path(run_ref)
        if not path.is_absolute():
            path = root / path
        try:
            path.relative_to(root)
        except ValueError:
            _fail("path_denied")
        _assert_no_symlink_components(path, stop=root)
        if not path.exists():
            _fail("path_not_found")
        if path.is_dir():
            _load_directory(path)
            return path
        _trusted_file(path, root=root)
        load_published_report(path)
        return path

    @staticmethod
    def _require_run(db_path: Path, run_id: int) -> None:
        path = Path(db_path)
        if not path.is_absolute():
            path = Path(os.path.abspath(path))
        try:
            _assert_no_symlink_components(path)
            _private_stat(path, directory=False)
        except ReportError:
            _fail("run_not_found")
        try:
            escaped = quote(str(path), safe="/")
            connection = sqlite3.connect(f"file:{escaped}?mode=ro", uri=True, timeout=1.0)
            try:
                row = connection.execute(
                    "SELECT 1 FROM runs WHERE id = ? LIMIT 1", (run_id,)
                ).fetchone()
            finally:
                connection.close()
        except (OSError, sqlite3.Error):
            _fail("run_not_found")
        if row is None:
            _fail("run_not_found")


def write_run_manifest(
    report_dir: Path,
    *,
    run_id: int,
    created_at: str | None = None,
) -> Path:
    """Publish a minimal manifest after :func:`write_reports` succeeds.

    This helper is intentionally explicit so pipeline callers can invoke it as
    the final local write.  It never accepts or stores a report path, URL,
    object ID, credential, or body value.
    """

    directory = Path(report_dir)
    _private_stat(directory, directory=True)
    if isinstance(run_id, bool) or not isinstance(run_id, int) or not 1 <= run_id <= 999_999_999:
        _fail("manifest_invalid")
    timestamp = created_at or datetime.now().astimezone().isoformat(timespec="seconds")
    manifest = {
        "artifacts": dict(ARTIFACT_FILENAMES),
        "created_at": timestamp,
        "run_id": run_id,
        "schema": MANIFEST_SCHEMA,
    }
    _validate_manifest(manifest)
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    destination = directory / MANIFEST_FILENAME
    if destination.exists() or destination.is_symlink():
        _fail("manifest_exists")
    temporary = directory / f".{MANIFEST_FILENAME}.stage"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination)
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except ReportError:
        raise
    except (OSError, ValueError):
        with suppress(OSError):
            temporary.unlink()
        _fail("manifest_unavailable")
    return destination


__all__ = [
    "ARTIFACT_FILENAMES",
    "MANIFEST_FILENAME",
    "MANIFEST_SCHEMA",
    "REPORT_SCHEMA",
    "ReportError",
    "ReportLocator",
    "load_published_report",
    "write_run_manifest",
]
