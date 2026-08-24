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
from datetime import UTC, datetime
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
_METHOD_RE: Final = re.compile(r"[A-Z]{1,10}\Z")
_ENDPOINT_RE: Final = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;:@%{}-]+/?)*\Z")
_OBJECT_REF_RE: Final = re.compile(r"obj_[0-9a-f]{64}\Z")
_IDENTITY_REF_RE: Final = re.compile(r"identity_[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_CAPABILITIES: Final = frozenset({"read", "post", "patch", "put", "delete"})
_PROOF_STATUSES: Final = frozenset({"proven", "not_proven", "inconclusive", "not_tested"})
_CLEANUP_STATUSES: Final = frozenset({"verified", "not_applicable", "inconclusive", "not_run"})
_COVERAGE_STATUSES: Final = frozenset({"complete", "partial", "not_tested"})
_COMPARISONS: Final = frozenset(
    {"object_id_match", "object_id_mismatch", "response_shape_mismatch", "unknown"}
)
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})


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


def _assert_no_symlink_components(
    path: Path, *, stop: Path | None = None, private: bool = False
) -> None:
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
        if private and stat.S_IMODE(metadata.st_mode) & 0o077:
            _fail("path_not_private")
        if private:
            uid_getter = getattr(os, "getuid", None)
            if uid_getter is not None and metadata.st_uid != int(uid_getter()):
                _fail("path_not_private")


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
    _assert_no_symlink_components(path, stop=root, private=True)
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
        parsed_created = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        _fail("manifest_invalid")
    if parsed_created.tzinfo is None:
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
    _validate_nested_report_fields(value)
    return dict(value)


def _mapping_with_keys(value: object, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail("report_schema_mismatch")
    return cast(Mapping[str, Any], value)


def _validate_nested_report_fields(document: Mapping[str, Any]) -> None:
    """Validate the closed P7 document shape, including every nested object."""

    capability_keys = {
        "attacker_identity_ref",
        "attacker_status",
        "capability",
        "cleanup",
        "comparison",
        "coverage",
        "owner_identity_ref",
        "owner_status",
        "status",
    }
    field_keys = {"name", "type"}
    evidence_keys = {
        "capabilities",
        "cleanup",
        "confidence",
        "coverage",
        "fields",
        "impacted_identity_refs",
        "object_ref",
        "remediation",
        "reproduction",
    }
    for finding in document["findings"]:
        finding_map = _mapping_with_keys(
            finding,
            {"description", "endpoint_template", "evidence", "method", "severity", "title"},
        )
        evidence = _mapping_with_keys(finding_map["evidence"], evidence_keys)
        _validate_evidence_nested(evidence, capability_keys, field_keys)
        _validate_finding_values(finding_map)
    for outcome in document["outcomes"]:
        outcome_map = _mapping_with_keys(
            outcome,
            {
                "attacker_status",
                "endpoint_template",
                "evidence",
                "method",
                "owner_status",
                "retryable",
                "verdict",
            },
        )
        outcome_evidence = outcome_map["evidence"]
        if not isinstance(outcome_evidence, Mapping):
            _fail("report_schema_mismatch")
        _validate_outcome_values(outcome_map, cast(Mapping[str, Any], outcome_evidence))
        if set(outcome_evidence) - {
            "attacker_status",
            "comparison",
            "error_code",
            "object_ref",
            "owner_status",
            "redacted",
            "retryable",
            "status",
        }:
            _fail("report_schema_mismatch")
    for resource in document["resources"]:
        resource_map = _mapping_with_keys(
            resource,
            {
                "capabilities",
                "confidence",
                "dataset",
                "endpoint_template",
                "fields",
                "provider",
                "total_discovered",
            },
        )
        fields = resource_map["fields"]
        if not isinstance(fields, list):
            _fail("report_schema_mismatch")
        for field in fields:
            _validate_field_values(_mapping_with_keys(field, field_keys))
        capabilities = resource_map["capabilities"]
        if not isinstance(capabilities, list):
            _fail("report_schema_mismatch")
        for capability in capabilities:
            capability_map = _mapping_with_keys(capability, capability_keys)
            _validate_capability_values(capability_map)
        _validate_resource_values(resource_map)
    limitations = document["limitations"]
    if any(not isinstance(item, str) for item in limitations):
        _fail("report_schema_mismatch")


def _validate_evidence_nested(
    evidence: Mapping[str, Any], capability_keys: set[str], field_keys: set[str]
) -> None:
    fields = evidence["fields"]
    if not isinstance(fields, list):
        _fail("report_schema_mismatch")
    for field in fields:
        field_map = _mapping_with_keys(field, field_keys)
        _validate_field_values(field_map)
    capabilities = evidence["capabilities"]
    if not isinstance(capabilities, list):
        _fail("report_schema_mismatch")
    for capability in capabilities:
        capability_map = _mapping_with_keys(capability, capability_keys)
        _validate_capability_values(capability_map)
    if not isinstance(evidence["impacted_identity_refs"], list):
        _fail("report_schema_mismatch")
    if not isinstance(evidence["reproduction"], list):
        _fail("report_schema_mismatch")
    if any(
        not isinstance(item, str) or not item.strip() or len(item) > 512
        for item in evidence["reproduction"]
    ):
        _fail("report_schema_mismatch")
    if any(
        not isinstance(item, str) or not _IDENTITY_REF_RE.fullmatch(item)
        for item in evidence["impacted_identity_refs"]
    ):
        _fail("report_schema_mismatch")
    object_ref = evidence["object_ref"]
    if object_ref is not None and (
        not isinstance(object_ref, str) or not _OBJECT_REF_RE.fullmatch(object_ref)
    ):
        _fail("report_schema_mismatch")
    for key in ("confidence", "remediation"):
        if (
            not isinstance(evidence[key], str)
            or not evidence[key].strip()
            or len(evidence[key]) > 512
        ):
            _fail("report_schema_mismatch")
    if (
        not isinstance(evidence["cleanup"], str)
        or not isinstance(evidence["coverage"], str)
        or evidence["cleanup"] not in _CLEANUP_STATUSES
        or evidence["coverage"] not in _COVERAGE_STATUSES
    ):
        _fail("report_schema_mismatch")


def _validate_string(value: object, *, nonempty: bool = True) -> None:
    if not isinstance(value, str) or len(value) > 512 or (nonempty and not value.strip()):
        _fail("report_schema_mismatch")


def _validate_field_values(field: Mapping[str, Any]) -> None:
    _validate_string(field["name"])
    _validate_string(field["type"])


def _validate_status(value: object) -> None:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599
    ):
        _fail("report_schema_mismatch")


def _validate_optional_ref(value: object) -> None:
    if value is not None and (
        not isinstance(value, str) or not _IDENTITY_REF_RE.fullmatch(value)
    ):
        _fail("report_schema_mismatch")


def _validate_capability_values(capability: Mapping[str, Any]) -> None:
    if (
        not isinstance(capability["capability"], str)
        or not isinstance(capability["status"], str)
        or capability["capability"] not in _CAPABILITIES
        or capability["status"] not in _PROOF_STATUSES
    ):
        _fail("report_schema_mismatch")
    if (
        not isinstance(capability["cleanup"], str)
        or not isinstance(capability["coverage"], str)
        or capability["cleanup"] not in _CLEANUP_STATUSES
        or capability["coverage"] not in _COVERAGE_STATUSES
    ):
        _fail("report_schema_mismatch")
    comparison = capability["comparison"]
    if comparison is not None and (
        not isinstance(comparison, str) or comparison not in _COMPARISONS
    ):
        _fail("report_schema_mismatch")
    _validate_optional_ref(capability["owner_identity_ref"])
    _validate_optional_ref(capability["attacker_identity_ref"])
    _validate_status(capability["owner_status"])
    _validate_status(capability["attacker_status"])


def _validate_finding_values(finding: Mapping[str, Any]) -> None:
    _validate_string(finding["endpoint_template"])
    if not isinstance(finding["endpoint_template"], str) or not _ENDPOINT_RE.fullmatch(
        finding["endpoint_template"]
    ):
        _fail("report_schema_mismatch")
    if not isinstance(finding["method"], str) or not _METHOD_RE.fullmatch(finding["method"]):
        _fail("report_schema_mismatch")
    if not isinstance(finding["severity"], str) or finding["severity"] not in _SEVERITIES:
        _fail("report_schema_mismatch")
    _validate_string(finding["title"])
    _validate_string(finding["description"])


def _validate_outcome_values(
    outcome: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    _validate_finding_values(
        {
            "endpoint_template": outcome["endpoint_template"],
            "method": outcome["method"],
            "severity": "info",
            "title": "outcome",
            "description": "outcome",
        }
    )
    if not isinstance(outcome["verdict"], str) or outcome["verdict"] not in {
        "bola",
        "protected",
        "inconclusive",
        "skipped",
    }:
        _fail("report_schema_mismatch")
    if not isinstance(outcome["retryable"], bool):
        _fail("report_schema_mismatch")
    _validate_status(outcome["owner_status"])
    _validate_status(outcome["attacker_status"])
    for key, value in evidence.items():
        if key in {"owner_status", "attacker_status"}:
            _validate_status(value)
        elif key == "comparison" and (
            not isinstance(value, str) or value not in _COMPARISONS - {"unknown"}
        ):
            _fail("report_schema_mismatch")
        elif key == "error_code":
            _validate_string(value)
        elif key == "object_ref" and (
            not isinstance(value, str) or not _OBJECT_REF_RE.fullmatch(value)
        ) or (
            key in {"retryable", "redacted"}
            and not isinstance(value, bool)
        ) or (
            key == "status"
            and (
                not isinstance(value, str)
                or value not in {"bola", "protected", "inconclusive", "skipped"}
            )
        ):
            _fail("report_schema_mismatch")


def _validate_resource_values(resource: Mapping[str, Any]) -> None:
    for key in ("provider", "confidence", "dataset"):
        _validate_string(resource[key])
    if not isinstance(resource["endpoint_template"], str) or not _ENDPOINT_RE.fullmatch(
        resource["endpoint_template"]
    ):
        _fail("report_schema_mismatch")
    if (
        isinstance(resource["total_discovered"], bool)
        or not isinstance(resource["total_discovered"], int)
        or not 0 <= resource["total_discovered"] <= 100_000
    ):
        _fail("report_schema_mismatch")


class _HTMLValidator(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.seen_html = False
        self.seen_body = False
        self.seen_script = False
        self.error = False
        self._stack: list[str] = []

    _VOID_TAGS = frozenset(
        {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }
    )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.lower()
        for name, value in attrs:
            if name.lower().startswith("on") or (
                isinstance(value, str) and value.strip().lower().startswith("javascript:")
            ):
                self.error = True
        if normalized == "html":
            self.seen_html = True
        elif normalized == "body":
            self.seen_body = True
        elif normalized in {"iframe", "object", "embed", "form"}:
            self.error = True
        elif normalized == "script":
            self.seen_script = True
        if normalized not in self._VOID_TAGS:
            self._stack.append(normalized)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self._stack and self._stack[-1] == tag.lower():
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if not self._stack or self._stack[-1] != normalized:
            self.error = True
            return
        self._stack.pop()

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
        normalized = text.strip().casefold()
        if (
            parser.error
            or parser._stack
            or not parser.seen_html
            or not parser.seen_body
            or not normalized.startswith("<!doctype html>")
            or not normalized.endswith("</html>")
        ):
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


def _validate_sarif(value: object) -> None:
    document = _mapping_with_keys(value, {"$schema", "version", "runs"})
    if (
        document["$schema"] != "https://json.schemastore.org/sarif-2.1.0.json"
        or document["version"] != "2.1.0"
        or not isinstance(document["runs"], list)
    ):
        _fail("report_schema_mismatch")
    for run in document["runs"]:
        run_map = _mapping_with_keys(run, {"tool", "invocations", "results"})
        tool = _mapping_with_keys(run_map["tool"], {"driver"})
        driver = _mapping_with_keys(
            tool["driver"], {"name", "informationUri", "rules"}
        )
        if (
            driver["name"] != "OpenBOLA"
            or driver["informationUri"] != "https://github.com/LeonardSEO/openbola"
            or not isinstance(driver["rules"], list)
        ):
            _fail("report_schema_mismatch")
        for rule in driver["rules"]:
            rule_map = _mapping_with_keys(
                rule, {"id", "name", "shortDescription", "defaultConfiguration"}
            )
            _validate_string(rule_map["id"])
            _validate_string(rule_map["name"])
            short = _mapping_with_keys(rule_map["shortDescription"], {"text"})
            _validate_string(short["text"])
            configuration = _mapping_with_keys(
                rule_map["defaultConfiguration"], {"level"}
            )
            if not isinstance(configuration["level"], str) or configuration["level"] not in {
                "error",
                "warning",
                "note",
            }:
                _fail("report_schema_mismatch")
        invocations = run_map["invocations"]
        if not isinstance(invocations, list):
            _fail("report_schema_mismatch")
        for invocation in invocations:
            invocation_map = _mapping_with_keys(
                invocation, {"executionSuccessful", "properties"}
            )
            if invocation_map["executionSuccessful"] is not True:
                _fail("report_schema_mismatch")
            properties = _mapping_with_keys(invocation_map["properties"], {"summary"})
            _validate_summary(properties["summary"])
        results = run_map["results"]
        if not isinstance(results, list):
            _fail("report_schema_mismatch")
        for result in results:
            result_map = _mapping_with_keys(
                result, {"ruleId", "level", "message", "locations", "properties"}
            )
            _validate_string(result_map["ruleId"])
            if not isinstance(result_map["level"], str) or result_map["level"] not in {
                "error",
                "warning",
                "note",
            }:
                _fail("report_schema_mismatch")
            message = _mapping_with_keys(result_map["message"], {"text"})
            _validate_string(message["text"])
            locations = result_map["locations"]
            if not isinstance(locations, list) or not locations:
                _fail("report_schema_mismatch")
            for location in locations:
                location_map = _mapping_with_keys(location, {"physicalLocation"})
                physical = _mapping_with_keys(
                    location_map["physicalLocation"], {"artifactLocation"}
                )
                artifact = _mapping_with_keys(physical["artifactLocation"], {"uri"})
                if not isinstance(artifact["uri"], str) or not artifact["uri"].startswith("api://openbola.invalid/"):
                    _fail("report_schema_mismatch")
            properties = _mapping_with_keys(
                result_map["properties"], {"endpoint_method", "endpoint_template", "evidence"}
            )
            if not isinstance(properties["endpoint_method"], str) or not _METHOD_RE.fullmatch(
                properties["endpoint_method"]
            ):
                _fail("report_schema_mismatch")
            if not isinstance(properties["endpoint_template"], str) or not _ENDPOINT_RE.fullmatch(
                properties["endpoint_template"]
            ):
                _fail("report_schema_mismatch")
            evidence = _mapping_with_keys(
                properties["evidence"],
                {
                    "capabilities",
                    "cleanup",
                    "confidence",
                    "coverage",
                    "fields",
                    "impacted_identity_refs",
                    "object_ref",
                    "remediation",
                    "reproduction",
                },
            )
            _validate_evidence_nested(
                evidence,
                {
                    "attacker_identity_ref",
                    "attacker_status",
                    "capability",
                    "cleanup",
                    "comparison",
                    "coverage",
                    "owner_identity_ref",
                    "owner_status",
                    "status",
                },
                {"name", "type"},
            )


def _validate_summary(value: object) -> None:
    summary = _mapping_with_keys(
        value,
        {"bola", "coverage", "executed", "inconclusive", "protected", "skipped"},
    )
    for name in ("bola", "executed", "inconclusive", "protected", "skipped"):
        if (
            isinstance(summary[name], bool)
            or not isinstance(summary[name], int)
            or summary[name] < 0
        ):
            _fail("report_schema_mismatch")
    coverage = _mapping_with_keys(
        summary["coverage"], {"completed", "ratio", "total_combinations"}
    )
    for name in ("completed", "total_combinations"):
        if (
            isinstance(coverage[name], bool)
            or not isinstance(coverage[name], int)
            or coverage[name] < 0
        ):
            _fail("report_schema_mismatch")
    if coverage["ratio"] is not None and (
        isinstance(coverage["ratio"], bool)
        or not isinstance(coverage["ratio"], (int, float))
    ):
        _fail("report_schema_mismatch")


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
    # A report directory must not be placed below a shared/group-writable
    # parent.  The approved root is checked separately by ``ReportLocator``;
    # this immediate-parent check also protects direct loader callers.
    if directory.parent != directory:
        _private_stat(directory.parent, directory=True)
    manifest_path = directory / MANIFEST_FILENAME
    _trusted_file(manifest_path, root=directory)
    manifest_value = _decode_json(
        _read_bounded(manifest_path, limit=_MAX_MANIFEST_BYTES), limit=_MAX_MANIFEST_BYTES
    )
    manifest = _validate_manifest(manifest_value)
    _validate_artifacts(directory, manifest)
    try:
        created_at = datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            _fail("manifest_invalid")
        created_timestamp = created_at.timestamp()
    except (TypeError, ValueError, OSError, OverflowError):
        _fail("manifest_invalid")
    if created_timestamp > datetime.now(UTC).timestamp() + 86_400:
        _fail("manifest_stale")
    for filename in ARTIFACT_FILENAMES.values():
        try:
            if (directory / filename).stat().st_mtime > created_timestamp + 86_400:
                _fail("manifest_stale")
        except OSError:
            _fail("report_unavailable")
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
        _validate_sarif(value)
        return {
            "format": format_name,
            "filename": candidate.name,
            "size": candidate.stat().st_size,
        }
    return _validate_text_artifact(candidate, format_name)


class ReportLocator:
    """Resolve numeric run IDs and explicit report paths without writes."""

    def resolve(self, run_ref: str, *, db_path: Path, data_root: Path) -> Path:
        if not isinstance(run_ref, str) or not run_ref or len(run_ref) > 2048:
            _fail("run_not_found")
        root = _trusted_root(Path(data_root))
        if _RUN_RE.fullmatch(run_ref):
            run_id = int(run_ref)
            report_directory = self._run_report_directory(db_path, run_id)
            if report_directory is not None:
                candidates: tuple[Path, ...] = (root / Path(*report_directory.split("/")),)
            else:
                candidates = (
                    root / "runs" / str(run_id),
                    root / "runs" / f"run-{run_id}",
                    root / f"run-{run_id}",
                    root / str(run_id),
                )
            for directory in candidates:
                if directory.exists() and not directory.is_symlink():
                    try:
                        _assert_no_symlink_components(directory, stop=root, private=True)
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
        _assert_no_symlink_components(path, stop=root, private=True)
        if not path.exists():
            _fail("path_not_found")
        if path.is_dir():
            _load_directory(path)
            return path
        _trusted_file(path, root=root)
        load_published_report(path)
        return path

    @staticmethod
    def _run_report_directory(db_path: Path, run_id: int) -> str | None:
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
                    "SELECT metadata_json FROM runs WHERE id = ? LIMIT 1", (run_id,)
                ).fetchone()
            finally:
                connection.close()
        except (OSError, sqlite3.Error):
            _fail("run_not_found")
        if row is None:
            _fail("run_not_found")
        metadata_raw = row[0]
        if not isinstance(metadata_raw, str):
            _fail("run_not_found")
        try:
            metadata_value = _decode_json(
                metadata_raw.encode("utf-8"), limit=_MAX_MANIFEST_BYTES
            )
        except ReportError:
            _fail("run_not_found")
        if not isinstance(metadata_value, Mapping):
            _fail("run_not_found")
        report_directory = metadata_value.get("report_directory")
        if report_directory is None:
            return None
        if (
            not isinstance(report_directory, str)
            or not _SAFE_NAME_RE.fullmatch(report_directory.split("/")[-1])
            or report_directory.startswith("/")
            or "\\" in report_directory
            or any(part in {"", ".", ".."} for part in report_directory.split("/"))
        ):
            _fail("run_not_found")
        return report_directory


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
    _assert_no_symlink_components(directory)
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
    temporary = directory / f".{MANIFEST_FILENAME}.stage"
    directory_fd = -1
    descriptor = -1
    published = False
    try:
        directory_fd = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            descriptor = -1
        try:
            # A hard-link publication is atomic and no-replace: unlike
            # ``os.replace`` it cannot overwrite a manifest created by a
            # concurrent writer.  The temporary name is unlinked only after
            # the destination link succeeds.
            os.link(
                temporary.name,
                MANIFEST_FILENAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            _fail("manifest_exists")
        os.unlink(temporary.name, dir_fd=directory_fd)
        published = True
        os.fsync(directory_fd)
    except ReportError:
        raise
    except (OSError, ValueError):
        with suppress(OSError):
            os.unlink(temporary.name, dir_fd=directory_fd if directory_fd >= 0 else None)
        _fail("manifest_unavailable")
    finally:
        if not published and directory_fd >= 0:
            with suppress(OSError):
                os.unlink(temporary.name, dir_fd=directory_fd)
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)
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
