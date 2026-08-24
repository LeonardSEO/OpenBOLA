"""Deterministic, credential-safe reports for BOLACheck runs.

Reports deliberately consume the typed phase contracts rather than a live
``StateStore``.  This keeps reporting read-only, makes the complete set of
probe outcomes explicit, and prevents a report containing zero findings from
being mistaken for proof that a target was tested.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from bola_checker.models import Finding, ProbeResult, Verdict
from bola_checker.state import ErrorCode

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_FAILURE_SEVERITIES = frozenset({"critical", "high"})
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_METHOD_RE = re.compile(r"[A-Z]{1,10}\Z")
_SAFE_ENDPOINT_RE = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;:@%{}-]+/?)*\Z")
_OBJECT_REF_RE = re.compile(r"obj_[0-9a-f]{64}\Z")
_SENSITIVE_EVIDENCE_KEY_RE = re.compile(
    r"(?:auth(?:orization|entication)?|api[-_]?key|bearer|body|cookie|credential|"
    r"header|pass(?:word)?|secret|session|token)",
    re.IGNORECASE,
)
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(?:api[-_ ]?key|authorization|authentication|bearer|cookie|"
    r"credential|password|secret|session|token)\b(?:\s*[:=]\s*|\s+)(?:bearer\s+)?"
    r"[^\s,;]+"
)
_ALLOWED_COMPARISONS = frozenset(
    {"object_id_match", "object_id_mismatch", "response_shape_mismatch"}
)
_ALLOWED_ERROR_CODES = frozenset(error_code.value for error_code in ErrorCode)
_ARTIFACT_FILENAMES = {
    "json": "bola_report.json",
    "junit": "bola_report.junit.xml",
    "markdown": "bola_report.md",
    "sarif": "bola_report.sarif",
}
_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 0x00000001
_LINUX_RENAMEAT2_SYSCALLS = {
    "aarch64": 276,
    "armv7l": 382,
    "i386": 353,
    "x86_64": 316,
}
_DEFAULT_LIMITATIONS = (
    "Only recorded probe outcomes are represented; untested combinations are not implied safe.",
    "Read probes compare authorization behavior and do not establish the absence of other flaws.",
    "Credentials, request headers, cookies, tokens, and bodies are excluded from this report.",
)


class FindingStore(Protocol):
    """The narrow StateStore read contract used by report construction."""

    def list_findings(self) -> list[Finding]: ...


@dataclass(frozen=True)
class RunSummary:
    """Count outcomes and completed coverage for one reporting input.

    ``total_combinations`` is the number of candidate owner/attacker/object
    combinations known to the caller.  Coverage only counts terminal BOLA or
    protected outcomes: inconclusive and skipped attempts cannot establish
    authorization coverage.
    """

    total_combinations: int
    executed: int
    protected: int
    bola: int
    inconclusive: int
    skipped: int

    def __post_init__(self) -> None:
        values = (
            self.total_combinations,
            self.executed,
            self.protected,
            self.bola,
            self.inconclusive,
            self.skipped,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
            raise ValueError("report summary counts must be non-negative integers")
        if self.executed != self.protected + self.bola + self.inconclusive + self.skipped:
            raise ValueError("executed must equal the sum of outcome counts")
        if self.total_combinations < self.completed:
            raise ValueError("total_combinations cannot be lower than completed coverage")

    @property
    def completed(self) -> int:
        """Return outcomes that established either protection or a BOLA."""

        return self.protected + self.bola

    @property
    def coverage(self) -> float | None:
        """Return completed-combination coverage, or ``None`` without a denominator."""

        if self.total_combinations == 0:
            return None
        return self.completed / self.total_combinations

    @classmethod
    def from_outcomes(
        cls,
        outcomes: Sequence[ProbeResult],
        *,
        total_combinations: int | None = None,
    ) -> RunSummary:
        """Build a summary without treating a missing outcome as a tested one."""

        counts = {verdict: 0 for verdict in Verdict}
        for outcome in outcomes:
            counts[outcome.verdict] += 1
        executed = len(outcomes)
        return cls(
            total_combinations=executed if total_combinations is None else total_combinations,
            executed=executed,
            protected=counts[Verdict.PROTECTED],
            bola=counts[Verdict.BOLA],
            inconclusive=counts[Verdict.INCONCLUSIVE],
            skipped=counts[Verdict.SKIPPED],
        )


@dataclass(frozen=True)
class ReportBundle:
    """The complete, safe input shared by every rendered report format."""

    findings: Sequence[Finding]
    outcomes: Sequence[ProbeResult]
    scope_target_label: str
    authorization_reference: str = field(repr=False)
    summary: RunSummary | None = None
    limitations: Sequence[str] = _DEFAULT_LIMITATIONS

    def __post_init__(self) -> None:
        findings = tuple(self.findings)
        outcomes = tuple(self.outcomes)
        limitations = tuple(self.limitations)
        if not isinstance(self.scope_target_label, str) or not self.scope_target_label.strip():
            raise ValueError("scope target label must be a non-empty string")
        if (
            not isinstance(self.authorization_reference, str)
            or not self.authorization_reference.strip()
        ):
            raise ValueError("authorization reference must be a non-empty string")
        if any(not isinstance(item, str) or not item.strip() for item in limitations):
            raise ValueError("report limitations must be non-empty strings")

        derived = RunSummary.from_outcomes(outcomes)
        summary = self.summary or derived
        if (
            summary.executed,
            summary.protected,
            summary.bola,
            summary.inconclusive,
            summary.skipped,
        ) != (
            derived.executed,
            derived.protected,
            derived.bola,
            derived.inconclusive,
            derived.skipped,
        ):
            raise ValueError("report summary does not match supplied probe outcomes")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "outcomes", outcomes)
        object.__setattr__(self, "limitations", limitations)
        object.__setattr__(self, "summary", summary)

    @property
    def authorization_reference_fingerprint(self) -> str:
        """Return an irreversible fingerprint; never render the source reference."""

        return "sha256:" + hashlib.sha256(
            self.authorization_reference.encode("utf-8")
        ).hexdigest()

    @classmethod
    def from_outcomes(
        cls,
        *,
        findings: Sequence[Finding],
        outcomes: Sequence[ProbeResult],
        scope_target_label: str,
        authorization_reference: str,
        total_combinations: int | None = None,
        limitations: Sequence[str] = _DEFAULT_LIMITATIONS,
    ) -> ReportBundle:
        """Construct a bundle and derive its counts from the supplied outcomes."""

        return cls(
            findings=findings,
            outcomes=outcomes,
            scope_target_label=scope_target_label,
            authorization_reference=authorization_reference,
            summary=RunSummary.from_outcomes(
                outcomes, total_combinations=total_combinations
            ),
            limitations=limitations,
        )

    @classmethod
    def from_state(
        cls,
        *,
        store: FindingStore,
        outcomes: Sequence[ProbeResult],
        scope_target_label: str,
        authorization_reference: str,
        total_combinations: int | None = None,
        limitations: Sequence[str] = _DEFAULT_LIMITATIONS,
    ) -> ReportBundle:
        """Read persisted findings through the StateStore's credential-safe API."""

        return cls.from_outcomes(
            findings=store.list_findings(),
            outcomes=outcomes,
            scope_target_label=scope_target_label,
            authorization_reference=authorization_reference,
            total_combinations=total_combinations,
            limitations=limitations,
        )


def serialize_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Return a minimal allowlisted evidence document suitable for reports.

    Sensitive containers are discarded without carrying their key names into a
    report.  Other unknown fields are rejected rather than guessed at, so a
    new executor field cannot accidentally become a credential disclosure.
    """

    if not isinstance(evidence, Mapping):
        raise TypeError("report evidence must be a mapping")
    safe: dict[str, Any] = {}
    redacted = False
    for key, value in evidence.items():
        if not isinstance(key, str):
            raise ValueError("report evidence keys must be strings")
        if _SENSITIVE_EVIDENCE_KEY_RE.search(key):
            redacted = True
            continue
        if key in {"owner_status", "attacker_status"}:
            if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
                raise ValueError("report evidence HTTP status is invalid")
            safe[key] = value
        elif key == "comparison":
            if not isinstance(value, str) or value not in _ALLOWED_COMPARISONS:
                raise ValueError("report evidence comparison is invalid")
            safe[key] = value
        elif key == "error_code":
            if not isinstance(value, str) or value not in _ALLOWED_ERROR_CODES:
                raise ValueError("report evidence error code is invalid")
            safe[key] = value
        elif key == "object_ref":
            if not isinstance(value, str) or not _OBJECT_REF_RE.fullmatch(value):
                raise ValueError("report evidence object reference is invalid")
            safe[key] = value
        elif key == "retryable":
            if not isinstance(value, bool):
                raise ValueError("report evidence retryable must be boolean")
            safe[key] = value
        elif key == "status":
            if not isinstance(value, str) or value not in {item.value for item in Verdict}:
                raise ValueError("report evidence status is invalid")
            safe[key] = value
        else:
            raise ValueError("report evidence contains a field outside the allowlist")
    if redacted:
        safe["redacted"] = True
    return {key: safe[key] for key in sorted(safe)}


def generate_json_report(bundle: ReportBundle) -> str:
    """Generate a canonical JSON report without timestamps or credential material."""

    return _canonical_json(_report_document(bundle)) + "\n"


def generate_junit_xml(bundle: ReportBundle) -> str:
    """Generate one JUnit testcase for every supplied probe outcome."""

    findings_by_endpoint = _findings_by_endpoint(bundle.findings)
    outcomes = _ordered_outcomes(bundle.outcomes)
    failures = sum(
        1
        for outcome in outcomes
        if outcome.verdict == Verdict.BOLA
        and _outcome_severity(outcome, findings_by_endpoint) in _FAILURE_SEVERITIES
    )
    skipped = sum(
        1
        for outcome in outcomes
        if outcome.verdict in {Verdict.INCONCLUSIVE, Verdict.SKIPPED}
    )
    summary = _summary(bundle)
    suite = ET.Element(
        "testsuite",
        {
            "name": "bolacheck.bola_idor",
            "tests": str(summary.executed),
            "failures": str(failures),
            "errors": "0",
            "skipped": str(skipped),
        },
    )
    for outcome in outcomes:
        method, endpoint = _outcome_endpoint(outcome)
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": "bola_idor", "name": _xml_text(f"{method} {endpoint}")},
        )
        severity = _outcome_severity(outcome, findings_by_endpoint)
        if outcome.verdict == Verdict.BOLA and severity in _FAILURE_SEVERITIES:
            finding = findings_by_endpoint[(method, endpoint)][0]
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "type": severity,
                    "message": _xml_text(finding.description),
                },
            )
            failure.text = _xml_text(_canonical_json(serialize_evidence(outcome.evidence)))
        elif outcome.verdict in {Verdict.INCONCLUSIVE, Verdict.SKIPPED}:
            skipped_node = ET.SubElement(
                case,
                "skipped",
                {"type": outcome.verdict.value, "message": _xml_text(_junit_skip_message(outcome))},
            )
            skipped_node.text = _xml_text(_canonical_json(serialize_evidence(outcome.evidence)))
    return ET.tostring(suite, encoding="unicode", short_empty_elements=True) + "\n"


def generate_markdown_report(bundle: ReportBundle) -> str:
    """Generate a safe, deterministic human-readable report."""

    summary = _summary(bundle)
    lines = ["# BOLA/IDOR assessment report", ""]
    lines.extend(
        [
            f"Scope target: {_markdown_inline(bundle.scope_target_label)}",
            f"Authorization reference fingerprint: `{bundle.authorization_reference_fingerprint}`",
            "",
            "## Outcome summary",
            "",
            "| Metric | Count |",
            "|---|---:|",
            f"| Candidate combinations | {summary.total_combinations} |",
            f"| Executed outcomes | {summary.executed} |",
            f"| Protected | {summary.protected} |",
            f"| BOLA | {summary.bola} |",
            f"| Inconclusive | {summary.inconclusive} |",
            f"| Skipped | {summary.skipped} |",
            f"| Completed coverage | {_coverage_text(summary)} |",
            "",
        ]
    )
    if summary.executed == 0:
        lines.extend(
            [
                "No probe outcomes were supplied. "
                "Zero findings does not mean this target was tested.",
                "",
            ]
        )
    elif not bundle.findings:
        lines.extend(
            [
                "No BOLA findings were recorded among the supplied outcomes.",
                "This is not evidence that the target contains no vulnerabilities.",
                "",
            ]
        )

    lines.extend(["## Limitations", ""])
    for limitation in bundle.limitations:
        lines.append(f"- {_markdown_inline(limitation)}")
    lines.append("")
    lines.extend(["## Findings", ""])
    findings = _ordered_findings(bundle.findings)
    if not findings:
        lines.append("No findings are included in this report.")
        lines.append("")
    for finding in findings:
        method, endpoint = _finding_endpoint(finding)
        severity = _finding_severity(finding)
        lines.extend(
            [
                f"### [{severity.upper()}] {_markdown_inline(method)} {_markdown_inline(endpoint)}",
                "",
                _markdown_inline(finding.title),
                "",
                _markdown_inline(finding.description),
                "",
            ]
        )
        evidence = _canonical_json(serialize_evidence(finding.evidence))
        fence = _markdown_fence(evidence)
        lines.extend([fence + "json", evidence, fence, ""])
    return "\n".join(lines)


def generate_sarif_report(bundle: ReportBundle) -> str:
    """Generate a deterministic SARIF 2.1.0 document from safe findings."""

    findings = _ordered_findings(bundle.findings)
    rules = []
    severities = sorted(
        {_finding_severity(item) for item in findings}, key=_SEVERITY_ORDER.__getitem__
    )
    for severity in severities:
        rules.append(
            {
                "id": f"BOLA.{severity.upper()}",
                "name": f"BOLA {severity}",
                "shortDescription": {"text": f"BOLA/IDOR finding ({severity})"},
                "defaultConfiguration": {"level": _sarif_level(severity)},
            }
        )
    results = []
    for finding in findings:
        method, endpoint = _finding_endpoint(finding)
        severity = _finding_severity(finding)
        results.append(
            {
                "ruleId": f"BOLA.{severity.upper()}",
                "level": _sarif_level(severity),
                "message": {"text": _safe_display_text(finding.description)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _safe_sarif_uri(endpoint)},
                        }
                    }
                ],
                "properties": {
                    "endpoint_method": method,
                    "endpoint_template": endpoint,
                    "evidence": serialize_evidence(finding.evidence),
                },
            }
        )
    summary = _summary(bundle)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BOLACheck",
                        "informationUri": "https://github.com/LeonardSEO/bolacheck",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"summary": _summary_document(summary)},
                    }
                ],
                "results": results,
            }
        ],
    }
    return _canonical_json(document) + "\n"


def write_reports(bundle: ReportBundle, *, output_dir: str | Path) -> dict[str, Path]:
    """Publish a complete report bundle through one atomic directory rename.

    The requested final directory must not exist.  Reports are staged in a
    private sibling directory, synced, then renamed into place.  This avoids a
    partially refreshed report set if serialization or one artifact write
    fails, and every path component is opened relative to a trusted directory
    file descriptor with ``O_NOFOLLOW``.
    """

    documents = {
        "json": generate_json_report(bundle),
        "junit": generate_junit_xml(bundle),
        "markdown": generate_markdown_report(bundle),
        "sarif": generate_sarif_report(bundle),
    }
    parent_fd, final_name, destination = _open_report_parent(output_dir)
    stage_name: str | None = None
    published = False
    primary_error: BaseException | None = None
    try:
        _require_absent(parent_fd, final_name)
        stage_name = _create_stage_directory(parent_fd, final_name)
        stage_fd = _open_directory(stage_name, parent_fd)
        try:
            for format_name, content in documents.items():
                _write_staged_file(
                    stage_fd,
                    _ARTIFACT_FILENAMES[format_name],
                    content.encode("utf-8"),
                )
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        _publish_directory_no_replace(parent_fd, stage_name, final_name)
        published = True
        _sync_parent_directory(parent_fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if stage_name is not None and not published:
            _cleanup_failed_stage(parent_fd, stage_name, primary_error)
        os.close(parent_fd)
    return {
        format_name: destination / filename
        for format_name, filename in _ARTIFACT_FILENAMES.items()
    }


def _report_document(bundle: ReportBundle) -> dict[str, Any]:
    summary = _summary(bundle)
    return {
        "authorization": {"reference_fingerprint": bundle.authorization_reference_fingerprint},
        "findings": [_finding_document(item) for item in _ordered_findings(bundle.findings)],
        "format": "bolacheck-report-v1",
        "limitations": [_safe_display_text(item) for item in bundle.limitations],
        "outcomes": [_outcome_document(item) for item in _ordered_outcomes(bundle.outcomes)],
        "scope": {"target_label": _safe_display_text(bundle.scope_target_label)},
        "summary": _summary_document(summary),
    }


def _summary_document(summary: RunSummary) -> dict[str, Any]:
    return {
        "bola": summary.bola,
        "coverage": {
            "completed": summary.completed,
            "ratio": summary.coverage,
            "total_combinations": summary.total_combinations,
        },
        "executed": summary.executed,
        "inconclusive": summary.inconclusive,
        "protected": summary.protected,
        "skipped": summary.skipped,
    }


def _finding_document(finding: Finding) -> dict[str, Any]:
    method, endpoint = _finding_endpoint(finding)
    return {
        "description": _safe_display_text(finding.description),
        "endpoint_template": endpoint,
        "evidence": serialize_evidence(finding.evidence),
        "method": method,
        "severity": _finding_severity(finding),
        "title": _safe_display_text(finding.title),
    }


def _outcome_document(outcome: ProbeResult) -> dict[str, Any]:
    method, endpoint = _outcome_endpoint(outcome)
    return {
        "attacker_status": _optional_status(outcome.attacker_status),
        "endpoint_template": endpoint,
        "evidence": serialize_evidence(outcome.evidence),
        "method": method,
        "owner_status": _optional_status(outcome.owner_status),
        "retryable": outcome.retryable,
        "verdict": outcome.verdict.value,
    }


def _ordered_findings(findings: Sequence[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[_finding_severity(finding)],
            *_finding_endpoint(finding),
            _safe_display_text(finding.title),
            _safe_display_text(finding.description),
            _canonical_json(serialize_evidence(finding.evidence)),
        ),
    )


def _ordered_outcomes(outcomes: Sequence[ProbeResult]) -> list[ProbeResult]:
    return sorted(
        outcomes,
        key=lambda outcome: (
            *_outcome_endpoint(outcome),
            outcome.verdict.value,
            _optional_status(outcome.owner_status),
            _optional_status(outcome.attacker_status),
            outcome.retryable,
            _canonical_json(serialize_evidence(outcome.evidence)),
        ),
    )


def _findings_by_endpoint(findings: Sequence[Finding]) -> dict[tuple[str, str], list[Finding]]:
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in _ordered_findings(findings):
        grouped.setdefault(_finding_endpoint(finding), []).append(finding)
    return grouped


def _outcome_severity(
    outcome: ProbeResult, findings_by_endpoint: Mapping[tuple[str, str], Sequence[Finding]]
) -> str | None:
    findings = findings_by_endpoint.get(_outcome_endpoint(outcome), ())
    if not findings:
        return None
    return min((_finding_severity(item) for item in findings), key=_SEVERITY_ORDER.__getitem__)


def _finding_endpoint(finding: Finding) -> tuple[str, str]:
    return _safe_method(finding.method), _safe_endpoint_template(finding.endpoint_template)


def _outcome_endpoint(outcome: ProbeResult) -> tuple[str, str]:
    return (
        _safe_method(outcome.target.method),
        _safe_endpoint_template(outcome.target.endpoint_template),
    )


def _finding_severity(finding: Finding) -> str:
    if not isinstance(finding.severity, str) or finding.severity not in _SEVERITIES:
        raise ValueError("finding severity is not supported by the report format")
    return finding.severity


def _safe_method(method: str) -> str:
    if not isinstance(method, str) or not _METHOD_RE.fullmatch(method):
        raise ValueError("report endpoint method must be uppercase HTTP syntax")
    return method


def _safe_endpoint_template(endpoint: str) -> str:
    if (
        not isinstance(endpoint, str)
        or not _SAFE_ENDPOINT_RE.fullmatch(endpoint)
        or "?" in endpoint
        or "#" in endpoint
        or any(part == ".." for part in endpoint.split("/"))
        or re.search(r"%(?:2f|5c)", endpoint, flags=re.IGNORECASE)
    ):
        raise ValueError("report endpoint template is not a safe path")
    return endpoint


def _optional_status(status_code: int | None) -> int | None:
    if status_code is None:
        return None
    if (
        isinstance(status_code, bool)
        or not isinstance(status_code, int)
        or not 100 <= status_code <= 599
    ):
        raise ValueError("report outcome HTTP status is invalid")
    return status_code


def _safe_display_text(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("report display text must be a string")
    compact = " ".join(value.split())
    return _SECRET_TEXT_RE.sub("[redacted]", compact)


def _xml_text(value: str) -> str:
    """Remove XML 1.0-invalid controls from untrusted display/evidence text."""

    return "".join(
        character
        for character in _safe_display_text(value)
        if character in {"\t", "\n", "\r"}
        or "\u0020" <= character <= "\ud7ff"
        or "\ue000" <= character <= "\ufffd"
        or "\U00010000" <= character <= "\U0010ffff"
    )


def _markdown_inline(value: str) -> str:
    text = _safe_display_text(value)
    return re.sub(r"([\\`*_{}\[\]<>#+.!|])", r"\\\1", text)


def _markdown_fence(content: str) -> str:
    runs = re.findall(r"`+", content)
    return "`" * max([3, *(len(run) + 1 for run in runs)])


def _coverage_text(summary: RunSummary) -> str:
    if summary.coverage is None:
        return f"{summary.completed}/{summary.total_combinations} (not measurable)"
    return f"{summary.completed}/{summary.total_combinations} ({summary.coverage:.0%})"


def _junit_skip_message(outcome: ProbeResult) -> str:
    if outcome.verdict == Verdict.INCONCLUSIVE:
        return "Probe outcome was inconclusive and does not establish authorization coverage."
    return "Probe was skipped and does not establish authorization coverage."


def _sarif_level(severity: str) -> str:
    if severity in _FAILURE_SEVERITIES:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _safe_sarif_uri(endpoint: str) -> str:
    """Use a synthetic safe authority so reports never publish a target URL."""

    return "api://bolacheck.invalid" + quote(_safe_endpoint_template(endpoint), safe="/-._~")


def _canonical_json(document: Any) -> str:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _summary(bundle: ReportBundle) -> RunSummary:
    if bundle.summary is None:  # pragma: no cover - ReportBundle normalizes this in __post_init__.
        raise RuntimeError("report bundle is missing a summary")
    return bundle.summary


def _open_report_parent(output_dir: str | Path) -> tuple[int, str, Path]:
    requested = Path(output_dir)
    components = requested.parts[1:] if requested.is_absolute() else requested.parts
    if not components or any(
        component in {"", ".", ".."} or "\x00" in component for component in components
    ):
        raise ValueError("report directory must name a new child without traversal")
    current_fd = _open_directory(os.sep if requested.is_absolute() else ".")
    try:
        for component in components[:-1]:
            with suppress(FileExistsError):
                os.mkdir(component, mode=0o700, dir_fd=current_fd)
            next_fd = _open_directory(component, current_fd)
            os.close(current_fd)
            current_fd = next_fd
    except BaseException:
        os.close(current_fd)
        raise
    destination = requested if requested.is_absolute() else Path.cwd() / requested
    return current_fd, components[-1], destination


def _open_directory(name: str, directory_fd: int | None = None) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("safe report publication requires O_NOFOLLOW support")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        if directory_fd is None:
            return os.open(name, flags)
        return os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ValueError("report path contains a symlink or non-directory") from error


def _require_absent(directory_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("report destination already exists")


def _publish_directory_no_replace(parent_fd: int, stage_name: str, final_name: str) -> None:
    """Atomically publish a staged directory without replacing a race-created target."""

    source = stage_name.encode("utf-8")
    destination = final_name.encode("utf-8")
    try:
        if sys.platform == "darwin":
            _darwin_rename_exclusive(parent_fd, source, destination)
        elif sys.platform.startswith("linux"):
            _linux_rename_no_replace(parent_fd, source, destination)
        else:
            raise RuntimeError("safe report publication requires native no-replace rename support")
    except OSError as error:
        if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ValueError("report destination already exists") from error
        raise


def _darwin_rename_exclusive(parent_fd: int, source: bytes, destination: bytes) -> None:
    """Call Darwin ``renameatx_np`` with ``RENAME_EXCL`` using dirfds."""

    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameatx_np", None)
    if rename is None:
        raise RuntimeError("safe report publication requires renameatx_np support")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename(parent_fd, source, parent_fd, destination, _RENAME_EXCL)
    if result != 0:
        _raise_native_rename_error()


def _linux_rename_no_replace(parent_fd: int, source: bytes, destination: bytes) -> None:
    """Call Linux ``renameat2`` or its syscall equivalent with ``RENAME_NOREPLACE``."""

    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is not None:
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = rename(parent_fd, source, parent_fd, destination, _RENAME_NOREPLACE)
        if result != 0:
            _raise_native_rename_error()
        return

    syscall_number = _LINUX_RENAMEAT2_SYSCALLS.get(platform.machine().lower())
    syscall = getattr(library, "syscall", None)
    if syscall_number is None or syscall is None:
        raise RuntimeError("safe report publication requires renameat2 support")
    syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = syscall(
        ctypes.c_long(syscall_number),
        ctypes.c_int(parent_fd),
        ctypes.c_char_p(source),
        ctypes.c_int(parent_fd),
        ctypes.c_char_p(destination),
        ctypes.c_uint(_RENAME_NOREPLACE),
    )
    if result != 0:
        _raise_native_rename_error()


def _raise_native_rename_error() -> None:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))


def _sync_parent_directory(parent_fd: int) -> None:
    """Durably record a staged-bundle publication or cleanup in its parent."""

    os.fsync(parent_fd)


def _cleanup_failed_stage(
    parent_fd: int, stage_name: str, primary_error: BaseException | None
) -> None:
    """Remove and sync a failed stage without masking its primary failure."""

    cleanup_error: BaseException | None = None
    durability_error: BaseException | None = None
    try:
        _remove_stage_directory(parent_fd, stage_name)
    except BaseException as error:
        cleanup_error = error
    try:
        _sync_parent_directory(parent_fd)
    except BaseException as error:
        durability_error = error

    if primary_error is not None:
        if cleanup_error is not None:
            primary_error.add_note(f"report stage cleanup failed: {cleanup_error!r}")
        if durability_error is not None:
            primary_error.add_note(f"report stage cleanup sync failed: {durability_error!r}")
        return
    if durability_error is not None:
        if cleanup_error is not None:
            raise durability_error from cleanup_error
        raise durability_error
    if cleanup_error is not None:
        raise cleanup_error


def _create_stage_directory(parent_fd: int, final_name: str) -> str:
    for _ in range(32):
        stage_name = f".{final_name}.stage-{uuid.uuid4().hex}"
        try:
            os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        return stage_name
    raise RuntimeError("could not allocate a private report staging directory")


def _write_staged_file(directory_fd: int, filename: str, payload: bytes) -> None:
    descriptor = os.open(
        filename,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_stage_directory(parent_fd: int, stage_name: str) -> None:
    """Remove a failed private stage without following any directory entry."""

    try:
        stage_fd = _open_directory(stage_name, parent_fd)
    except ValueError:
        with suppress(FileNotFoundError, IsADirectoryError):
            os.unlink(stage_name, dir_fd=parent_fd)
        return
    try:
        _remove_directory_contents(stage_fd)
    finally:
        os.close(stage_fd)
    try:
        os.rmdir(stage_name, dir_fd=parent_fd)
    except FileNotFoundError:
        return


def _remove_directory_contents(directory_fd: int) -> None:
    for entry in os.listdir(directory_fd):
        metadata = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = _open_directory(entry, directory_fd)
            try:
                _remove_directory_contents(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(entry, dir_fd=directory_fd)
        else:
            os.unlink(entry, dir_fd=directory_fd)
