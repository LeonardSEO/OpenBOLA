"""Deterministic, credential-safe reports for OpenBOLA runs.

Reports deliberately consume the typed phase contracts rather than a live
``StateStore``.  This keeps reporting read-only, makes the complete set of
probe outcomes explicit, and prevents a report containing zero findings from
being mistaken for proof that a target was tested.
"""

from __future__ import annotations

import csv
import ctypes
import errno
import hashlib
import html
import io
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
from typing import Any, Literal, NoReturn, Protocol, TypeVar, cast
from urllib.parse import quote

from openbola.models import Finding, ProbeResult, Verdict
from openbola.state import ErrorCode

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
    "json": "report.json",
    "markdown": "report.md",
    "csv": "report.csv",
    "html": "report.html",
    "junit": "junit.xml",
    "sarif": "report.sarif",
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

# These aliases are deliberately closed.  Report renderers must not accept an
# arbitrary verb or status supplied by a legacy ``Finding`` row.
CapabilityName = Literal["read", "post", "patch", "put", "delete"]
ProofStatus = Literal["proven", "not_proven", "inconclusive", "not_tested"]
CleanupStatus = Literal["verified", "not_applicable", "inconclusive", "not_run"]
CoverageStatus = Literal["complete", "partial", "not_tested"]

_CAPABILITIES = frozenset({"read", "post", "patch", "put", "delete"})
_PROOF_STATUSES = frozenset({"proven", "not_proven", "inconclusive", "not_tested"})
_CLEANUP_STATUSES = frozenset({"verified", "not_applicable", "inconclusive", "not_run"})
_COVERAGE_STATUSES = frozenset({"complete", "partial", "not_tested"})
_IDENTITY_REF_RE = re.compile(r"identity_[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_TEXT_LIMIT = 512
_COUNT_LIMIT = 100_000
_LEGACY_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "authentication",
        "api_key",
        "api-key",
        "bearer",
        "body",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "header",
        "headers",
        "password",
        "pass",
        "session",
        "token",
    }
)
_LEGACY_CAPABILITY_LIMITATION = (
    "Legacy evidence omitted capability proof; mutation lifecycle claims are not inferred."
)


def _raise_report_finding_type(value: object) -> NoReturn:
    raise TypeError("report findings must contain ReportFinding or Finding values")


def _report_finding_from_legacy(finding: Finding) -> ReportFinding:
    """Adapt one persisted finding at the report boundary.

    The legacy row is consumed immediately and only its validated, opaque
    projection enters the typed report contract.  In particular, the source
    evidence mapping is never retained on the resulting value.
    """

    if not isinstance(finding, Finding):
        return _raise_report_finding_type(finding)
    endpoint = _safe_endpoint_template(finding.endpoint_template)
    method = _safe_method(finding.method)
    severity = _finding_severity(finding)
    return ReportFinding(
        endpoint_template=endpoint,
        method=method,
        severity=severity,
        title=_typed_text(finding.title, field_name="finding title"),
        description=_typed_text(finding.description, field_name="finding description"),
        evidence=FindingEvidence.from_legacy_mapping(
            finding.evidence,
            method=method,
            endpoint_template=endpoint,
        ),
    )


def _typed_text(value: str, *, field_name: str) -> str:
    """Validate and sanitize bounded human-readable report text."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"report {field_name} must be a non-empty string")
    sanitized = _safe_display_text(value)
    if not sanitized or len(sanitized) > _TEXT_LIMIT:
        raise ValueError(f"report {field_name} exceeds the display limit")
    return sanitized


def _typed_optional_ref(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _IDENTITY_REF_RE.fullmatch(value):
        raise ValueError(f"report {field_name} must be an opaque identity reference")
    return value


def _identity_fingerprint(value: str, *, field_name: str) -> str:
    """Turn a legacy identity label into an opaque, stable report reference."""

    if not isinstance(value, str) or not value.strip() or len(value) > _TEXT_LIMIT:
        raise ValueError(f"report {field_name} is invalid")
    return "identity_" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _typed_status(value: int | None, *, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise ValueError(f"report {field_name} HTTP status is invalid")
    return value


_SortValue = TypeVar("_SortValue")


def _validate_sorted_unique(
    values: tuple[_SortValue, ...], *, key: Any, field_name: str
) -> None:
    ordered = tuple(sorted(values, key=key))
    if values != ordered:
        raise ValueError(f"report {field_name} must be sorted")
    if len(set(values)) != len(values):
        raise ValueError(f"report {field_name} must be unique")


@dataclass(frozen=True)
class CapabilityProof:
    capability: CapabilityName
    status: ProofStatus
    owner_identity_ref: str | None
    attacker_identity_ref: str | None
    owner_status: int | None
    attacker_status: int | None
    comparison: str | None
    cleanup: CleanupStatus
    coverage: CoverageStatus

    def __post_init__(self) -> None:
        if self.capability not in _CAPABILITIES:
            raise ValueError("report capability is not supported")
        if self.status not in _PROOF_STATUSES:
            raise ValueError("report capability status is not supported")
        if self.cleanup not in _CLEANUP_STATUSES:
            raise ValueError("report cleanup status is not supported")
        if self.coverage not in _COVERAGE_STATUSES:
            raise ValueError("report coverage status is not supported")
        _typed_optional_ref(self.owner_identity_ref, field_name="owner identity")
        _typed_optional_ref(self.attacker_identity_ref, field_name="attacker identity")
        _typed_status(self.owner_status, field_name="owner")
        _typed_status(self.attacker_status, field_name="attacker")
        if self.comparison is not None and (
            not isinstance(self.comparison, str)
            or (
                self.comparison not in _ALLOWED_COMPARISONS
                and self.comparison != "unknown"
            )
        ):
            raise ValueError("report capability comparison is invalid")


@dataclass(frozen=True)
class ReportField:
    name: str
    type_name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _typed_text(self.name, field_name="field name"))
        object.__setattr__(
            self, "type_name", _typed_text(self.type_name, field_name="field type")
        )


def _field_key(item: ReportField) -> tuple[str, str]:
    return item.name, item.type_name


def _capability_key(item: CapabilityProof) -> tuple[Any, ...]:
    return (
        item.capability,
        item.status,
        item.owner_identity_ref or "",
        item.attacker_identity_ref or "",
        item.owner_status or 0,
        item.attacker_status or 0,
        item.comparison or "",
        item.cleanup,
        item.coverage,
    )


@dataclass(frozen=True)
class ResourceReport:
    provider: str
    confidence: str
    dataset: str
    endpoint_template: str
    total_discovered: int
    fields: tuple[ReportField, ...]
    capabilities: tuple[CapabilityProof, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.provider, "provider"),
            (self.confidence, "confidence"),
            (self.dataset, "dataset"),
        ):
            _typed_text(value, field_name=name)
        object.__setattr__(self, "provider", _typed_text(self.provider, field_name="provider"))
        object.__setattr__(
            self, "confidence", _typed_text(self.confidence, field_name="confidence")
        )
        object.__setattr__(self, "dataset", _typed_text(self.dataset, field_name="dataset"))
        _safe_endpoint_template(self.endpoint_template)
        if (
            isinstance(self.total_discovered, bool)
            or not isinstance(self.total_discovered, int)
            or not 0 <= self.total_discovered <= _COUNT_LIMIT
        ):
            raise ValueError("report total discovered count is invalid")
        fields = tuple(self.fields)
        capabilities = tuple(self.capabilities)
        if any(not isinstance(item, ReportField) for item in fields):
            raise TypeError("report fields must contain ReportField values")
        if any(not isinstance(item, CapabilityProof) for item in capabilities):
            raise TypeError("report capabilities must contain CapabilityProof values")
        _validate_sorted_unique(fields, key=_field_key, field_name="fields")
        _validate_sorted_unique(capabilities, key=_capability_key, field_name="capabilities")
        object.__setattr__(self, "fields", fields)
        object.__setattr__(self, "capabilities", capabilities)


@dataclass(frozen=True)
class FindingEvidence:
    object_ref: str | None
    impacted_identity_refs: tuple[str, ...]
    fields: tuple[ReportField, ...]
    capabilities: tuple[CapabilityProof, ...]
    confidence: str
    reproduction: tuple[str, ...]
    remediation: str
    cleanup: CleanupStatus
    coverage: CoverageStatus

    def __post_init__(self) -> None:
        if self.object_ref is not None and not _OBJECT_REF_RE.fullmatch(self.object_ref):
            raise ValueError("report object reference is invalid")
        identities = tuple(self.impacted_identity_refs)
        if any(
            not isinstance(item, str) or not _IDENTITY_REF_RE.fullmatch(item)
            for item in identities
        ):
            raise ValueError("report impacted identity reference is invalid")
        _validate_sorted_unique(identities, key=lambda item: item, field_name="identity references")
        fields = tuple(self.fields)
        capabilities = tuple(self.capabilities)
        if any(not isinstance(item, ReportField) for item in fields):
            raise TypeError("report fields must contain ReportField values")
        if any(not isinstance(item, CapabilityProof) for item in capabilities):
            raise TypeError("report capabilities must contain CapabilityProof values")
        _validate_sorted_unique(fields, key=_field_key, field_name="fields")
        _validate_sorted_unique(capabilities, key=_capability_key, field_name="capabilities")
        reproduction = tuple(self.reproduction)
        if any(not isinstance(item, str) for item in reproduction):
            raise ValueError("report reproduction steps must be strings")
        reproduction = tuple(
            _typed_text(item, field_name="reproduction step") for item in reproduction
        )
        if self.cleanup not in _CLEANUP_STATUSES:
            raise ValueError("report cleanup status is not supported")
        if self.coverage not in _COVERAGE_STATUSES:
            raise ValueError("report coverage status is not supported")
        object.__setattr__(self, "impacted_identity_refs", identities)
        object.__setattr__(self, "fields", fields)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(
            self, "confidence", _typed_text(self.confidence, field_name="confidence")
        )
        object.__setattr__(self, "reproduction", reproduction)
        object.__setattr__(
            self, "remediation", _typed_text(self.remediation, field_name="remediation")
        )

    @classmethod
    def from_legacy_mapping(
        cls,
        evidence: Mapping[str, Any],
        *,
        method: str,
        endpoint_template: str,
    ) -> FindingEvidence:
        """Convert one old evidence mapping into a closed report contract.

        Legacy evidence has no ownership labels or mutation lifecycle facts;
        those are intentionally represented as empty/unknown values instead
        of being guessed from a read result.
        """

        if not isinstance(evidence, Mapping):
            raise TypeError("legacy report evidence must be a mapping")
        method = _safe_method(method)
        endpoint_template = _safe_endpoint_template(endpoint_template)
        allowed = {
            "owner_status",
            "attacker_status",
            "owner_identity",
            "attacker_identity",
            "comparison",
            "object_ref",
            "status",
            "retryable",
            "error_code",
        }
        safe: dict[str, Any] = {}
        for key, value in evidence.items():
            if not isinstance(key, str):
                raise ValueError("report evidence keys must be strings")
            normalized = key.lower()
            if normalized in _LEGACY_SENSITIVE_KEYS:
                continue
            if normalized not in allowed:
                raise ValueError("report evidence contains a field outside the allowlist")
            safe[normalized] = value
        owner_status = _typed_status(safe.get("owner_status"), field_name="owner")
        attacker_status = _typed_status(safe.get("attacker_status"), field_name="attacker")
        owner_identity_ref = (
            _identity_fingerprint(safe["owner_identity"], field_name="owner identity")
            if "owner_identity" in safe
            else None
        )
        attacker_identity_ref = (
            _identity_fingerprint(safe["attacker_identity"], field_name="attacker identity")
            if "attacker_identity" in safe
            else None
        )
        comparison = safe.get("comparison")
        if comparison is not None and (
            not isinstance(comparison, str)
            or comparison not in _ALLOWED_COMPARISONS
        ):
            raise ValueError("report evidence comparison is invalid")
        object_ref = safe.get("object_ref")
        if object_ref is not None and (
            not isinstance(object_ref, str) or not _OBJECT_REF_RE.fullmatch(object_ref)
        ):
            raise ValueError("report evidence object reference is invalid")
        status_value = safe.get("status")
        if status_value is not None and (
            not isinstance(status_value, str)
            or status_value not in {item.value for item in Verdict}
        ):
            raise ValueError("report evidence status is invalid")
        if "retryable" in safe and not isinstance(safe["retryable"], bool):
            raise ValueError("report evidence retryable must be boolean")
        if "error_code" in safe and (
            not isinstance(safe["error_code"], str)
            or safe["error_code"] not in _ALLOWED_ERROR_CODES
        ):
            raise ValueError("report evidence error code is invalid")

        if status_value == Verdict.INCONCLUSIVE.value or "error_code" in safe:
            proof_status: ProofStatus = "inconclusive"
        elif status_value == Verdict.SKIPPED.value:
            proof_status = "not_tested"
        elif status_value == Verdict.PROTECTED.value or comparison == "object_id_mismatch":
            proof_status = "not_proven"
        elif (
            method == "GET"
            and comparison == "object_id_match"
            and attacker_status is not None
            and 200 <= attacker_status <= 299
        ):
            proof_status = "proven"
        else:
            proof_status = "not_tested"
        proof = CapabilityProof(
            "read",
            proof_status,
            owner_identity_ref,
            attacker_identity_ref,
            owner_status,
            attacker_status,
            comparison,
            "not_applicable",
            "partial",
        )
        return cls(
            object_ref,
            (),
            (),
            (proof,),
            "legacy",
            (f"{method} {endpoint_template}",),
            "Enforce object-level authorization checks.",
            "not_applicable",
            "partial",
        )


@dataclass(frozen=True)
class ReportFinding:
    endpoint_template: str
    method: str
    severity: str
    title: str
    description: str
    evidence: FindingEvidence

    def __post_init__(self) -> None:
        _safe_endpoint_template(self.endpoint_template)
        _safe_method(self.method)
        if self.severity not in _SEVERITIES:
            raise ValueError("finding severity is not supported by the report format")
        if not isinstance(self.evidence, FindingEvidence):
            raise TypeError("report finding evidence must be FindingEvidence")
        object.__setattr__(self, "title", _typed_text(self.title, field_name="finding title"))
        object.__setattr__(
            self, "description", _typed_text(self.description, field_name="finding description")
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

    findings: Sequence[ReportFinding]
    outcomes: Sequence[ProbeResult]
    scope_target_label: str
    authorization_reference: str = field(repr=False)
    summary: RunSummary | None = None
    limitations: Sequence[str] = _DEFAULT_LIMITATIONS
    resources: Sequence[ResourceReport] = ()

    def __post_init__(self) -> None:
        raw_findings = tuple(self.findings)
        findings: tuple[ReportFinding, ...] = tuple(
            item
            if isinstance(item, ReportFinding)
            else _report_finding_from_legacy(item)
            if isinstance(item, Finding)
            else _raise_report_finding_type(item)
            for item in raw_findings
        )
        outcomes = tuple(self.outcomes)
        limitations = tuple(self.limitations)
        resources = tuple(self.resources)
        if not isinstance(self.scope_target_label, str) or not self.scope_target_label.strip():
            raise ValueError("scope target label must be a non-empty string")
        if (
            not isinstance(self.authorization_reference, str)
            or not self.authorization_reference.strip()
        ):
            raise ValueError("authorization reference must be a non-empty string")
        if any(not isinstance(item, str) or not item.strip() for item in limitations):
            raise ValueError("report limitations must be non-empty strings")
        if any(not isinstance(item, ResourceReport) for item in resources):
            raise TypeError("report resources must contain ResourceReport values")
        resources = tuple(sorted(resources, key=_resource_key))
        if resources and len(set(resources)) != len(resources):
            raise ValueError("report resources must be unique")
        if any(isinstance(item, Finding) for item in raw_findings) and (
            _LEGACY_CAPABILITY_LIMITATION not in limitations
        ):
            limitations = tuple(limitations) + (_LEGACY_CAPABILITY_LIMITATION,)

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
        object.__setattr__(self, "resources", resources)

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
        findings: Sequence[Finding | ReportFinding],
        outcomes: Sequence[ProbeResult],
        scope_target_label: str,
        authorization_reference: str,
        total_combinations: int | None = None,
        limitations: Sequence[str] = _DEFAULT_LIMITATIONS,
        resources: Sequence[ResourceReport] = (),
    ) -> ReportBundle:
        """Construct a bundle and derive its counts from the supplied outcomes."""

        return cls(
            findings=cast(Sequence[ReportFinding], findings),
            outcomes=outcomes,
            scope_target_label=scope_target_label,
            authorization_reference=authorization_reference,
            summary=RunSummary.from_outcomes(
                outcomes, total_combinations=total_combinations
            ),
            limitations=limitations,
            resources=resources,
        )

    @classmethod
    def from_legacy_findings(
        cls,
        *,
        findings: Sequence[Finding],
        outcomes: Sequence[ProbeResult] = (),
        scope_target_label: str,
        authorization_reference: str,
        total_combinations: int | None = None,
        limitations: Sequence[str] = _DEFAULT_LIMITATIONS,
        resources: Sequence[ResourceReport] = (),
    ) -> ReportBundle:
        """Adapt persisted ``Finding`` rows exactly once at the report boundary."""

        return cls.from_outcomes(
            findings=findings,
            outcomes=outcomes,
            scope_target_label=scope_target_label,
            authorization_reference=authorization_reference,
            total_combinations=total_combinations,
            limitations=limitations,
            resources=resources,
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
        resources: Sequence[ResourceReport] = (),
    ) -> ReportBundle:
        """Read persisted findings through the StateStore's credential-safe API."""

        return cls.from_outcomes(
            findings=store.list_findings(),
            outcomes=outcomes,
            scope_target_label=scope_target_label,
            authorization_reference=authorization_reference,
            total_combinations=total_combinations,
            limitations=limitations,
            resources=resources,
        )


def serialize_evidence(evidence: Mapping[str, Any] | FindingEvidence) -> dict[str, Any]:
    """Return a minimal allowlisted evidence document suitable for reports.

    Sensitive containers are discarded without carrying their key names into a
    report.  Other unknown fields are rejected rather than guessed at, so a
    new executor field cannot accidentally become a credential disclosure.
    """

    if isinstance(evidence, FindingEvidence):
        # Compatibility projection for the pre-P7 renderers.  The canonical
        # typed document uses ``_typed_evidence_document`` instead; this view
        # intentionally exposes only the old bounded read-proof fields.
        proof = next(iter(evidence.capabilities), None)
        safe_typed: dict[str, Any] = {}
        if evidence.object_ref is not None:
            safe_typed["object_ref"] = evidence.object_ref
        if proof is not None:
            if proof.owner_status is not None:
                safe_typed["owner_status"] = proof.owner_status
            if proof.attacker_status is not None:
                safe_typed["attacker_status"] = proof.attacker_status
            if proof.comparison is not None:
                safe_typed["comparison"] = proof.comparison
        return {key: safe_typed[key] for key in sorted(safe_typed)}
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

    return _canonical_json(canonical_report_document(bundle)) + "\n"


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
            "name": "openbola.bola_idor",
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
            failure.text = _xml_text(_canonical_json(_outcome_document(outcome)))
        elif outcome.verdict in {Verdict.INCONCLUSIVE, Verdict.SKIPPED}:
            skipped_node = ET.SubElement(
                case,
                "skipped",
                {"type": outcome.verdict.value, "message": _xml_text(_junit_skip_message(outcome))},
            )
            skipped_node.text = _xml_text(_canonical_json(_outcome_document(outcome)))
    return ET.tostring(suite, encoding="unicode", short_empty_elements=True) + "\n"


def generate_markdown_report(bundle: ReportBundle) -> str:
    """Generate a safe, deterministic human-readable report."""

    document = canonical_report_document(bundle)
    summary = _summary(bundle)
    lines = ["# BOLA/IDOR assessment report", ""]
    lines.extend(
        [
            f"Scope target: {_markdown_inline(cast(str, document['scope']['target_label']))}",
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
    for limitation in cast(list[str], document["limitations"]):
        lines.append(f"- {_markdown_inline(limitation)}")
    lines.append("")
    lines.extend(["## Resources", ""])
    if not bundle.resources:
        lines.extend(["No discovered resources are included in this report.", ""])
    else:
        lines.extend(
            [
                "| Provider | Dataset | Endpoint | Discovered | Capabilities |",
                "|---|---|---|---:|---|",
            ]
        )
        for resource in sorted(bundle.resources, key=_resource_key):
            capabilities = ", ".join(
                f"{item.capability}: {item.status}" for item in resource.capabilities
            ) or "none"
            lines.append(
                "| "
                + " | ".join(
                    (
                        _markdown_inline(resource.provider),
                        _markdown_inline(resource.dataset),
                        _markdown_inline(resource.endpoint_template),
                        str(resource.total_discovered),
                        _markdown_inline(capabilities),
                    )
                )
                + " |"
            )
        lines.append("")
    lines.extend(["## Findings", ""])
    findings = _ordered_typed_findings(bundle.findings)
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
        evidence = _canonical_json(_typed_evidence_document(finding.evidence))
        fence = _markdown_fence(evidence)
        lines.extend([fence + "json", evidence, fence, ""])
    return "\n".join(lines)


_CSV_HEADER = (
    "provider",
    "confidence",
    "dataset",
    "endpoint_template",
    "total_discovered",
    "field_names",
    "field_types",
    "capability",
    "capability_status",
    "owner_identity_ref",
    "attacker_identity_ref",
    "owner_status",
    "attacker_status",
    "cleanup_status",
    "coverage_status",
)


def generate_csv_report(bundle: ReportBundle) -> str:
    """Generate the deterministic resource/capability matrix as CSV."""

    document = canonical_report_document(bundle)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(_CSV_HEADER)
    resources = cast(list[dict[str, Any]], document["resources"])
    for resource in resources:
        fields = tuple(cast(list[dict[str, str]], resource["fields"]))
        field_names = ";".join(item["name"] for item in fields)
        field_types = ";".join(item["type"] for item in fields)
        for capability in cast(list[dict[str, Any]], resource["capabilities"]):
            row = (
                resource["provider"],
                resource["confidence"],
                resource["dataset"],
                resource["endpoint_template"],
                resource["total_discovered"],
                field_names,
                field_types,
                capability["capability"],
                capability["status"],
                capability["owner_identity_ref"] or "",
                capability["attacker_identity_ref"] or "",
                capability["owner_status"] or "",
                capability["attacker_status"] or "",
                capability["cleanup"],
                capability["coverage"],
            )
            writer.writerow(row)
    return output.getvalue()


def generate_html_report(bundle: ReportBundle) -> str:
    """Generate a self-contained, CSP-constrained HTML report."""

    document = canonical_report_document(bundle)

    def esc(value: object) -> str:
        return html.escape(_safe_display_text(str(value)), quote=True)

    summary = _summary(bundle)
    rows: list[str] = []
    for finding in _ordered_typed_findings(bundle.findings):
        rows.append(
            "<tr class=\"finding\">"
            f"<td>{esc(finding.severity)}</td>"
            f"<td>{esc(finding.method)} {esc(finding.endpoint_template)}</td>"
            f"<td>{esc(finding.title)}</td>"
            f"<td>{esc(finding.description)}</td>"
            "</tr>"
        )
    if not rows:
        rows.append(
            '<tr class="finding"><td colspan="4">'
            "No findings are included in this report.</td></tr>"
        )

    resource_rows: list[str] = []
    for resource in sorted(bundle.resources, key=_resource_key):
        for capability in resource.capabilities:
            resource_rows.append(
                "<tr class=\"resource\">"
                f"<td>{esc(resource.provider)}</td>"
                f"<td>{esc(resource.dataset)}</td>"
                f"<td>{esc(resource.endpoint_template)}</td>"
                f"<td>{resource.total_discovered}</td>"
                f"<td>{esc(capability.capability)}</td>"
                f"<td>{esc(capability.status)}</td>"
                "</tr>"
            )
    if not resource_rows:
        resource_rows.append(
            '<tr class="resource"><td colspan="6">'
            "No discovered resources are included in this report.</td></tr>"
        )

    target = cast(dict[str, str], document["scope"])["target_label"]
    fingerprint = cast(dict[str, str], document["authorization"])["reference_fingerprint"]
    return "".join(
        (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; style-src \'unsafe-inline\'; '
            'script-src \'unsafe-inline\'">',
            "<title>OpenBOLA report</title><style>",
            "body{font-family:system-ui,sans-serif;line-height:1.4;margin:2rem;"
            "background:#fff;color:#111}table{border-collapse:collapse;width:100%;margin:1rem 0}"
            "th,td{border:1px solid #bbb;padding:.4rem;text-align:left}"
            "input{padding:.4rem;min-width:18rem}"
            "</style></head><body>",
            "<h1>BOLA/IDOR assessment report</h1>",
            f"<p>Scope target: <span>{esc(target)}</span><br>"
            f"Authorization reference fingerprint: <code>{esc(fingerprint)}</code></p>",
            "<h2>Outcome summary</h2><ul>",
            f"<li>Candidate combinations: {summary.total_combinations}</li>",
            f"<li>Executed outcomes: {summary.executed}</li>",
            f"<li>Protected: {summary.protected}</li>",
            f"<li>BOLA: {summary.bola}</li>",
            f"<li>Completed coverage: {esc(_coverage_text(summary))}</li>",
            "</ul>",
            '<label for="report-filter">Filter findings</label> '
            '<input id="report-filter" type="search" autocomplete="off">',
            "<h2>Resources</h2><table><thead><tr><th>Provider</th><th>Dataset</th><th>Endpoint</th><th>Discovered</th><th>Capability</th><th>Status</th></tr></thead><tbody>",
            "".join(resource_rows),
            "</tbody></table>",
            "<h2>Findings</h2><table><thead><tr>"
            "<th>Severity</th><th>Endpoint</th><th>Title</th><th>Description</th>"
            "</tr></thead><tbody id=\"findings\">",
            "".join(rows),
            "</tbody></table>",
            "<script>const filter=document.getElementById('report-filter');"
            "const findings=document.querySelectorAll('#findings .finding');"
            "filter.addEventListener('input',()=>{const query=filter.value.toLowerCase();"
            "findings.forEach(row=>{row.hidden=!row.textContent.toLowerCase()"
            ".includes(query);});});</script>",
            "</body></html>\n",
        )
    )


def generate_sarif_report(bundle: ReportBundle) -> str:
    """Generate a deterministic SARIF 2.1.0 document from safe findings."""

    canonical = canonical_report_document(bundle)
    findings = _ordered_typed_findings(bundle.findings)
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
                    "evidence": _typed_evidence_document(finding.evidence),
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenBOLA",
                        "informationUri": "https://github.com/LeonardSEO/openbola",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"summary": canonical["summary"]},
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
        "markdown": generate_markdown_report(bundle),
        "csv": generate_csv_report(bundle),
        "html": generate_html_report(bundle),
        "junit": generate_junit_xml(bundle),
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
        "format": "openbola-report-v1",
        "limitations": [_safe_display_text(item) for item in bundle.limitations],
        "outcomes": [_outcome_document(item) for item in _ordered_outcomes(bundle.outcomes)],
        "scope": {"target_label": _safe_display_text(bundle.scope_target_label)},
        "summary": _summary_document(summary),
    }


def canonical_report_document(bundle: ReportBundle) -> dict[str, Any]:
    """Return the typed, schema-versioned report document.

    This is the sole generic-dictionary boundary for P7.  All findings and
    resources have already passed the immutable typed contracts before this
    function emits JSON-compatible values.
    """

    summary = _summary(bundle)
    return {
        "authorization": {"reference_fingerprint": bundle.authorization_reference_fingerprint},
        "findings": [
            _typed_finding_document(item) for item in _ordered_typed_findings(bundle.findings)
        ],
        "format": "openbola-report-v1",
        "limitations": [_safe_display_text(item) for item in bundle.limitations],
        "outcomes": [_outcome_document(item) for item in _ordered_outcomes(bundle.outcomes)],
        "resources": [
            _resource_document(item) for item in sorted(bundle.resources, key=_resource_key)
        ],
        "schema_version": 1,
        "scope": {"target_label": _safe_display_text(bundle.scope_target_label)},
        "summary": _summary_document(summary),
    }


def _resource_key(resource: ResourceReport) -> tuple[Any, ...]:
    return (
        resource.provider,
        resource.dataset,
        resource.endpoint_template,
        resource.confidence,
        resource.total_discovered,
        tuple(_field_key(item) for item in resource.fields),
        tuple(_capability_key(item) for item in resource.capabilities),
    )


def _typed_finding_document(finding: ReportFinding) -> dict[str, Any]:
    return {
        "description": finding.description,
        "endpoint_template": finding.endpoint_template,
        "evidence": _typed_evidence_document(finding.evidence),
        "method": finding.method,
        "severity": finding.severity,
        "title": finding.title,
    }


def _typed_evidence_document(evidence: FindingEvidence) -> dict[str, Any]:
    return {
        "capabilities": [_capability_document(item) for item in evidence.capabilities],
        "cleanup": evidence.cleanup,
        "confidence": evidence.confidence,
        "coverage": evidence.coverage,
        "fields": [
            {"name": item.name, "type": item.type_name} for item in evidence.fields
        ],
        "impacted_identity_refs": list(evidence.impacted_identity_refs),
        "object_ref": evidence.object_ref,
        "remediation": evidence.remediation,
        "reproduction": list(evidence.reproduction),
    }


def _capability_document(proof: CapabilityProof) -> dict[str, Any]:
    return {
        "attacker_identity_ref": proof.attacker_identity_ref,
        "attacker_status": proof.attacker_status,
        "capability": proof.capability,
        "cleanup": proof.cleanup,
        "comparison": proof.comparison,
        "coverage": proof.coverage,
        "owner_identity_ref": proof.owner_identity_ref,
        "owner_status": proof.owner_status,
        "status": proof.status,
    }


def _resource_document(resource: ResourceReport) -> dict[str, Any]:
    return {
        "capabilities": [_capability_document(item) for item in resource.capabilities],
        "confidence": resource.confidence,
        "dataset": resource.dataset,
        "endpoint_template": resource.endpoint_template,
        "fields": [{"name": item.name, "type": item.type_name} for item in resource.fields],
        "provider": resource.provider,
        "total_discovered": resource.total_discovered,
    }


def _ordered_typed_findings(findings: Sequence[ReportFinding]) -> list[ReportFinding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.method,
            finding.endpoint_template,
            finding.title,
            finding.description,
            _canonical_json(_typed_evidence_document(finding.evidence)),
        ),
    )


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


def _finding_document(finding: Finding | ReportFinding) -> dict[str, Any]:
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


def _ordered_findings(findings: Sequence[Finding | ReportFinding]) -> list[Finding | ReportFinding]:
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


def _findings_by_endpoint(
    findings: Sequence[Finding | ReportFinding],
) -> dict[tuple[str, str], list[Finding | ReportFinding]]:
    grouped: dict[tuple[str, str], list[Finding | ReportFinding]] = {}
    for finding in _ordered_findings(findings):
        grouped.setdefault(_finding_endpoint(finding), []).append(finding)
    return grouped


def _outcome_severity(
    outcome: ProbeResult,
    findings_by_endpoint: Mapping[tuple[str, str], Sequence[Finding | ReportFinding]],
) -> str | None:
    findings = findings_by_endpoint.get(_outcome_endpoint(outcome), ())
    if not findings:
        return None
    return min((_finding_severity(item) for item in findings), key=_SEVERITY_ORDER.__getitem__)


def _finding_endpoint(finding: Finding | ReportFinding) -> tuple[str, str]:
    return _safe_method(finding.method), _safe_endpoint_template(finding.endpoint_template)


def _outcome_endpoint(outcome: ProbeResult) -> tuple[str, str]:
    return (
        _safe_method(outcome.target.method),
        _safe_endpoint_template(outcome.target.endpoint_template),
    )


def _finding_severity(finding: Finding | ReportFinding) -> str:
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

    return "api://openbola.invalid" + quote(_safe_endpoint_template(endpoint), safe="/-._~")


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
