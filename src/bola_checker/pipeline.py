"""Synchronous, authorization-first orchestration for local and CI use.

The pipeline is intentionally boring: it loads a confirmed scope, imports
already-sanitized traffic (or in-memory records), correlates strong ownership,
and delegates every request to :class:`ProbeExecutor`.  Concrete object IDs
are process-local mappings only; the SQLite state and reports receive opaque
references.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from bola_checker.capture import CaptureError, parse_har_records
from bola_checker.credentials import CredentialVault
from bola_checker.endpoints import (
    CandidateLocation,
    build_test_targets,
    correlate_ownership,
    discover_endpoint_candidates,
    executable_ownership,
)
from bola_checker.executor import ExecutorLimits, ProbeExecutor
from bola_checker.extract import extract_requests
from bola_checker.models import (
    CredentialKind,
    CredentialRef,
    ProbeMode,
    ProbeResult,
    ProbeTarget,
    RequestRecord,
    Verdict,
)
from bola_checker.reporting import ReportBundle, write_reports
from bola_checker.scope import ScopeError, ScopeGuard
from bola_checker.state import StateStore, canonical_finding_text, object_ref_fingerprint

_SAFE_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_REDACTED = "[REDACTED]"
_MAX_RECORDS = 10_000
_MAX_RECORDS_FILE_BYTES = 8 * 1024 * 1024
_MAX_RECORD_BODY_BYTES = 1 * 1024 * 1024


class PipelineError(RuntimeError):
    """A bounded, user-facing orchestration error."""


@dataclass(frozen=True)
class IdentityInput:
    """Traffic and credential source for one identity.

    ``records`` is useful for tests and local integrations.  CLI callers use
    ``har_path`` or ``records_path`` and an environment variable reference;
    plaintext credential values are deliberately not accepted by the CLI.
    """

    name: str
    records: Sequence[RequestRecord | Mapping[str, Any]] = ()
    har_path: Path | None = None
    records_path: Path | None = None
    credential_env: str | None = None
    credential: CredentialRef | None = None
    identity_hints: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _SAFE_IDENTITY.fullmatch(self.name) is None:
            raise ValueError("identity name is not a safe identifier")
        sources = int(bool(self.records)) + int(self.har_path is not None) + int(
            self.records_path is not None
        )
        if sources > 1:
            raise ValueError("identity input must choose one traffic source")
        if self.credential_env is not None and not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*\Z", self.credential_env
        ):
            raise ValueError("credential environment variable name is invalid")
        if self.credential is not None and self.credential.identity != self.name:
            raise ValueError("credential identity does not match input identity")


@dataclass(frozen=True)
class PipelineResult:
    """Safe summary plus process-local outcomes for callers that need detail."""

    run_id: int
    outcomes: tuple[ProbeResult, ...]
    report_paths: Mapping[str, Path]
    ownership_persisted: int
    ownership_conflicts: int
    pending_count: int
    scope_target_label: str
    skipped_candidates: int = 0
    skip_reasons: Mapping[str, int] = field(default_factory=dict)

    @property
    def findings_count(self) -> int:
        return sum(1 for result in self.outcomes if result.verdict is Verdict.BOLA)

    def public_summary(self) -> dict[str, Any]:
        counts = {verdict.value: 0 for verdict in Verdict}
        for result in self.outcomes:
            counts[result.verdict.value] += 1
        return {
            "run_id": self.run_id,
            "scope_target_label": self.scope_target_label,
            "ownership_persisted": self.ownership_persisted,
            "ownership_conflicts": self.ownership_conflicts,
            "pending_count": self.pending_count,
            "skipped_candidates": self.skipped_candidates,
            "skip_reasons": dict(self.skip_reasons),
            "outcomes": counts,
            "findings": counts[Verdict.BOLA.value],
            "reports": {name: str(path) for name, path in self.report_paths.items()},
        }


def _record_from_mapping(value: Mapping[str, Any], identity: str) -> RequestRecord:
    """Convert a safe structural record without accepting transport secrets."""

    url = value.get("url")
    method = value.get("method", "GET")
    if not isinstance(url, str) or not isinstance(method, str):
        raise PipelineError("traffic records require string url and method")
    headers = value.get("headers", {})
    response_headers = value.get("response_headers", {})
    if not isinstance(headers, Mapping) or not isinstance(response_headers, Mapping):
        raise PipelineError("traffic record headers must be mappings")
    safe_headers = {str(key): str(item) for key, item in headers.items()}
    # A records JSON file is an evidence input, not a credential transport.
    # Reject obvious auth values rather than persisting or replaying them.
    for key, item in safe_headers.items():
        if (
            key.casefold() in {"authorization", "cookie", "x-api-key", "api-key"}
            and item != _REDACTED
        ):
            raise PipelineError("traffic evidence must not contain plaintext credentials")
    response_body = value.get("response_body")
    if isinstance(response_body, (dict, list)):
        response_body = json.dumps(response_body, separators=(",", ":")).encode()
    elif isinstance(response_body, str):
        response_body = response_body.encode()
    elif response_body is not None and not isinstance(response_body, bytes):
        raise PipelineError("response_body must be JSON-compatible")
    request_body = value.get("body")
    if isinstance(request_body, str):
        request_body = request_body.encode()
    elif request_body is not None and not isinstance(request_body, bytes):
        request_body = json.dumps(request_body, separators=(",", ":")).encode()
    if (
        request_body is not None and len(request_body) > _MAX_RECORD_BODY_BYTES
    ) or (
        response_body is not None and len(response_body) > _MAX_RECORD_BODY_BYTES
    ):
        raise PipelineError("traffic record body exceeds the safety limit")
    return RequestRecord(
        identity=identity,
        method=method,
        url=url,
        headers=safe_headers,
        body=request_body,
        response_status=value.get("response_status", 200),
        response_headers={str(key): str(item) for key, item in response_headers.items()},
        response_body=response_body,
    )


def _normalize_record(record: RequestRecord) -> RequestRecord:
    """Normalize in-memory fixture bodies to the shared byte contract."""

    def body_bytes(value: object) -> bytes | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode()
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":")).encode()
        raise PipelineError("request and response bodies must be bytes or JSON values")

    return RequestRecord(
        identity=record.identity,
        method=record.method,
        url=record.url,
        headers=record.headers,
        body=body_bytes(record.body),
        response_status=record.response_status,
        response_headers=record.response_headers,
        response_body=body_bytes(record.response_body),
    )


def _load_identity_records(identity: IdentityInput) -> list[RequestRecord]:
    try:
        if identity.records:
            values = identity.records
            return [
                _normalize_record(item)
                if isinstance(item, RequestRecord)
                else _record_from_mapping(item, identity.name)
                for item in values
            ]
        if identity.har_path is not None:
            return parse_har_records(identity.har_path, identity.name)
        if identity.records_path is not None:
            path = identity.records_path
            if path.is_symlink() or not path.is_file():
                raise PipelineError("records input must be a regular non-symlink file")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = -1
            try:
                descriptor = os.open(path, flags)
                with os.fdopen(descriptor, "rb") as source:
                    descriptor = -1
                    encoded = source.read(_MAX_RECORDS_FILE_BYTES + 1)
            except OSError as error:
                raise PipelineError("records input could not be read safely") from error
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            if len(encoded) > _MAX_RECORDS_FILE_BYTES:
                raise PipelineError("records input exceeds the safety limit")
            raw = json.loads(encoded.decode("utf-8"))
            if isinstance(raw, Mapping):
                raw = raw.get("records", raw.get("entries"))
            if not isinstance(raw, list) or len(raw) > _MAX_RECORDS:
                raise PipelineError("records file must contain a bounded list")
            if any(not isinstance(item, Mapping) for item in raw):
                raise PipelineError("records file entries must be objects")
            return [_record_from_mapping(item, identity.name) for item in raw]
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        CaptureError,
        TypeError,
        ValueError,
    ) as error:
        raise PipelineError(
            f"traffic for identity {identity.name!r} could not be loaded"
        ) from error
    raise PipelineError(f"identity {identity.name!r} has no traffic source")


def _credential_for_identity(
    identity: IdentityInput,
    records: Sequence[RequestRecord],
    vault: CredentialVault,
) -> CredentialRef:
    if identity.credential is not None:
        if identity.credential.secret_ref.startswith("env:"):
            vault.register_env_ref(identity.credential)
        return identity.credential
    if identity.credential_env is not None:
        return vault.environment_reference(
            identity=identity.name,
            kind=CredentialKind.BEARER,
            name="Authorization",
            variable=identity.credential_env,
        )
    # In-memory integrations may supply raw request headers.  They are never
    # persisted; extraction turns them into vault references immediately.
    extracted = extract_requests(records, vault)
    refs = [item for item in extracted.credential_refs if item.identity == identity.name]
    if not refs:
        raise PipelineError(
            f"no credential found for {identity.name!r}; use an environment reference"
        )
    return refs[0]


def _object_mapping(
    records: Iterable[RequestRecord],
) -> tuple[
    dict[tuple[str, str, str, str, str, str], str],
    dict[tuple[str, str, str, str], str],
]:
    """Keep location/locator provenance and derive path-only executable IDs."""

    mapping: dict[tuple[str, str, str, str, str, str], str] = {}
    path_mapping: dict[tuple[str, str, str, str], str] = {}
    for record in records:
        origin = _origin(record.url)
        for candidate in discover_endpoint_candidates([record]):
            object_ref = object_ref_fingerprint(candidate.object_id)
            mapping_key = (
                origin,
                candidate.endpoint_template,
                candidate.method,
                object_ref,
                candidate.location.value,
                candidate.locator,
            )
            mapping.setdefault(mapping_key, candidate.object_id)
            if (
                candidate.location is CandidateLocation.PATH
                and candidate.endpoint_template.count("{id}") == 1
                and "{id2}" not in candidate.endpoint_template
            ):
                path_mapping.setdefault(
                    (origin, candidate.endpoint_template, candidate.method, object_ref),
                    candidate.object_id,
                )
    return mapping, path_mapping


def _origin(url: str, *, allow_query: bool = True) -> str:
    """Return one canonical scheme/host/effective-port origin."""

    parsed = urlsplit(url)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or (not allow_query and parsed.query)
        or parsed.fragment
    ):
        raise PipelineError("traffic and base URL must be credential-free HTTP(S) origins")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").casefold()
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except (UnicodeError, ValueError) as error:
        raise PipelineError("traffic contains an invalid URL origin") from error
    return f"{parsed.scheme.casefold()}://{hostname}:{port}"


def run_pipeline(
    scope_path: str | Path,
    base_url: str,
    identities: Sequence[IdentityInput | tuple[str, str, str]],
    db_path: str | Path = "bola_state.db",
    report_dir: str | Path = "reports",
    *,
    limits: ExecutorLimits | None = None,
    now: datetime | None = None,
    mode: ProbeMode = ProbeMode.READ,
) -> PipelineResult:
    """Run one fully scoped, deterministic engagement.

    The legacy tuple shape is accepted as ``(name, findings_json, records_json)``;
    the findings file is retained for compatibility but structural records are
    loaded from the third element. New callers should use :class:`IdentityInput`.
    """

    clock = now or datetime.now(UTC)
    try:
        guard = ScopeGuard.from_file(scope_path, now=clock)
    except ScopeError as error:
        raise PipelineError("target is outside the confirmed scope") from error
    if mode is not ProbeMode.READ:
        raise PipelineError(
            "the CLI pipeline is read-only; use the explicit executor API for mutations"
        )

    normalized: list[IdentityInput] = []
    for item in identities:
        if isinstance(item, IdentityInput):
            normalized.append(item)
        elif isinstance(item, tuple) and len(item) == 3:
            normalized.append(IdentityInput(name=item[0], records_path=Path(item[2])))
        else:
            raise PipelineError("identity inputs must use IdentityInput or a three-item tuple")
    if len(normalized) < 2:
        raise PipelineError("at least two identities are required")

    all_records: list[RequestRecord] = []
    loaded_records: list[tuple[IdentityInput, list[RequestRecord]]] = []
    identity_hints: dict[str, str] = {}
    base_origin = _origin(base_url, allow_query=False)
    for identity in normalized:
        records = _load_identity_records(identity)
        if len(records) > _MAX_RECORDS:
            raise PipelineError("traffic record count exceeds the safety limit")
        for record in records:
            try:
                decision = guard.require_allowed(record.url, record.method, now=clock)
            except ScopeError as error:
                raise PipelineError(
                    f"traffic for {identity.name!r} is outside the confirmed scope"
                ) from error
            if _origin(decision.canonical_url) != base_origin:
                raise PipelineError(
                    "all imported traffic must use the exact base URL origin"
                )
        loaded_records.append((identity, records))
        all_records.extend(records)

    database_path = Path(db_path).absolute()
    if database_path.exists() or database_path.is_symlink():
        raise PipelineError(
            "state database already exists; start each scan with a new database path"
        )
    parent = database_path.parent
    current = Path(database_path.anchor)
    for component in parent.parts[1:]:
        current /= component
        if current.is_symlink() or not current.is_dir():
            raise PipelineError("state database parent must be a real directory")
    try:
        store = StateStore(database_path)
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as error:
        raise PipelineError("state database could not be initialized") from error
    vault = CredentialVault()
    credentials: dict[str, CredentialRef] = {}
    path_object_ids: dict[tuple[str, str, str, str], str] = {}
    discovered_candidates = []

    for identity, records in loaded_records:
        credential = _credential_for_identity(identity, records, vault)
        credentials[identity.name] = credential
        store.add_identity(identity.name, credential=credential)
        _mapping, path_mapping = _object_mapping(records)
        path_object_ids.update(path_mapping)
        discovered_candidates.extend(discover_endpoint_candidates(records))
        # Local fixtures and many APIs expose an owner identifier equal to the
        # operator-supplied identity name. Explicit hints still override this
        # conservative convenience mapping.
        identity_hints.setdefault(identity.name, identity.name)
        identity_hints.update(identity.identity_hints)

    # Scope path rules describe concrete requests, not bare origins. Reuse a
    # path observed in the authorized traffic to validate the supplied origin;
    # the executor performs the authoritative check again on every probe.
    if not all_records:
        raise PipelineError("at least one authorized traffic record is required")
    first_path = urlsplit(all_records[0].url).path or "/"
    base = urlsplit(base_url)
    scoped_base = urlunsplit((base.scheme, base.netloc, first_path, "", ""))
    try:
        guard.require_allowed(scoped_base, "GET", now=clock)
    except ScopeError as error:
        raise PipelineError("target is outside the confirmed scope") from error

    # Correlation uses response bodies in the current process only. The state
    # bridge persists opaque object refs and canonical route templates.
    correlations = correlate_ownership(all_records, identity_hints)
    executable_correlations = executable_ownership(correlations)
    path_keys = {
        (origin, template, method, object_ref)
        for origin, template, method, object_ref in path_object_ids
    }
    path_route_keys = {
        (template, method, object_ref)
        for origin, template, method, object_ref in path_keys
        if origin == base_origin
    }
    supported_correlations = [
        evidence
        for evidence in correlations
        if evidence.confidence.value == "heuristic"
        or (
            evidence.endpoint_template,
            evidence.method,
            object_ref_fingerprint(evidence.object_id),
        )
        in path_route_keys
    ]
    persisted = build_test_targets(store, supported_correlations)
    candidate_keys = {
        (
            candidate.endpoint_template,
            candidate.method,
            object_ref_fingerprint(candidate.object_id),
        )
        for candidate in discovered_candidates
    }
    strong_keys = {
        (item.endpoint_template, item.method, object_ref_fingerprint(item.object_id))
        for item in executable_correlations
    }
    skip_reasons: dict[str, int] = {}
    unsupported_strong = strong_keys - path_route_keys
    if unsupported_strong:
        skip_reasons["non_path_or_multiple_placeholders"] = len(unsupported_strong)
    if candidate_keys - strong_keys:
        skip_reasons["no_strong_ownership_evidence"] = len(candidate_keys - strong_keys)
    skipped_candidates = sum(skip_reasons.values())
    pending = tuple(store.untested_combinations())
    endpoints = {int(item["id"]): item for item in store.list_endpoints()}
    identities_by_id = {int(item["id"]): item for item in store.list_identities()}
    run_label = "run_" + hashlib.sha256(b"bolacheck-pipeline").hexdigest()
    run_id = store.start_run(run_label)
    executor = ProbeExecutor(
        guard,
        vault,
        limits=limits,
        state_store=store,
        run_id=run_id,
        now=clock,
    )
    outcomes: list[ProbeResult] = []
    for combination in pending:
        endpoint = endpoints.get(combination.endpoint_id)
        owner = identities_by_id.get(combination.owner_identity_id)
        attacker = identities_by_id.get(combination.attacker_identity_id)
        endpoint_key = (
            base_origin,
            str(endpoint.get("template", "")) if endpoint else "",
            str(endpoint.get("method", "")) if endpoint else "",
            combination.object_ref,
        )
        concrete_id = path_object_ids.get(endpoint_key)
        if endpoint is None or owner is None or attacker is None or concrete_id is None:
            continue  # Reopened state without a current capture fails closed.
        owner_name, attacker_name = str(owner["name"]), str(attacker["name"])
        owner_credential = credentials.get(owner_name)
        attacker_credential = credentials.get(attacker_name)
        if owner_credential is None or attacker_credential is None:
            continue
        method = str(endpoint["method"])
        target = ProbeTarget(
            base_url=base_url,
            endpoint_template=str(endpoint["template"]),
            method=method,
            object_id=concrete_id,
            owner_identity=owner_name,
            attacker_identity=attacker_name,
            owner_credential=owner_credential,
            attacker_credential=attacker_credential,
            mode=ProbeMode.READ,
        )
        if method not in {"GET", "HEAD", "OPTIONS"}:
            result = ProbeResult(
                target=target,
                verdict=Verdict.SKIPPED,
                owner_status=None,
                attacker_status=None,
                evidence={"error_code": "scope_denied", "retryable": False},
            )
            store.record_probe_result(result, run_id=run_id)
        else:
            result = executor.run(target)
        outcomes.append(result)
        if result.verdict is Verdict.BOLA:
            evidence = dict(result.evidence)
            evidence["object_ref"] = object_ref_fingerprint(concrete_id)
            title, description = canonical_finding_text(
                severity="high",
                endpoint_template=target.endpoint_template,
                method=target.method,
                evidence=evidence,
            )
            from bola_checker.models import Finding

            store.add_finding(
                Finding(
                    target.endpoint_template,
                    target.method,
                    "high",
                    title,
                    description,
                    evidence,
                )
            )

    bundle = ReportBundle.from_state(
        store=store,
        outcomes=tuple(outcomes),
        scope_target_label=guard.config.client_name,
        authorization_reference=guard.config.authorization_reference,
        total_combinations=len(pending),
        limitations=tuple(
            [
                "Only recorded probe outcomes are represented; untested combinations "
                "are not implied safe.",
                "Read probes compare authorization behavior and do not establish the "
                "absence of other flaws.",
                "Credentials, request headers, cookies, tokens, and bodies are "
                "excluded from this report.",
            ]
            + [
                f"{count} candidate(s) were skipped before execution ({reason.replace('_', ' ')})."
                for reason, count in sorted(skip_reasons.items())
            ]
        ),
    )
    try:
        report_paths = write_reports(bundle, output_dir=report_dir)
    except (OSError, ValueError, RuntimeError) as error:
        raise PipelineError("report bundle could not be published atomically") from error
    return PipelineResult(
        run_id=run_id,
        outcomes=tuple(outcomes),
        report_paths=report_paths,
        ownership_persisted=len(persisted.persisted),
        ownership_conflicts=len(persisted.conflicts),
        pending_count=len(pending),
        scope_target_label=guard.config.client_name,
        skipped_candidates=skipped_candidates,
        skip_reasons=skip_reasons,
    )


__all__ = ["IdentityInput", "PipelineError", "PipelineResult", "run_pipeline"]
