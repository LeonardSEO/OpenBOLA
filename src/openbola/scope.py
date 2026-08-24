"""Fail-closed authorization scope validation for every network operation.

This module deliberately does not perform network I/O. A caller that wants
CIDR enforcement for a hostname must inject a resolver; every returned address
is checked and returned in the decision that the executor must use.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit, urlunsplit

import yaml
from yaml.nodes import MappingNode, ScalarNode


class ScopeError(ValueError):
    """Raised when a scope is invalid, expired, or does not authorize a request."""


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Sequence[str]]
PathRuleKind = Literal["glob", "regex"]

_DEFAULT_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HTTP_METHOD_RE = re.compile(r"[A-Z]+\Z")
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"(?=.{{1,253}}\Z)(?:{_HOST_LABEL}\.)*{_HOST_LABEL}\Z", re.ASCII)
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_ENCODED_SEPARATOR_RE = re.compile(r"%(?:2[fF]|5[cC])")
_NUMERIC_IPV4_LITERAL_RE = re.compile(
    r"(?:0[xX][0-9a-fA-F]+|0[0-7]*|[0-9]+)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]*|[0-9]+)){0,3}\Z"
)
_IP_NETWORK_TYPES = (ipaddress.IPv4Network, ipaddress.IPv6Network)
_MAX_PATH_RULE_LENGTH = 512
_MAX_URL_LENGTH = 8192
_LOADED_SCOPE_MARKER = object()
_SCOPE_KEYS = frozenset(
    {
        "client_name",
        "authorization_reference",
        "confirmed",
        "starts_at",
        "expires_at",
        "allowed_hosts",
        "allowed_cidrs",
        "allowed_paths",
        "read_methods",
        "mutation_grants",
    }
)
_MUTATION_GRANT_KEYS = frozenset(
    {
        "methods",
        "path_patterns",
        "allowed_fields",
        "record_scope",
        "max_records",
        "max_requests",
        "allow_canary_create_delete",
    }
)
# Mirrors ExecutorLimits.max_requests's existing 1..100_000 bound in executor.py.
# Duplicated deliberately: scope.py does not import executor.py.
_MUTATION_REQUEST_HARD_CAP = 100_000


class _ScopeLoader(yaml.SafeLoader):
    """Safe YAML loader which additionally rejects syntax that hides values."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML aliases and anchors are not permitted in scope files.")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> Any:
        seen_keys: set[tuple[str, str]] = set()
        for key_node, _ in node.value:
            if not isinstance(key_node, ScalarNode):
                raise yaml.YAMLError("Scope mappings may use scalar keys only.")
            if key_node.value == "<<":
                raise yaml.YAMLError("YAML merge keys are not permitted in scope files.")
            key = (key_node.tag, key_node.value)
            if key in seen_keys:
                raise yaml.YAMLError(
                    "Duplicate YAML mapping keys are not permitted in scope files."
                )
            seen_keys.add(key)
        return super().construct_mapping(node, deep=deep)


@dataclass(frozen=True)
class PathRule:
    """An anchored regular expression or segment-safe glob for a URL path."""

    kind: PathRuleKind
    pattern: str
    compiled_regex: re.Pattern[str] = field(repr=False, compare=False)

    def matches(self, path: str) -> bool:
        return self.compiled_regex.fullmatch(path) is not None


class MutationRecordScope(StrEnum):
    EXPLICIT = "explicit"
    ALL_DISCOVERED = "all_discovered"


@dataclass(frozen=True)
class MutationGrant:
    """An explicit authorization for mutation methods on the listed paths."""

    methods: frozenset[str]
    path_rules: tuple[PathRule, ...]
    allowed_fields: frozenset[str]
    record_scope: MutationRecordScope
    max_records: int
    max_requests: int
    allow_canary_create_delete: bool

    def permits(self, method: str, path: str) -> bool:
        return method in self.methods and any(rule.matches(path) for rule in self.path_rules)


@dataclass(frozen=True)
class _ScopeFileMetadata:
    """Identity and freshness data for the reviewed scope file."""

    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class ScopeConfig:
    """A validated, immutable authorization document."""

    client_name: str
    authorization_reference: str
    confirmed: bool
    starts_at: datetime
    expires_at: datetime
    allowed_hosts: tuple[str, ...]
    allowed_cidrs: tuple[IPNetwork, ...]
    allowed_paths: tuple[PathRule, ...]
    read_methods: frozenset[str]
    mutation_grants: tuple[MutationGrant, ...]
    _source_marker: object | None = field(default=None, init=False, repr=False, compare=False)
    _source_path: Path | None = field(default=None, init=False, repr=False, compare=False)
    _source_metadata: _ScopeFileMetadata | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _source_digest: bytes | None = field(default=None, init=False, repr=False, compare=False)


@dataclass(frozen=True)
class ScopeDecision:
    """The exact canonical request and peer set authorized by a scope check.

    The executor must send :attr:`canonical_url` exactly as returned, connect
    only to :attr:`connect_ips` when it is non-empty, and validate the actual
    peer address after connecting. A redirect target requires a new decision.
    """

    canonical_url: str = field(repr=False)
    hostname: str
    method: str
    resolved_ips: frozenset[IPAddress]

    @property
    def connect_ips(self) -> frozenset[IPAddress]:
        """The CIDR-approved peer addresses that may be used for this request."""
        return self.resolved_ips


class ScopeGuard:
    """Check a request URL and method against a validated scope.

    Redirects are intentionally not followed here. The executor must call
    :meth:`require_allowed` separately for every redirect target.
    """

    def __init__(
        self,
        config: ScopeConfig,
        *,
        resolver: Resolver | None = None,
        now: datetime | None = None,
    ) -> None:
        normalized = _validate_scope_config(config, now=now)
        _require_loaded_scope(config)
        _inherit_loaded_scope_provenance(config, normalized)
        self.config = normalized
        self._resolver = resolver

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        resolver: Resolver | None = None,
        now: datetime | None = None,
    ) -> ScopeGuard:
        """Load a confirmed, currently-active scope file into a guard."""
        return cls(load_scope(path, now=now), resolver=resolver, now=now)

    def is_allowed(self, url: str, method: str, *, now: datetime | None = None) -> bool:
        """Return whether a request is allowed without exposing policy errors."""
        try:
            self.require_allowed(url, method, now=now)
        except ScopeError:
            return False
        return True

    @property
    def scope_digest(self) -> str:
        """Return the digest of the currently reviewed scope file.

        The digest is metadata for in-process plans and journals.  Reading it
        revalidates the loaded scope provenance first, so a plan cannot bind
        itself to a scope file that changed after confirmation.
        """
        _require_loaded_scope(self.config)
        digest = self.config._source_digest
        if not isinstance(digest, bytes):  # pragma: no cover - provenance guard
            raise ScopeError("ScopeConfig source provenance is incomplete.")
        return digest.hex()

    def require_allowed(
        self,
        url: str,
        method: str,
        *,
        now: datetime | None = None,
    ) -> ScopeDecision:
        """Return a decision, or raise :class:`ScopeError` if the request is unauthorized."""
        _require_loaded_scope(self.config)
        _require_active(self.config, now)
        canonical_url, host, path = _parse_request_url(url)
        normalized_method = _validate_request_method(method)

        direct_ip = _as_ip_address(host)
        if direct_ip is None:
            self._require_hostname_allowed(host)
            resolved_ips = self._require_resolved_ips_allowed(host)
        else:
            self._require_ip_allowed(direct_ip)
            resolved_ips = frozenset({direct_ip})

        if not any(rule.matches(path) for rule in self.config.allowed_paths):
            raise ScopeError("Request path is not authorized by allowed_paths.")
        if normalized_method not in self.config.read_methods and not any(
            grant.permits(normalized_method, path) for grant in self.config.mutation_grants
        ):
            raise ScopeError(
                "Request method is not authorized by read_methods or a mutation grant."
            )

        return ScopeDecision(
            canonical_url=canonical_url,
            hostname=host,
            method=normalized_method,
            resolved_ips=resolved_ips,
        )

    def _require_hostname_allowed(self, hostname: str) -> None:
        if not self.config.allowed_hosts:
            return
        if any(_hostname_matches(hostname, pattern) for pattern in self.config.allowed_hosts):
            return
        raise ScopeError("Request hostname is not authorized by allowed_hosts.")

    def _require_resolved_ips_allowed(self, hostname: str) -> frozenset[IPAddress]:
        if not self.config.allowed_cidrs:
            return frozenset()
        if self._resolver is None:
            raise ScopeError(
                "A resolver is required when allowed_cidrs is configured for a hostname."
            )
        try:
            address_values = self._resolver(hostname)
        except Exception as error:
            raise ScopeError(
                "Injected resolver failed while validating the request hostname."
            ) from error
        if not address_values:
            raise ScopeError("Injected resolver returned no addresses for the request hostname.")

        addresses: set[IPAddress] = set()
        for value in address_values:
            if not isinstance(value, str):
                raise ScopeError("Injected resolver returned a non-string IP address.")
            address = _as_ip_address(value)
            if address is None:
                raise ScopeError("Injected resolver returned an invalid IP address.")
            self._require_ip_allowed(address)
            addresses.add(address)
        return frozenset(addresses)

    def _require_ip_allowed(self, address: IPAddress) -> None:
        if not self.config.allowed_cidrs:
            raise ScopeError("IP targets require an allowed_cidrs policy.")
        if not any(address in network for network in self.config.allowed_cidrs):
            raise ScopeError("Request IP address is not authorized by allowed_cidrs.")


def load_scope(path: str | Path, *, now: datetime | None = None) -> ScopeConfig:
    """Load and validate a YAML authorization scope, failing closed on any ambiguity."""
    scope_path = Path(path)
    try:
        source_path, source_bytes, source_metadata = _read_scope_source(scope_path)
        raw_document = yaml.load(
            source_bytes.decode("utf-8"),
            Loader=_ScopeLoader,  # noqa: S506 - _ScopeLoader subclasses yaml.SafeLoader.
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ScopeError("Scope file could not be read as unambiguous YAML.") from error
    if not isinstance(raw_document, Mapping):
        raise ScopeError("Scope file must contain a YAML mapping.")

    unknown_keys = set(raw_document).difference(_SCOPE_KEYS)
    if unknown_keys:
        fields = ", ".join(sorted(unknown_keys))
        raise ScopeError(f"Scope file contains unknown field(s): {fields}.")

    config = ScopeConfig(
        client_name=_required_text(raw_document, "client_name"),
        authorization_reference=_required_text(raw_document, "authorization_reference"),
        confirmed=_confirmed(raw_document),
        starts_at=_utc_timestamp(raw_document, "starts_at"),
        expires_at=_utc_timestamp(raw_document, "expires_at"),
        allowed_hosts=_allowed_hosts(raw_document),
        allowed_cidrs=_allowed_cidrs(raw_document),
        allowed_paths=_path_rules(raw_document, "allowed_paths"),
        read_methods=_read_methods(raw_document),
        mutation_grants=_mutation_grants(raw_document),
    )
    config = _validate_scope_config(config, now=now)
    _mark_loaded_scope(config, source_path, source_metadata, hashlib.sha256(source_bytes).digest())
    return config


def require_in_scope(
    url: str,
    config: ScopeConfig,
    *,
    method: str = "GET",
    resolver: Resolver | None = None,
    now: datetime | None = None,
) -> ScopeDecision:
    """Enforce all phase-0 checks and return the decision for one request."""
    return ScopeGuard(config, resolver=resolver, now=now).require_allowed(url, method, now=now)


def _validate_scope_config(config: ScopeConfig, *, now: datetime | None) -> ScopeConfig:
    """Rebuild a config after validating public dataclass inputs fail closed."""
    if type(config) is not ScopeConfig:
        raise ScopeError("ScopeGuard requires a ScopeConfig instance.")
    if type(config.confirmed) is not bool or config.confirmed is not True:
        raise ScopeError("confirmed must be the exact YAML boolean true.")

    normalized = ScopeConfig(
        client_name=_config_text(config.client_name, "client_name"),
        authorization_reference=_config_text(
            config.authorization_reference,
            "authorization_reference",
        ),
        confirmed=True,
        starts_at=_utc_datetime(config.starts_at, "starts_at"),
        expires_at=_utc_datetime(config.expires_at, "expires_at"),
        allowed_hosts=_normalise_allowed_hosts(config.allowed_hosts),
        allowed_cidrs=_normalise_allowed_cidrs(config.allowed_cidrs),
        allowed_paths=_normalise_path_rules(config.allowed_paths, "allowed_paths"),
        read_methods=_normalise_read_methods(config.read_methods),
        mutation_grants=_normalise_mutation_grants(config.mutation_grants),
    )
    if normalized.starts_at >= normalized.expires_at:
        raise ScopeError("starts_at must be earlier than expires_at.")
    if not normalized.allowed_hosts and not normalized.allowed_cidrs:
        raise ScopeError("At least one allowed_hosts or allowed_cidrs entry is required.")
    _require_active(normalized, now)
    return normalized


def _read_scope_source(scope_path: Path) -> tuple[Path, bytes, _ScopeFileMetadata]:
    """Read a scope file only if it is a stable, non-symlink regular file."""
    source_path = scope_path.absolute()
    before = _scope_file_metadata(source_path)
    try:
        source_bytes = source_path.read_bytes()
    except OSError as error:
        raise ScopeError("Scope file could not be read.") from error
    after = _scope_file_metadata(source_path)
    if before != after:
        raise ScopeError("Scope file changed while it was being read.")
    return source_path, source_bytes, after


def _scope_file_metadata(path: Path) -> _ScopeFileMetadata:
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise ScopeError("Scope file does not exist or could not be inspected.") from error
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ScopeError("Scope file must be a non-symlink regular file.")
    return _ScopeFileMetadata(
        device=file_stat.st_dev,
        inode=file_stat.st_ino,
        size=file_stat.st_size,
        modified_ns=file_stat.st_mtime_ns,
    )


def _mark_loaded_scope(
    config: ScopeConfig,
    source_path: Path,
    source_metadata: _ScopeFileMetadata,
    source_digest: bytes,
) -> None:
    """Set provenance only after YAML and policy validation have succeeded."""
    object.__setattr__(config, "_source_marker", _LOADED_SCOPE_MARKER)
    object.__setattr__(config, "_source_path", source_path)
    object.__setattr__(config, "_source_metadata", source_metadata)
    object.__setattr__(config, "_source_digest", source_digest)


def _require_loaded_scope(config: ScopeConfig) -> None:
    if config._source_marker is not _LOADED_SCOPE_MARKER:
        raise ScopeError("ScopeConfig must originate from load_scope on a confirmed scope file.")
    if (
        not isinstance(config._source_path, Path)
        or not isinstance(config._source_metadata, _ScopeFileMetadata)
        or not isinstance(config._source_digest, bytes)
    ):
        raise ScopeError("ScopeConfig source provenance is incomplete.")
    source_path, source_bytes, source_metadata = _read_scope_source(config._source_path)
    if source_path != config._source_path or source_metadata != config._source_metadata:
        raise ScopeError("ScopeConfig source file metadata no longer matches the reviewed scope.")
    if hashlib.sha256(source_bytes).digest() != config._source_digest:
        raise ScopeError("ScopeConfig source file digest no longer matches the reviewed scope.")


def _inherit_loaded_scope_provenance(source: ScopeConfig, target: ScopeConfig) -> None:
    """Preserve verified provenance when the guard normalizes a loaded config."""
    object.__setattr__(target, "_source_marker", source._source_marker)
    object.__setattr__(target, "_source_path", source._source_path)
    object.__setattr__(target, "_source_metadata", source._source_metadata)
    object.__setattr__(target, "_source_digest", source._source_digest)


def _required_text(document: Mapping[object, object], field: str) -> str:
    return _config_text(document.get(field), field)


def _config_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopeError(f"{field} must be a non-empty string.")
    return value.strip()


def _confirmed(document: Mapping[object, object]) -> bool:
    value = document.get("confirmed")
    if type(value) is not bool or value is not True:
        raise ScopeError("confirmed must be the exact YAML boolean true.")
    return True


def _utc_timestamp(document: Mapping[object, object], field: str) -> datetime:
    value = document.get(field)
    if not isinstance(value, str):
        raise ScopeError(f"{field} must be an ISO-8601 UTC timestamp string.")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ScopeError(f"{field} must be an ISO-8601 UTC timestamp string.") from error
    return _utc_datetime(timestamp, field)


def _utc_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise ScopeError(f"{field} must be a UTC-aware datetime.")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ScopeError(f"{field} must use UTC (Z or +00:00).")
    return value.astimezone(UTC)


def _allowed_hosts(document: Mapping[object, object]) -> tuple[str, ...]:
    return _normalise_allowed_hosts(tuple(_string_list(document, "allowed_hosts", required=False)))


def _normalise_allowed_hosts(values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not all(isinstance(value, str) for value in values):
        raise ScopeError("allowed_hosts must be a tuple of hostname strings.")
    normalized: list[str] = []
    for value in values:
        if not value or value != value.strip():
            raise ScopeError("allowed_hosts must contain non-empty strings without whitespace.")
        host = value.lower()
        wildcard = host.startswith("*.")
        suffix = host[2:] if wildcard else host
        if "*" in suffix:
            raise ScopeError(
                "allowed_hosts entries must be exact hostnames or leftmost *. wildcards."
            )
        try:
            normalized_suffix = _normalise_request_host(suffix)
        except ScopeError as error:
            raise ScopeError("allowed_hosts contains an invalid hostname pattern.") from error
        if _as_ip_address(normalized_suffix) is not None:
            raise ScopeError(
                "allowed_hosts entries must be exact hostnames or leftmost *. wildcards."
            )
        normalized.append(f"*.{normalized_suffix}" if wildcard else normalized_suffix)
    if len(set(normalized)) != len(normalized):
        raise ScopeError("allowed_hosts must not contain duplicate entries.")
    return tuple(normalized)


def _allowed_cidrs(document: Mapping[object, object]) -> tuple[IPNetwork, ...]:
    values = _string_list(document, "allowed_cidrs", required=False)
    networks: list[IPNetwork] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except ValueError as error:
            raise ScopeError("allowed_cidrs must contain valid canonical CIDR networks.") from error
    return _normalise_allowed_cidrs(tuple(networks))


def _normalise_allowed_cidrs(values: object) -> tuple[IPNetwork, ...]:
    if not isinstance(values, tuple) or not all(
        isinstance(value, _IP_NETWORK_TYPES) for value in values
    ):
        raise ScopeError("allowed_cidrs must be a tuple of IP network objects.")
    networks = tuple(values)
    if len(set(networks)) != len(networks):
        raise ScopeError("allowed_cidrs must not contain duplicate entries.")
    return networks


def _path_rules(document: Mapping[object, object], field: str) -> tuple[PathRule, ...]:
    return tuple(_path_rule(value, field) for value in _string_list(document, field, required=True))


def _normalise_path_rules(values: object, field: str) -> tuple[PathRule, ...]:
    if not isinstance(values, tuple) or not values:
        raise ScopeError(f"{field} must be a non-empty tuple of PathRule objects.")
    rules: list[PathRule] = []
    for value in values:
        if not isinstance(value, PathRule):
            raise ScopeError(f"{field} must contain PathRule objects.")
        rules.append(_path_rule(f"{value.kind}:{value.pattern}", field))
    if len(set((rule.kind, rule.pattern) for rule in rules)) != len(rules):
        raise ScopeError(f"{field} must not contain duplicate path rules.")
    return tuple(rules)


def _path_rule(value: str, field: str) -> PathRule:
    if len(value) > _MAX_PATH_RULE_LENGTH or _contains_control_characters(value):
        raise ScopeError(f"{field} contains an unsafe path rule.")
    if value.startswith("glob:"):
        pattern = value.removeprefix("glob:")
        _validate_glob_pattern(pattern)
        return PathRule(kind="glob", pattern=pattern, compiled_regex=_compile_segment_glob(pattern))
    if value.startswith("regex:"):
        pattern = value.removeprefix("regex:")
        if (
            not pattern.startswith("^/")
            or not pattern.endswith("$")
            or "(" in pattern
            or "\\" in pattern
            or "//" in pattern
            or any(character in pattern for character in "?#")
        ):
            raise ScopeError(
                "Regex path rules must be anchored, path-only, and use the safe regex subset."
            )
        try:
            return PathRule(kind="regex", pattern=pattern, compiled_regex=re.compile(pattern))
        except re.error as error:
            raise ScopeError("Regex path rule is invalid.") from error
    raise ScopeError(f"{field} entries must start with glob: or regex:.")


def _validate_glob_pattern(pattern: str) -> None:
    if (
        not pattern.startswith("/")
        or "\\" in pattern
        or "//" in pattern
        or any(character in pattern for character in "?#")
    ):
        raise ScopeError("Glob path rules must start with / and match unambiguous paths only.")


def _compile_segment_glob(pattern: str) -> re.Pattern[str]:
    """Compile `*` within one segment and `**` as the explicit recursive wildcard."""
    parts = ["^"]
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                parts.append(".*")
                index += 2
            else:
                parts.append("[^/]*")
                index += 1
        elif character == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(character))
            index += 1
    parts.append("$")
    return re.compile("".join(parts))


def _read_methods(document: Mapping[object, object]) -> frozenset[str]:
    if "read_methods" not in document:
        return _DEFAULT_READ_METHODS
    methods = frozenset(_methods(document.get("read_methods"), "read_methods"))
    return _normalise_read_methods(methods)


def _normalise_read_methods(value: object) -> frozenset[str]:
    if not isinstance(value, frozenset) or not all(isinstance(method, str) for method in value):
        raise ScopeError("read_methods must be a frozenset of exact uppercase HTTP methods.")
    if not value or not value.issubset(_DEFAULT_READ_METHODS):
        raise ScopeError("read_methods may contain only GET, HEAD, and OPTIONS.")
    if not all(_HTTP_METHOD_RE.fullmatch(method) for method in value):
        raise ScopeError("read_methods must contain exact uppercase HTTP methods.")
    return value


def _mutation_grants(document: Mapping[object, object]) -> tuple[MutationGrant, ...]:
    if "mutation_grants" not in document:
        return ()
    raw_grants = document.get("mutation_grants")
    if not isinstance(raw_grants, list):
        raise ScopeError("mutation_grants must be a list.")
    grants: list[MutationGrant] = []
    for raw_grant in raw_grants:
        if not isinstance(raw_grant, Mapping) or set(raw_grant) != _MUTATION_GRANT_KEYS:
            raise ScopeError(
                "Each mutation grant must contain exactly methods, path_patterns, "
                "allowed_fields, record_scope, max_records, max_requests, and "
                "allow_canary_create_delete."
            )
        methods = frozenset(_methods(raw_grant.get("methods"), "mutation grant methods"))
        grants.append(
            MutationGrant(
                methods=methods,
                path_rules=_path_rules(raw_grant, "path_patterns"),
                allowed_fields=_allowed_fields(raw_grant),
                record_scope=_mutation_grant_record_scope(raw_grant),
                max_records=_mutation_grant_positive_int(
                    raw_grant, "max_records", max_value=_MUTATION_REQUEST_HARD_CAP
                ),
                max_requests=_mutation_grant_positive_int(
                    raw_grant, "max_requests", max_value=_MUTATION_REQUEST_HARD_CAP
                ),
                allow_canary_create_delete=_mutation_grant_bool(
                    raw_grant, "allow_canary_create_delete"
                ),
            )
        )
    return _normalise_mutation_grants(tuple(grants))


def _normalise_mutation_grants(value: object) -> tuple[MutationGrant, ...]:
    if not isinstance(value, tuple) or not all(isinstance(grant, MutationGrant) for grant in value):
        raise ScopeError("mutation_grants must be a tuple of MutationGrant objects.")
    grants: list[MutationGrant] = []
    for grant in value:
        if not isinstance(grant.methods, frozenset) or not grant.methods:
            raise ScopeError("Mutation grants require a non-empty frozenset of methods.")
        if not all(
            isinstance(method, str) and _HTTP_METHOD_RE.fullmatch(method)
            for method in grant.methods
        ):
            raise ScopeError("Mutation grants must contain exact uppercase HTTP methods.")
        if not grant.methods.issubset(_MUTATION_METHODS):
            raise ScopeError("Mutation grants may contain only POST, PUT, PATCH, and DELETE.")
        if (
            not isinstance(grant.allowed_fields, frozenset)
            or not grant.allowed_fields
            or not all(
                isinstance(name, str) and name and name == name.strip()
                for name in grant.allowed_fields
            )
        ):
            raise ScopeError(
                "allowed_fields must be a non-empty frozenset of non-empty field names."
            )
        if not isinstance(grant.record_scope, MutationRecordScope):
            raise ScopeError("record_scope must be a MutationRecordScope value.")
        if (
            isinstance(grant.max_records, bool)
            or not isinstance(grant.max_records, int)
            or not 1 <= grant.max_records <= _MUTATION_REQUEST_HARD_CAP
        ):
            raise ScopeError(
                f"max_records must be an integer between 1 and {_MUTATION_REQUEST_HARD_CAP}."
            )
        if (
            isinstance(grant.max_requests, bool)
            or not isinstance(grant.max_requests, int)
            or not 1 <= grant.max_requests <= _MUTATION_REQUEST_HARD_CAP
        ):
            raise ScopeError(
                f"max_requests must be an integer between 1 and {_MUTATION_REQUEST_HARD_CAP}."
            )
        if grant.max_records > grant.max_requests:
            raise ScopeError("max_records must not exceed max_requests.")
        if type(grant.allow_canary_create_delete) is not bool:
            raise ScopeError(
                "allow_canary_create_delete must be the exact YAML boolean true or false."
            )
        grants.append(
            MutationGrant(
                methods=grant.methods,
                path_rules=_normalise_path_rules(grant.path_rules, "mutation grant path_patterns"),
                allowed_fields=frozenset(grant.allowed_fields),
                record_scope=grant.record_scope,
                max_records=grant.max_records,
                max_requests=grant.max_requests,
                allow_canary_create_delete=grant.allow_canary_create_delete,
            )
        )
    return tuple(grants)


def _allowed_fields(raw_grant: Mapping[object, object]) -> frozenset[str]:
    values = _string_list(raw_grant, "allowed_fields", required=True)
    if len(set(values)) != len(values):
        raise ScopeError("allowed_fields must not contain duplicate field names.")
    return frozenset(values)


def _mutation_grant_record_scope(raw_grant: Mapping[object, object]) -> MutationRecordScope:
    value = raw_grant.get("record_scope")
    if not isinstance(value, str):
        raise ScopeError("record_scope must be a string.")
    try:
        return MutationRecordScope(value)
    except ValueError as error:
        allowed = ", ".join(member.value for member in MutationRecordScope)
        raise ScopeError(f"record_scope must be one of: {allowed}.") from error


def _mutation_grant_positive_int(
    raw_grant: Mapping[object, object],
    field_name: str,
    *,
    max_value: int,
) -> int:
    value = raw_grant.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= max_value:
        raise ScopeError(f"{field_name} must be an integer between 1 and {max_value}.")
    return value


def _mutation_grant_bool(raw_grant: Mapping[object, object], field_name: str) -> bool:
    value = raw_grant.get(field_name)
    if type(value) is not bool:
        raise ScopeError(f"{field_name} must be the exact YAML boolean true or false.")
    return value


def _methods(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ScopeError(f"{field} must be a non-empty list of exact uppercase HTTP methods.")
    methods: list[str] = []
    for method in value:
        if not isinstance(method, str) or not _HTTP_METHOD_RE.fullmatch(method):
            raise ScopeError(f"{field} must contain exact uppercase HTTP methods.")
        methods.append(method)
    if len(set(methods)) != len(methods):
        raise ScopeError(f"{field} must not contain duplicate methods.")
    return methods


def _string_list(document: Mapping[object, object], field: str, *, required: bool) -> list[str]:
    if field not in document:
        if required:
            raise ScopeError(f"{field} is required.")
        return []
    values = document.get(field)
    if not isinstance(values, list):
        raise ScopeError(f"{field} must be a list.")
    strings: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ScopeError(
                f"{field} must contain non-empty strings without surrounding whitespace."
            )
        strings.append(value)
    if required and not strings:
        raise ScopeError(f"{field} must contain at least one entry.")
    return strings


def _require_active(config: ScopeConfig, now: datetime | None) -> None:
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None or current_time.utcoffset() != timedelta(0):
        raise ScopeError("Scope checks require a UTC-aware current time.")
    current_time = current_time.astimezone(UTC)
    if current_time < config.starts_at:
        raise ScopeError("Scope has not started yet.")
    if current_time >= config.expires_at:
        raise ScopeError("Scope has expired.")


def _parse_request_url(url: str) -> tuple[str, str, str]:
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise ScopeError("Request URL must be a non-empty, bounded string.")
    if _contains_control_characters(url):
        raise ScopeError("Request URL must not contain control characters.")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ScopeError("Request URL is malformed.") from error
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
        raise ScopeError("Request URL must be an absolute http or https URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ScopeError("Request URL must not contain userinfo.")
    if parsed.fragment:
        raise ScopeError("Request URL must not contain a fragment.")
    if port is not None and not 0 < port < 65536:
        raise ScopeError("Request URL contains an invalid port.")

    host = _normalise_request_host(parsed.hostname)
    path = _validate_request_path(parsed.path or "/")
    query = _canonicalize_query(parsed.query)
    rendered_host = f"[{host}]" if _as_ip_address(host) and ":" in host else host
    rendered_port = ""
    if port is not None and (parsed.scheme, port) not in {("http", 80), ("https", 443)}:
        rendered_port = f":{port}"
    canonical_url = urlunsplit((parsed.scheme, f"{rendered_host}{rendered_port}", path, query, ""))
    return canonical_url, host, path


def _validate_request_path(path: str) -> str:
    if not path.startswith("/"):
        raise ScopeError("Request path must be absolute.")
    if "\\" in path or "//" in path or _contains_control_characters(path):
        raise ScopeError("Request path contains an ambiguous separator or control character.")
    decoded = _decode_percent_encoded(path, "Request path")
    if "\\" in decoded:
        raise ScopeError("Request path contains an encoded slash or backslash.")
    if _contains_control_characters(decoded):
        raise ScopeError("Request path contains a percent-decoded control character.")
    if any(segment in {".", ".."} for segment in path.split("/")) or any(
        segment in {".", ".."} for segment in decoded.split("/")
    ):
        raise ScopeError("Request path contains a raw or percent-decoded dot segment.")
    return _canonicalize_percent_escapes(path)


def _canonicalize_query(query: str) -> str:
    if _contains_control_characters(query):
        raise ScopeError("Request URL query must not contain control characters.")
    decoded = _decode_percent_encoded(query, "Request URL query")
    if _contains_control_characters(decoded):
        raise ScopeError("Request URL query contains a percent-decoded control character.")
    return _canonicalize_percent_escapes(query)


def _decode_percent_encoded(value: str, label: str) -> str:
    current = value
    while "%" in current:
        index = 0
        while index < len(current):
            if current[index] == "%" and not _PERCENT_ESCAPE_RE.match(current, index):
                raise ScopeError(f"{label} contains an invalid percent escape.")
            index += 1
        if _ENCODED_SEPARATOR_RE.search(current):
            raise ScopeError(f"{label} contains an encoded slash or backslash.")
        try:
            decoded = unquote(current, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ScopeError(f"{label} contains invalid UTF-8 percent encoding.") from error
        if decoded == current:
            break
        current = decoded
    return current


def _canonicalize_percent_escapes(value: str) -> str:
    return _PERCENT_ESCAPE_RE.sub(lambda match: match.group(0).upper(), value)


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _normalise_request_host(hostname: str) -> str:
    """Validate a request host before applying hostname or wildcard policy."""
    if (
        not hostname
        or _contains_control_characters(hostname)
        or "\\" in hostname
        or "%" in hostname
    ):
        raise ScopeError("Request hostname contains invalid characters.")
    normalized = hostname.lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized or normalized.endswith("."):
        raise ScopeError("Request hostname has an invalid trailing root dot.")

    address = _as_ip_address(normalized)
    if address is not None:
        return str(address)
    if _NUMERIC_IPV4_LITERAL_RE.fullmatch(normalized):
        raise ScopeError("Request hostname uses a non-canonical IPv4 literal.")
    if normalized.startswith(".") or ".." in normalized or not _HOSTNAME_RE.fullmatch(normalized):
        raise ScopeError("Request hostname has invalid labels.")
    return normalized


def _validate_request_method(method: str) -> str:
    if not isinstance(method, str) or not _HTTP_METHOD_RE.fullmatch(method):
        raise ScopeError("Request method must be an exact uppercase HTTP method.")
    return method


def _hostname_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname != pattern[2:]
    return hostname == pattern


def _as_ip_address(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None
