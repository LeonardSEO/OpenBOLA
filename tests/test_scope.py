from __future__ import annotations

import ipaddress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from openbola.scope import (
    ScopeConfig,
    ScopeDecision,
    ScopeError,
    ScopeGuard,
    load_scope,
    require_in_scope,
)

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def _scope_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "client_name": "Example B.V.",
        "authorization_reference": "PT-2026-014",
        "confirmed": True,
        "starts_at": "2026-08-23T10:00:00Z",
        "expires_at": "2026-08-23T14:00:00Z",
        "allowed_hosts": ["api.example.test", "*.staging.example.test"],
        "allowed_cidrs": [],
        "allowed_paths": ["glob:/v1/*"],
    }
    document.update(overrides)
    return document


def _write_scope(path: Path, **overrides: Any) -> Path:
    path.write_text(yaml.safe_dump(_scope_document(**overrides)), encoding="utf-8")
    return path


def test_missing_scope_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="does not exist"):
        load_scope(tmp_path / "missing.yaml", now=NOW)


@pytest.mark.parametrize("confirmed", [False, "true"])
def test_confirmed_must_be_exact_yaml_boolean_true(tmp_path: Path, confirmed: object) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", confirmed=confirmed)

    with pytest.raises(ScopeError, match="exact YAML boolean true"):
        load_scope(scope_file, now=NOW)


def test_empty_authorization_reference_is_rejected(tmp_path: Path) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", authorization_reference="   ")

    with pytest.raises(ScopeError, match="authorization_reference"):
        load_scope(scope_file, now=NOW)


def test_expired_scope_is_rejected(tmp_path: Path) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", expires_at="2026-08-23T11:59:59Z")

    with pytest.raises(ScopeError, match="expired"):
        load_scope(scope_file, now=NOW)


def test_wildcard_host_requires_a_subdomain(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        allowed_hosts=["*.example.test"],
    )
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    guard.require_allowed("https://one.example.test/v1/items", "GET", now=NOW)
    with pytest.raises(ScopeError, match="hostname"):
        guard.require_allowed("https://example.test/v1/items", "GET", now=NOW)


@pytest.mark.parametrize("host", [".example.test", "a..example.test", "api.example.test.."])
def test_request_hostname_is_validated_before_wildcard_matching(tmp_path: Path, host: str) -> None:
    guard = ScopeGuard.from_file(_write_scope(tmp_path / "scope.yaml"), now=NOW)

    with pytest.raises(ScopeError, match="hostname"):
        guard.require_allowed(f"https://{host}/v1/items", "GET", now=NOW)


def test_request_hostname_allows_exactly_one_root_dot(tmp_path: Path) -> None:
    guard = ScopeGuard.from_file(_write_scope(tmp_path / "scope.yaml"), now=NOW)

    decision = guard.require_allowed("https://api.example.test./v1/items", "GET", now=NOW)

    assert decision.hostname == "api.example.test"
    assert decision.canonical_url == "https://api.example.test/v1/items"


@pytest.mark.parametrize(
    "host",
    ["127.000.000.001", "0177.0.0.1", "0x7f000001", "2130706433", "127.1"],
)
def test_noncanonical_ipv4_literals_are_rejected_before_transport(
    tmp_path: Path,
    host: str,
) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        allowed_hosts=[],
        allowed_cidrs=["127.0.0.0/8"],
    )
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    with pytest.raises(ScopeError, match="non-canonical IPv4"):
        guard.require_allowed(f"https://{host}/v1/items", "GET", now=NOW)


@pytest.mark.parametrize("host", ["api.example.test..", "api..example.test"])
def test_policy_hosts_reject_multiple_or_empty_labels(tmp_path: Path, host: str) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", allowed_hosts=[host])

    with pytest.raises(ScopeError, match="allowed_hosts"):
        load_scope(scope_file, now=NOW)


def test_policy_host_allows_exactly_one_trailing_root_dot(tmp_path: Path) -> None:
    config = load_scope(
        _write_scope(tmp_path / "scope.yaml", allowed_hosts=["api.example.test."]),
        now=NOW,
    )

    assert config.allowed_hosts == ("api.example.test",)


def test_cidr_policy_checks_direct_and_all_resolved_addresses(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        allowed_hosts=["api.example.test"],
        allowed_cidrs=["192.0.2.0/24"],
    )
    guard = ScopeGuard.from_file(scope_file, resolver=lambda _: ["192.0.2.10"], now=NOW)

    decision = guard.require_allowed("https://api.example.test/v1/items", "GET", now=NOW)
    assert decision == ScopeDecision(
        canonical_url="https://api.example.test/v1/items",
        hostname="api.example.test",
        method="GET",
        resolved_ips=frozenset({ipaddress.ip_address("192.0.2.10")}),
    )
    assert decision.connect_ips == decision.resolved_ips
    guard.require_allowed("https://192.0.2.44/v1/items", "GET", now=NOW)
    with pytest.raises(ScopeError, match="IP address"):
        guard.require_allowed("https://198.51.100.4/v1/items", "GET", now=NOW)

    mixed_answer_guard = ScopeGuard.from_file(
        scope_file,
        resolver=lambda _: ["192.0.2.10", "198.51.100.4"],
        now=NOW,
    )
    with pytest.raises(ScopeError, match="IP address"):
        mixed_answer_guard.require_allowed("https://api.example.test/v1/items", "GET", now=NOW)


def test_path_rules_are_evaluated_against_the_path_only(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        allowed_paths=["glob:/v1/projects/*", "regex:^/health/[0-9]+$"],
    )
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    guard.require_allowed(
        "https://api.example.test/v1/projects/42?token=not-reported",
        "GET",
        now=NOW,
    )
    guard.require_allowed("https://api.example.test/health/42", "HEAD", now=NOW)
    with pytest.raises(ScopeError, match="path"):
        guard.require_allowed("https://api.example.test/v1/users/42", "GET", now=NOW)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/projects/../admin",
        "/v1/projects/%2e%2e/admin",
        "/v1/projects/%252e%252e/admin",
        "/v1/projects/item%2fadmin",
        "/v1/projects/item%5cadmin",
        "/v1//projects",
        "/v1/projects\\admin",
        "/v1/projects/%0aadmin",
    ],
)
def test_ambiguous_or_encoded_path_bypasses_are_rejected(tmp_path: Path, path: str) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", allowed_paths=["glob:/v1/**"])
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    with pytest.raises(ScopeError, match="path|slash|control"):
        guard.require_allowed(f"https://api.example.test{path}", "GET", now=NOW)


def test_segment_glob_does_not_cross_slashes_but_recursive_glob_does(tmp_path: Path) -> None:
    one_segment_scope = _write_scope(
        tmp_path / "one-segment.yaml",
        allowed_paths=["glob:/v1/*"],
    )
    one_segment_guard = ScopeGuard.from_file(one_segment_scope, now=NOW)
    one_segment_guard.require_allowed("https://api.example.test/v1/item", "GET", now=NOW)
    with pytest.raises(ScopeError, match="path"):
        one_segment_guard.require_allowed("https://api.example.test/v1/item/nested", "GET", now=NOW)

    recursive_scope = _write_scope(
        tmp_path / "recursive.yaml",
        allowed_paths=["glob:/v1/**"],
    )
    ScopeGuard.from_file(recursive_scope, now=NOW).require_allowed(
        "https://api.example.test/v1/item/nested",
        "GET",
        now=NOW,
    )


def test_read_methods_and_mutation_grants_are_separate(tmp_path: Path) -> None:
    scope_file = _write_scope(
        tmp_path / "scope.yaml",
        mutation_grants=[
            {
                "methods": ["POST"],
                "path_patterns": ["glob:/v1/reports"],
            }
        ],
    )
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    guard.require_allowed("https://api.example.test/v1/items", "OPTIONS", now=NOW)
    guard.require_allowed("https://api.example.test/v1/reports", "POST", now=NOW)
    with pytest.raises(ScopeError, match="method"):
        guard.require_allowed("https://api.example.test/v1/items", "POST", now=NOW)
    with pytest.raises(ScopeError, match="exact uppercase"):
        guard.require_allowed("https://api.example.test/v1/items", "get", now=NOW)


def test_userinfo_url_is_rejected_without_echoing_it(tmp_path: Path) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml")
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    with pytest.raises(ScopeError, match="userinfo"):
        guard.require_allowed("https://user:password@api.example.test/v1/items", "GET", now=NOW)


@pytest.mark.parametrize(
    ("replacement", "match"),
    [
        ({"confirmed": False}, "confirmed"),
        ({"authorization_reference": ""}, "authorization_reference"),
        ({"expires_at": datetime(2026, 8, 23, 11, 0, tzinfo=UTC)}, "expired"),
        ({"allowed_hosts": (), "allowed_cidrs": ()}, "At least one"),
    ],
)
def test_scope_guard_revalidates_direct_scope_config_bypasses(
    tmp_path: Path,
    replacement: dict[str, object],
    match: str,
) -> None:
    config = load_scope(_write_scope(tmp_path / "scope.yaml"), now=NOW)

    with pytest.raises(ScopeError, match=match):
        ScopeGuard(replace(config, **replacement), now=NOW)


def test_scope_guard_rejects_a_handmade_but_policy_valid_scope_config(tmp_path: Path) -> None:
    loaded = load_scope(_write_scope(tmp_path / "scope.yaml"), now=NOW)
    handmade = ScopeConfig(
        client_name=loaded.client_name,
        authorization_reference=loaded.authorization_reference,
        confirmed=loaded.confirmed,
        starts_at=loaded.starts_at,
        expires_at=loaded.expires_at,
        allowed_hosts=loaded.allowed_hosts,
        allowed_cidrs=loaded.allowed_cidrs,
        allowed_paths=loaded.allowed_paths,
        read_methods=loaded.read_methods,
        mutation_grants=loaded.mutation_grants,
    )

    with pytest.raises(ScopeError, match="originate from load_scope"):
        ScopeGuard(handmade, now=NOW)


def test_scope_guard_rejects_a_loaded_scope_when_the_source_file_changes(tmp_path: Path) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml")
    config = load_scope(scope_file, now=NOW)
    scope_file.write_text(scope_file.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

    with pytest.raises(ScopeError, match="metadata|digest"):
        ScopeGuard(config, now=NOW)


@pytest.mark.parametrize("change", ["contents", "replacement", "symlink"])
def test_existing_guard_rechecks_scope_provenance_for_every_request(
    tmp_path: Path,
    change: str,
) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml")
    guard = ScopeGuard.from_file(scope_file, now=NOW)

    if change == "contents":
        changed_contents = scope_file.read_text(encoding="utf-8") + "# changed\n"
        scope_file.write_text(changed_contents, encoding="utf-8")
    else:
        original_file = tmp_path / "original-scope.yaml"
        scope_file.rename(original_file)
        if change == "replacement":
            _write_scope(scope_file)
        else:
            scope_file.symlink_to(original_file)

    with pytest.raises(ScopeError, match="regular|metadata|digest"):
        guard.require_allowed("https://api.example.test/v1/items", "GET", now=NOW)


def test_require_in_scope_returns_the_guard_decision(tmp_path: Path) -> None:
    config = load_scope(_write_scope(tmp_path / "scope.yaml"), now=NOW)

    decision = require_in_scope("https://api.example.test/v1/items", config, now=NOW)

    assert isinstance(decision, ScopeDecision)
    assert decision.canonical_url == "https://api.example.test/v1/items"


def test_scope_decision_canonicalizes_host_default_port_and_percent_escape(tmp_path: Path) -> None:
    config = load_scope(_write_scope(tmp_path / "scope.yaml"), now=NOW)

    decision = require_in_scope(
        "https://API.EXAMPLE.TEST:443/v1/items?filter=%7e",
        config,
        now=NOW,
    )

    assert decision.canonical_url == "https://api.example.test/v1/items?filter=%7E"


def test_unanchored_regex_rule_is_rejected(tmp_path: Path) -> None:
    scope_file = _write_scope(tmp_path / "scope.yaml", allowed_paths=["regex:/v1/.*"])

    with pytest.raises(ScopeError, match="Regex path rules"):
        load_scope(scope_file, now=NOW)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda content: content + "client_name: Duplicate B.V.\n",
        lambda content: content.replace(
            "client_name: Example B.V.",
            "client_name: &owner Example B.V.",
        ).replace("authorization_reference: PT-2026-014", "authorization_reference: *owner"),
        lambda content: content + "<<: {client_name: Merged B.V.}\n",
    ],
    ids=["duplicate-key", "alias", "merge-key"],
)
def test_ambiguous_yaml_constructs_are_rejected(
    tmp_path: Path,
    mutator: Any,
) -> None:
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(mutator(yaml.safe_dump(_scope_document())), encoding="utf-8")

    with pytest.raises(ScopeError, match="unambiguous YAML"):
        load_scope(scope_file, now=NOW)
