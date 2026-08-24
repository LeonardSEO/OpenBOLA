"""Optional, non-executing AI test-plan generation."""

from __future__ import annotations

import importlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from numbers import Real
from types import MappingProxyType
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from openbola.handles import SecretHandle

MAX_SUGGESTIONS = 10
MAX_PROPOSED_TESTS = MAX_SUGGESTIONS
MAX_AI_OUTPUT_BYTES = 32 * 1024
MAX_CONTEXT_BYTES = 16 * 1024
MAX_ENDPOINT_PATTERNS = 50
MAX_CANDIDATES = 100
MAX_PROVIDER_TIMEOUT_SECONDS = 120.0

_MAX_ENDPOINT_TEMPLATE_LENGTH = 256
_MAX_FIELD_HINT_LENGTH = 128
_MAX_REASONING_LENGTH = 240
_FENCE = chr(96) * 3
_FENCED_JSON_RE = re.compile(rf"\A{_FENCE}json\r?\n(?P<json>.*?)\r?\n{_FENCE}\Z", re.DOTALL)
_SAFE_FIELD_NAME_RE = re.compile(r"(?:id|[A-Za-z_][A-Za-z0-9_]*(?:_id|Id|ID))\Z")
_SENSITIVE_NAME_PARTS = (
    "apikey", "token", "secret", "password", "passwd", "auth", "cookie",
    "session", "credential", "bearer", "privatekey",
)
_MAX_HANDLE_LENGTH = 256
_MAX_MODEL_LENGTH = 128
_MAX_PROVIDER_URL_LENGTH = 2048
_MAX_HEADER_NAME_LENGTH = 128
_MAX_HEADER_VALUE_LENGTH = 512
_MAX_RATIONALE_LENGTH = 240
_SAFE_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class HTTPMethod(StrEnum):
    """HTTP methods the AI may name; scope policy decides whether they run."""

    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class ObjectIDLocation(StrEnum):
    """Supported locations of an object identifier in a captured request."""

    PATH = "path"
    QUERY_PARAM = "query_param"
    BODY_NESTED = "body_nested"
    GRAPHQL_FIELD = "graphql_field"


def _validate_opaque_handle(value: object, *, field_name: str) -> str:
    """Validate a handle without interpreting or deriving its value."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_HANDLE_LENGTH
        or any(ord(character) < 32 or character.isspace() for character in value)
    ):
        raise ValueError(f"{field_name} must be a non-empty opaque handle")
    return value


def _normalise_contract_method(value: object) -> str:
    method = _normalise_method(value)
    if method is None:
        raise ValueError("method must be a supported HTTP method")
    return method


def _normalise_field_handles(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("field_handles must be a sequence of opaque handles")
    handles = tuple(
        _validate_opaque_handle(item, field_name="field handle")
        for item in value
    )
    if len(set(handles)) != len(handles):
        raise ValueError("field_handles must not contain duplicates")
    return handles


def _validate_text(value: object, *, field_name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or character.isspace() for character in value)
    ):
        raise ValueError(f"{field_name} must be non-empty and bounded")
    return value


def _validate_base_url(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PROVIDER_URL_LENGTH
        or any(ord(character) < 32 or character.isspace() for character in value)
    ):
        raise ValueError("provider base_url must be an HTTPS origin")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError as error:
        raise ValueError("provider base_url must be an HTTPS origin") from error
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("provider base_url must be an HTTPS origin")
    return value.rstrip("/")


def _validate_safe_headers(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError("safe_headers must be a mapping")
    headers: dict[str, str] = {}
    for name, header_value in value.items():
        if (
            not isinstance(name, str)
            or not name
            or len(name) > _MAX_HEADER_NAME_LENGTH
            or _SAFE_HEADER_NAME_RE.fullmatch(name) is None
            or _is_sensitive_name(name)
        ):
            raise ValueError("safe_headers contains an unsafe header name")
        if (
            not isinstance(header_value, str)
            or len(header_value) > _MAX_HEADER_VALUE_LENGTH
            or any(ord(character) < 32 or ord(character) == 127 for character in header_value)
        ):
            raise ValueError("safe_headers contains an unsafe header value")
        headers[name] = header_value
    return MappingProxyType(headers)


@dataclass(frozen=True)
class AIProviderConfig:
    """Configuration for a BYOK provider; it does not grant network authority."""

    kind: Literal["openai_compatible", "azure_openai"]
    base_url: str
    model: str
    api_key: SecretHandle
    azure_deployment: str | None = None
    api_version: str | None = None
    safe_headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in {"openai_compatible", "azure_openai"}:
            raise ValueError("provider kind is unsupported")
        object.__setattr__(self, "base_url", _validate_base_url(self.base_url))
        object.__setattr__(
            self,
            "model",
            _validate_text(self.model, field_name="model", maximum=_MAX_MODEL_LENGTH),
        )
        if not isinstance(self.api_key, SecretHandle):
            raise ValueError("api_key must be a SecretHandle")
        _validate_opaque_handle(self.api_key.id, field_name="api_key id")
        _validate_text(self.api_key.purpose, field_name="api_key purpose", maximum=128)

        if self.kind == "azure_openai":
            if self.azure_deployment is None or self.api_version is None:
                raise ValueError("Azure provider requires deployment and API version")
            object.__setattr__(
                self,
                "azure_deployment",
                _validate_text(
                    self.azure_deployment,
                    field_name="azure deployment",
                    maximum=_MAX_MODEL_LENGTH,
                ),
            )
            object.__setattr__(
                self,
                "api_version",
                _validate_text(
                    self.api_version,
                    field_name="API version",
                    maximum=_MAX_MODEL_LENGTH,
                ),
            )
        elif self.azure_deployment is not None or self.api_version is not None:
            raise ValueError("Azure settings are only valid for the Azure provider")

        object.__setattr__(self, "safe_headers", _validate_safe_headers(self.safe_headers))


@dataclass(frozen=True)
class PlanningCandidate:
    """Sanitized observed candidate containing handles but no resolved values."""

    endpoint_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    record_handle: str
    endpoint_template: str
    method: str
    field_handles: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in (
            "endpoint_handle",
            "owner_identity_handle",
            "attacker_identity_handle",
            "record_handle",
        ):
            _validate_opaque_handle(getattr(self, field_name), field_name=field_name)
        if not isinstance(self.endpoint_template, str) or not _is_safe_endpoint_template(
            self.endpoint_template
        ):
            raise ValueError("endpoint_template must be a relative path template")
        object.__setattr__(self, "method", _normalise_contract_method(self.method))
        object.__setattr__(self, "field_handles", _normalise_field_handles(self.field_handles))


@dataclass(frozen=True)
class ProposedTest:
    """A typed AI proposal that remains non-executable until later validation."""

    endpoint_handle: str
    owner_identity_handle: str
    attacker_identity_handle: str
    record_handle: str
    method: str
    field_handles: tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        for field_name in (
            "endpoint_handle",
            "owner_identity_handle",
            "attacker_identity_handle",
            "record_handle",
        ):
            _validate_opaque_handle(getattr(self, field_name), field_name=field_name)
        object.__setattr__(self, "method", _normalise_contract_method(self.method))
        object.__setattr__(self, "field_handles", _normalise_field_handles(self.field_handles))
        rationale = self.rationale
        if (
            not isinstance(rationale, str)
            or not rationale.strip()
            or len(rationale) > _MAX_RATIONALE_LENGTH
            or "\n" in rationale
            or "\r" in rationale
        ):
            raise ValueError("rationale must be concise and bounded")
        object.__setattr__(self, "rationale", rationale.strip())


@dataclass(frozen=True)
class ProposedPlan:
    """Bounded collection of typed proposals; never contains resolved values."""

    tests: tuple[ProposedTest, ...]

    def __post_init__(self) -> None:
        if isinstance(self.tests, (str, bytes)) or not isinstance(self.tests, Sequence):
            raise ValueError("tests must be a sequence")
        tests = tuple(self.tests)
        if len(tests) > MAX_PROPOSED_TESTS:
            raise ValueError("plan contains too many tests")
        if any(not isinstance(test, ProposedTest) for test in tests):
            raise ValueError("plan contains an invalid test")
        object.__setattr__(self, "tests", tests)


def build_sanitized_context(
    candidates: Sequence[PlanningCandidate],
) -> dict[str, object]:
    """Build the allowlisted, bounded context sent to a planning provider."""

    if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
        raise ValueError("planning candidates must be a sequence")
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError("too many planning candidates")
    normalized: set[PlanningCandidate] = set()
    for candidate in candidates:
        if not isinstance(candidate, PlanningCandidate):
            raise ValueError("planning candidates must be typed values")
        normalized.add(candidate)
    ordered = sorted(
        normalized,
        key=lambda candidate: (
            candidate.endpoint_handle,
            candidate.owner_identity_handle,
            candidate.attacker_identity_handle,
            candidate.record_handle,
            candidate.method,
            candidate.field_handles,
        ),
    )
    payload_candidates = [
        {
            "endpoint_handle": candidate.endpoint_handle,
            "owner_identity_handle": candidate.owner_identity_handle,
            "attacker_identity_handle": candidate.attacker_identity_handle,
            "record_handle": candidate.record_handle,
            "endpoint_template": candidate.endpoint_template,
            "method": candidate.method,
            "field_handles": list(candidate.field_handles),
        }
        for candidate in ordered
    ]
    context: dict[str, object] = {
        "schema": "openbola-ai-context-v1",
        "candidates": payload_candidates,
    }
    try:
        serialized = json.dumps(context, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        raise ValueError("planning context cannot be serialized") from error
    if len(serialized.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ValueError("AI context exceeds the maximum safe size")
    return context


class TestSuggestion(BaseModel):
    """A typed idea only, never an executable request description."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    endpoint_template: str = Field(min_length=1, max_length=_MAX_ENDPOINT_TEMPLATE_LENGTH)
    method: HTTPMethod
    object_id_location: ObjectIDLocation
    object_id_field_hint: str = Field(min_length=1, max_length=_MAX_FIELD_HINT_LENGTH)
    reasoning: str = Field(min_length=1, max_length=_MAX_REASONING_LENGTH)
    id_field_for_diff: str = Field(default="id", min_length=1, max_length=_MAX_FIELD_HINT_LENGTH)

    @field_validator("endpoint_template")
    @classmethod
    def endpoint_template_must_be_a_path(cls, value: str) -> str:
        if not _is_safe_endpoint_template(value):
            raise ValueError("endpoint_template must be a relative path template")
        return value

    @field_validator("object_id_field_hint", "id_field_for_diff")
    @classmethod
    def field_hint_must_be_safe(cls, value: str) -> str:
        if not _is_safe_field_name(value):
            raise ValueError("field hints must be short, non-sensitive identifier field names")
        return value

    @field_validator("reasoning")
    @classmethod
    def reasoning_must_be_concise(cls, value: str) -> str:
        if "\n" in value or "\r" in value or len(value.split()) > 40:
            raise ValueError("reasoning must be one concise line")
        return value


class TestPlan(BaseModel):
    """A bounded collection of non-executable test suggestions."""

    __test__: ClassVar[bool] = False
    model_config = ConfigDict(extra="forbid")
    suggestions: list[TestSuggestion] = Field(default_factory=list, max_length=MAX_SUGGESTIONS)


@runtime_checkable
class LLMAdapter(Protocol):
    """Provider boundary for producing a validated, non-executable plan."""

    def propose_tests(self, context: Mapping[str, Any]) -> TestPlan:
        """Return suggestions grounded in context; never execute a target request."""


class CodexCLIAdapterDisabledError(RuntimeError):
    """Raised because a general Codex agent cannot meet this module's boundary."""


SYSTEM_PROMPT = """\
You are a constrained planning component for an authorization-first BOLA/IDOR
testing tool. You must never execute requests or propose endpoints, methods,
or identifier locations not present in the supplied structural context. Return
only JSON matching the provided schema. A downstream deterministic executor
will independently enforce ScopeGuard and mutation policy before any request.
"""


def _is_sensitive_name(value: str) -> bool:
    normalized = "".join(character for character in value.casefold() if character.isalnum())
    return any(part in normalized for part in _SENSITIVE_NAME_PARTS)


def _is_safe_endpoint_template(value: str) -> bool:
    if (
        not value.startswith("/")
        or value.startswith("//")
        or len(value) > _MAX_ENDPOINT_TEMPLATE_LENGTH
        or not value.isascii()
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        return False
    segments = value.split("/")
    return (
        "%" not in value
        and "\\" not in value
        and "?" not in value
        and "#" not in value
        and all(segment not in {".", ".."} for segment in segments)
        and all(
            segment or index in {0, len(segments) - 1}
            for index, segment in enumerate(segments)
        )
    )


def _is_safe_field_name(value: str) -> bool:
    return (
        bool(_SAFE_FIELD_NAME_RE.fullmatch(value))
        and len(value) <= min(_MAX_FIELD_HINT_LENGTH, 64)
        and not _is_sensitive_name(value)
    )


def _canonical_locator(location: str, id_field: str) -> str:
    prefixes = {
        ObjectIDLocation.PATH.value: "path",
        ObjectIDLocation.QUERY_PARAM.value: "query",
        ObjectIDLocation.BODY_NESTED.value: "body",
        ObjectIDLocation.GRAPHQL_FIELD.value: "graphql",
    }
    return f"{prefixes[location]}:{id_field}"


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, Real):
        raise ValueError("provider timeout must be a finite positive number")
    normalized = float(timeout)
    if not math.isfinite(normalized) or not 0 < normalized <= MAX_PROVIDER_TIMEOUT_SECONDS:
        raise ValueError(
            "provider timeout must be greater than zero and at most "
            f"{MAX_PROVIDER_TIMEOUT_SECONDS:g}"
        )
    return normalized


def _as_sequence(value: Any, name: str, limit: int) -> Sequence[Any]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"AI context {name} must be a list")
    if len(value) > limit:
        raise ValueError(f"AI context has too many {name}")
    return list(value)


def _value(item: Any, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _normalise_method(value: Any) -> str | None:
    if not isinstance(value, (str, HTTPMethod)):
        return None
    try:
        return HTTPMethod(str(value).upper()).value
    except ValueError:
        return None


def _normalise_location(value: Any) -> str | None:
    if not isinstance(value, (str, ObjectIDLocation)):
        return None
    aliases = {
        "path": ObjectIDLocation.PATH.value,
        "query": ObjectIDLocation.QUERY_PARAM.value,
        "query_param": ObjectIDLocation.QUERY_PARAM.value,
        "json_body": ObjectIDLocation.BODY_NESTED.value,
        "body_nested": ObjectIDLocation.BODY_NESTED.value,
        "graphql_variable": ObjectIDLocation.GRAPHQL_FIELD.value,
        "graphql_field": ObjectIDLocation.GRAPHQL_FIELD.value,
    }
    return aliases.get(str(value))


def _normalise_template(value: Any) -> str | None:
    return value if isinstance(value, str) and _is_safe_endpoint_template(value) else None


def _normalise_methods(value: Any) -> set[str] | None:
    if value is None:
        return None
    methods = _as_sequence(value, "allowed_methods", len(HTTPMethod))
    normalised = {_normalise_method(method) for method in methods}
    if None in normalised or not normalised:
        raise ValueError("AI context contains an unsupported HTTP method")
    return {method for method in normalised if method is not None}


def sanitize_context(context: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return only endpoint paths, methods, and candidate locations for an AI."""

    if not isinstance(context, Mapping):
        raise ValueError("AI context must be a mapping")
    global_methods = _normalise_methods(context.get("allowed_methods"))
    raw_patterns = _as_sequence(
        context.get("endpoint_patterns"), "endpoint_patterns", MAX_ENDPOINT_PATTERNS
    )
    raw_candidates = _as_sequence(context.get("candidates"), "candidates", MAX_CANDIDATES)

    pattern_methods: dict[str, set[str]] = {}
    for pattern in raw_patterns:
        template = _normalise_template(
            _value(pattern, "endpoint_template", _value(pattern, "template"))
        )
        if template is None:
            raise ValueError("AI context contains an unsafe endpoint template")
        methods = _normalise_methods(
            _value(pattern, "allowed_methods", _value(pattern, "methods"))
        )
        pattern_methods.setdefault(template, set()).update(methods or set())

    candidates: list[dict[str, str]] = []
    for candidate in raw_candidates:
        template = _normalise_template(_value(candidate, "endpoint_template"))
        method = _normalise_method(_value(candidate, "method"))
        location = _normalise_location(_value(candidate, "location"))
        id_field = _value(candidate, "id_field", _value(candidate, "object_id_field_hint"))
        if (
            template is None
            or method is None
            or location is None
            or not isinstance(id_field, str)
            or not _is_safe_field_name(id_field)
        ):
            raise ValueError("AI context contains an unsafe endpoint candidate")
        pattern_methods.setdefault(template, set()).add(method)
        candidates.append(
            {
                "endpoint_template": template,
                "method": method,
                "location": location,
                "id_field": id_field,
                "locator": _canonical_locator(location, id_field),
            }
        )

    if not pattern_methods:
        raise ValueError("AI context has no endpoint patterns")
    endpoint_patterns: list[dict[str, Any]] = []
    for template in sorted(pattern_methods):
        methods = pattern_methods[template]
        if global_methods is not None:
            methods &= global_methods
        if methods:
            endpoint_patterns.append(
                {"endpoint_template": template, "allowed_methods": sorted(methods)}
            )
    if not endpoint_patterns:
        raise ValueError("AI context has no endpoint methods permitted for planning")

    permitted_templates = {item["endpoint_template"] for item in endpoint_patterns}
    permitted_methods = {
        (item["endpoint_template"], method)
        for item in endpoint_patterns
        for method in item["allowed_methods"]
    }
    candidates = [
        candidate
        for candidate in candidates
        if candidate["endpoint_template"] in permitted_templates
        and (candidate["endpoint_template"], candidate["method"]) in permitted_methods
    ]
    sanitized: dict[str, list[dict[str, Any]]] = {
        "endpoint_patterns": endpoint_patterns,
        "candidates": candidates,
    }
    if len(json.dumps(sanitized, separators=(",", ":")).encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ValueError("AI context exceeds the maximum safe size")
    return sanitized


def _build_user_prompt(sanitized_context: Mapping[str, Any]) -> str:
    context_json = json.dumps(sanitized_context, ensure_ascii=True, separators=(",", ":"))
    schema_json = json.dumps(TestPlan.model_json_schema(), ensure_ascii=True, separators=(",", ":"))
    return (
        "Structural context (redacted):\n"
        f"{context_json}\n\nReturn a TestPlan JSON object matching this schema:\n{schema_json}"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant: {value}")


def _parse_test_plan(raw: str) -> TestPlan:
    """Strictly parse one JSON object, optionally in one exact JSON fence."""

    if not isinstance(raw, str):
        raise ValueError("AI output must be text")
    if len(raw.encode("utf-8")) > MAX_AI_OUTPUT_BYTES:
        raise ValueError("AI output exceeds the maximum size")
    candidate = raw.strip()
    match = _FENCED_JSON_RE.fullmatch(candidate)
    if match is not None:
        candidate = match.group("json")
    elif candidate.startswith(_FENCE):
        raise ValueError("AI output must use one exact JSON fenced block")
    if not candidate:
        raise ValueError("AI output is empty")
    try:
        parsed = json.loads(
            candidate,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("AI output is not valid strict JSON") from error
    try:
        return TestPlan.model_validate(parsed)
    except ValidationError as error:
        raise ValueError("AI output does not match the TestPlan schema") from error


def validate_plan_for_context(plan: TestPlan, sanitized_context: Mapping[str, Any]) -> TestPlan:
    """Reject suggestions not fully grounded in the sanitized context."""

    allowed_methods: dict[str, set[str]] = {}
    for pattern in sanitized_context.get("endpoint_patterns", []):
        if not isinstance(pattern, Mapping):
            raise ValueError("sanitized AI context is malformed")
        template = pattern.get("endpoint_template")
        methods = pattern.get("allowed_methods")
        if (
            not isinstance(template, str)
            or isinstance(methods, (str, bytes))
            or not isinstance(methods, Sequence)
        ):
            raise ValueError("sanitized AI context is malformed")
        allowed_methods[template] = {method for method in methods if isinstance(method, str)}
    candidate_references = {
        (
            candidate.get("endpoint_template"),
            candidate.get("method"),
            candidate.get("location"),
            candidate.get("id_field"),
            candidate.get("locator"),
        )
        for candidate in sanitized_context.get("candidates", [])
        if isinstance(candidate, Mapping)
    }
    for suggestion in plan.suggestions:
        endpoint_methods = allowed_methods.get(suggestion.endpoint_template)
        if endpoint_methods is None or suggestion.method.value not in endpoint_methods:
            raise ValueError(
                "AI suggestion references an endpoint or method outside sanitized context"
            )
        reference = (
            suggestion.endpoint_template,
            suggestion.method.value,
            suggestion.object_id_location.value,
        )
        if not any(
            candidate[:3] == reference
            and suggestion.object_id_field_hint in {candidate[3], candidate[4]}
            and suggestion.id_field_for_diff in {candidate[3], candidate[4]}
            for candidate in candidate_references
        ):
            raise ValueError("AI suggestion references a candidate outside sanitized context")
    return plan


def _plan_from_output(raw: str, sanitized_context: Mapping[str, Any]) -> TestPlan:
    return validate_plan_for_context(_parse_test_plan(raw), sanitized_context)


class LiteLLMAdapter:
    """Lazy LiteLLM adapter; LiteLLM remains an optional dependency."""

    def __init__(self, model: str, api_key: str | None = None, timeout: float = 30.0) -> None:
        self.model = model
        self.api_key = api_key
        self.timeout = _validate_timeout(timeout)

    def propose_tests(self, context: Mapping[str, Any]) -> TestPlan:
        sanitized_context = sanitize_context(context)
        try:
            litellm = importlib.import_module("litellm")
        except ImportError as error:
            raise RuntimeError("LiteLLM support requires installing openbola[ai]") from error
        response = litellm.completion(
            model=self.model,
            api_key=self.api_key,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(sanitized_context)},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "openbola_test_plan",
                    "strict": True,
                    "schema": TestPlan.model_json_schema(),
                },
            },
            temperature=0,
            timeout=self.timeout,
        )
        return _plan_from_output(_litellm_content(response), sanitized_context)


def _litellm_content(response: Any) -> str:
    """Extract completion text without depending on LiteLLM response classes."""

    choices = (
        response.get("choices")
        if isinstance(response, Mapping)
        else getattr(response, "choices", None)
    )
    if not isinstance(choices, Sequence) or not choices:
        raise RuntimeError("LiteLLM returned no completion choices")
    choice = choices[0]
    message = (
        choice.get("message") if isinstance(choice, Mapping) else getattr(choice, "message", None)
    )
    content = (
        message.get("content")
        if isinstance(message, Mapping)
        else getattr(message, "content", None)
    )
    if not isinstance(content, str):
        raise RuntimeError("LiteLLM returned no text content")
    return content


class CodexCLIAdapter:
    """Fail-closed placeholder for the unsupported general-agent provider.

    A generic Codex CLI process can read a working tree and may have tools or
    network capabilities that this module cannot technically restrict. It is
    deliberately disabled instead of treating a read-only filesystem sandbox
    or prompt instructions as network isolation.
    """

    def __init__(self, codex_bin: str = "codex", timeout: float = 60.0) -> None:
        self.codex_bin = codex_bin
        self.timeout = _validate_timeout(timeout)

    def propose_tests(self, context: Mapping[str, Any]) -> TestPlan:
        del context
        raise CodexCLIAdapterDisabledError(
            "CodexCLIAdapter is disabled: a general agent cannot be guaranteed not to use tools "
            "or network access"
        )
