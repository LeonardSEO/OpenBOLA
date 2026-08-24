# OpenBOLA P3: Login Recipes & Automated Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `LoginRecipe`/`LoginSecretField` contracts (spec §5) and an automated, Playwright-driven login flow to `src/openbola/capture.py`, so `capture_har` can complete an ordinary username/password (+ optional TOTP) login without an operator manually clicking through it, while keeping every existing safety property (scope-enforced routing, sanitized-only persistence, lazy optional Playwright import) unchanged.

**Architecture:** `src/openbola/capture.py` already launches a scope-guarded Playwright browser context and supports one flavor of login (`interactive_login=True`: open a page, wait for a human to close it). This plan adds a second flavor (`login_recipe`: fill selectors with resolved `SecretHandle` values from P1's `SessionValueRegistry`, submit, wait for `success_url_pattern`) as a sibling branch in the same `if`/`elif` the existing code already has, reusing the file's established validation idioms (`_validate_target_url`), its lazy-Playwright-import pattern, and its existing fake-Playwright test doubles (`Context`/`Browser`/`Chromium`/`Manager`) rather than introducing new ones. CAPTCHA/WebAuthn operator-pause handling (spec §5's other login case) is explicitly out of scope here — it needs a TUI "waiting for operator" state that doesn't exist until P8, so an automated recipe that can't reach `success_url_pattern` simply fails closed with `CaptureError` in this plan, same as any other capture failure.

**Tech Stack:** Python 3.11+, the existing `playwright.async_api` (optional `openbola[capture]` extra, already installed in this environment), stdlib `hmac`/`hashlib`/`base64`/`struct`/`time` for TOTP (no new third-party dependency — this matches the codebase's existing preference for dependency-light contracts in `models.py`/`credentials.py`/`handles.py`), pytest with `pytest-asyncio`-free `asyncio.run()` (the file's existing async test pattern).

**Spec:** `docs/superpowers/specs/2026-08-24-openbola-v1-design.md` (§5 Login recipes, §7 step 4 Automated capture)

## Global Constraints

- Recipes persist selectors, URL patterns, and secret handles; secret values live in the OS vault — this plan resolves a `SecretHandle` via `SessionValueRegistry.resolve_secret` only immediately before filling the corresponding field, never earlier and never logged (spec §5).
- CAPTCHA and WebAuthn pause the recipe for operator completion; ordinary username/password and optional TOTP fields may be automated when their values are stored in the OS vault (spec §5) — this plan implements the automatable half only; a recipe that cannot complete automatically (CAPTCHA, WebAuthn, or any other reason `success_url_pattern` isn't reached) raises `CaptureError`, it does not attempt to pause for an operator.
- No plaintext raw HAR, token, cookie, password, record identifier, original mutation value, or full response persistence (spec §2 non-goals) — this plan must not weaken `capture.py`'s existing sanitization; it must not introduce a new code path that writes an unredacted request/response to disk or to the in-memory collector's persisted-eligible fields.
- Handles use random, non-semantic identifiers; only the active process resolves a handle immediately before a policy-approved operation (spec §5, and P1's `SessionValueRegistry` contract this plan consumes).

---

### Task 1: `LoginSecretField` and `LoginRecipe` contracts

**Files:**
- Modify: `src/openbola/capture.py` (add two dataclasses, reusing the existing `_validate_target_url` helper)
- Test: `tests/test_capture.py` (append new tests)

**Interfaces:**
- Consumes: `SecretHandle` from `openbola.handles` (P1, already merged).
- Produces: `LoginSecretField(selector: str, secret: SecretHandle, kind: Literal["static", "totp"] = "static")` and `LoginRecipe(name, start_url, username_selector, password_selector, submit_selector, success_url_pattern, username_secret, password_secret, extra_secret_fields: tuple[LoginSecretField, ...] = ())` — both frozen dataclasses. Task 3 constructs a `LoginRecipe` and passes it to `capture_har` via a new `CaptureConfig.login_recipe` field.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_capture.py`:

```python
def test_login_secret_field_requires_non_empty_selector() -> None:
    from openbola.capture import LoginSecretField
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="totp_seed", value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

    with pytest.raises(CaptureError, match="selector"):
        LoginSecretField(selector="", secret=handle, kind="totp")


def test_login_secret_field_rejects_unknown_kind() -> None:
    from openbola.capture import LoginSecretField
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    handle = registry.store_secret(purpose="totp_seed", value="seed")

    with pytest.raises(CaptureError, match="kind"):
        LoginSecretField(selector="#otp", secret=handle, kind="sms")  # type: ignore[arg-type]


def test_login_secret_field_rejects_non_secret_handle() -> None:
    from openbola.capture import LoginSecretField

    with pytest.raises(CaptureError, match="SecretHandle"):
        LoginSecretField(selector="#otp", secret="not-a-handle")  # type: ignore[arg-type]


def _valid_login_recipe() -> Any:
    from openbola.capture import LoginRecipe
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    return LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    ), registry


def test_login_recipe_accepts_a_minimal_valid_recipe() -> None:
    recipe, _ = _valid_login_recipe()
    assert recipe.name == "staging-portal"
    assert recipe.extra_secret_fields == ()


def test_login_recipe_rejects_empty_name() -> None:
    from openbola.capture import LoginRecipe

    recipe, _ = _valid_login_recipe()
    with pytest.raises(CaptureError, match="name"):
        LoginRecipe(
            name="  ",
            start_url=recipe.start_url,
            username_selector=recipe.username_selector,
            password_selector=recipe.password_selector,
            submit_selector=recipe.submit_selector,
            success_url_pattern=recipe.success_url_pattern,
            username_secret=recipe.username_secret,
            password_secret=recipe.password_secret,
        )


@pytest.mark.parametrize(
    "bad_start_url",
    [
        "not-a-url",
        "ftp://app.example.test/login",
        "https://user:pass@app.example.test/login",
        "https://app.example.test/login?next=/x",
    ],
)
def test_login_recipe_rejects_unsafe_start_url(bad_start_url: str) -> None:
    from openbola.capture import LoginRecipe

    recipe, _ = _valid_login_recipe()
    with pytest.raises(CaptureError, match="start_url"):
        LoginRecipe(
            name=recipe.name,
            start_url=bad_start_url,
            username_selector=recipe.username_selector,
            password_selector=recipe.password_selector,
            submit_selector=recipe.submit_selector,
            success_url_pattern=recipe.success_url_pattern,
            username_secret=recipe.username_secret,
            password_secret=recipe.password_secret,
        )


def test_login_recipe_rejects_empty_success_url_pattern() -> None:
    from openbola.capture import LoginRecipe

    recipe, _ = _valid_login_recipe()
    with pytest.raises(CaptureError, match="success_url_pattern"):
        LoginRecipe(
            name=recipe.name,
            start_url=recipe.start_url,
            username_selector=recipe.username_selector,
            password_selector=recipe.password_selector,
            submit_selector=recipe.submit_selector,
            success_url_pattern="   ",
            username_secret=recipe.username_secret,
            password_secret=recipe.password_secret,
        )


def test_login_recipe_accepts_extra_totp_field() -> None:
    from openbola.capture import LoginRecipe, LoginSecretField
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
        extra_secret_fields=(
            LoginSecretField(
                selector="#otp",
                secret=registry.store_secret(
                    purpose="totp_seed", value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                ),
                kind="totp",
            ),
        ),
    )
    assert recipe.extra_secret_fields[0].kind == "totp"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_capture.py -k "login_secret_field or login_recipe" -v`
Expected: `ImportError`/`ModuleNotFoundError`-shaped failures — `LoginSecretField` and `LoginRecipe` do not exist in `openbola.capture` yet.

- [ ] **Step 3: Add the two dataclasses**

In `src/openbola/capture.py`, add this import (the file currently imports `Any, Protocol` from `typing` on line 15 — extend it):

Current line 15:
```python
from typing import Any, Protocol
```

Replace with:
```python
from typing import Any, Literal, Protocol
```

Add this import for `SecretHandle` alongside the existing `openbola` imports (lines 18-19):

Current:
```python
from openbola.models import RequestRecord
from openbola.scope import ScopeDecision, ScopeError, ScopeGuard
```

Replace with:
```python
from openbola.handles import SecretHandle
from openbola.models import RequestRecord
from openbola.scope import ScopeDecision, ScopeError, ScopeGuard
```

Then, immediately after the `CaptureConfig` class (after its `__post_init__` ends, before `class CaptureCollector(Protocol):`), insert:

```python
_LOGIN_SECRET_FIELD_KINDS = frozenset({"static", "totp"})


@dataclass(frozen=True)
class LoginSecretField:
    """One extra credential-bearing field a login recipe fills, e.g. a TOTP code."""

    selector: str
    secret: SecretHandle
    kind: Literal["static", "totp"] = "static"

    def __post_init__(self) -> None:
        if not self.selector.strip():
            raise CaptureError("LoginSecretField selector must not be empty")
        if not isinstance(self.secret, SecretHandle):
            raise CaptureError("LoginSecretField secret must be a SecretHandle")
        if self.kind not in _LOGIN_SECRET_FIELD_KINDS:
            raise CaptureError(f"LoginSecretField kind must be one of {sorted(_LOGIN_SECRET_FIELD_KINDS)}")


@dataclass(frozen=True)
class LoginRecipe:
    """Selectors, URL patterns, and secret handles for one automated login flow."""

    name: str
    start_url: str = field(repr=False)
    username_selector: str
    password_selector: str
    submit_selector: str
    success_url_pattern: str
    username_secret: SecretHandle
    password_secret: SecretHandle
    extra_secret_fields: tuple[LoginSecretField, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise CaptureError("LoginRecipe name must not be empty")
        try:
            _validate_target_url(self.start_url)
        except CaptureError as exc:
            raise CaptureError("LoginRecipe start_url is unsafe") from exc
        for field_name in ("username_selector", "password_selector", "submit_selector"):
            if not getattr(self, field_name).strip():
                raise CaptureError(f"LoginRecipe {field_name} must not be empty")
        if not self.success_url_pattern.strip():
            raise CaptureError("LoginRecipe success_url_pattern must not be empty")
        for secret_field_name in ("username_secret", "password_secret"):
            if not isinstance(getattr(self, secret_field_name), SecretHandle):
                raise CaptureError(f"LoginRecipe {secret_field_name} must be a SecretHandle")
        if not isinstance(self.extra_secret_fields, tuple) or not all(
            isinstance(item, LoginSecretField) for item in self.extra_secret_fields
        ):
            raise CaptureError("LoginRecipe extra_secret_fields must be a tuple of LoginSecretField")
```

Note: `_validate_target_url` already rejects a URL with query parameters (see its existing body, which raises `CaptureError("target_url must not contain query parameters or fragments")` — `LoginRecipe.start_url` reuses this exact function unchanged, so it inherits that same restriction; the test above expects `"https://app.example.test/login?next=/x"` to be rejected for this reason).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_capture.py -k "login_secret_field or login_recipe" -v`
Expected: all pass (3 + 1 + 1 + 1 + 4 parametrized + 1 + 1 = 12 test cases).

- [ ] **Step 5: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/capture.py tests/test_capture.py
.venv/bin/mypy src/openbola/capture.py
```

Expected: full suite passes (277 pre-existing + the new tests), ruff and mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/openbola/capture.py tests/test_capture.py
git commit -m "feat: add LoginRecipe and LoginSecretField contracts"
```

---

### Task 2: TOTP code generation

**Files:**
- Modify: `src/openbola/capture.py` (add `_totp_code` helper and its stdlib imports)
- Test: `tests/test_capture.py` (append new tests)

**Interfaces:**
- Consumes: nothing beyond stdlib (`base64`, `hmac`, `hashlib`, `struct`, `time` — `hashlib` is already imported by this file for a different purpose; the others are new).
- Produces: `_totp_code(secret_base32: str, *, now: float | None = None, period: int = 30, digits: int = 6) -> str`, an RFC 6238 TOTP generator. Task 3's `_perform_login` calls this for any `LoginSecretField` whose `kind == "totp"`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_capture.py`. These test vectors were derived by running the exact algorithm below against the RFC 6238 Appendix B reference key (ASCII `"12345678901234567890"`, base32-encoded) and cross-checked against RFC 6238's own published 8-digit vector at T=59 (`94287082`), which the same key and counter reproduce under this implementation — so the 6-digit values below are independently verified, not guessed:

```python
_TOTP_TEST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32("12345678901234567890")


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1234567890, "005924"),
    ],
)
def test_totp_code_matches_known_vectors(now: int, expected: str) -> None:
    from openbola.capture import _totp_code

    assert _totp_code(_TOTP_TEST_SECRET, now=now) == expected


def test_totp_code_is_six_digits_and_zero_padded() -> None:
    from openbola.capture import _totp_code

    code = _totp_code(_TOTP_TEST_SECRET, now=59)
    assert len(code) == 6
    assert code.isdigit()


def test_totp_code_accepts_lowercase_and_unpadded_secret() -> None:
    from openbola.capture import _totp_code

    lowercase = _TOTP_TEST_SECRET.lower().rstrip("=")
    assert _totp_code(lowercase, now=59) == _totp_code(_TOTP_TEST_SECRET, now=59)


def test_totp_code_rejects_invalid_base32_secret() -> None:
    from openbola.capture import _totp_code

    with pytest.raises(CaptureError, match="base32"):
        _totp_code("not-valid-base32!!!", now=59)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_capture.py -k totp -v`
Expected: `ImportError`/`AttributeError` — `_totp_code` does not exist yet.

- [ ] **Step 3: Add the imports and the helper**

In `src/openbola/capture.py`, the import block currently reads (lines 5-16):

```python
import importlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
```

Replace with (adding `base64`, `hmac`, `struct`, `time`; `hashlib` is not currently imported by this file — check first: if `import hashlib` is not already present, add it too, since `_totp_code` needs `hashlib.sha1`):

```python
import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import stat
import struct
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
```

Then add this constant and function near the bottom of the file, immediately before the final `_redact_json` function (or any other clearly-separated location — placement among the other private helpers is fine as long as it's below the dataclasses and above nothing that needs it earlier):

```python
_TOTP_PERIOD_SECONDS = 30
_TOTP_DIGITS = 6


def _totp_code(
    secret_base32: str,
    *,
    now: float | None = None,
    period: int = _TOTP_PERIOD_SECONDS,
    digits: int = _TOTP_DIGITS,
) -> str:
    """Compute the current RFC 6238 TOTP code for a base32-encoded seed."""
    padded = secret_base32.strip().upper().replace(" ", "")
    padded += "=" * (-len(padded) % 8)
    try:
        key = base64.b32decode(padded)
    except ValueError as exc:
        raise CaptureError("TOTP secret must be valid base32") from exc
    counter = int((now if now is not None else time.time()) // period)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = truncated % (10**digits)
    return str(code).zfill(digits)
```

(`hashlib.sha1` is used here only as an HMAC digest per RFC 6238 — the same construction TOTP authenticator apps use everywhere; it is not used for any security-sensitive hashing purpose that would call for a stronger digest.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_capture.py -k totp -v`
Expected: all 6 pass (3 parametrized + 3 individual).

- [ ] **Step 5: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/capture.py tests/test_capture.py
.venv/bin/mypy src/openbola/capture.py
```

Expected: full suite passes, ruff and mypy clean. If `ruff` flags `S324` (weak hash) on `hashlib.sha1`, add `# noqa: S324 - RFC 6238 HMAC-SHA1, not a security digest` on that line — check whether `S324` is actually in this project's enabled rule set first (`pyproject.toml`'s `[tool.ruff.lint] select`); if it isn't selected, no suppression is needed.

- [ ] **Step 6: Commit**

```bash
git add src/openbola/capture.py tests/test_capture.py
git commit -m "feat: add RFC 6238 TOTP code generation for login recipes"
```

---

### Task 3: Automated login flow wired into `capture_har`

**Files:**
- Modify: `src/openbola/capture.py` (`CaptureConfig` gains `login_recipe`; new `_perform_login`; `capture_har` gains `registry` parameter and a new branch)
- Test: `tests/test_capture.py` (append new tests, following the file's existing fake-Playwright pattern)

**Interfaces:**
- Consumes: `LoginRecipe`/`LoginSecretField` (Task 1), `_totp_code` (Task 2), `SessionValueRegistry` (from `openbola.handles`, P1 — the same Protocol `InMemorySessionValueRegistry` implements: `resolve_secret(handle: SecretHandle) -> str`).
- Produces: `CaptureConfig(..., login_recipe: LoginRecipe | None = None)` and `capture_har(config, scope_guard, *, collector=None, registry=None)`. When `config.login_recipe` is set, `registry` is required and `capture_har` performs the automated login before returning the sanitized HAR — this is the deliverable spec §7 step 4 calls "automated capture."

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_capture.py`. These reuse the exact fake `Context`/`Browser`/`Chromium`/`Manager` shape already used elsewhere in this file (see e.g. `test_capture_cleanup_and_safe_output` above), adding a fake `Page` with `goto`/`fill`/`click`/`wait_for_url`/`close`:

```python
def _login_harness(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_at: str | None = None,
) -> tuple[list[tuple[str, tuple[Any, ...]]], type]:
    from openbola import capture

    calls: list[tuple[str, tuple[Any, ...]]] = []

    class FakePlaywrightError(Exception):
        pass

    class Page:
        async def goto(self, url: str, **kwargs: object) -> None:
            calls.append(("goto", (url,)))
            if fail_at == "goto":
                raise FakePlaywrightError("goto failed")

        async def fill(self, selector: str, value: str, **kwargs: object) -> None:
            calls.append(("fill", (selector, value)))
            if fail_at == f"fill:{selector}":
                raise FakePlaywrightError("fill failed")

        async def click(self, selector: str, **kwargs: object) -> None:
            calls.append(("click", (selector,)))
            if fail_at == "click":
                raise FakePlaywrightError("click failed")

        async def wait_for_url(self, pattern: str, **kwargs: object) -> None:
            calls.append(("wait_for_url", (pattern,)))
            if fail_at == "wait_for_url":
                raise FakePlaywrightError("timed out")

        async def close(self) -> None:
            calls.append(("close", ()))

    class Context:
        async def route(self, pattern: str, handler: object) -> None:
            return None

        async def new_page(self) -> Page:
            return Page()

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self, *, service_workers: str) -> Context:
            return Context()

        async def close(self) -> None:
            return None

    class Chromium:
        async def launch(self, **kwargs: object) -> Browser:
            return Browser()

    class Manager:
        async def __aenter__(self) -> object:
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *args: object) -> None:
            return None

    class Collector:
        def attach(self, context: object) -> None:
            return None

        async def entries(self) -> list[dict[str, object]]:
            return []

    monkeypatch.setattr(
        capture.importlib,
        "import_module",
        lambda _: SimpleNamespace(
            async_playwright=lambda: Manager(),
            Error=FakePlaywrightError,
        ),
    )
    return calls, Collector


def _login_config(tmp_path: Path, recipe: Any) -> Any:
    from openbola.capture import CaptureConfig

    return CaptureConfig(
        target_url="https://app.example.test/",
        capture_root=tmp_path,
        output_path=Path("out.har"),
        identity="alice",
        login_recipe=recipe,
    )


def test_capture_har_performs_automated_login(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openbola.capture import LoginRecipe, LoginSecretField, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
        extra_secret_fields=(
            LoginSecretField(
                selector="#otp",
                secret=registry.store_secret(
                    purpose="totp_seed", value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                ),
                kind="totp",
            ),
        ),
    )
    calls, Collector = _login_harness(monkeypatch)

    output = asyncio.run(
        capture_har(
            _login_config(tmp_path, recipe),
            Guard(),
            collector=Collector(),
            registry=registry,
        )
    )

    assert output.exists()
    kinds = [name for name, _ in calls]
    assert kinds == ["goto", "fill", "fill", "fill", "click", "wait_for_url", "close"]
    assert calls[0] == ("goto", ("https://app.example.test/login",))
    assert calls[1] == ("fill", ("#email", "alice"))
    assert calls[2] == ("fill", ("#password", "hunter2"))
    assert calls[3][1][0] == "#otp"
    assert calls[3][1][1] != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # TOTP seed never filled verbatim
    assert calls[3][1][1].isdigit() and len(calls[3][1][1]) == 6
    assert calls[4] == ("click", ("#submit",))
    assert calls[5] == ("wait_for_url", ("**/dashboard",))


def test_capture_har_wraps_login_failure_as_capture_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.capture import LoginRecipe, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )
    _, Collector = _login_harness(monkeypatch, fail_at="wait_for_url")

    with pytest.raises(CaptureError, match="login"):
        asyncio.run(
            capture_har(
                _login_config(tmp_path, recipe),
                Guard(),
                collector=Collector(),
                registry=registry,
            )
        )


def test_capture_config_rejects_login_recipe_with_interactive_login(tmp_path: Path) -> None:
    from openbola.capture import CaptureConfig, LoginRecipe
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )
    with pytest.raises(CaptureError, match="mutually exclusive"):
        CaptureConfig(
            target_url="https://app.example.test/",
            capture_root=tmp_path,
            output_path=Path("out.har"),
            identity="alice",
            headless=False,
            interactive_login=True,
            login_recipe=recipe,
        )


def test_capture_har_requires_registry_when_login_recipe_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from openbola.capture import LoginRecipe, capture_har
    from openbola.handles import InMemorySessionValueRegistry

    registry = InMemorySessionValueRegistry()
    recipe = LoginRecipe(
        name="staging-portal",
        start_url="https://app.example.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_url_pattern="**/dashboard",
        username_secret=registry.store_secret(purpose="username", value="alice"),
        password_secret=registry.store_secret(purpose="password", value="hunter2"),
    )
    _, Collector = _login_harness(monkeypatch)

    with pytest.raises(CaptureError, match="registry"):
        asyncio.run(
            capture_har(_login_config(tmp_path, recipe), Guard(), collector=Collector())
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_capture.py -k "automated_login or login_failure or login_recipe_with_interactive or registry_when_login" -v`
Expected: failures — `CaptureConfig` has no `login_recipe` parameter yet, `capture_har` has no `registry` parameter yet.

- [ ] **Step 3: Extend `CaptureConfig`**

In `src/openbola/capture.py`, the current `CaptureConfig` class reads (lines 46-64):

```python
@dataclass(frozen=True)
class CaptureConfig:
    target_url: str = field(repr=False)
    capture_root: Path
    output_path: Path
    identity: str
    headless: bool = True
    interactive_login: bool = False
    max_har_bytes: int = DEFAULT_MAX_HAR_BYTES

    def __post_init__(self) -> None:
        _validate_target_url(self.target_url)
        _validated_output_path(self.capture_root, self.output_path)
        if not self.identity.strip():
            raise CaptureError("identity must not be empty")
        if self.interactive_login and self.headless:
            raise CaptureError("interactive_login requires headless=False")
        if self.max_har_bytes <= 0:
            raise CaptureError("max_har_bytes must be greater than zero")
```

Replace with (adding `login_recipe` after `max_har_bytes`, and one new mutual-exclusivity check — note `LoginRecipe` is defined later in the file per Task 1's placement, so this dataclass's type annotation must be a forward reference; `from __future__ import annotations` is already active at the top of this file, so a bare `LoginRecipe` annotation works without quoting):

```python
@dataclass(frozen=True)
class CaptureConfig:
    target_url: str = field(repr=False)
    capture_root: Path
    output_path: Path
    identity: str
    headless: bool = True
    interactive_login: bool = False
    max_har_bytes: int = DEFAULT_MAX_HAR_BYTES
    login_recipe: LoginRecipe | None = None

    def __post_init__(self) -> None:
        _validate_target_url(self.target_url)
        _validated_output_path(self.capture_root, self.output_path)
        if not self.identity.strip():
            raise CaptureError("identity must not be empty")
        if self.interactive_login and self.headless:
            raise CaptureError("interactive_login requires headless=False")
        if self.max_har_bytes <= 0:
            raise CaptureError("max_har_bytes must be greater than zero")
        if self.login_recipe is not None and self.interactive_login:
            raise CaptureError("login_recipe and interactive_login are mutually exclusive")
```

- [ ] **Step 4: Add `_perform_login`**

In `src/openbola/capture.py`, immediately after the `_totp_code` function added in Task 2, insert:

```python
_LOGIN_TIMEOUT_MS = 15_000


async def _perform_login(page: Any, recipe: LoginRecipe, registry: Any) -> None:
    """Fill and submit a login recipe; the caller translates failures to CaptureError."""
    await page.goto(recipe.start_url, timeout=_LOGIN_TIMEOUT_MS)
    await page.fill(
        recipe.username_selector,
        registry.resolve_secret(recipe.username_secret),
        timeout=_LOGIN_TIMEOUT_MS,
    )
    await page.fill(
        recipe.password_selector,
        registry.resolve_secret(recipe.password_secret),
        timeout=_LOGIN_TIMEOUT_MS,
    )
    for extra in recipe.extra_secret_fields:
        value = registry.resolve_secret(extra.secret)
        if extra.kind == "totp":
            value = _totp_code(value)
        await page.fill(extra.selector, value, timeout=_LOGIN_TIMEOUT_MS)
    await page.click(recipe.submit_selector, timeout=_LOGIN_TIMEOUT_MS)
    await page.wait_for_url(recipe.success_url_pattern, timeout=_LOGIN_TIMEOUT_MS)
```

This function takes `registry: Any` rather than `registry: SessionValueRegistry` because `capture.py` does not import `openbola.handles.SessionValueRegistry` (only the concrete `SecretHandle` type, for `LoginRecipe`'s fields) — adding that import is unnecessary here since `registry` is used purely structurally (duck-typed: anything with a `resolve_secret` method works, matching the `Protocol`'s own structural-typing intent).

- [ ] **Step 5: Wire the new branch into `capture_har`**

In `src/openbola/capture.py`, the current `capture_har` function reads (lines 121-162):

```python
async def capture_har(
    config: CaptureConfig, scope_guard: ScopeGuard, *, collector: CaptureCollector | None = None
) -> Path:
    """Write a sanitized HAR after a session without navigating the target URL."""
    try:
        async_api = importlib.import_module("playwright.async_api")
        async_playwright = async_api.async_playwright
    except (ImportError, AttributeError) as exc:
        raise CaptureError("Playwright unavailable. Install openbola[capture].") from exc

    if not isinstance(scope_guard, ScopeGuard):
        raise CaptureError("scope_guard must be a ScopeGuard")
    active_collector = collector or InMemoryEventCollector()
    policy_failures: list[ScopeError] = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=config.headless,
            args=["--no-proxy-server"],
        )
        try:
            context = await browser.new_context(service_workers="block")
            try:
                await context.route("**/*", _scoped_route(scope_guard, policy_failures))
                active_collector.attach(context)
                if config.interactive_login:
                    page = await context.new_page()
                    await page.wait_for_event("close")
            finally:
                await context.close()
        finally:
            await browser.close()
    entries = await active_collector.entries()
    if policy_failures:
        raise CaptureError("a browser request was denied by the confirmed scope")
    output_path = _validated_output_path(config.capture_root, config.output_path)
    _write_sanitized_har(
        config.capture_root,
        config.output_path,
        entries,
        max_bytes=config.max_har_bytes,
    )
    return output_path
```

Replace with (the only changes: a new `registry` parameter, a validation check for it, and a new `if` branch before the existing `elif` — note `if config.interactive_login:` becomes `elif config.interactive_login:`):

```python
async def capture_har(
    config: CaptureConfig,
    scope_guard: ScopeGuard,
    *,
    collector: CaptureCollector | None = None,
    registry: Any | None = None,
) -> Path:
    """Write a sanitized HAR after a session without navigating the target URL."""
    try:
        async_api = importlib.import_module("playwright.async_api")
        async_playwright = async_api.async_playwright
    except (ImportError, AttributeError) as exc:
        raise CaptureError("Playwright unavailable. Install openbola[capture].") from exc

    if not isinstance(scope_guard, ScopeGuard):
        raise CaptureError("scope_guard must be a ScopeGuard")
    if config.login_recipe is not None and registry is None:
        raise CaptureError("registry is required when config.login_recipe is set")
    active_collector = collector or InMemoryEventCollector()
    policy_failures: list[ScopeError] = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=config.headless,
            args=["--no-proxy-server"],
        )
        try:
            context = await browser.new_context(service_workers="block")
            try:
                await context.route("**/*", _scoped_route(scope_guard, policy_failures))
                active_collector.attach(context)
                if config.login_recipe is not None:
                    page = await context.new_page()
                    try:
                        await _perform_login(page, config.login_recipe, registry)
                    except async_api.Error as exc:
                        raise CaptureError(
                            "automated login did not reach success_url_pattern"
                        ) from exc
                    finally:
                        await page.close()
                elif config.interactive_login:
                    page = await context.new_page()
                    await page.wait_for_event("close")
            finally:
                await context.close()
        finally:
            await browser.close()
    entries = await active_collector.entries()
    if policy_failures:
        raise CaptureError("a browser request was denied by the confirmed scope")
    output_path = _validated_output_path(config.capture_root, config.output_path)
    _write_sanitized_har(
        config.capture_root,
        config.output_path,
        entries,
        max_bytes=config.max_har_bytes,
    )
    return output_path
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_capture.py -k "automated_login or login_failure or login_recipe_with_interactive or registry_when_login" -v`
Expected: all 4 pass.

- [ ] **Step 7: Run the full suite and static checks**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/openbola/capture.py tests/test_capture.py
.venv/bin/mypy src/openbola/capture.py
```

Expected: full suite passes (Task 1's 12 + Task 2's 6 + this task's 4 new tests, plus all pre-existing), ruff and mypy clean. If `mypy --strict` flags `registry: Any | None = None` as an unnecessarily loose type where a `Protocol` would be preferable, that is an acceptable, intentional choice per Step 4's note above — do not silence it by adding an unused import; if `mypy` genuinely errors (not just a style linter), report it as a concern for the controller rather than guessing at a fix.

- [ ] **Step 8: Commit**

```bash
git add src/openbola/capture.py tests/test_capture.py
git commit -m "feat: wire automated login recipes into capture_har"
```

---

## Self-Review Notes

- **Spec coverage:** §5's `LoginRecipe` contract (selectors, `success_url_pattern`, `SecretHandle` fields, `extra_secret_fields`) is Task 1. §5's "ordinary username/password and optional TOTP fields may be automated" is Tasks 2-3. §5's CAPTCHA/WebAuthn operator-pause case is explicitly deferred (documented in Global Constraints and the plan header) — it needs TUI infrastructure (P8) this plan doesn't have. §7 step 4's "one isolated Playwright context per identity" is already satisfied by the pre-existing design: each `capture_har()` call already creates its own browser+context scoped to `config.identity`; running it once per identity (a session-orchestration concern) is P8/P9's job, not this plan's.
- **Placeholder scan:** every step has literal code; the TOTP test vectors were verified by actually running the algorithm (shown in the task description), not invented.
- **Type consistency:** `LoginRecipe`/`LoginSecretField` field names and the `Literal["static", "totp"]` kind match spec §5's own dataclass sketch closely (the spec's own snippet names the extra-fields tuple `extra_secret_fields: tuple[LoginSecretField, ...]` without defining `LoginSecretField`'s shape — this plan fills that specific gap with `selector`/`secret`/`kind`, the minimum needed for `_perform_login` to do its job; a later plan can extend `kind` with more values without breaking this one, since `_normalise`-style revalidation isn't part of this contract — `LoginRecipe` validates once at construction, matching `models.py`'s existing dataclasses, not `scope.py`'s YAML-loader-plus-revalidation pattern, because recipes aren't loaded from an untrusted file in this plan).
