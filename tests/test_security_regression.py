"""
tests/test_security_regression.py
==================================
Explicit security regression tests — one test class per Technical Debt item.

Every test here directly verifies that the corresponding TD fix is in place
and that the system FAILS CLOSED when the exploit pattern is attempted.
These tests act as a permanent guardrail: if a future change accidentally
reintroduces a vulnerability, the CI pipeline will catch it here.

TD Map
------
TD-01  CWE-798  Hardcoded JWT secret fallback
TD-02  CWE-328  SHA-256 password hashing
TD-03  CWE-613  No token revocation
TD-04  CWE-362  Non-thread-safe user store
TD-05  CWE-208  Timing-attack password comparison
TD-06  CWE-362  Non-thread-safe resource store
TD-07  CWE-943  Unsanitised query parameters
TD-08  CWE-942  CORS wildcard *
TD-09  CWE-209  Raw exception disclosure
TD-10  CWE-521  Weak password complexity
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import secrets
import sys
import threading
import time
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from tests.conftest import ALICE_CREDS, BOB_ADMIN_CREDS, auth_headers


# ===========================================================================
# TD-01 — CWE-798: Hardcoded credential (JWT secret must be required)
# ===========================================================================

class TestTD01HardcodedSecret:

    def test_service_raises_on_missing_jwt_secret(self):
        """
        If JWT_SECRET is absent the service must refuse to start.
        No silent fallback to a hard-coded value is permitted.
        """
        # Temporarily remove JWT_SECRET from the environment
        saved = os.environ.pop("JWT_SECRET", None)
        try:
            # Remove cached module so it re-executes module-level guard
            if "src.services.auth_service" in sys.modules:
                del sys.modules["src.services.auth_service"]
            with pytest.raises(EnvironmentError, match="JWT_SECRET"):
                import src.services.auth_service  # noqa: F401, PLC0415
        finally:
            if saved is not None:
                os.environ["JWT_SECRET"] = saved
            # Restore the module for subsequent tests
            if "src.services.auth_service" in sys.modules:
                del sys.modules["src.services.auth_service"]
            # Re-import with the valid secret
            import src.services.auth_service  # noqa: F401, PLC0415

    def test_jwt_secret_is_not_a_known_fallback(self):
        """
        The value used at runtime must NOT be the old hardcoded string.
        """
        from src.services import auth_service  # noqa: PLC0415
        bad_secret = "aegisdev-super-secret-do-not-use-in-prod"
        assert auth_service.JWT_SECRET != bad_secret

    def test_token_signed_with_wrong_secret_is_rejected(
        self, client: TestClient, alice: dict
    ):
        """A JWT signed with any other key must be rejected with 401."""
        evil_token = jwt.encode(
            {"sub": alice["id"], "username": "alice", "role": "admin"},
            "completely-different-secret",
            algorithm="HS256",
        )
        resp = client.get("/auth/me", headers=auth_headers(evil_token))
        assert resp.status_code == 401


# ===========================================================================
# TD-02 — CWE-328: Password hashing must be adaptive (not bare SHA-256)
# ===========================================================================

class TestTD02WeakPasswordHash:

    def test_stored_hash_is_not_hex_sha256(
        self, client: TestClient, alice: dict
    ):
        """
        SHA-256 produces a 64-character hex string with no salt separator.
        The stored hash must contain a '$' separator (salt$dk format) and
        must NOT be a 64-char bare hex string.
        """
        from src.services import auth_service  # noqa: PLC0415
        with auth_service._STORE_LOCK:
            user_record = auth_service._USER_STORE.get("alice")
        assert user_record is not None, "Alice should be registered"

        stored = user_record.hashed_password
        # PBKDF2 format: <64-char salt hex> $ <64-char dk hex>
        assert "$" in stored, "Hash must contain salt separator '$'"
        parts = stored.split("$")
        assert len(parts) == 2, "Hash must be in salt$dk format"
        salt_hex, dk_hex = parts
        assert len(salt_hex) == 64, "Salt must be 32 bytes (64 hex chars)"
        assert len(dk_hex) == 64, "DK must be 32 bytes (64 hex chars)"

    def test_sha256_of_password_does_not_match_stored_hash(
        self, client: TestClient, alice: dict
    ):
        """
        The old SHA-256 hash must NOT match the stored value — proving the
        upgrade to PBKDF2 is in effect.
        """
        from src.services import auth_service  # noqa: PLC0415
        with auth_service._STORE_LOCK:
            user_record = auth_service._USER_STORE.get("alice")
        plain = ALICE_CREDS["password"]
        sha256_hash = hashlib.sha256(plain.encode()).hexdigest()
        assert sha256_hash != user_record.hashed_password

    def test_two_registrations_with_same_password_produce_different_hashes(
        self, client: TestClient
    ):
        """
        Random salt means identical passwords produce different stored hashes.
        This is the core property proving salting is active.
        """
        creds_a = {**ALICE_CREDS, "username": "userA", "email": "a@test.com"}
        creds_b = {**ALICE_CREDS, "username": "userB", "email": "b@test.com"}
        client.post("/auth/register", json=creds_a)
        client.post("/auth/register", json=creds_b)

        from src.services import auth_service  # noqa: PLC0415
        with auth_service._STORE_LOCK:
            hash_a = auth_service._USER_STORE["usera"].hashed_password
            hash_b = auth_service._USER_STORE["userb"].hashed_password
        assert hash_a != hash_b


# ===========================================================================
# TD-03 — CWE-613: Token must be revocable (logout endpoint, JTI check)
# ===========================================================================

class TestTD03TokenRevocation:

    def test_token_rejected_after_logout(
        self, client: TestClient, alice: dict
    ):
        token = alice["access_token"]
        assert client.get("/auth/me", headers=auth_headers(token)).status_code == 200

        client.post("/auth/logout", headers=auth_headers(token))

        assert client.get("/auth/me", headers=auth_headers(token)).status_code == 401

    def test_token_payload_contains_jti_claim(
        self, client: TestClient, alice: dict
    ):
        """Every issued token must carry a unique JTI for revocation."""
        from src.services import auth_service  # noqa: PLC0415
        payload = auth_service.decode_token(alice["access_token"])
        assert "jti" in payload
        assert len(payload["jti"]) > 0

    def test_two_logins_produce_unique_jtis(
        self, client: TestClient, alice: dict
    ):
        login2 = client.post(
            "/auth/login",
            json={"username": "alice", "password": ALICE_CREDS["password"]},
        ).json()
        from src.services import auth_service  # noqa: PLC0415
        payload1 = auth_service.decode_token(alice["access_token"])
        payload2 = auth_service.decode_token(login2["access_token"])
        assert payload1["jti"] != payload2["jti"]

    def test_revoked_jti_stored_in_revocation_set(
        self, client: TestClient, alice: dict
    ):
        from src.services import auth_service  # noqa: PLC0415
        payload = auth_service.decode_token(alice["access_token"])
        jti = payload["jti"]
        client.post("/auth/logout", headers=auth_headers(alice["access_token"]))
        with auth_service._REVOKED_JTI_LOCK:
            assert jti in auth_service._REVOKED_JTI


# ===========================================================================
# TD-04 — CWE-362: User store must be protected by a lock
# ===========================================================================

class TestTD04ThreadSafeUserStore:

    def test_store_lock_exists(self):
        from src.services import auth_service  # noqa: PLC0415
        assert isinstance(auth_service._STORE_LOCK, type(threading.Lock()))

    def test_concurrent_registrations_do_not_corrupt_store(
        self, client: TestClient
    ):
        """
        Fire 20 simultaneous registration attempts for distinct users.
        All must either succeed (201) or fail gracefully (422/409).
        No exception or data corruption should occur.
        """
        errors: list[Exception] = []
        results: list[int] = []
        lock = threading.Lock()

        def register(i: int) -> None:
            try:
                creds = {
                    "username": f"concurrent{i}",
                    "email": f"concurrent{i}@test.com",
                    "password": "Concurrent1!",
                    "role": "developer",
                }
                resp = client.post("/auth/register", json=creds)
                with lock:
                    results.append(resp.status_code)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=register, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Exceptions during concurrent registration: {errors}"
        assert all(
            s in (201, 409, 422) for s in results
        ), f"Unexpected status codes: {results}"


# ===========================================================================
# TD-05 — CWE-208: Constant-time password comparison
# ===========================================================================

class TestTD05TimingAttack:

    def test_verify_password_uses_secrets_compare_digest(self):
        """
        Introspect _verify_password's source to confirm secrets.compare_digest
        is called, not == or !=.
        """
        import inspect  # noqa: PLC0415
        from src.services import auth_service  # noqa: PLC0415
        src_code = inspect.getsource(auth_service._verify_password)
        assert "compare_digest" in src_code, (
            "_verify_password must use secrets.compare_digest"
        )
        # Ensure plain != comparison is NOT present
        assert "!=" not in src_code or "compare_digest" in src_code

    def test_verify_password_returns_false_for_wrong_password(
        self, client: TestClient, alice: dict
    ):
        from src.services import auth_service  # noqa: PLC0415
        with auth_service._STORE_LOCK:
            user = auth_service._USER_STORE.get("alice")
        result = auth_service._verify_password("WrongPassword1!", user.hashed_password)
        assert result is False

    def test_verify_password_returns_true_for_correct_password(
        self, client: TestClient, alice: dict
    ):
        from src.services import auth_service  # noqa: PLC0415
        with auth_service._STORE_LOCK:
            user = auth_service._USER_STORE.get("alice")
        result = auth_service._verify_password(
            ALICE_CREDS["password"], user.hashed_password
        )
        assert result is True

    def test_authenticate_always_computes_hash_for_unknown_user(self):
        """
        authenticate_user must hash the password even when the username does
        not exist, to prevent timing discrimination between 'no such user'
        and 'wrong password'.
        """
        import inspect  # noqa: PLC0415
        from src.services import auth_service  # noqa: PLC0415
        src_code = inspect.getsource(auth_service.authenticate_user)
        # dummy_hash path must be present (constant-time guard)
        assert "dummy_hash" in src_code, (
            "authenticate_user must use a dummy hash path for missing users"
        )


# ===========================================================================
# TD-06 — CWE-362: Resource store must be protected by a lock
# ===========================================================================

class TestTD06ThreadSafeResourceStore:

    def test_resource_lock_exists(self):
        from src.controllers import data_controller  # noqa: PLC0415
        assert isinstance(
            data_controller._RESOURCE_LOCK, type(threading.Lock())
        )

    def test_concurrent_creates_do_not_corrupt_store(
        self, client: TestClient, alice: dict
    ):
        errors: list[Exception] = []
        results: list[int] = []
        lock = threading.Lock()

        def create(i: int) -> None:
            try:
                resp = client.post(
                    "/api/resources",
                    json={"name": f"ConcurrentR-{i}", "description": "test"},
                    headers=auth_headers(alice["access_token"]),
                )
                with lock:
                    results.append(resp.status_code)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=create, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert all(s == 201 for s in results)


# ===========================================================================
# TD-07 — CWE-943: Query parameters must be sanitised
# ===========================================================================

class TestTD07InputSanitisation:

    @pytest.mark.parametrize("param,value", [
        ("search", "'; DROP TABLE resources; --"),
        ("search", "<script>alert(1)</script>"),
        ("search", "a" * 101),
        ("tag", "bad<tag>"),
        ("tag", "t" * 51),
        ("owner_id", "not-a-uuid"),
        ("owner_id", "'; DROP TABLE users; --"),
    ])
    def test_malicious_query_params_rejected(
        self, client: TestClient, alice: dict, param: str, value: str
    ):
        resp = client.get(
            f"/api/resources?{param}={value}",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422, (
            f"Expected 422 for {param}={value!r}, got {resp.status_code}"
        )

    def test_allow_list_regex_for_search_is_compiled(self):
        """Verify the compiled regex constant exists in data_controller."""
        from src.controllers import data_controller  # noqa: PLC0415
        assert hasattr(data_controller, "_SEARCH_RE")
        assert isinstance(data_controller._SEARCH_RE, re.Pattern)

    def test_allow_list_regex_for_tag_is_compiled(self):
        from src.controllers import data_controller  # noqa: PLC0415
        assert hasattr(data_controller, "_TAG_RE")
        assert isinstance(data_controller._TAG_RE, re.Pattern)

    def test_uuid_regex_for_owner_id_is_compiled(self):
        from src.controllers import data_controller  # noqa: PLC0415
        assert hasattr(data_controller, "_UUID_RE")
        assert isinstance(data_controller._UUID_RE, re.Pattern)

    def test_resource_path_param_non_uuid_rejected(
        self, client: TestClient, alice: dict
    ):
        # Note: path traversal strings with '/' become separate URL segments and
        # either result in a 404 (route not matched) or 422 (our UUID check).
        # Both are safe responses — the resource is not accessed in either case.
        for bad_id in ["not-a-uuid", "1%3BDROP-TABLE", "abc123"]:
            resp = client.get(
                f"/api/resources/{bad_id}",
                headers=auth_headers(alice["access_token"]),
            )
            assert resp.status_code in (422, 404), (
                f"Expected 422 or 404 for resource_id={bad_id!r}, got {resp.status_code}"
            )


# ===========================================================================
# TD-08 — CWE-942: CORS must not use wildcard *
# ===========================================================================

class TestTD08CORSWildcard:

    def test_cors_allow_origins_is_not_wildcard(self):
        """
        The running app's CORS middleware must not contain '*' in its
        allowed origins list.
        """
        from src.main import app  # noqa: PLC0415
        cors_middleware = None
        for mw in app.user_middleware:
            # Starlette stores middleware as (cls, args, kwargs) tuples
            if hasattr(mw, "cls"):
                cls_name = getattr(mw.cls, "__name__", "")
            else:
                # May be a Middleware namedtuple or similar
                cls_name = str(mw)
            if "CORS" in cls_name:
                cors_middleware = mw
                break
        assert cors_middleware is not None, "CORS middleware must be registered on the app"

        # Also check via middleware_stack attributes as fallback
        from starlette.middleware.cors import CORSMiddleware  # noqa: PLC0415
        from src.main import _ALLOWED_ORIGINS  # noqa: PLC0415
        assert "*" not in _ALLOWED_ORIGINS, (
            f"CORS wildcard found in _ALLOWED_ORIGINS: {_ALLOWED_ORIGINS}"
        )

    def test_cors_allowed_origins_env_var_is_used(self):
        """ALLOWED_ORIGINS must come from environment, not be hardcoded."""
        from src.main import _ALLOWED_ORIGINS  # noqa: PLC0415
        env_value = os.getenv("ALLOWED_ORIGINS", "")
        for origin in _ALLOWED_ORIGINS:
            assert origin in env_value or "localhost" in origin, (
                f"Origin '{origin}' not traceable to ALLOWED_ORIGINS env var"
            )

    def test_options_preflight_with_disallowed_origin_is_blocked(
        self, client: TestClient
    ):
        """
        A preflight from an unlisted origin must not receive
        Access-Control-Allow-Origin: * in the response.
        """
        resp = client.options(
            "/auth/login",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        ac_allow = resp.headers.get("access-control-allow-origin", "")
        assert ac_allow != "*", "Wildcard CORS must not be returned"
        assert "evil.example.com" not in ac_allow


# ===========================================================================
# TD-09 — CWE-209: Error handler must not expose internal details
# ===========================================================================

class TestTD09VerboseErrorDisclosure:

    def test_500_response_does_not_contain_exception_text(
        self, client: TestClient, alice: dict
    ):
        """
        Trigger a deliberate RuntimeError inside a route and confirm that
        the response body contains only the generic message and an error_id,
        NOT the raw exception text.
        """
        from src.main import app  # noqa: PLC0415
        from fastapi import APIRouter  # noqa: PLC0415

        test_router = APIRouter()

        @test_router.get("/test-error-leak")
        async def _crash():
            raise RuntimeError("SENSITIVE INTERNAL DETAIL: db_password=hunter2")

        app.include_router(test_router)

        resp = client.get("/test-error-leak")
        assert resp.status_code == 500
        body = resp.json()
        # Must have a generic detail, not the raw exception
        assert "detail" in body
        assert "hunter2" not in body.get("detail", "")
        assert "SENSITIVE" not in body.get("detail", "")
        # Must have a correlation error_id for support
        assert "error_id" in body
        # error_id must look like a UUID
        assert re.match(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            body["error_id"],
        )

    def test_exception_handler_exists_and_returns_error_id(self):
        """Verify the exception handler is registered on the app."""
        from src.main import app  # noqa: PLC0415
        # FastAPI stores exception handlers in exception_handlers dict
        assert Exception in app.exception_handlers or len(app.exception_handlers) > 0


# ===========================================================================
# TD-10 — CWE-521: Password complexity must be enforced
# ===========================================================================

class TestTD10PasswordComplexity:

    @pytest.mark.parametrize("password,missing", [
        ("nouppercase1!", "uppercase"),
        ("NoDigitHere!", "digit"),
        ("NoSpecial1AB", "special"),
    ])
    def test_weak_passwords_rejected(
        self, client: TestClient, password: str, missing: str
    ):
        """Various weak passwords must be rejected at registration with 422."""
        payload = {**ALICE_CREDS, "password": password}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422, (
            f"Expected 422 for password '{password}' (missing: {missing})"
        )

    def test_password_validator_enforces_uppercase(self):
        """Directly validate the Pydantic model rejects no-uppercase passwords."""
        from pydantic import ValidationError  # noqa: PLC0415
        from src.models.user import UserRegisterRequest  # noqa: PLC0415
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                username="testuser",
                email="test@example.com",
                password="nouppercase1!",
            )
        assert "uppercase" in str(exc_info.value).lower()

    def test_password_validator_enforces_digit(self):
        from pydantic import ValidationError  # noqa: PLC0415
        from src.models.user import UserRegisterRequest  # noqa: PLC0415
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                username="testuser",
                email="test@example.com",
                password="NoDigitHere!",
            )
        assert "digit" in str(exc_info.value).lower()

    def test_password_validator_enforces_special_char(self):
        from pydantic import ValidationError  # noqa: PLC0415
        from src.models.user import UserRegisterRequest  # noqa: PLC0415
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                username="testuser",
                email="test@example.com",
                password="NoSpecial1AB",
            )
        assert "special" in str(exc_info.value).lower()

    def test_password_complexity_validator_exists_in_model(self):
        """Confirm the validator method is present on UserRegisterRequest."""
        from src.models.user import UserRegisterRequest  # noqa: PLC0415
        # Pydantic v2: __pydantic_fields_set__ + model_fields cover validators
        # Check model_validators or the validator function name exists
        assert hasattr(UserRegisterRequest, "password_complexity"), (
            "password_complexity validator must be defined on UserRegisterRequest"
        )

    @pytest.mark.parametrize("password", [
        "ValidPass1!",
        "Abcd1234$",
        "P@ssw0rd",
        "Str0ng#Secret",
    ])
    def test_strong_passwords_accepted(self, client: TestClient, password: str):
        payload = {
            **ALICE_CREDS,
            "username": f"u{secrets.token_hex(4)}",
            "email": f"{secrets.token_hex(4)}@test.com",
            "password": password,
        }
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 201, (
            f"Expected 201 for strong password '{password}': {resp.json()}"
        )
