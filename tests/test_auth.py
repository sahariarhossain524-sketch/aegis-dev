"""
tests/test_auth.py
==================
Tests for the /auth/* endpoints:
  - User registration (happy path, duplicate detection)
  - Password policy enforcement (TD-10 fix verification)
  - Username format enforcement
  - Login (valid credentials, wrong password, unknown user)
  - JWT bearer auth on /auth/me
  - Token revocation via /auth/logout (TD-03 fix verification)
  - Admin-only /auth/users endpoint (role enforcement)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    ALICE_CREDS,
    BOB_ADMIN_CREDS,
    CHARLIE_VIEWER_CREDS,
    auth_headers,
)


# ===========================================================================
# Registration
# ===========================================================================

class TestRegistration:

    def test_register_success_returns_201_and_profile(self, client: TestClient):
        resp = client.post("/auth/register", json=ALICE_CREDS)
        assert resp.status_code == 201
        body = resp.json()
        assert body["username"] == "alice"
        assert body["email"] == "alice@example.com"
        assert body["role"] == "developer"
        assert body["is_active"] is True
        assert "id" in body
        assert "hashed_password" not in body  # never exposed

    def test_register_duplicate_username_returns_409(self, client: TestClient):
        client.post("/auth/register", json=ALICE_CREDS)
        resp = client.post("/auth/register", json=ALICE_CREDS)
        assert resp.status_code == 409
        assert "already taken" in resp.json()["detail"].lower()

    def test_register_duplicate_email_different_username_returns_409(
        self, client: TestClient
    ):
        client.post("/auth/register", json=ALICE_CREDS)
        payload = {**ALICE_CREDS, "username": "alice2"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 409
        assert "already registered" in resp.json()["detail"].lower()

    def test_register_admin_role(self, client: TestClient):
        resp = client.post("/auth/register", json=BOB_ADMIN_CREDS)
        assert resp.status_code == 201
        assert resp.json()["role"] == "admin"

    def test_register_viewer_role(self, client: TestClient):
        resp = client.post("/auth/register", json=CHARLIE_VIEWER_CREDS)
        assert resp.status_code == 201
        assert resp.json()["role"] == "viewer"

    def test_register_missing_required_fields_returns_422(self, client: TestClient):
        resp = client.post("/auth/register", json={"username": "only"})
        assert resp.status_code == 422

    def test_register_invalid_email_returns_422(self, client: TestClient):
        payload = {**ALICE_CREDS, "email": "not-an-email"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422

    def test_register_username_too_short_returns_422(self, client: TestClient):
        payload = {**ALICE_CREDS, "username": "ab"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422

    def test_register_username_too_long_returns_422(self, client: TestClient):
        payload = {**ALICE_CREDS, "username": "a" * 33}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422


# ===========================================================================
# Password Policy (TD-10 fix verification)
# ===========================================================================

class TestPasswordPolicy:

    def _register_with_password(self, client: TestClient, password: str):
        payload = {**ALICE_CREDS, "password": password}
        return client.post("/auth/register", json=payload)

    def test_password_no_uppercase_rejected(self, client: TestClient):
        resp = self._register_with_password(client, "nouppercase1!")
        assert resp.status_code == 422
        detail = str(resp.json())
        assert "uppercase" in detail.lower()

    def test_password_no_digit_rejected(self, client: TestClient):
        resp = self._register_with_password(client, "NoDigitHere!")
        assert resp.status_code == 422
        detail = str(resp.json())
        assert "digit" in detail.lower()

    def test_password_no_special_char_rejected(self, client: TestClient):
        resp = self._register_with_password(client, "NoSpecial1A")
        assert resp.status_code == 422
        detail = str(resp.json())
        assert "special" in detail.lower()

    def test_password_too_short_rejected(self, client: TestClient):
        resp = self._register_with_password(client, "Sh0rt!")
        assert resp.status_code == 422

    def test_password_exceeds_max_length_rejected(self, client: TestClient):
        # max_length=128
        resp = self._register_with_password(client, "Aa1!" + "x" * 125)
        assert resp.status_code == 422

    def test_valid_complex_password_accepted(self, client: TestClient):
        resp = self._register_with_password(client, "ValidPass1!")
        assert resp.status_code == 201

    @pytest.mark.parametrize("password,suffix", [
        ("SecurePass1!", "a"),
        ("P@ssw0rd#Complex", "b"),
        ("Abcd1234$$$", "c"),
        ("MyStr0ng&Secret", "d"),
    ])
    def test_various_valid_passwords_accepted(
        self, client: TestClient, password: str, suffix: str
    ):
        payload = {
            "username": f"valpwduser{suffix}",
            "email": f"valpwduser{suffix}@test.com",
            "password": password,
            "role": "developer",
        }
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 201, f"Expected 201 for password '{password}': {resp.json()}"


# ===========================================================================
# Username Format Validation
# ===========================================================================

class TestUsernameFormat:

    def test_username_with_spaces_rejected(self, client: TestClient):
        payload = {**ALICE_CREDS, "username": "alice smith"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422

    def test_username_with_at_symbol_rejected(self, client: TestClient):
        payload = {**ALICE_CREDS, "username": "alice@evil"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422

    def test_username_with_sql_injection_rejected(self, client: TestClient):
        payload = {**ALICE_CREDS, "username": "'; DROP TABLE users; --"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 422

    def test_username_with_hyphen_and_underscore_accepted(
        self, client: TestClient
    ):
        payload = {**ALICE_CREDS, "username": "alice_dev-01"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 201


# ===========================================================================
# Login
# ===========================================================================

class TestLogin:

    def test_login_valid_credentials_returns_token(
        self, client: TestClient, alice: dict
    ):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": ALICE_CREDS["password"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] > 0

    def test_login_wrong_password_returns_401(
        self, client: TestClient, alice: dict
    ):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "WrongPass1!"},
        )
        assert resp.status_code == 401

    def test_login_unknown_user_returns_401(self, client: TestClient):
        resp = client.post(
            "/auth/login",
            json={"username": "ghost", "password": "GhostPass1!"},
        )
        assert resp.status_code == 401

    def test_login_error_message_does_not_enumerate_users(
        self, client: TestClient, alice: dict
    ):
        """
        Both 'user not found' and 'wrong password' must return identical
        error messages to prevent username enumeration (CWE-204).
        """
        resp_wrong_pass = client.post(
            "/auth/login",
            json={"username": "alice", "password": "WrongPass1!"},
        )
        resp_no_user = client.post(
            "/auth/login",
            json={"username": "nonexistent_xyz", "password": "AnyPass1!"},
        )
        assert resp_wrong_pass.json()["detail"] == resp_no_user.json()["detail"]

    def test_login_case_insensitive_username(
        self, client: TestClient, alice: dict
    ):
        """Username lookup is case-insensitive."""
        resp = client.post(
            "/auth/login",
            json={"username": "ALICE", "password": ALICE_CREDS["password"]},
        )
        assert resp.status_code == 200


# ===========================================================================
# /auth/me — Protected profile endpoint
# ===========================================================================

class TestGetProfile:

    def test_me_with_valid_token_returns_profile(
        self, client: TestClient, alice: dict
    ):
        resp = client.get("/auth/me", headers=auth_headers(alice["access_token"]))
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"

    def test_me_without_token_returns_403_or_401(self, client: TestClient):
        # FastAPI HTTPBearer returns 403 when no credentials provided
        resp = client.get("/auth/me")
        assert resp.status_code in (401, 403)

    def test_me_with_invalid_token_returns_401(self, client: TestClient):
        resp = client.get(
            "/auth/me", headers={"Authorization": "Bearer totally.invalid.token"}
        )
        assert resp.status_code == 401

    def test_me_with_tampered_token_returns_401(
        self, client: TestClient, alice: dict
    ):
        token = alice["access_token"]
        # Tamper last 4 chars of the signature segment
        tampered = token[:-4] + "XXXX"
        resp = client.get("/auth/me", headers=auth_headers(tampered))
        assert resp.status_code == 401


# ===========================================================================
# /auth/logout — Token revocation (TD-03 fix verification)
# ===========================================================================

class TestLogout:

    def test_logout_returns_204(self, client: TestClient, alice: dict):
        resp = client.post(
            "/auth/logout", headers=auth_headers(alice["access_token"])
        )
        assert resp.status_code == 204

    def test_token_is_invalid_after_logout(
        self, client: TestClient, alice: dict
    ):
        """
        After logout the same token must be rejected — verifies TD-03 fix.
        The JTI is added to the revocation set and decode_token raises.
        """
        token = alice["access_token"]
        # Confirm token works before logout
        pre = client.get("/auth/me", headers=auth_headers(token))
        assert pre.status_code == 200

        # Logout
        client.post("/auth/logout", headers=auth_headers(token))

        # Same token must now be rejected
        post = client.get("/auth/me", headers=auth_headers(token))
        assert post.status_code == 401

    def test_second_login_issues_new_token_after_logout(
        self, client: TestClient, alice: dict
    ):
        """New login after logout produces a fresh, valid token."""
        old_token = alice["access_token"]
        client.post("/auth/logout", headers=auth_headers(old_token))

        new_login = client.post(
            "/auth/login",
            json={"username": "alice", "password": ALICE_CREDS["password"]},
        )
        assert new_login.status_code == 200
        new_token = new_login.json()["access_token"]
        assert new_token != old_token

        me = client.get("/auth/me", headers=auth_headers(new_token))
        assert me.status_code == 200

    def test_logout_without_token_returns_403_or_401(self, client: TestClient):
        resp = client.post("/auth/logout")
        assert resp.status_code in (401, 403)


# ===========================================================================
# /auth/users — Admin-only listing
# ===========================================================================

class TestAdminUsers:

    def test_admin_can_list_all_users(
        self, client: TestClient, alice: dict, bob_admin: dict
    ):
        resp = client.get(
            "/auth/users", headers=auth_headers(bob_admin["access_token"])
        )
        assert resp.status_code == 200
        usernames = [u["username"] for u in resp.json()]
        assert "alice" in usernames
        assert "bobadmin" in usernames

    def test_non_admin_cannot_list_users_returns_403(
        self, client: TestClient, alice: dict
    ):
        resp = client.get(
            "/auth/users", headers=auth_headers(alice["access_token"])
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_list_users(self, client: TestClient):
        resp = client.get("/auth/users")
        assert resp.status_code in (401, 403)
