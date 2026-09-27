"""
conftest.py — Shared fixtures for the AegisDev test suite.

Design decisions
----------------
* JWT_SECRET must be set **before** any src.* import because
  src/services/auth_service.py reads it at module-load time and raises
  EnvironmentError if absent.  We patch os.environ in the session-scoped
  autouse fixture, then reload every relevant module so the secret is
  picked up cleanly regardless of import order.
* Each test gets a fresh, empty in-memory store via the `reset_stores`
  function-scoped fixture (autouse).  This prevents test-order pollution.
* The `client` fixture provides a FastAPI TestClient wired to the app.
* Named user fixtures (alice, bob_admin) pre-register users and return
  a dict with both profile fields and a valid access_token.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Session-scoped environment bootstrap
# Must run before any src.* code is imported.
# ---------------------------------------------------------------------------
TEST_JWT_SECRET = "test-secret-for-pytest-suite-do-not-use-in-prod-abc123XYZ!"
TEST_ALLOWED_ORIGINS = "http://localhost:3000"

# Set env vars immediately at collection time so module-level code in
# auth_service.py sees them when it is first imported.
os.environ.setdefault("JWT_SECRET", TEST_JWT_SECRET)
os.environ.setdefault("ALLOWED_ORIGINS", TEST_ALLOWED_ORIGINS)
os.environ.setdefault("ACCESS_TOKEN_TTL", "3600")


# ---------------------------------------------------------------------------
# Reload helper — ensures a clean module state across parametrised sessions
# ---------------------------------------------------------------------------

def _reload_app() -> None:
    """
    Reload all src.* modules so that module-level state (stores, locks,
    revocation sets) is reset to empty dicts/sets.  Called by reset_stores.
    """
    mods_to_reload = [
        "src.models.user",
        "src.services.auth_service",
        "src.controllers.auth_controller",
        "src.controllers.data_controller",
        "src.main",
    ]
    for name in mods_to_reload:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_stores():
    """
    Function-scoped autouse fixture.
    Reloads all src modules before each test, producing fresh empty stores
    and a clean revocation set.  Guarantees test isolation.
    """
    _reload_app()
    yield
    # No teardown needed — next test's setup will reload again.


@pytest.fixture()
def client() -> TestClient:
    """Return a FastAPI TestClient bound to the current app instance."""
    # Import after reload so we always get the freshly reloaded app object.
    # raise_server_exceptions=False so that the app's own exception handler
    # (not pytest) intercepts unhandled errors — required for TD-09 test.
    from src.main import app  # noqa: PLC0415
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Seed data helpers
# ---------------------------------------------------------------------------

ALICE_CREDS = {
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePass1!",
    "role": "developer",
}

BOB_ADMIN_CREDS = {
    "username": "bobadmin",
    "email": "bob@example.com",
    "password": "AdminPass1!",
    "role": "admin",
}

CHARLIE_VIEWER_CREDS = {
    "username": "charlie",
    "email": "charlie@example.com",
    "password": "ViewerPass1!",
    "role": "viewer",
}


def _register_and_login(client: TestClient, creds: dict) -> dict:
    """Register a user, log in, and return profile + token."""
    reg_resp = client.post("/auth/register", json=creds)
    assert reg_resp.status_code == 201, f"Registration failed: {reg_resp.json()}"
    profile = reg_resp.json()

    login_resp = client.post(
        "/auth/login",
        json={"username": creds["username"], "password": creds["password"]},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.json()}"
    token_data = login_resp.json()

    return {**profile, "access_token": token_data["access_token"]}


@pytest.fixture()
def alice(client: TestClient) -> dict:
    """Pre-registered developer user with a valid access token."""
    return _register_and_login(client, ALICE_CREDS)


@pytest.fixture()
def bob_admin(client: TestClient) -> dict:
    """Pre-registered admin user with a valid access token."""
    return _register_and_login(client, BOB_ADMIN_CREDS)


@pytest.fixture()
def charlie_viewer(client: TestClient) -> dict:
    """Pre-registered viewer user with a valid access token."""
    return _register_and_login(client, CHARLIE_VIEWER_CREDS)


def auth_headers(token: str) -> dict:
    """Convenience helper: build Authorization header dict."""
    return {"Authorization": f"Bearer {token}"}
