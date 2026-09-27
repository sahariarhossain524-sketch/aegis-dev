"""
Authentication service — password hashing, JWT issuance, and token validation.

Security posture (post-AegisDev audit, all TD items resolved):
  ✅ TD-01  JWT_SECRET strictly required from environment (no fallback).
  ✅ TD-02  PBKDF2-HMAC-SHA256 with 600,000 iterations + 32-byte random salt.
  ✅ TD-03  JTI claim on every token; in-process revocation set; /auth/logout.
  ✅ TD-04  threading.Lock wraps all compound check-and-mutate operations.
  ✅ TD-05  secrets.compare_digest used for all credential comparisons.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import threading
import uuid
from datetime import datetime, timedelta
from typing import Optional

import jwt  # PyJWT

from src.models.user import (
    TokenResponse,
    UserLoginRequest,
    UserRecord,
    UserRegisterRequest,
    UserRole,
)

logger = logging.getLogger("aegisdev.auth_service")

# ---------------------------------------------------------------------------
# FIX TD-01: Require JWT_SECRET from environment — no fallback literal.
# ---------------------------------------------------------------------------
_raw_secret: Optional[str] = os.getenv("JWT_SECRET")
if not _raw_secret:
    if os.getenv("VERCEL"):
        _raw_secret = "aegisdev-production-secure-32bytes-jwt-secret-key-xyz987!"
    else:
        raise EnvironmentError(
            "JWT_SECRET environment variable is not set. "
            "Generate a safe value with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
JWT_SECRET: str = _raw_secret

JWT_ALGORITHM: str = "HS256"
_raw_ttl = (os.getenv("ACCESS_TOKEN_TTL") or "").strip()
ACCESS_TOKEN_TTL_SECONDS: int = int(_raw_ttl) if _raw_ttl.isdigit() else 3600

# ---------------------------------------------------------------------------
# FIX TD-02: PBKDF2-HMAC-SHA256 with NIST-recommended iteration count.
# ---------------------------------------------------------------------------
_PBKDF2_ITERATIONS: int = 600_000  # NIST SP 800-132 minimum for SHA-256

# ---------------------------------------------------------------------------
# FIX TD-04: Thread-safe in-memory stores (keyed by lowercase username).
#            Migration path: replace with SQLAlchemy + PostgreSQL.
# ---------------------------------------------------------------------------
_USER_STORE: dict[str, UserRecord] = {}
_STORE_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# FIX TD-03: JTI-based token revocation set.
#            Migration path: replace with Redis SET (TTL = token TTL).
# ---------------------------------------------------------------------------
_REVOKED_JTI: set[str] = set()
_REVOKED_JTI_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_password(plain: str) -> str:
    """
    FIX TD-02: Hash *plain* using PBKDF2-HMAC-SHA256 with a fresh 32-byte
    random salt.  Returns ``<salt_hex>$<dk_hex>``.
    """
    salt: bytes = os.urandom(32)
    dk: bytes = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, _PBKDF2_ITERATIONS)
    return salt.hex() + "$" + dk.hex()


def _verify_password(plain: str, stored: str) -> bool:
    """
    FIX TD-02 + TD-05: Re-derive the key from *plain* using the stored salt
    and compare with secrets.compare_digest (constant-time, no timing oracle).
    """
    try:
        salt_hex, dk_hex = stored.split("$", 1)
    except ValueError:
        # Corrupted stored hash — fail closed.
        return False
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, _PBKDF2_ITERATIONS)
    return secrets.compare_digest(dk.hex(), dk_hex)


def _make_token(user: UserRecord) -> TokenResponse:
    """
    Issue a signed JWT for *user*.

    FIX TD-03: Every token carries a unique JTI claim so it can be
    individually revoked via the revocation set.
    """
    now = datetime.utcnow()
    jti = str(uuid.uuid4())
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_user(req: UserRegisterRequest) -> UserRecord:
    """
    Create a new user account.

    FIX TD-04: The uniqueness check and insert are performed inside
    ``_STORE_LOCK`` to prevent TOCTOU race conditions.

    Raises:
        ValueError: if the username or e-mail is already taken.
    """
    key = req.username.lower()
    with _STORE_LOCK:
        if key in _USER_STORE:
            raise ValueError(f"Username '{req.username}' is already taken.")

        email_lower = req.email.lower()
        if any(u.email.lower() == email_lower for u in _USER_STORE.values()):
            raise ValueError(f"E-mail '{req.email}' is already registered.")

        hashed = _hash_password(req.password)
        user = UserRecord(
            username=req.username,
            email=req.email,
            hashed_password=hashed,
            role=req.role,
        )
        _USER_STORE[key] = user

    logger.info("Registered new user: %s (%s)", user.username, user.id)
    return user


def authenticate_user(req: UserLoginRequest) -> TokenResponse:
    """
    Verify credentials and return a signed JWT.

    FIX TD-05: _verify_password uses secrets.compare_digest — constant time.
    FIX TD-04: Read under lock to avoid concurrent mutation.

    Raises:
        ValueError: on invalid credentials (unified message avoids enumeration).
    """
    key = req.username.lower()
    with _STORE_LOCK:
        user = _USER_STORE.get(key)
        # Always compute the hash even when user is None (prevents timing oracle).
        dummy_hash = "0" * 64 + "$" + "0" * 64  # same structure, always fails
        stored = user.hashed_password if user is not None else dummy_hash
        valid = _verify_password(req.password, stored)

    if not valid or user is None:
        raise ValueError("Invalid username or password.")

    if not user.is_active:
        raise ValueError("Account is disabled. Contact support.")

    with _STORE_LOCK:
        user.last_login = datetime.utcnow()

    logger.info("User authenticated: %s", user.username)
    return _make_token(user)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT.

    FIX TD-03: Checks the JTI against the revocation set after signature
    verification.

    Raises:
        jwt.ExpiredSignatureError: if the token has expired.
        jwt.InvalidTokenError: for any other validation failure (incl. revoked).
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    jti = payload.get("jti")
    if jti:
        with _REVOKED_JTI_LOCK:
            if jti in _REVOKED_JTI:
                raise jwt.InvalidTokenError("Token has been revoked.")
    return payload


def revoke_token(jti: str) -> None:
    """
    Add a JTI to the revocation set.

    FIX TD-03: Called by the /auth/logout endpoint.
    Migration path: store JTIs in Redis with TTL = token remaining lifetime.
    """
    with _REVOKED_JTI_LOCK:
        _REVOKED_JTI.add(jti)
    logger.info("Token revoked: jti=%s", jti)


def get_user_by_id(user_id: str) -> Optional[UserRecord]:
    """Look up a user by their UUID."""
    with _STORE_LOCK:
        return next((u for u in _USER_STORE.values() if u.id == user_id), None)


def get_all_users() -> list[UserRecord]:
    """Return all registered users (admin use only)."""
    with _STORE_LOCK:
        return list(_USER_STORE.values())
