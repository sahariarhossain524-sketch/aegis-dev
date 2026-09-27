"""
Authentication controller — /auth/* endpoints.

Security posture (post-AegisDev audit):
  ✅ TD-03  /auth/logout endpoint revokes the caller's JWT via JTI.
"""

from __future__ import annotations

import logging
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.models.user import (
    TokenResponse,
    UserLoginRequest,
    UserProfileResponse,
    UserRegisterRequest,
)
from src.services import auth_service

logger = logging.getLogger("aegisdev.auth_controller")
router = APIRouter()
bearer_scheme = HTTPBearer()


# ---------------------------------------------------------------------------
# Dependency — extract & validate the caller's identity from the JWT
# ---------------------------------------------------------------------------

def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> dict:
    """
    Decode the Bearer token and return its payload.

    Raises:
        HTTPException 401: for expired or invalid tokens.
    """
    try:
        payload = auth_service.decode_token(credentials.credentials)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin(current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """Gate access to admin-only endpoints."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required.",
        )
    return current_user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=UserProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(req: UserRegisterRequest):
    """
    Create a new user account and return the profile.

    - **username**: 3–32 alphanumeric characters
    - **email**: valid e-mail address
    - **password**: minimum 8 characters
    - **role**: `developer` (default), `viewer`, or `admin`
    """
    try:
        user = auth_service.register_user(req)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    return UserProfileResponse(**user.to_dict())


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and obtain a JWT",
)
async def login(req: UserLoginRequest):
    """
    Validate credentials and return a signed JWT access token.

    Note: Brute-force protection should be enforced at the API gateway layer
    (e.g. rate-limiting middleware or a WAF rule).
    """
    try:
        token_resp = auth_service.authenticate_user(req)
    except ValueError as exc:
        # Return 401 for all credential failures (avoids username enumeration).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_resp


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the current session token",
)
async def logout(current_user: Annotated[dict, Depends(get_current_user)]):
    """
    FIX TD-03: Revoke the caller's JWT by adding its JTI to the revocation
    set.  Subsequent requests using the same token will receive 401.
    """
    jti = current_user.get("jti")
    if jti:
        auth_service.revoke_token(jti)


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get current user's profile",
)
async def get_profile(current_user: Annotated[dict, Depends(get_current_user)]):
    """Return the profile of the authenticated user."""
    user = auth_service.get_user_by_id(current_user["sub"])
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return UserProfileResponse(**user.to_dict())


@router.get(
    "/users",
    response_model=list[UserProfileResponse],
    summary="[Admin] List all users",
)
async def list_users(admin: Annotated[dict, Depends(require_admin)]):
    """Return all registered users. Requires admin role."""
    return [UserProfileResponse(**u.to_dict()) for u in auth_service.get_all_users()]
