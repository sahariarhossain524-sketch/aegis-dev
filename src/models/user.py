"""
User data models and Pydantic schema definitions.

Security posture (post-AegisDev audit):
  ✅ TD-10  Password complexity validator enforces uppercase, digit, and
            special-character requirements (OWASP ASVS 2.1.1, CWE-521).
  ✅ TD-07  ResourceCreateRequest tag validation hardened; search/tag
            constraints are enforced at the Query() layer in data_controller.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class UserRole(str, Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class ResourceStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DRAFT = "draft"


# ---------------------------------------------------------------------------
# ORM-style in-memory entity (replaces a real DB model for this demo)
# ---------------------------------------------------------------------------

class UserRecord:
    """
    Represents a persisted user row.  In production this maps to a SQLAlchemy
    model or similar ORM entity.
    """

    def __init__(
        self,
        username: str,
        email: str,
        hashed_password: str,
        role: UserRole = UserRole.DEVELOPER,
    ):
        self.id: str = str(uuid.uuid4())
        self.username: str = username
        self.email: str = email
        self.hashed_password: str = hashed_password
        self.role: UserRole = role
        self.created_at: datetime = datetime.utcnow()
        self.last_login: Optional[datetime] = None
        self.is_active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_active": self.is_active,
        }


# ---------------------------------------------------------------------------
# Resource entity
# ---------------------------------------------------------------------------

class ResourceRecord:
    """Represents a generic project resource (e.g. a code review task)."""

    def __init__(
        self,
        name: str,
        description: str,
        owner_id: str,
        tags: list[str] | None = None,
    ):
        self.id: str = str(uuid.uuid4())
        self.name: str = name
        self.description: str = description
        self.owner_id: str = owner_id
        self.tags: list[str] = tags or []
        self.status: ResourceStatus = ResourceStatus.DRAFT
        self.created_at: datetime = datetime.utcnow()
        self.updated_at: datetime = datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "tags": self.tags,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------

# Compiled once at import time for performance.
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
_TAG_RE = re.compile(r'^[\w-]+$')
_PASSWORD_UPPER_RE = re.compile(r'[A-Z]')
_PASSWORD_DIGIT_RE = re.compile(r'[0-9]')
_PASSWORD_SPECIAL_RE = re.compile(r'[^A-Za-z0-9]')


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.DEVELOPER

    @field_validator("username")
    @classmethod
    def username_format(cls, v: str) -> str:
        """
        FIX TD-10 (partial): Enforce strict allow-list for usernames.
        Only alphanumeric characters, hyphens, and underscores are permitted.
        """
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username may only contain letters, digits, hyphens, and underscores."
            )
        return v

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        """
        FIX TD-10: Enforce OWASP ASVS 2.1.1 password complexity requirements.
        Password must include at least one uppercase letter, one digit, and
        one special character.
        """
        missing: list[str] = []
        if not _PASSWORD_UPPER_RE.search(v):
            missing.append("one uppercase letter")
        if not _PASSWORD_DIGIT_RE.search(v):
            missing.append("one digit (0–9)")
        if not _PASSWORD_SPECIAL_RE.search(v):
            missing.append("one special character (e.g. !@#$%)")
        if missing:
            raise ValueError(
                f"Password must contain: {', '.join(missing)}."
            )
        return v


class UserLoginRequest(BaseModel):
    username: str = Field(..., max_length=32)
    password: str = Field(..., max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole
    created_at: str
    last_login: Optional[str]
    is_active: bool


class ResourceCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field(..., max_length=1000)
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def tags_valid(cls, v: list[str]) -> list[str]:
        """
        FIX TD-07 (partial): Enforce tag allow-list and count limit.
        Each tag must consist of word characters and hyphens only.
        """
        if len(v) > 20:
            raise ValueError("A resource may not have more than 20 tags.")
        cleaned: list[str] = []
        for tag in v:
            t = tag.strip().lower()
            if len(t) > 50:
                raise ValueError(f"Tag '{t[:20]}…' exceeds the 50-character limit.")
            if not _TAG_RE.match(t):
                raise ValueError(
                    f"Tag '{t}' contains invalid characters. "
                    "Only letters, digits, hyphens, and underscores are allowed."
                )
            cleaned.append(t)
        return cleaned


class ResourceUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=1000)
    tags: Optional[list[str]] = None
    status: Optional[ResourceStatus] = None

    @field_validator("tags")
    @classmethod
    def tags_valid(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Apply the same tag validation on update payloads."""
        if v is None:
            return v
        if len(v) > 20:
            raise ValueError("A resource may not have more than 20 tags.")
        cleaned: list[str] = []
        for tag in v:
            t = tag.strip().lower()
            if len(t) > 50:
                raise ValueError(f"Tag '{t[:20]}…' exceeds the 50-character limit.")
            if not _TAG_RE.match(t):
                raise ValueError(
                    f"Tag '{t}' contains invalid characters."
                )
            cleaned.append(t)
        return cleaned


class ResourceResponse(BaseModel):
    id: str
    name: str
    description: str
    owner_id: str
    tags: list[str]
    status: ResourceStatus
    created_at: str
    updated_at: str


class PaginatedResourceResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[ResourceResponse]
