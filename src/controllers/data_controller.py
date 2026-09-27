"""
Data controller — resource management endpoints with query filtering,
pagination, and owner-scoped access control.

Security posture (post-AegisDev audit):
  ✅ TD-06  threading.Lock guards all compound mutations on _RESOURCE_STORE.
  ✅ TD-07  search capped at 100 chars with strict allow-list regex.
           tag capped at 50 chars with allow-list regex.
           owner_id validated as UUID format.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.controllers.auth_controller import get_current_user
from src.models.user import (
    PaginatedResourceResponse,
    ResourceCreateRequest,
    ResourceRecord,
    ResourceResponse,
    ResourceStatus,
    ResourceUpdateRequest,
)

logger = logging.getLogger("aegisdev.data_controller")
router = APIRouter()

# ---------------------------------------------------------------------------
# FIX TD-06: Thread-safe in-memory resource store.
#            Migration path: replace with SQLAlchemy + PostgreSQL.
# ---------------------------------------------------------------------------
_RESOURCE_STORE: dict[str, ResourceRecord] = {}
_RESOURCE_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# FIX TD-07: Compiled allow-list patterns for query parameters.
# ---------------------------------------------------------------------------
_SEARCH_RE = re.compile(r'^[\w\s\-\.]+$')
_TAG_RE = re.compile(r'^[\w\-]+$')
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record_to_response(r: ResourceRecord) -> ResourceResponse:
    return ResourceResponse(**r.to_dict())


def _assert_owner_or_admin(resource: ResourceRecord, caller: dict) -> None:
    """Raise 403 if the caller neither owns the resource nor is an admin."""
    if resource.owner_id != caller["sub"] and caller.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to modify this resource.",
        )


def _validate_uuid_param(value: Optional[str], param_name: str) -> None:
    """
    FIX TD-07: Reject owner_id values that are not well-formed UUIDs to
    prevent injection if this layer is ever ported to a SQL backend.
    """
    if value is not None and not _UUID_RE.match(value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{param_name}' must be a valid UUID.",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/resources",
    response_model=ResourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new resource",
)
async def create_resource(
    req: ResourceCreateRequest,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """Create a new project resource owned by the authenticated user."""
    resource = ResourceRecord(
        name=req.name,
        description=req.description,
        owner_id=current_user["sub"],
        tags=req.tags,
    )
    with _RESOURCE_LOCK:
        _RESOURCE_STORE[resource.id] = resource
    logger.info("Resource created: %s by user %s", resource.id, current_user["sub"])
    return _record_to_response(resource)


@router.get(
    "/resources",
    response_model=PaginatedResourceResponse,
    summary="List resources with optional filtering",
)
async def list_resources(
    current_user: Annotated[dict, Depends(get_current_user)],
    status_filter: Optional[ResourceStatus] = Query(None, alias="status"),
    # FIX TD-07: search — max 100 chars, strict allow-list pattern.
    search: Optional[str] = Query(
        None,
        max_length=100,
        description="Case-insensitive name search (letters, digits, spaces, hyphens, dots)",
    ),
    # FIX TD-07: tag — max 50 chars, strict allow-list pattern.
    tag: Optional[str] = Query(
        None,
        max_length=50,
        description="Filter by tag (word characters and hyphens only)",
    ),
    owner_id: Optional[str] = Query(None, description="Filter by owner UUID"),
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Return a paginated list of resources."""
    # Validate pattern constraints for search and tag (FastAPI Query max_length
    # handles length; we apply the allow-list regex here for extra safety).
    if search is not None and not _SEARCH_RE.match(search):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'search' contains invalid characters. Use letters, digits, spaces, hyphens, and dots only.",
        )
    if tag is not None and not _TAG_RE.match(tag):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'tag' contains invalid characters. Use letters, digits, hyphens, and underscores only.",
        )
    _validate_uuid_param(owner_id, "owner_id")

    with _RESOURCE_LOCK:
        items = list(_RESOURCE_STORE.values())

    # Viewers and developers see only their own resources unless they're admin.
    if current_user.get("role") != "admin":
        items = [r for r in items if r.owner_id == current_user["sub"]]

    # Query filters — all inputs are sanitised above before reaching here.
    if status_filter:
        items = [r for r in items if r.status == status_filter]
    if tag:
        items = [r for r in items if tag.lower() in r.tags]
    if owner_id:
        items = [r for r in items if r.owner_id == owner_id]
    if search:
        items = [r for r in items if search.lower() in r.name.lower()]

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return PaginatedResourceResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_record_to_response(r) for r in page_items],
    )


@router.get(
    "/resources/{resource_id}",
    response_model=ResourceResponse,
    summary="Get a single resource by ID",
)
async def get_resource(
    resource_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    _validate_uuid_param(resource_id, "resource_id")
    with _RESOURCE_LOCK:
        resource = _RESOURCE_STORE.get(resource_id)
    if not resource:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
    _assert_owner_or_admin(resource, current_user)
    return _record_to_response(resource)


@router.patch(
    "/resources/{resource_id}",
    response_model=ResourceResponse,
    summary="Partially update a resource",
)
async def update_resource(
    resource_id: str,
    req: ResourceUpdateRequest,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    _validate_uuid_param(resource_id, "resource_id")
    with _RESOURCE_LOCK:
        resource = _RESOURCE_STORE.get(resource_id)
        if not resource:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
        _assert_owner_or_admin(resource, current_user)

        if req.name is not None:
            resource.name = req.name
        if req.description is not None:
            resource.description = req.description
        if req.tags is not None:
            resource.tags = req.tags
        if req.status is not None:
            resource.status = req.status
        resource.updated_at = datetime.utcnow()

    logger.info("Resource updated: %s by user %s", resource_id, current_user["sub"])
    return _record_to_response(resource)


@router.delete(
    "/resources/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a resource",
)
async def delete_resource(
    resource_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    _validate_uuid_param(resource_id, "resource_id")
    with _RESOURCE_LOCK:
        resource = _RESOURCE_STORE.get(resource_id)
        if not resource:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
        _assert_owner_or_admin(resource, current_user)
        del _RESOURCE_STORE[resource_id]
    logger.info("Resource deleted: %s by user %s", resource_id, current_user["sub"])
