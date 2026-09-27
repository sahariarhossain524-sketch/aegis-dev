"""
tests/test_resources.py
=======================
Tests for the /api/resources CRUD endpoints:
  - Create resource (auth required)
  - List resources with filtering (status, tag, search, owner_id)
  - Pagination correctness and bounds
  - Get, Patch, Delete — happy path
  - Authorization boundary enforcement (owner vs other user vs admin)
  - Input validation for search/tag query params (TD-07 fix verification)
  - UUID format validation on path params
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_resource(
    client: TestClient,
    token: str,
    name: str = "My Resource",
    description: str = "A test resource",
    tags: list[str] | None = None,
) -> dict:
    payload = {"name": name, "description": description, "tags": tags or []}
    resp = client.post(
        "/api/resources", json=payload, headers=auth_headers(token)
    )
    assert resp.status_code == 201, f"Create failed: {resp.json()}"
    return resp.json()


# ===========================================================================
# Create Resource
# ===========================================================================

class TestCreateResource:

    def test_create_returns_201_with_correct_fields(
        self, client: TestClient, alice: dict
    ):
        r = _create_resource(client, alice["access_token"], name="Sprint-42")
        assert r["name"] == "Sprint-42"
        assert r["status"] == "draft"
        assert r["owner_id"] == alice["id"]
        assert "id" in r

    def test_create_requires_auth(self, client: TestClient):
        resp = client.post(
            "/api/resources",
            json={"name": "x", "description": "y"},
        )
        assert resp.status_code in (401, 403)

    def test_create_with_tags(self, client: TestClient, alice: dict):
        r = _create_resource(
            client, alice["access_token"], tags=["backend", "security"]
        )
        assert "backend" in r["tags"]
        assert "security" in r["tags"]

    def test_create_empty_name_rejected(self, client: TestClient, alice: dict):
        resp = client.post(
            "/api/resources",
            json={"name": "", "description": "desc"},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_create_name_too_long_rejected(self, client: TestClient, alice: dict):
        resp = client.post(
            "/api/resources",
            json={"name": "x" * 121, "description": "desc"},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_create_description_too_long_rejected(
        self, client: TestClient, alice: dict
    ):
        resp = client.post(
            "/api/resources",
            json={"name": "ok", "description": "x" * 1001},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_create_too_many_tags_rejected(
        self, client: TestClient, alice: dict
    ):
        resp = client.post(
            "/api/resources",
            json={"name": "ok", "description": "ok", "tags": [f"tag{i}" for i in range(21)]},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_create_tag_with_invalid_chars_rejected(
        self, client: TestClient, alice: dict
    ):
        resp = client.post(
            "/api/resources",
            json={"name": "ok", "description": "ok", "tags": ["bad tag!"]},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422


# ===========================================================================
# List Resources — basic
# ===========================================================================

class TestListResources:

    def test_list_returns_paginated_response(
        self, client: TestClient, alice: dict
    ):
        _create_resource(client, alice["access_token"], name="R1")
        _create_resource(client, alice["access_token"], name="R2")

        resp = client.get(
            "/api/resources", headers=auth_headers(alice["access_token"])
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert body["page"] == 1
        assert len(body["items"]) == 2

    def test_list_requires_auth(self, client: TestClient):
        resp = client.get("/api/resources")
        assert resp.status_code in (401, 403)

    def test_user_sees_only_own_resources(
        self, client: TestClient, alice: dict, charlie_viewer: dict
    ):
        _create_resource(client, alice["access_token"], name="Alice-R")
        _create_resource(client, charlie_viewer["access_token"], name="Charlie-R")

        alice_list = client.get(
            "/api/resources", headers=auth_headers(alice["access_token"])
        ).json()
        charlie_list = client.get(
            "/api/resources", headers=auth_headers(charlie_viewer["access_token"])
        ).json()

        assert alice_list["total"] == 1
        assert alice_list["items"][0]["name"] == "Alice-R"
        assert charlie_list["total"] == 1
        assert charlie_list["items"][0]["name"] == "Charlie-R"

    def test_admin_sees_all_resources(
        self, client: TestClient, alice: dict, bob_admin: dict
    ):
        _create_resource(client, alice["access_token"], name="Alice-R")
        _create_resource(client, bob_admin["access_token"], name="Admin-R")

        resp = client.get(
            "/api/resources", headers=auth_headers(bob_admin["access_token"])
        )
        assert resp.json()["total"] == 2


# ===========================================================================
# List Resources — Filtering
# ===========================================================================

class TestResourceFiltering:

    def test_filter_by_status(self, client: TestClient, alice: dict):
        r = _create_resource(client, alice["access_token"], name="DraftItem")
        # Patch to active
        client.patch(
            f"/api/resources/{r['id']}",
            json={"status": "active"},
            headers=auth_headers(alice["access_token"]),
        )
        _create_resource(client, alice["access_token"], name="StillDraft")

        resp = client.get(
            "/api/resources?status=active",
            headers=auth_headers(alice["access_token"]),
        )
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["name"] == "DraftItem"

    def test_filter_by_tag(self, client: TestClient, alice: dict):
        _create_resource(
            client, alice["access_token"], name="Tagged", tags=["security"]
        )
        _create_resource(
            client, alice["access_token"], name="Untagged", tags=[]
        )
        resp = client.get(
            "/api/resources?tag=security",
            headers=auth_headers(alice["access_token"]),
        )
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["name"] == "Tagged"

    def test_filter_by_search(self, client: TestClient, alice: dict):
        _create_resource(client, alice["access_token"], name="Sprint Review")
        _create_resource(client, alice["access_token"], name="Database Migration")

        resp = client.get(
            "/api/resources?search=Sprint",
            headers=auth_headers(alice["access_token"]),
        )
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["name"] == "Sprint Review"

    def test_search_is_case_insensitive(self, client: TestClient, alice: dict):
        _create_resource(client, alice["access_token"], name="Sprint Review")
        resp = client.get(
            "/api/resources?search=sprint",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.json()["total"] == 1


# ===========================================================================
# Search / Tag Input Validation (TD-07 fix verification)
# ===========================================================================

class TestQueryParamValidation:

    def test_search_with_special_chars_rejected(
        self, client: TestClient, alice: dict
    ):
        """
        Verifies TD-07 fix: allow-list regex rejects non-safe search terms.
        A semicolon (SQL injection character) must return 422.
        """
        resp = client.get(
            "/api/resources?search=evil';DROP TABLE",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_search_exceeding_max_length_rejected(
        self, client: TestClient, alice: dict
    ):
        """Search is capped at 100 characters."""
        long_search = "a" * 101
        resp = client.get(
            f"/api/resources?search={long_search}",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_tag_with_special_chars_rejected(
        self, client: TestClient, alice: dict
    ):
        resp = client.get(
            "/api/resources?tag=bad<tag>",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_tag_exceeding_max_length_rejected(
        self, client: TestClient, alice: dict
    ):
        long_tag = "t" * 51
        resp = client.get(
            f"/api/resources?tag={long_tag}",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_owner_id_non_uuid_rejected(self, client: TestClient, alice: dict):
        resp = client.get(
            "/api/resources?owner_id=not-a-uuid",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_resource_id_non_uuid_rejected(
        self, client: TestClient, alice: dict
    ):
        resp = client.get(
            "/api/resources/not-a-uuid",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_valid_search_accepted(self, client: TestClient, alice: dict):
        _create_resource(client, alice["access_token"], name="Sprint Review")
        resp = client.get(
            "/api/resources?search=Sprint Review",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 200


# ===========================================================================
# Pagination
# ===========================================================================

class TestPagination:

    def _seed_resources(
        self, client: TestClient, token: str, count: int
    ) -> None:
        for i in range(count):
            _create_resource(client, token, name=f"Resource-{i:03d}")

    def test_pagination_first_page(self, client: TestClient, alice: dict):
        self._seed_resources(client, alice["access_token"], 25)
        resp = client.get(
            "/api/resources?page=1&page_size=10",
            headers=auth_headers(alice["access_token"]),
        )
        body = resp.json()
        assert body["total"] == 25
        assert body["page"] == 1
        assert body["page_size"] == 10
        assert len(body["items"]) == 10

    def test_pagination_second_page(self, client: TestClient, alice: dict):
        self._seed_resources(client, alice["access_token"], 25)
        resp = client.get(
            "/api/resources?page=2&page_size=10",
            headers=auth_headers(alice["access_token"]),
        )
        body = resp.json()
        assert len(body["items"]) == 10
        assert body["page"] == 2

    def test_pagination_last_partial_page(self, client: TestClient, alice: dict):
        self._seed_resources(client, alice["access_token"], 25)
        resp = client.get(
            "/api/resources?page=3&page_size=10",
            headers=auth_headers(alice["access_token"]),
        )
        body = resp.json()
        assert len(body["items"]) == 5

    def test_page_size_exceeding_max_100_rejected(
        self, client: TestClient, alice: dict
    ):
        resp = client.get(
            "/api/resources?page_size=101",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422

    def test_page_zero_rejected(self, client: TestClient, alice: dict):
        resp = client.get(
            "/api/resources?page=0",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 422


# ===========================================================================
# Get / Patch / Delete — happy path
# ===========================================================================

class TestResourceCRUD:

    def test_get_resource_by_id(self, client: TestClient, alice: dict):
        created = _create_resource(
            client, alice["access_token"], name="GetMe"
        )
        resp = client.get(
            f"/api/resources/{created['id']}",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "GetMe"

    def test_get_nonexistent_returns_404(self, client: TestClient, alice: dict):
        import uuid
        fake_id = str(uuid.uuid4())
        resp = client.get(
            f"/api/resources/{fake_id}",
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 404

    def test_patch_resource_name(self, client: TestClient, alice: dict):
        r = _create_resource(client, alice["access_token"], name="Original")
        resp = client.patch(
            f"/api/resources/{r['id']}",
            json={"name": "Updated"},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    def test_patch_resource_status(self, client: TestClient, alice: dict):
        r = _create_resource(client, alice["access_token"])
        assert r["status"] == "draft"
        resp = client.patch(
            f"/api/resources/{r['id']}",
            json={"status": "active"},
            headers=auth_headers(alice["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

    def test_delete_resource(self, client: TestClient, alice: dict):
        r = _create_resource(client, alice["access_token"])
        del_resp = client.delete(
            f"/api/resources/{r['id']}",
            headers=auth_headers(alice["access_token"]),
        )
        assert del_resp.status_code == 204

        get_resp = client.get(
            f"/api/resources/{r['id']}",
            headers=auth_headers(alice["access_token"]),
        )
        assert get_resp.status_code == 404


# ===========================================================================
# Authorization boundaries
# ===========================================================================

class TestAuthorizationBoundaries:

    def test_other_user_cannot_read_resource(
        self, client: TestClient, alice: dict, charlie_viewer: dict
    ):
        r = _create_resource(client, alice["access_token"], name="AliceOnly")
        resp = client.get(
            f"/api/resources/{r['id']}",
            headers=auth_headers(charlie_viewer["access_token"]),
        )
        assert resp.status_code == 403

    def test_other_user_cannot_patch_resource(
        self, client: TestClient, alice: dict, charlie_viewer: dict
    ):
        r = _create_resource(client, alice["access_token"])
        resp = client.patch(
            f"/api/resources/{r['id']}",
            json={"name": "Hijacked"},
            headers=auth_headers(charlie_viewer["access_token"]),
        )
        assert resp.status_code == 403

    def test_other_user_cannot_delete_resource(
        self, client: TestClient, alice: dict, charlie_viewer: dict
    ):
        r = _create_resource(client, alice["access_token"])
        resp = client.delete(
            f"/api/resources/{r['id']}",
            headers=auth_headers(charlie_viewer["access_token"]),
        )
        assert resp.status_code == 403

    def test_admin_can_patch_any_resource(
        self, client: TestClient, alice: dict, bob_admin: dict
    ):
        r = _create_resource(client, alice["access_token"], name="AliceR")
        resp = client.patch(
            f"/api/resources/{r['id']}",
            json={"name": "AdminPatched"},
            headers=auth_headers(bob_admin["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "AdminPatched"

    def test_admin_can_delete_any_resource(
        self, client: TestClient, alice: dict, bob_admin: dict
    ):
        r = _create_resource(client, alice["access_token"])
        resp = client.delete(
            f"/api/resources/{r['id']}",
            headers=auth_headers(bob_admin["access_token"]),
        )
        assert resp.status_code == 204

    def test_unauthenticated_cannot_create_resource(
        self, client: TestClient
    ):
        resp = client.post(
            "/api/resources",
            json={"name": "Stealth", "description": "No auth"},
        )
        assert resp.status_code in (401, 403)
