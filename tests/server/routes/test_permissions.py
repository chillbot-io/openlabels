"""
Tests for Permissions Explorer API endpoints.

Tests focus on:
- Exposure summary computation
- Directory permission listing with filters
- ACL detail retrieval
- Principal access lookup
- Exposure level derivation logic
- Tenant isolation
"""

import pytest
from uuid import uuid4

from openlabels.server.routes.permissions import _exposure_level


# ── Unit Tests ──────────────────────────────────────────────────────────


class TestExposureLevel:
    """Tests for _exposure_level() helper."""

    def test_unknown_when_no_sd(self):
        assert _exposure_level(None, None, None, sd_exists=False) == "UNKNOWN"

    def test_public_when_world_accessible(self):
        assert _exposure_level(True, False, False, sd_exists=True) == "PUBLIC"

    def test_public_trumps_other_flags(self):
        assert _exposure_level(True, True, True, sd_exists=True) == "PUBLIC"

    def test_org_wide_when_authenticated_users(self):
        assert _exposure_level(False, True, False, sd_exists=True) == "ORG_WIDE"

    def test_internal_when_custom_acl(self):
        assert _exposure_level(False, False, True, sd_exists=True) == "INTERNAL"

    def test_private_when_no_flags(self):
        assert _exposure_level(False, False, False, sd_exists=True) == "PRIVATE"

    def test_none_flags_with_sd_existing(self):
        assert _exposure_level(None, None, None, sd_exists=True) == "PRIVATE"


# ── API Endpoint Tests ──────────────────────────────────────────────────


@pytest.fixture
async def setup_permissions_data(test_db):
    """Set up directory tree and security descriptor test data."""
    from sqlalchemy import select
    from openlabels.server.models import (
        Tenant, User, ScanTarget, DirectoryTree, SecurityDescriptor,
    )

    # Get existing tenant/user from test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create a target
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Permissions Test Target",
        adapter="filesystem",
        config={"path": "/data/test"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.flush()

    # Create security descriptors
    sd_public = SecurityDescriptor(
        sd_hash="sd_public_hash",
        world_accessible=True,
        authenticated_users=False,
        custom_acl=False,
        owner_sid="S-1-5-32-544",
        group_sid="S-1-5-32-545",
        dacl_sddl="D:(A;;GA;;;WD)",
        permissions_json={"Everyone": ["READ", "EXECUTE"]},
    )
    sd_private = SecurityDescriptor(
        sd_hash="sd_private_hash",
        world_accessible=False,
        authenticated_users=False,
        custom_acl=False,
        owner_sid="S-1-5-32-544",
    )
    sd_org = SecurityDescriptor(
        sd_hash="sd_org_hash",
        world_accessible=False,
        authenticated_users=True,
        custom_acl=False,
        permissions_json={"Authenticated Users": ["READ"]},
    )
    test_db.add_all([sd_public, sd_private, sd_org])
    await test_db.flush()

    # Create directories
    dirs = []
    # Public directory
    d1 = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/test/public",
        dir_name="public",
        sd_hash="sd_public_hash",
        child_dir_count=2,
        child_file_count=10,
    )
    # Private directory
    d2 = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/test/private",
        dir_name="private",
        sd_hash="sd_private_hash",
        child_dir_count=0,
        child_file_count=5,
    )
    # Org-wide directory
    d3 = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/test/shared",
        dir_name="shared",
        sd_hash="sd_org_hash",
        child_dir_count=1,
        child_file_count=3,
    )
    # Unknown (no SD)
    d4 = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/test/unknown",
        dir_name="unknown",
        sd_hash=None,
        child_dir_count=0,
        child_file_count=1,
    )
    dirs = [d1, d2, d3, d4]
    test_db.add_all(dirs)
    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "dirs": dirs,
    }


class TestExposureSummary:
    """Tests for GET /api/permissions/exposure endpoint."""

    async def test_returns_exposure_summary(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/permissions/exposure")
        assert response.status_code == 200
        data = response.json()
        assert "total_directories" in data
        assert "with_security_descriptor" in data
        assert "world_accessible" in data
        assert "authenticated_users" in data
        assert "custom_acl" in data
        assert "private" in data

    async def test_counts_are_correct(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/permissions/exposure")
        data = response.json()
        assert data["total_directories"] == 4
        assert data["with_security_descriptor"] == 3
        assert data["world_accessible"] == 1
        assert data["authenticated_users"] == 1
        assert data["private"] == 1  # sd_private has no flags set

    async def test_filter_by_target(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(
            f"/api/permissions/exposure?target_id={target_id}"
        )
        assert response.status_code == 200
        assert response.json()["total_directories"] == 4

    async def test_filter_by_nonexistent_target(self, test_client, setup_permissions_data):
        response = await test_client.get(
            f"/api/permissions/exposure?target_id={uuid4()}"
        )
        assert response.status_code == 200
        assert response.json()["total_directories"] == 0


class TestListDirectoryPermissions:
    """Tests for GET /api/permissions/{target_id}/directories endpoint."""

    async def test_returns_paginated_directories(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(f"/api/permissions/{target_id}/directories")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    async def test_returns_root_directories(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(f"/api/permissions/{target_id}/directories")
        data = response.json()
        # All 4 dirs have no parent, so they're all roots
        assert data["total"] == 4

    async def test_directories_have_exposure_level(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(f"/api/permissions/{target_id}/directories")
        data = response.json()
        for item in data["items"]:
            assert "exposure_level" in item
            assert item["exposure_level"] in {"PUBLIC", "ORG_WIDE", "INTERNAL", "PRIVATE", "UNKNOWN"}

    async def test_filter_by_public_exposure(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(
            f"/api/permissions/{target_id}/directories?exposure=PUBLIC"
        )
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["exposure_level"] == "PUBLIC"

    async def test_filter_by_unknown_exposure(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(
            f"/api/permissions/{target_id}/directories?exposure=UNKNOWN"
        )
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["dir_name"] == "unknown"

    async def test_empty_result_for_wrong_target(self, test_client, setup_permissions_data):
        response = await test_client.get(f"/api/permissions/{uuid4()}/directories")
        data = response.json()
        assert data["total"] == 0


class TestGetDirectoryACL:
    """Tests for GET /api/permissions/{target_id}/acl/{dir_id} endpoint."""

    async def test_returns_acl_detail(self, test_client, setup_permissions_data):
        target = setup_permissions_data["target"]
        public_dir = setup_permissions_data["dirs"][0]  # public dir
        response = await test_client.get(
            f"/api/permissions/{target.id}/acl/{public_dir.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["dir_path"] == "/data/test/public"
        assert data["exposure_level"] == "PUBLIC"
        assert data["world_accessible"] is True
        assert data["owner_sid"] == "S-1-5-32-544"

    async def test_returns_private_acl(self, test_client, setup_permissions_data):
        target = setup_permissions_data["target"]
        private_dir = setup_permissions_data["dirs"][1]
        response = await test_client.get(
            f"/api/permissions/{target.id}/acl/{private_dir.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["exposure_level"] == "PRIVATE"
        assert data["world_accessible"] is False

    async def test_returns_404_for_nonexistent_dir(self, test_client, setup_permissions_data):
        target = setup_permissions_data["target"]
        response = await test_client.get(
            f"/api/permissions/{target.id}/acl/{uuid4()}"
        )
        assert response.status_code == 404

    async def test_returns_404_for_wrong_target(self, test_client, setup_permissions_data):
        public_dir = setup_permissions_data["dirs"][0]
        response = await test_client.get(
            f"/api/permissions/{uuid4()}/acl/{public_dir.id}"
        )
        assert response.status_code == 404


class TestLookupPrincipalAccess:
    """Tests for GET /api/permissions/principal/{principal} endpoint."""

    async def test_finds_principal_with_access(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/permissions/principal/Everyone")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert data["items"][0]["dir_path"] == "/data/test/public"

    async def test_returns_empty_for_unknown_principal(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/permissions/principal/NonexistentUser")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0

    async def test_returns_permissions_list(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/permissions/principal/Everyone")
        data = response.json()
        if data["total"] > 0:
            item = data["items"][0]
            assert "permissions" in item
            assert isinstance(item["permissions"], list)
