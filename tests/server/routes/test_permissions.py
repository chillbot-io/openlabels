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

import hashlib
from uuid import uuid4

import pytest

from openlabels.server.routes.permissions import _exposure_level


def _sd_hash(name: str) -> bytes:
    """Create a deterministic 32-byte hash from a name string."""
    return hashlib.sha256(name.encode()).digest()


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
        DirectoryTree,
        ScanTarget,
        SecurityDescriptor,
        Tenant,
        User,
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
    public_hash = _sd_hash("sd_public_hash")
    private_hash = _sd_hash("sd_private_hash")
    org_hash = _sd_hash("sd_org_hash")

    sd_public = SecurityDescriptor(
        sd_hash=public_hash,
        tenant_id=tenant.id,
        world_accessible=True,
        authenticated_users=False,
        custom_acl=False,
        owner_sid="S-1-5-32-544",
        group_sid="S-1-5-32-545",
        dacl_sddl="D:(A;;GA;;;WD)",
        permissions_json={"Everyone": ["READ", "EXECUTE"]},
    )
    sd_private = SecurityDescriptor(
        sd_hash=private_hash,
        tenant_id=tenant.id,
        world_accessible=False,
        authenticated_users=False,
        custom_acl=False,
        owner_sid="S-1-5-32-544",
    )
    sd_org = SecurityDescriptor(
        sd_hash=org_hash,
        tenant_id=tenant.id,
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
        sd_hash=public_hash,
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
        sd_hash=private_hash,
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
        sd_hash=org_hash,
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
    """Tests for GET /api/v1/permissions/exposure endpoint."""

    async def test_returns_exposure_summary(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/v1/permissions/exposure")
        assert response.status_code == 200
        data = response.json()
        assert "total_directories" in data
        assert "with_security_descriptor" in data
        assert "world_accessible" in data
        assert "authenticated_users" in data
        assert "custom_acl" in data
        assert "private" in data

    async def test_counts_are_correct(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/v1/permissions/exposure")
        data = response.json()
        assert data["total_directories"] == 4
        assert data["with_security_descriptor"] == 3
        assert data["world_accessible"] == 1
        assert data["authenticated_users"] == 1
        assert data["private"] == 1  # sd_private has no flags set

    async def test_filter_by_target(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/exposure?target_id={target_id}"
        )
        assert response.status_code == 200
        assert response.json()["total_directories"] == 4

    async def test_filter_by_nonexistent_target(self, test_client, setup_permissions_data):
        response = await test_client.get(
            f"/api/v1/permissions/exposure?target_id={uuid4()}"
        )
        assert response.status_code == 200
        assert response.json()["total_directories"] == 0


class TestListDirectoryPermissions:
    """Tests for GET /api/v1/permissions/{target_id}/directories endpoint."""

    async def test_returns_paginated_directories(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(f"/api/v1/permissions/{target_id}/directories")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    async def test_returns_root_directories(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(f"/api/v1/permissions/{target_id}/directories")
        data = response.json()
        # All 4 dirs have no parent, so they're all roots
        assert data["total"] == 4

    async def test_directories_have_exposure_level(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(f"/api/v1/permissions/{target_id}/directories")
        data = response.json()
        for item in data["items"]:
            assert "exposure_level" in item
            assert item["exposure_level"] in {"PUBLIC", "ORG_WIDE", "INTERNAL", "PRIVATE", "UNKNOWN"}

    async def test_filter_by_public_exposure(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/{target_id}/directories?exposure=PUBLIC"
        )
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["exposure_level"] == "PUBLIC"

    async def test_filter_by_unknown_exposure(self, test_client, setup_permissions_data):
        target_id = str(setup_permissions_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/{target_id}/directories?exposure=UNKNOWN"
        )
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["dir_name"] == "unknown"

    async def test_empty_result_for_wrong_target(self, test_client, setup_permissions_data):
        response = await test_client.get(f"/api/v1/permissions/{uuid4()}/directories")
        data = response.json()
        assert data["total"] == 0


class TestGetDirectoryACL:
    """Tests for GET /api/v1/permissions/{target_id}/acl/{dir_id} endpoint."""

    async def test_returns_acl_detail(self, test_client, setup_permissions_data):
        target = setup_permissions_data["target"]
        public_dir = setup_permissions_data["dirs"][0]  # public dir
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{public_dir.id}"
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
            f"/api/v1/permissions/{target.id}/acl/{private_dir.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["exposure_level"] == "PRIVATE"
        assert data["world_accessible"] is False

    async def test_returns_404_for_nonexistent_dir(self, test_client, setup_permissions_data):
        target = setup_permissions_data["target"]
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{uuid4()}"
        )
        assert response.status_code == 404

    async def test_returns_404_for_wrong_target(self, test_client, setup_permissions_data):
        public_dir = setup_permissions_data["dirs"][0]
        response = await test_client.get(
            f"/api/v1/permissions/{uuid4()}/acl/{public_dir.id}"
        )
        assert response.status_code == 404


class TestLookupPrincipalAccess:
    """Tests for GET /api/v1/permissions/principal/{principal} endpoint."""

    async def test_finds_principal_with_access(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/v1/permissions/principal/Everyone")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert data["items"][0]["dir_path"] == "/data/test/public"

    async def test_returns_empty_for_unknown_principal(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/v1/permissions/principal/NonexistentUser")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0

    async def test_returns_permissions_list(self, test_client, setup_permissions_data):
        response = await test_client.get("/api/v1/permissions/principal/Everyone")
        data = response.json()
        if data["total"] > 0:
            item = data["items"][0]
            assert "permissions" in item
            assert isinstance(item["permissions"], list)


# ── Story 10: New Endpoint Tests ──────────────────────────────────────


@pytest.fixture
async def setup_tree_data(test_db):
    """Set up a hierarchical directory tree with varied exposure levels."""
    from sqlalchemy import select

    from openlabels.server.models import (
        DirectoryTree,
        FolderInventory,
        RemediationAction,
        ScanTarget,
        SecurityDescriptor,
        Tenant,
        User,
    )

    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Tree Test Target",
        adapter="filesystem",
        config={"path": "/data/tree"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.flush()

    # Security descriptors
    tree_public_hash = _sd_hash("tree_sd_public")
    tree_org_hash = _sd_hash("tree_sd_org")
    tree_private_hash = _sd_hash("tree_sd_private")

    sd_public = SecurityDescriptor(
        sd_hash=tree_public_hash,
        tenant_id=tenant.id,
        world_accessible=True,
        authenticated_users=False,
        custom_acl=False,
        owner_sid="S-1-5-32-544",
        group_sid="S-1-5-32-545",
        dacl_sddl="D:(A;;GA;;;WD)",
        permissions_json={"Everyone": ["READ", "EXECUTE"]},
    )
    sd_org = SecurityDescriptor(
        sd_hash=tree_org_hash,
        tenant_id=tenant.id,
        world_accessible=False,
        authenticated_users=True,
        custom_acl=False,
        permissions_json={"Authenticated Users": ["READ"]},
    )
    sd_private = SecurityDescriptor(
        sd_hash=tree_private_hash,
        tenant_id=tenant.id,
        world_accessible=False,
        authenticated_users=False,
        custom_acl=False,
        owner_sid="S-1-5-32-544",
    )
    test_db.add_all([sd_public, sd_org, sd_private])
    await test_db.flush()

    # Root directory (public)
    root = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/tree",
        dir_name="tree",
        sd_hash=tree_public_hash,
        parent_id=None,
        child_dir_count=2,
        child_file_count=5,
    )
    test_db.add(root)
    await test_db.flush()

    # Child 1: org-wide
    child1 = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/tree/shared",
        dir_name="shared",
        sd_hash=tree_org_hash,
        parent_id=root.id,
        child_dir_count=1,
        child_file_count=3,
    )
    # Child 2: private
    child2 = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/tree/private",
        dir_name="private",
        sd_hash=tree_private_hash,
        parent_id=root.id,
        child_dir_count=0,
        child_file_count=2,
    )
    test_db.add_all([child1, child2])
    await test_db.flush()

    # Grandchild under child1
    grandchild = DirectoryTree(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        dir_path="/data/tree/shared/docs",
        dir_name="docs",
        sd_hash=tree_public_hash,
        parent_id=child1.id,
        child_dir_count=0,
        child_file_count=8,
    )
    test_db.add(grandchild)
    await test_db.flush()

    # Folder inventory: root has sensitive files
    fi_root = FolderInventory(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        folder_path="/data/tree",
        adapter="filesystem",
        has_sensitive_files=True,
        highest_risk_tier="HIGH",
        total_entities_found=15,
        file_count=5,
    )
    # Folder inventory: grandchild also has sensitive files
    fi_grandchild = FolderInventory(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        folder_path="/data/tree/shared/docs",
        adapter="filesystem",
        has_sensitive_files=True,
        highest_risk_tier="CRITICAL",
        total_entities_found=42,
        file_count=8,
    )
    # Folder inventory: child1 shared but NO sensitive files
    fi_child1 = FolderInventory(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        folder_path="/data/tree/shared",
        adapter="filesystem",
        has_sensitive_files=False,
        highest_risk_tier="MINIMAL",
        total_entities_found=0,
        file_count=3,
    )
    test_db.add_all([fi_root, fi_grandchild, fi_child1])
    await test_db.flush()

    # Remediation action under root dir
    remediation = RemediationAction(
        id=uuid4(),
        tenant_id=tenant.id,
        action_type="quarantine",
        status="completed",
        source_path="/data/tree/secret.docx",
        dest_path="/quarantine/secret.docx",
        performed_by=user.email,
    )
    remediation2 = RemediationAction(
        id=uuid4(),
        tenant_id=tenant.id,
        action_type="lockdown",
        status="pending",
        source_path="/data/tree/shared/report.xlsx",
        performed_by=user.email,
    )
    test_db.add_all([remediation, remediation2])
    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "root": root,
        "child1": child1,
        "child2": child2,
        "grandchild": grandchild,
        "remediation": remediation,
        "remediation2": remediation2,
    }


class TestFolderTree:
    """Tests for GET /api/v1/permissions/{target_id}/tree endpoint."""

    async def test_returns_tree_structure(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        response = await test_client.get(f"/api/v1/permissions/{target_id}/tree")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Root node
        assert len(data) == 1
        root = data[0]
        assert root["dir_name"] == "tree"
        assert root["exposure_level"] == "PUBLIC"

    async def test_tree_has_children(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        response = await test_client.get(f"/api/v1/permissions/{target_id}/tree")
        data = response.json()
        root = data[0]
        assert len(root["children"]) == 2
        child_names = {c["dir_name"] for c in root["children"]}
        assert child_names == {"shared", "private"}

    async def test_tree_respects_depth(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        # depth=1 should only show root with no children populated
        response = await test_client.get(
            f"/api/v1/permissions/{target_id}/tree?depth=1"
        )
        data = response.json()
        root = data[0]
        assert root["dir_name"] == "tree"
        assert root["children"] == []

    async def test_tree_depth_3_includes_grandchild(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/{target_id}/tree?depth=3"
        )
        data = response.json()
        root = data[0]
        shared = next(c for c in root["children"] if c["dir_name"] == "shared")
        assert len(shared["children"]) == 1
        assert shared["children"][0]["dir_name"] == "docs"

    async def test_tree_from_subtree(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        parent_id = str(setup_tree_data["child1"].id)
        response = await test_client.get(
            f"/api/v1/permissions/{target_id}/tree?parent_id={parent_id}"
        )
        data = response.json()
        assert len(data) == 1
        assert data[0]["dir_name"] == "docs"

    async def test_tree_exposure_badges(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/{target_id}/tree?depth=3"
        )
        data = response.json()
        root = data[0]
        assert root["exposure_level"] == "PUBLIC"
        shared = next(c for c in root["children"] if c["dir_name"] == "shared")
        assert shared["exposure_level"] == "ORG_WIDE"
        private = next(c for c in root["children"] if c["dir_name"] == "private")
        assert private["exposure_level"] == "PRIVATE"

    async def test_tree_empty_for_wrong_target(self, test_client, setup_tree_data):
        response = await test_client.get(f"/api/v1/permissions/{uuid4()}/tree")
        assert response.status_code == 200
        assert response.json() == []


class TestAtRiskDirectories:
    """Tests for GET /api/v1/permissions/at-risk endpoint."""

    async def test_returns_at_risk_directories(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/at-risk")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    async def test_finds_public_dirs_with_sensitive_files(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/at-risk?min_exposure=PUBLIC")
        data = response.json()
        # root (/data/tree) is PUBLIC + sensitive; grandchild (/data/tree/shared/docs) is PUBLIC + sensitive
        assert data["total"] == 2
        paths = {item["dir_path"] for item in data["items"]}
        assert "/data/tree" in paths
        assert "/data/tree/shared/docs" in paths

    async def test_org_wide_includes_both(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/at-risk?min_exposure=ORG_WIDE")
        data = response.json()
        # ORG_WIDE includes PUBLIC + ORG_WIDE, but child1 (shared/ORG_WIDE) has no sensitive files
        # So still just root + grandchild
        assert data["total"] == 2

    async def test_at_risk_scoped_to_target(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/at-risk?target_id={target_id}"
        )
        data = response.json()
        assert data["total"] >= 1

    async def test_at_risk_empty_for_wrong_target(self, test_client, setup_tree_data):
        response = await test_client.get(
            f"/api/v1/permissions/at-risk?target_id={uuid4()}"
        )
        data = response.json()
        assert data["total"] == 0

    async def test_at_risk_includes_risk_info(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/at-risk")
        data = response.json()
        for item in data["items"]:
            assert "exposure_level" in item
            assert "has_sensitive_files" in item
            assert item["has_sensitive_files"] is True
            assert "highest_risk_tier" in item
            assert "total_entities_found" in item


class TestDirectoryRemediation:
    """Tests for GET /api/v1/permissions/{target_id}/acl/{dir_id}/remediation endpoint."""

    async def test_returns_remediation_actions(self, test_client, setup_tree_data):
        target = setup_tree_data["target"]
        root = setup_tree_data["root"]
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{root.id}/remediation"
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2

    async def test_remediation_has_correct_fields(self, test_client, setup_tree_data):
        target = setup_tree_data["target"]
        root = setup_tree_data["root"]
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{root.id}/remediation"
        )
        data = response.json()
        for action in data:
            assert "id" in action
            assert "action_type" in action
            assert "status" in action
            assert "source_path" in action
            assert "performed_by" in action

    async def test_remediation_includes_quarantine(self, test_client, setup_tree_data):
        target = setup_tree_data["target"]
        root = setup_tree_data["root"]
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{root.id}/remediation"
        )
        data = response.json()
        action_types = {a["action_type"] for a in data}
        assert "quarantine" in action_types
        assert "lockdown" in action_types

    async def test_remediation_404_for_nonexistent_dir(self, test_client, setup_tree_data):
        target = setup_tree_data["target"]
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{uuid4()}/remediation"
        )
        assert response.status_code == 404

    async def test_remediation_empty_for_dir_without_actions(self, test_client, setup_tree_data):
        target = setup_tree_data["target"]
        child2 = setup_tree_data["child2"]  # private dir, no remediation actions
        response = await test_client.get(
            f"/api/v1/permissions/{target.id}/acl/{child2.id}/remediation"
        )
        assert response.status_code == 200
        assert response.json() == []


class TestExportExposureReport:
    """Tests for GET /api/v1/permissions/export endpoint."""

    async def test_returns_csv(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/export")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "attachment" in response.headers.get("content-disposition", "")

    async def test_csv_has_header_and_rows(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/export")
        lines = response.text.strip().split("\n")
        # Header + data rows
        assert len(lines) >= 2
        header = lines[0]
        assert "dir_path" in header
        assert "exposure_level" in header
        assert "has_sensitive_files" in header

    async def test_csv_contains_all_directories(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/export")
        lines = response.text.strip().split("\n")
        # 4 directories + header
        assert len(lines) == 5

    async def test_csv_filter_by_exposure(self, test_client, setup_tree_data):
        response = await test_client.get("/api/v1/permissions/export?exposure=PUBLIC")
        lines = response.text.strip().split("\n")
        # Header + public dirs (root + grandchild)
        assert len(lines) == 3
        # All data rows should be PUBLIC
        for line in lines[1:]:
            assert "PUBLIC" in line

    async def test_csv_filter_by_target(self, test_client, setup_tree_data):
        target_id = str(setup_tree_data["target"].id)
        response = await test_client.get(
            f"/api/v1/permissions/export?target_id={target_id}"
        )
        assert response.status_code == 200
        lines = response.text.strip().split("\n")
        assert len(lines) >= 2

    async def test_csv_empty_for_wrong_target(self, test_client, setup_tree_data):
        response = await test_client.get(
            f"/api/v1/permissions/export?target_id={uuid4()}"
        )
        assert response.status_code == 200
        lines = response.text.strip().split("\n")
        # Just the header
        assert len(lines) == 1
