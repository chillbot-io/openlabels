"""Tests for browse API endpoints (/browse)."""

from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy import text

from openlabels.adapters.base import FolderInfo


class MockAdapter:
    def __init__(self, folders: list[FolderInfo]):
        self._folders = folders

    async def list_folders(self, path, recursive=True):
        for f in self._folders:
            yield f

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


@pytest.fixture
async def populated_target(test_client, test_db):
    """Create a target and directory tree under the test_client's tenant."""
    from openlabels.jobs.index import bootstrap_directory_tree
    from openlabels.server.models import ScanTarget, Tenant

    # Find the tenant the test_client fixture created
    row = (await test_db.execute(text(
        "SELECT id FROM tenants WHERE name LIKE 'Test Tenant%' ORDER BY id DESC LIMIT 1"
    ))).one()
    tenant_id = row.id

    target = ScanTarget(
        tenant_id=tenant_id,
        name="browse-test-target",
        adapter="filesystem",
        config={"path": "/data"},
    )
    test_db.add(target)
    await test_db.flush()

    adapter = MockAdapter([
        FolderInfo(path="/data", name="data", inode=1, parent_inode=None,
                   child_dir_count=3, child_file_count=0,
                   modified=datetime(2024, 6, 1, tzinfo=timezone.utc)),
        FolderInfo(path="/data/alpha", name="alpha", inode=2, parent_inode=1,
                   child_dir_count=0, child_file_count=10),
        FolderInfo(path="/data/beta", name="beta", inode=3, parent_inode=1,
                   child_dir_count=1, child_file_count=5),
        FolderInfo(path="/data/beta/gamma", name="gamma", inode=4, parent_inode=3,
                   child_dir_count=0, child_file_count=2),
    ])

    await bootstrap_directory_tree(
        session=test_db,
        adapter=adapter,
        tenant_id=tenant_id,
        target_id=target.id,
        scan_path="/data",
    )
    await test_db.commit()

    return tenant_id, target


class TestBrowseFolders:

    async def test_root_folders(self, test_client, test_db, populated_target):
        """Browse with no parent_id returns root-level directories."""
        tenant_id, target = populated_target
        resp = await test_client.get(f"/api/v1/browse/{target.id}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["target_id"] == str(target.id)
        assert body["parent_id"] is None
        assert body["total"] >= 1
        paths = [f["dir_path"] for f in body["folders"]]
        assert "/data" in paths

    async def test_children_of_parent(self, test_client, test_db, populated_target):
        """Browse with parent_id returns its children."""
        tenant_id, target = populated_target

        row = (await test_db.execute(text(
            "SELECT id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt AND dir_path = '/data'"
        ), {"tid": tenant_id, "tgt": target.id})).one()

        resp = await test_client.get(
            f"/api/v1/browse/{target.id}",
            params={"parent_id": str(row.id)},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["parent_id"] == str(row.id)
        assert body["parent_path"] == "/data"
        names = {f["dir_name"] for f in body["folders"]}
        assert "alpha" in names
        assert "beta" in names
        assert body["total"] == 2

    async def test_pagination(self, test_client, test_db, populated_target):
        """Limit and offset work correctly."""
        tenant_id, target = populated_target

        row = (await test_db.execute(text(
            "SELECT id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt AND dir_path = '/data'"
        ), {"tid": tenant_id, "tgt": target.id})).one()

        resp = await test_client.get(
            f"/api/v1/browse/{target.id}",
            params={"parent_id": str(row.id), "limit": 1, "offset": 0},
        )

        body = resp.json()
        assert len(body["folders"]) == 1
        assert body["total"] == 2

        resp2 = await test_client.get(
            f"/api/v1/browse/{target.id}",
            params={"parent_id": str(row.id), "limit": 1, "offset": 1},
        )
        body2 = resp2.json()
        assert len(body2["folders"]) == 1
        assert body2["folders"][0]["dir_name"] != body["folders"][0]["dir_name"]

    async def test_child_counts_in_response(self, test_client, test_db, populated_target):
        """Response includes child_dir_count and child_file_count."""
        tenant_id, target = populated_target
        resp = await test_client.get(f"/api/v1/browse/{target.id}")

        body = resp.json()
        root = [f for f in body["folders"] if f["dir_path"] == "/data"]
        assert len(root) == 1
        assert root[0]["child_dir_count"] == 3
        assert root[0]["child_file_count"] == 0

    async def test_dir_modified_is_iso_string(self, test_client, test_db, populated_target):
        """dir_modified should be formatted as an ISO string."""
        tenant_id, target = populated_target
        resp = await test_client.get(f"/api/v1/browse/{target.id}")

        body = resp.json()
        root = [f for f in body["folders"] if f["dir_path"] == "/data"][0]
        assert root["dir_modified"] is not None
        parsed = datetime.fromisoformat(root["dir_modified"])
        assert parsed.year == 2024

    async def test_empty_parent_returns_empty(self, test_client, test_db, populated_target):
        """Browsing a leaf directory returns no children."""
        tenant_id, target = populated_target

        row = (await test_db.execute(text(
            "SELECT id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt AND dir_path = '/data/alpha'"
        ), {"tid": tenant_id, "tgt": target.id})).one()

        resp = await test_client.get(
            f"/api/v1/browse/{target.id}",
            params={"parent_id": str(row.id)},
        )
        body = resp.json()
        assert body["total"] == 0
        assert body["folders"] == []

    async def test_folders_ordered_by_name(self, test_client, test_db, populated_target):
        """Results should be alphabetically sorted by dir_name."""
        tenant_id, target = populated_target

        row = (await test_db.execute(text(
            "SELECT id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt AND dir_path = '/data'"
        ), {"tid": tenant_id, "tgt": target.id})).one()

        resp = await test_client.get(
            f"/api/v1/browse/{target.id}",
            params={"parent_id": str(row.id)},
        )
        body = resp.json()
        names = [f["dir_name"] for f in body["folders"]]
        assert names == sorted(names)


class TestBrowseTenantIsolation:

    async def test_parent_id_from_other_tenant_returns_no_parent_path(
        self, test_client, test_db, populated_target,
    ):
        """parent_id belonging to another tenant must NOT leak that
        tenant's dir_path.  The fix filters db.get() by tenant_id."""
        from openlabels.server.models import ScanTarget, Tenant, generate_uuid

        # Create a directory belonging to a DIFFERENT tenant
        other_tenant = Tenant(name="other-tenant-isolation-test")
        test_db.add(other_tenant)
        await test_db.flush()

        other_target = ScanTarget(
            tenant_id=other_tenant.id,
            name="other-target",
            adapter="filesystem",
            config={"path": "/secret"},
        )
        test_db.add(other_target)
        await test_db.flush()

        from openlabels.jobs.index import bootstrap_directory_tree

        adapter = MockAdapter([
            FolderInfo(path="/secret", name="secret", inode=100),
        ])
        await bootstrap_directory_tree(
            session=test_db, adapter=adapter,
            tenant_id=other_tenant.id, target_id=other_target.id,
            scan_path="/secret",
        )
        await test_db.flush()

        # Get the other tenant's directory ID
        other_dir = (await test_db.execute(text(
            "SELECT id FROM directory_tree "
            "WHERE tenant_id = :tid AND dir_path = '/secret'"
        ), {"tid": other_tenant.id})).one()

        # Now browse OUR target with the OTHER tenant's parent_id
        _, target = populated_target
        resp = await test_client.get(
            f"/api/v1/browse/{target.id}",
            params={"parent_id": str(other_dir.id)},
        )

        body = resp.json()
        # parent_path must be None — we must NOT see "/secret"
        assert body["parent_path"] is None
        assert body["folders"] == []


class TestTreeStats:

    async def test_returns_correct_counts(self, test_client, test_db, populated_target):
        """tree_stats returns accurate total_dirs and with_parent_link."""
        tenant_id, target = populated_target
        resp = await test_client.get(f"/api/v1/browse/{target.id}/stats")

        assert resp.status_code == 200
        body = resp.json()
        assert body["target_id"] == str(target.id)
        assert body["total_dirs"] == 4
        assert body["with_parent_link"] == 3

    async def test_world_accessible_dirs_zero_without_sd(self, test_client, test_db, populated_target):
        """Without security descriptors, world_accessible_dirs should be 0."""
        tenant_id, target = populated_target
        resp = await test_client.get(f"/api/v1/browse/{target.id}/stats")

        body = resp.json()
        assert body["world_accessible_dirs"] == 0

    async def test_last_updated_is_set(self, test_client, test_db, populated_target):
        """last_updated should be a non-null ISO timestamp."""
        tenant_id, target = populated_target
        resp = await test_client.get(f"/api/v1/browse/{target.id}/stats")

        body = resp.json()
        assert body["last_updated"] is not None
        datetime.fromisoformat(body["last_updated"])
