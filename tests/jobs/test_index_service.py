"""Tests for directory tree index service (jobs/index.py).

Integration tests use the test_db fixture and require PostgreSQL.
"""

from datetime import datetime, timezone
from uuid import UUID

import pytest

from openlabels.adapters.base import FolderInfo
from openlabels.jobs.index import _folder_info_to_row


class MockAdapter:
    """Minimal async adapter yielding pre-built FolderInfo objects."""

    def __init__(self, folders: list[FolderInfo]):
        self._folders = folders

    async def list_folders(self, path, recursive=True):
        for f in self._folders:
            yield f

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class TestFolderInfoToRow:

    def test_all_fields_populated(self):
        from openlabels.server.models import generate_uuid

        tenant_id = generate_uuid()
        target_id = generate_uuid()
        info = FolderInfo(
            path="/data/finance",
            name="finance",
            modified=datetime(2024, 1, 15, tzinfo=timezone.utc),
            adapter="filesystem",
            inode=12345,
            parent_inode=100,
            child_dir_count=3,
            child_file_count=10,
        )

        row = _folder_info_to_row(info, tenant_id, target_id)

        assert row["tenant_id"] == tenant_id
        assert row["target_id"] == target_id
        assert row["dir_path"] == "/data/finance"
        assert row["dir_name"] == "finance"
        assert row["dir_ref"] == 12345
        assert row["parent_ref"] == 100
        assert row["child_dir_count"] == 3
        assert row["child_file_count"] == 10
        assert row["dir_modified"] == datetime(2024, 1, 15, tzinfo=timezone.utc)
        assert row["flags"] == 0
        assert isinstance(row["id"], UUID)
        assert row["discovered_at"] is not None
        assert row["updated_at"] is not None

    def test_name_derived_from_path_when_empty(self):
        from openlabels.server.models import generate_uuid

        info = FolderInfo(path="/data/finance/reports", name="")
        row = _folder_info_to_row(info, generate_uuid(), generate_uuid())

        assert row["dir_name"] == "reports"

    def test_name_derived_from_path_for_root(self):
        """When name is empty and path is just '/', use path itself."""
        from openlabels.server.models import generate_uuid

        info = FolderInfo(path="/", name="")
        row = _folder_info_to_row(info, generate_uuid(), generate_uuid())

        # PurePosixPath("/").name is "", so fallback is the path "/"
        assert row["dir_name"] == "/"

    def test_generates_unique_ids(self):
        from openlabels.server.models import generate_uuid

        info = FolderInfo(path="/a", name="a")
        tid = generate_uuid()
        row1 = _folder_info_to_row(info, tid, generate_uuid())
        row2 = _folder_info_to_row(info, tid, generate_uuid())

        assert row1["id"] != row2["id"]

    def test_none_inode_preserved(self):
        """Cloud adapters pass None for inode/parent_inode."""
        from openlabels.server.models import generate_uuid

        info = FolderInfo(path="/cloud/bucket/prefix", name="prefix")
        row = _folder_info_to_row(info, generate_uuid(), generate_uuid())

        assert row["dir_ref"] is None
        assert row["parent_ref"] is None


class TestBootstrapDirectoryTree:

    @pytest.fixture
    async def tenant_and_target(self, test_db):
        from openlabels.server.models import ScanTarget, Tenant

        tenant = Tenant(name="test-index-tenant")
        test_db.add(tenant)
        await test_db.flush()

        target = ScanTarget(
            tenant_id=tenant.id,
            name="test-index-target",
            adapter="filesystem",
            config={"path": "/tmp"},
        )
        test_db.add(target)
        await test_db.flush()

        return tenant, target

    async def test_inserts_directories_into_db(self, test_db, tenant_and_target):
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target
        adapter = MockAdapter([
            FolderInfo(path="/data", name="data", inode=1, parent_inode=None,
                       child_dir_count=2, child_file_count=0),
            FolderInfo(path="/data/a", name="a", inode=2, parent_inode=1,
                       child_dir_count=0, child_file_count=5),
            FolderInfo(path="/data/b", name="b", inode=3, parent_inode=1,
                       child_dir_count=0, child_file_count=3),
        ])

        result = await bootstrap_directory_tree(
            session=test_db,
            adapter=adapter,
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/data",
        )

        assert result["total_dirs"] == 3

        rows = (await test_db.execute(text(
            "SELECT dir_path, dir_name, dir_ref, parent_ref, child_dir_count, child_file_count "
            "FROM directory_tree WHERE tenant_id = :tid AND target_id = :tgt "
            "ORDER BY dir_path"
        ), {"tid": tenant.id, "tgt": target.id})).all()

        assert len(rows) == 3
        assert rows[0].dir_path == "/data"
        assert rows[0].dir_name == "data"
        assert rows[0].dir_ref == 1
        assert rows[0].child_dir_count == 2
        assert rows[1].dir_path == "/data/a"
        assert rows[1].child_file_count == 5
        assert rows[2].dir_path == "/data/b"

    async def test_upsert_is_idempotent(self, test_db, tenant_and_target):
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target
        folders = [
            FolderInfo(path="/data", name="data", inode=1,
                       child_dir_count=1, child_file_count=0),
            FolderInfo(path="/data/a", name="a", inode=2, parent_inode=1,
                       child_dir_count=0, child_file_count=5),
        ]

        # Run twice
        await bootstrap_directory_tree(
            test_db, MockAdapter(folders), tenant.id, target.id, "/data",
        )
        await bootstrap_directory_tree(
            test_db, MockAdapter(folders), tenant.id, target.id, "/data",
        )

        count = (await test_db.execute(text(
            "SELECT count(*) FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt"
        ), {"tid": tenant.id, "tgt": target.id})).scalar()

        assert count == 2  # Not 4

    async def test_upsert_updates_changed_fields(self, test_db, tenant_and_target):
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target

        # First run: 5 files
        await bootstrap_directory_tree(
            test_db,
            MockAdapter([FolderInfo(path="/d", name="d", inode=1, child_file_count=5)]),
            tenant.id, target.id, "/d",
        )

        # Second run: 10 files
        await bootstrap_directory_tree(
            test_db,
            MockAdapter([FolderInfo(path="/d", name="d", inode=1, child_file_count=10)]),
            tenant.id, target.id, "/d",
        )

        row = (await test_db.execute(text(
            "SELECT child_file_count FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt AND dir_path = '/d'"
        ), {"tid": tenant.id, "tgt": target.id})).one()

        assert row.child_file_count == 10

    async def test_parent_resolution_by_inode(self, test_db, tenant_and_target):
        """Inode-based parent resolution: child.parent_ref → parent.dir_ref."""
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target
        adapter = MockAdapter([
            FolderInfo(path="/root", name="root", inode=100, parent_inode=None),
            FolderInfo(path="/root/child", name="child", inode=200, parent_inode=100),
            FolderInfo(path="/root/child/grandchild", name="grandchild",
                       inode=300, parent_inode=200),
        ])

        result = await bootstrap_directory_tree(
            test_db, adapter, tenant.id, target.id, "/root",
        )

        assert result["parent_links_resolved"] >= 2

        rows = (await test_db.execute(text(
            "SELECT dir_path, parent_id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt ORDER BY dir_path"
        ), {"tid": tenant.id, "tgt": target.id})).all()

        by_path = {r.dir_path: r for r in rows}

        # Root has no parent
        assert by_path["/root"].parent_id is None
        # Child's parent_id points to root's id
        assert by_path["/root/child"].parent_id is not None
        # Grandchild's parent_id points to child's id
        assert by_path["/root/child/grandchild"].parent_id is not None
        assert by_path["/root/child/grandchild"].parent_id != by_path["/root/child"].parent_id

    async def test_parent_resolution_by_path(self, test_db, tenant_and_target):
        """Path-based parent resolution for cloud adapters (no inodes)."""
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target
        adapter = MockAdapter([
            FolderInfo(path="/bucket/prefix", name="prefix"),
            FolderInfo(path="/bucket/prefix/subdir", name="subdir"),
        ])

        result = await bootstrap_directory_tree(
            test_db, adapter, tenant.id, target.id, "/bucket/prefix",
        )

        assert result["parent_links_resolved"] >= 1

        rows = (await test_db.execute(text(
            "SELECT dir_path, parent_id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt ORDER BY dir_path"
        ), {"tid": tenant.id, "tgt": target.id})).all()

        by_path = {r.dir_path: r for r in rows}
        assert by_path["/bucket/prefix/subdir"].parent_id is not None

    async def test_progress_callback_fires(self, test_db, tenant_and_target):
        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target
        # Need > UPSERT_BATCH_SIZE folders to trigger mid-batch callback.
        # For a simpler test: just verify the final callback fires.
        progress_values = []

        def on_progress(count):
            progress_values.append(count)

        adapter = MockAdapter([
            FolderInfo(path=f"/d/{i}", name=str(i)) for i in range(5)
        ])

        await bootstrap_directory_tree(
            test_db, adapter, tenant.id, target.id, "/d",
            on_progress=on_progress,
        )

        # Final flush should fire progress with total count
        assert len(progress_values) >= 1
        assert progress_values[-1] == 5

    async def test_clear_directory_tree(self, test_db, tenant_and_target):
        from openlabels.jobs.index import bootstrap_directory_tree, clear_directory_tree

        tenant, target = tenant_and_target
        adapter = MockAdapter([
            FolderInfo(path="/d", name="d"),
            FolderInfo(path="/d/a", name="a"),
        ])

        await bootstrap_directory_tree(
            test_db, adapter, tenant.id, target.id, "/d",
        )

        deleted = await clear_directory_tree(test_db, tenant.id, target.id)
        assert deleted == 2

    async def test_get_index_stats(self, test_db, tenant_and_target):
        from openlabels.jobs.index import bootstrap_directory_tree, get_index_stats

        tenant, target = tenant_and_target
        adapter = MockAdapter([
            FolderInfo(path="/s", name="s", inode=1),
            FolderInfo(path="/s/a", name="a", inode=2, parent_inode=1),
            FolderInfo(path="/s/b", name="b", inode=3, parent_inode=1),
        ])

        await bootstrap_directory_tree(
            test_db, adapter, tenant.id, target.id, "/s",
        )

        stats = await get_index_stats(test_db, tenant.id, target.id)

        assert stats["total_dirs"] == 3
        assert stats["with_parent_link"] == 2  # a and b linked to s
        assert stats["last_updated"] is not None

    async def test_self_referencing_inode_does_not_create_parent_link(
        self, test_db, tenant_and_target,
    ):
        """A directory whose parent_inode equals its own inode should not
        link to itself (the SQL has child.id != parent.id guard)."""
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree

        tenant, target = tenant_and_target
        adapter = MockAdapter([
            FolderInfo(path="/self", name="self", inode=42, parent_inode=42),
        ])

        await bootstrap_directory_tree(
            test_db, adapter, tenant.id, target.id, "/self",
        )

        row = (await test_db.execute(text(
            "SELECT parent_id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt AND dir_path = '/self'"
        ), {"tid": tenant.id, "tgt": target.id})).one()

        assert row.parent_id is None
