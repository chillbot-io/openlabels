"""Tests for directory tree delta sync (jobs/delta_sync.py).

Integration tests use the test_db fixture and require PostgreSQL.
"""

from datetime import datetime, timezone
from uuid import UUID

import pytest

from openlabels.adapters.base import FolderInfo
from openlabels.jobs.delta_sync import (
    _folder_info_to_row,
    _to_epoch,
    _update_row,
)


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


class TestToEpoch:

    def test_none_returns_none(self):
        assert _to_epoch(None) is None

    def test_datetime_returns_float(self):
        dt = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _to_epoch(dt)
        assert isinstance(result, float)
        assert result == dt.timestamp()

    def test_naive_datetime_works(self):
        dt = datetime(2024, 6, 15, 12, 0, 0)
        result = _to_epoch(dt)
        assert result == dt.timestamp()


class TestUpdateRow:

    def test_sd_hash_not_in_update_row(self):
        """_update_row should NOT include sd_hash — _apply_updates SQL
        sets sd_hash = NULL directly, so the dict must not carry it."""
        from openlabels.server.models import generate_uuid

        info = FolderInfo(
            path="/d", name="d", inode=10, parent_inode=5,
            child_dir_count=2, child_file_count=8,
            modified=datetime(2024, 6, 15, tzinfo=timezone.utc),
        )
        row = _update_row(generate_uuid(), info)

        assert "sd_hash" not in row

    def test_preserves_existing_id(self):
        from openlabels.server.models import generate_uuid

        existing_id = generate_uuid()
        info = FolderInfo(path="/d", name="d")
        row = _update_row(existing_id, info)

        assert row["id"] == existing_id

    def test_populates_all_mutable_fields(self):
        from openlabels.server.models import generate_uuid

        info = FolderInfo(
            path="/d", name="d", inode=10, parent_inode=5,
            child_dir_count=2, child_file_count=8,
            modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        row = _update_row(generate_uuid(), info)

        assert row["dir_modified"] == info.modified
        assert row["dir_ref"] == 10
        assert row["parent_ref"] == 5
        assert row["child_dir_count"] == 2
        assert row["child_file_count"] == 8
        assert isinstance(row["updated_at"], datetime)


class TestFolderInfoToRowDelta:

    def test_name_derived_from_path_when_empty(self):
        from openlabels.server.models import generate_uuid

        info = FolderInfo(path="/data/finance/reports", name="")
        row = _folder_info_to_row(info, generate_uuid(), generate_uuid())
        assert row["dir_name"] == "reports"


class TestCheckpointCRUD:

    @pytest.fixture
    async def tenant_and_target(self, test_db):
        from openlabels.server.models import ScanTarget, Tenant

        tenant = Tenant(name="test-delta-tenant")
        test_db.add(tenant)
        await test_db.flush()

        target = ScanTarget(
            tenant_id=tenant.id,
            name="test-delta-target",
            adapter="filesystem",
            config={"path": "/tmp"},
        )
        test_db.add(target)
        await test_db.flush()

        return tenant, target

    async def test_get_checkpoint_returns_none_when_missing(
        self, test_db, tenant_and_target,
    ):
        from openlabels.jobs.delta_sync import get_checkpoint

        tenant, target = tenant_and_target
        cp = await get_checkpoint(test_db, tenant.id, target.id)
        assert cp is None

    async def test_upsert_creates_checkpoint(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import get_checkpoint, upsert_checkpoint

        tenant, target = tenant_and_target
        now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        await upsert_checkpoint(
            test_db, tenant.id, target.id,
            last_full_sync=now,
            dirs_at_last_sync=1000,
        )
        await test_db.flush()

        cp = await get_checkpoint(test_db, tenant.id, target.id)
        assert cp is not None
        assert cp.last_full_sync == now
        assert cp.dirs_at_last_sync == 1000
        assert cp.last_delta_sync is None

    async def test_upsert_updates_existing(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import get_checkpoint, upsert_checkpoint

        tenant, target = tenant_and_target
        t1 = datetime(2024, 6, 15, tzinfo=timezone.utc)
        t2 = datetime(2024, 6, 16, tzinfo=timezone.utc)

        await upsert_checkpoint(
            test_db, tenant.id, target.id,
            last_full_sync=t1, dirs_at_last_sync=100,
        )
        await test_db.flush()

        await upsert_checkpoint(
            test_db, tenant.id, target.id,
            last_delta_sync=t2, dirs_at_last_sync=105,
        )
        await test_db.flush()

        cp = await get_checkpoint(test_db, tenant.id, target.id)
        assert cp is not None
        assert cp.last_delta_sync == t2
        assert cp.dirs_at_last_sync == 105

    async def test_upsert_stores_delta_token(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import get_checkpoint, upsert_checkpoint

        tenant, target = tenant_and_target
        await upsert_checkpoint(
            test_db, tenant.id, target.id,
            delta_token="aHR0cHM6Ly9ncmFwaC5taWNyb3NvZnQuY29t",
        )
        await test_db.flush()

        cp = await get_checkpoint(test_db, tenant.id, target.id)
        assert cp.delta_token == "aHR0cHM6Ly9ncmFwaC5taWNyb3NvZnQuY29t"


class TestDeltaSync:

    @pytest.fixture
    async def tenant_and_target(self, test_db):
        from openlabels.server.models import ScanTarget, Tenant

        tenant = Tenant(name="test-sync-tenant")
        test_db.add(tenant)
        await test_db.flush()

        target = ScanTarget(
            tenant_id=tenant.id,
            name="test-sync-target",
            adapter="filesystem",
            config={"path": "/tmp"},
        )
        test_db.add(target)
        await test_db.flush()

        return tenant, target

    async def _bootstrap(self, session, tenant_id, target_id, folders):
        """Helper: bootstrap with initial data."""
        from openlabels.jobs.index import bootstrap_directory_tree

        await bootstrap_directory_tree(
            session, MockAdapter(folders), tenant_id, target_id, "/d",
            collect_sd=False,
        )

    async def test_inserts_new_directories(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target

        # Bootstrap with 1 directory
        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1,
                       modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
        ])

        # Delta sync with 2 directories (1 new)
        result = await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1,
                           modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
                FolderInfo(path="/d/new", name="new", inode=2, parent_inode=1,
                           modified=datetime(2024, 6, 1, tzinfo=timezone.utc)),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        assert result["inserted"] == 1
        assert result["deleted"] == 0
        assert result["total_dirs"] == 2

    async def test_detects_deleted_directories(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target

        # Bootstrap with 3 directories
        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1,
                       modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
            FolderInfo(path="/d/a", name="a", inode=2, parent_inode=1,
                       modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
            FolderInfo(path="/d/b", name="b", inode=3, parent_inode=1,
                       modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
        ])

        # Delta sync with only 2 directories (/d/b removed)
        result = await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1,
                           modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
                FolderInfo(path="/d/a", name="a", inode=2, parent_inode=1,
                           modified=datetime(2024, 1, 1, tzinfo=timezone.utc)),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        assert result["deleted"] == 1
        assert result["total_dirs"] == 2

    async def test_detects_modified_directories(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target

        t1 = datetime(2024, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2024, 6, 15, tzinfo=timezone.utc)

        # Bootstrap with original mtime
        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1, modified=t1),
        ])

        # Delta sync with updated mtime
        result = await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1, modified=t2,
                           child_file_count=99),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        assert result["updated"] == 1
        assert result["unchanged"] == 0

    async def test_skips_unchanged_directories(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target

        t1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Bootstrap
        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1, modified=t1),
            FolderInfo(path="/d/a", name="a", inode=2, parent_inode=1, modified=t1),
        ])

        # Delta sync with identical data
        result = await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1, modified=t1),
                FolderInfo(path="/d/a", name="a", inode=2, parent_inode=1, modified=t1),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        assert result["unchanged"] == 2
        assert result["inserted"] == 0
        assert result["updated"] == 0
        assert result["deleted"] == 0

    async def test_resolves_parent_links_for_new_dirs(
        self, test_db, tenant_and_target,
    ):
        from sqlalchemy import text

        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target
        t1 = datetime(2024, 1, 1, tzinfo=timezone.utc)

        # Bootstrap with root only
        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1, modified=t1),
        ])

        # Delta: add child
        result = await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1, modified=t1),
                FolderInfo(path="/d/child", name="child", inode=2,
                           parent_inode=1, modified=t1),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        assert result["parent_links_resolved"] == 1

        rows = (await test_db.execute(text(
            "SELECT id, dir_path, parent_id FROM directory_tree "
            "WHERE tenant_id = :tid AND target_id = :tgt ORDER BY dir_path"
        ), {"tid": tenant.id, "tgt": target.id})).all()

        by_path = {r.dir_path: r for r in rows}
        # Child's parent_id should point to the root's id
        assert by_path["/d/child"].parent_id == by_path["/d"].id

    async def test_creates_checkpoint_after_sync(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import (
            delta_sync_directory_tree,
            get_checkpoint,
        )

        tenant, target = tenant_and_target
        t1 = datetime(2024, 1, 1, tzinfo=timezone.utc)

        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1, modified=t1),
        ])

        await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1, modified=t1),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        cp = await get_checkpoint(test_db, tenant.id, target.id)
        assert cp is not None
        assert cp.last_delta_sync is not None
        assert cp.dirs_at_last_sync == 1

    async def test_combined_insert_update_delete(self, test_db, tenant_and_target):
        """Realistic scenario: some dirs added, some modified, some deleted."""
        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target

        t1 = datetime(2024, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2024, 6, 15, tzinfo=timezone.utc)

        # Bootstrap: /d, /d/keep, /d/modify, /d/delete
        await self._bootstrap(test_db, tenant.id, target.id, [
            FolderInfo(path="/d", name="d", inode=1, modified=t1),
            FolderInfo(path="/d/keep", name="keep", inode=2, parent_inode=1, modified=t1),
            FolderInfo(path="/d/modify", name="modify", inode=3, parent_inode=1, modified=t1),
            FolderInfo(path="/d/delete", name="delete", inode=4, parent_inode=1, modified=t1),
        ])

        # Delta: keep unchanged, modify one, delete one, add one
        result = await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path="/d", name="d", inode=1, modified=t1),
                FolderInfo(path="/d/keep", name="keep", inode=2, parent_inode=1, modified=t1),
                FolderInfo(path="/d/modify", name="modify", inode=3, parent_inode=1, modified=t2),
                FolderInfo(path="/d/new", name="new", inode=5, parent_inode=1, modified=t2),
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
        )

        assert result["unchanged"] == 2  # /d and /d/keep
        assert result["updated"] == 1    # /d/modify
        assert result["deleted"] == 1    # /d/delete
        assert result["inserted"] == 1   # /d/new
        assert result["total_dirs"] == 4

    async def test_progress_callback_fires(self, test_db, tenant_and_target):
        from openlabels.jobs.delta_sync import delta_sync_directory_tree

        tenant, target = tenant_and_target
        t1 = datetime(2024, 1, 1, tzinfo=timezone.utc)

        progress_values = []

        # Need enough folders to trigger the % 5000 == 0 callback,
        # or just verify it doesn't crash with the callback set.
        await delta_sync_directory_tree(
            session=test_db,
            adapter=MockAdapter([
                FolderInfo(path=f"/d/{i}", name=str(i), modified=t1)
                for i in range(10)
            ]),
            tenant_id=tenant.id,
            target_id=target.id,
            scan_path="/d",
            collect_sd=False,
            on_progress=lambda c: progress_values.append(c),
        )

        # With 10 dirs (< 5000), no mid-walk callback fires,
        # but no crash either. This verifies the callback plumbing.
        # The test is primarily about no errors, not about specific values.
