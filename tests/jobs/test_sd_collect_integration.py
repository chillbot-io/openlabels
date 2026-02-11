"""Integration tests for SD collection orchestrator and DB helpers."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

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
async def target_with_real_dirs(test_db):
    """Create tenant, target, and index real temp directories."""
    from openlabels.jobs.index import bootstrap_directory_tree
    from openlabels.server.models import ScanTarget, Tenant

    tenant = Tenant(name="sd-test-tenant")
    test_db.add(tenant)
    await test_db.flush()

    target = ScanTarget(
        tenant_id=tenant.id,
        name="sd-test-target",
        adapter="filesystem",
        config={"path": "/tmp"},
    )
    test_db.add(target)
    await test_db.flush()

    return tenant, target, test_db


class TestCollectSecurityDescriptors:

    async def test_collects_and_stores_sds(self, target_with_real_dirs):
        """Full pipeline: index dirs, collect SDs, verify DB state."""
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a").mkdir()
            (Path(tmpdir) / "b").mkdir()

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            # First, index the directories
            await bootstrap_directory_tree(
                session=session,
                adapter=adapter,
                tenant_id=tenant.id,
                target_id=target.id,
                scan_path=tmpdir,
            )

            # Now collect security descriptors
            stats = await collect_security_descriptors(
                session=session,
                tenant_id=tenant.id,
                target_id=target.id,
            )

            assert stats["total_dirs"] == 3  # root + a + b
            assert stats["unique_sds"] >= 1
            assert "elapsed_seconds" in stats

            # Verify sd_hash was set on directory_tree rows
            result = await session.execute(text(
                "SELECT count(*) FROM directory_tree "
                "WHERE tenant_id = :tid AND target_id = :tgt AND sd_hash IS NOT NULL"
            ), {"tid": tenant.id, "tgt": target.id})
            assert result.scalar() == 3

            # Verify security_descriptors table has entries
            sd_count = (await session.execute(text(
                "SELECT count(*) FROM security_descriptors"
            ))).scalar()
            assert sd_count >= 1

    async def test_deduplicates_identical_permissions(self, target_with_real_dirs):
        """Dirs with same permissions should produce one SD row."""
        import os
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a"
            b = Path(tmpdir) / "b"
            a.mkdir()
            b.mkdir()
            os.chmod(str(a), 0o755)
            os.chmod(str(b), 0o755)
            os.chmod(tmpdir, 0o755)

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            stats = await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )

            # All 3 dirs have same mode → 1 unique SD
            assert stats["unique_sds"] == 1

    async def test_idempotent_on_second_run(self, target_with_real_dirs):
        """Second collect should find 0 dirs (all already have sd_hash)."""
        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "x").mkdir()

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            # First run
            await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )

            # Second run — all dirs already have sd_hash
            stats2 = await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )
            assert stats2["total_dirs"] == 0
            assert stats2["unique_sds"] == 0

    async def test_world_accessible_counted(self, target_with_real_dirs):
        """Directories with world-readable perms are counted."""
        import os

        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "public"
            b = Path(tmpdir) / "private"
            a.mkdir()
            b.mkdir()
            os.chmod(str(a), 0o755)
            os.chmod(str(b), 0o700)
            os.chmod(tmpdir, 0o755)

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            stats = await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )

            # tmpdir and "public" are 0o755 (world-accessible), "private" is not
            assert stats["world_accessible"] >= 2

    async def test_progress_callback(self, target_with_real_dirs):
        """on_progress fires with (processed, total) args."""
        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "p").mkdir()

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            calls = []
            await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
                on_progress=lambda p, t: calls.append((p, t)),
            )

            assert len(calls) >= 1
            # Last call should have processed == total
            assert calls[-1][0] == calls[-1][1]


class TestPaginationEdgeCases:

    async def test_all_dirs_get_sd_hash_with_many_dirs(self, target_with_real_dirs):
        """Regression: OFFSET pagination skipped rows when sd_hash was
        updated mid-loop (the WHERE sd_hash IS NULL result set shrank).
        Keyset pagination must process every directory."""
        import os
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create enough directories that batching is exercised
            for i in range(20):
                d = Path(tmpdir) / f"dir_{i:03d}"
                d.mkdir()
                os.chmod(str(d), 0o755)
            os.chmod(tmpdir, 0o755)

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            stats = await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )

            # Must have processed ALL 21 dirs (root + 20 children)
            assert stats["total_dirs"] == 21

            # Verify zero directories are left without sd_hash
            missing = (await session.execute(text(
                "SELECT count(*) FROM directory_tree "
                "WHERE tenant_id = :tid AND target_id = :tgt AND sd_hash IS NULL"
            ), {"tid": tenant.id, "tgt": target.id})).scalar()
            assert missing == 0

    async def test_no_dirs_skipped_after_partial_batch_flush(self, target_with_real_dirs):
        """Even when _update_dirtree_hashes flushes mid-batch (every 2000 rows),
        subsequent reads must not skip any directories."""
        import os
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(10):
                (Path(tmpdir) / f"sub_{i:02d}").mkdir()

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            stats = await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )

            total_in_db = (await session.execute(text(
                "SELECT count(*) FROM directory_tree "
                "WHERE tenant_id = :tid AND target_id = :tgt"
            ), {"tid": tenant.id, "tgt": target.id})).scalar()

            # Every indexed directory must have been processed
            assert stats["total_dirs"] == total_in_db

            # And every one must have sd_hash set
            with_hash = (await session.execute(text(
                "SELECT count(*) FROM directory_tree "
                "WHERE tenant_id = :tid AND target_id = :tgt AND sd_hash IS NOT NULL"
            ), {"tid": tenant.id, "tgt": target.id})).scalar()
            assert with_hash == total_in_db


class TestGetSDStats:

    async def test_returns_correct_counts(self, target_with_real_dirs):
        """get_sd_stats returns unique_sds, world_accessible, etc."""
        import os
        from sqlalchemy import text

        from openlabels.jobs.index import bootstrap_directory_tree
        from openlabels.jobs.sd_collect import collect_security_descriptors, get_sd_stats

        tenant, target, session = target_with_real_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a").mkdir()
            os.chmod(str(Path(tmpdir) / "a"), 0o755)
            os.chmod(tmpdir, 0o755)

            from openlabels.adapters.filesystem import FilesystemAdapter
            adapter = FilesystemAdapter()

            await bootstrap_directory_tree(
                session=session, adapter=adapter,
                tenant_id=tenant.id, target_id=target.id, scan_path=tmpdir,
            )

            await collect_security_descriptors(
                session=session, tenant_id=tenant.id, target_id=target.id,
            )

            stats = await get_sd_stats(session, tenant.id, target.id)

            assert stats["unique_sds"] >= 1
            assert stats["world_accessible"] >= 1
            assert isinstance(stats["custom_acl"], int)
            assert isinstance(stats["authenticated_users"], int)

    async def test_returns_zeros_when_no_sds(self, target_with_real_dirs):
        """When no SDs collected, stats should be all zeros."""
        from openlabels.jobs.sd_collect import get_sd_stats

        tenant, target, session = target_with_real_dirs

        stats = await get_sd_stats(session, tenant.id, target.id)
        assert stats["unique_sds"] == 0
        assert stats["world_accessible"] == 0
