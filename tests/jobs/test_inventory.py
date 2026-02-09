"""
Comprehensive tests for the data inventory service.

Tests focus on:
- On-demand inventory lookups with bounded LRU cache
- Delta scan logic (should_scan_folder, should_scan_file)
- Content hash computation
- Folder and file inventory updates
- Missing file detection (DB UPDATE approach)
- Inventory statistics (DB aggregation)
"""

import sys
import os
import hashlib

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.inventory import (
    InventoryService,
    get_folder_path,
    _FILE_CACHE_MAX,
    _FOLDER_CACHE_MAX,
)


def _make_service(session=None):
    """Create an InventoryService with a session that returns None for DB lookups."""
    if session is None:
        session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_exec_result)
    session.add = MagicMock()
    return InventoryService(session, uuid4(), uuid4())


class TestGetFolderPath:
    """Tests for get_folder_path utility function."""

    def test_extracts_parent_from_file_path(self):
        """Should return the parent directory of a file path."""
        result = get_folder_path("/home/user/documents/report.pdf")
        assert result == "/home/user/documents"

    def test_handles_root_file(self):
        """Should return root for file at root."""
        result = get_folder_path("/file.txt")
        assert result == "/"

    def test_handles_nested_path(self):
        """Should handle deeply nested paths."""
        result = get_folder_path("/a/b/c/d/e/file.txt")
        assert result == "/a/b/c/d/e"

    def test_handles_windows_style_path(self):
        """Should handle paths with backslashes (converted by Path)."""
        # Path normalizes separators
        result = get_folder_path("C:/Users/name/file.txt")
        assert "Users" in result and "name" in result

    def test_handles_relative_path(self):
        """Should handle relative paths."""
        result = get_folder_path("folder/subfolder/file.txt")
        assert result == "folder/subfolder"


class TestOnDemandLookup:
    """Tests for on-demand LRU cache lookups (_get_folder_inv, _get_file_inv)."""

    async def test_folder_cache_hit(self):
        """Should return cached folder without DB query."""
        service = _make_service()
        mock_folder = MagicMock()
        service._folder_cache["/test"] = mock_folder

        result = await service._get_folder_inv("/test")

        assert result is mock_folder
        # DB should not be queried
        service.session.execute.assert_not_awaited()

    async def test_folder_cache_miss_queries_db(self):
        """Should query DB on cache miss and cache the result."""
        service = _make_service()
        mock_folder = MagicMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_folder
        service.session.execute = AsyncMock(return_value=mock_result)

        result = await service._get_folder_inv("/test")

        assert result is mock_folder
        assert service._folder_cache["/test"] is mock_folder
        service.session.execute.assert_awaited_once()

    async def test_folder_cache_miss_returns_none(self):
        """Should return None when not in cache or DB."""
        service = _make_service()

        result = await service._get_folder_inv("/nonexistent")

        assert result is None
        assert "/nonexistent" not in service._folder_cache

    async def test_file_cache_hit(self):
        """Should return cached file without DB query."""
        service = _make_service()
        mock_file = MagicMock()
        service._file_cache["/test/file.txt"] = mock_file

        result = await service._get_file_inv("/test/file.txt")

        assert result is mock_file
        service.session.execute.assert_not_awaited()

    async def test_file_cache_miss_queries_db(self):
        """Should query DB on cache miss and cache the result."""
        service = _make_service()
        mock_file = MagicMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_file
        service.session.execute = AsyncMock(return_value=mock_result)

        result = await service._get_file_inv("/test/file.txt")

        assert result is mock_file
        assert service._file_cache["/test/file.txt"] is mock_file

    async def test_file_cache_miss_returns_none(self):
        """Should return None when not in cache or DB."""
        service = _make_service()

        result = await service._get_file_inv("/nonexistent.txt")

        assert result is None

    async def test_folder_cache_evicts_oldest(self):
        """Should evict oldest entries when cache exceeds limit."""
        service = _make_service()

        # Fill beyond limit
        for i in range(_FOLDER_CACHE_MAX + 10):
            service._cache_folder(f"/folder/{i}", MagicMock())

        assert len(service._folder_cache) == _FOLDER_CACHE_MAX

    async def test_file_cache_evicts_oldest(self):
        """Should evict oldest entries when cache exceeds limit."""
        service = _make_service()

        for i in range(_FILE_CACHE_MAX + 10):
            service._cache_file(f"/file/{i}.txt", MagicMock())

        assert len(service._file_cache) == _FILE_CACHE_MAX

    async def test_cache_moves_to_end_on_hit(self):
        """LRU: accessing an entry should move it to the end."""
        service = _make_service()
        service._cache_folder("/a", MagicMock())
        service._cache_folder("/b", MagicMock())
        service._cache_folder("/c", MagicMock())

        # Access /a to move it to end
        await service._get_folder_inv("/a")

        keys = list(service._folder_cache.keys())
        assert keys[-1] == "/a"


class TestShouldScanFolder:
    """Tests for should_scan_folder delta logic."""

    @pytest.fixture
    def service(self):
        return _make_service()

    async def test_returns_true_for_force_full_scan(self, service):
        """Should return True when force_full_scan is True."""
        # Even if folder is in cache
        mock_folder = MagicMock()
        mock_folder.last_scanned_at = datetime.now(timezone.utc)
        mock_folder.has_sensitive_files = False
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test", force_full_scan=True)

        assert result is True

    async def test_returns_true_for_new_folder(self, service):
        """Should return True for folder not in cache or DB."""
        result = await service.should_scan_folder("/new/folder")

        assert result is True

    async def test_returns_true_when_never_scanned(self, service):
        """Should return True when folder was never scanned."""
        mock_folder = MagicMock()
        mock_folder.last_scanned_at = None
        mock_folder.has_sensitive_files = False
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test")

        assert result is True

    async def test_returns_true_when_folder_modified(self, service):
        """Should return True when folder modified since last scan."""
        old_time = datetime.now(timezone.utc) - timedelta(days=1)
        new_time = datetime.now(timezone.utc)

        mock_folder = MagicMock()
        mock_folder.last_scanned_at = old_time
        mock_folder.folder_modified = old_time
        mock_folder.has_sensitive_files = False
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test", folder_modified=new_time)

        assert result is True

    async def test_returns_true_when_has_sensitive_files(self, service):
        """Should always return True for folders with sensitive files."""
        mock_folder = MagicMock()
        mock_folder.last_scanned_at = datetime.now(timezone.utc)
        mock_folder.folder_modified = None
        mock_folder.has_sensitive_files = True
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test")

        assert result is True

    async def test_returns_false_when_unchanged(self, service):
        """Should return False for unchanged folder without sensitive files."""
        scan_time = datetime.now(timezone.utc)

        mock_folder = MagicMock()
        mock_folder.last_scanned_at = scan_time
        mock_folder.folder_modified = scan_time - timedelta(hours=1)
        mock_folder.has_sensitive_files = False
        service._folder_cache["/test"] = mock_folder

        # Folder modified time is older than last scan
        result = await service.should_scan_folder(
            "/test",
            folder_modified=scan_time - timedelta(hours=2)
        )

        assert result is False


class TestShouldScanFile:
    """Tests for should_scan_file delta logic."""

    @pytest.fixture
    def service(self):
        return _make_service()

    @pytest.fixture
    def mock_file_info(self):
        """Create a mock FileInfo object."""
        file_info = MagicMock()
        file_info.path = "/test/file.txt"
        file_info.size = 1024
        file_info.modified = datetime.now(timezone.utc)
        return file_info

    async def test_returns_true_for_force_full_scan(self, service, mock_file_info):
        """Should return True with 'full_scan' reason when forced."""
        should_scan, reason = await service.should_scan_file(
            mock_file_info,
            force_full_scan=True
        )

        assert should_scan is True
        assert reason == "full_scan"

    async def test_returns_true_for_new_file(self, service, mock_file_info):
        """Should return True with 'new_file' reason for new files."""
        should_scan, reason = await service.should_scan_file(mock_file_info)

        assert should_scan is True
        assert reason == "new_file"

    async def test_returns_true_when_flagged_for_rescan(self, service, mock_file_info):
        """Should return True when file is flagged for rescan."""
        mock_inv = MagicMock()
        mock_inv.needs_rescan = True
        mock_inv.content_hash = "abc123"
        mock_inv.file_modified = datetime.now(timezone.utc)
        mock_inv.file_size = 1024
        service._file_cache[mock_file_info.path] = mock_inv

        should_scan, reason = await service.should_scan_file(mock_file_info)

        assert should_scan is True
        assert reason == "flagged_rescan"

    async def test_returns_true_when_content_changed(self, service, mock_file_info):
        """Should return True when content hash differs."""
        mock_inv = MagicMock()
        mock_inv.needs_rescan = False
        mock_inv.content_hash = "old_hash"
        mock_inv.file_modified = mock_file_info.modified
        mock_inv.file_size = mock_file_info.size
        service._file_cache[mock_file_info.path] = mock_inv

        should_scan, reason = await service.should_scan_file(
            mock_file_info,
            content_hash="new_hash"
        )

        assert should_scan is True
        assert reason == "content_changed"

    async def test_returns_true_when_modified_time_newer(self, service, mock_file_info):
        """Should return True when file modification time is newer."""
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)

        mock_inv = MagicMock()
        mock_inv.needs_rescan = False
        mock_inv.content_hash = None
        mock_inv.file_modified = old_time
        mock_inv.file_size = mock_file_info.size
        service._file_cache[mock_file_info.path] = mock_inv

        should_scan, reason = await service.should_scan_file(mock_file_info)

        assert should_scan is True
        assert reason == "modified_time"

    async def test_returns_true_when_size_changed(self, service, mock_file_info):
        """Should return True when file size differs."""
        mock_inv = MagicMock()
        mock_inv.needs_rescan = False
        mock_inv.content_hash = None
        mock_inv.file_modified = None
        mock_inv.file_size = 2048  # Different from mock_file_info.size (1024)
        service._file_cache[mock_file_info.path] = mock_inv

        should_scan, reason = await service.should_scan_file(mock_file_info)

        assert should_scan is True
        assert reason == "size_changed"

    async def test_returns_false_when_unchanged(self, service, mock_file_info):
        """Should return False with 'unchanged' for unchanged file."""
        mock_inv = MagicMock()
        mock_inv.needs_rescan = False
        mock_inv.content_hash = "same_hash"
        mock_inv.file_modified = mock_file_info.modified
        mock_inv.file_size = mock_file_info.size
        service._file_cache[mock_file_info.path] = mock_inv

        should_scan, reason = await service.should_scan_file(
            mock_file_info,
            content_hash="same_hash"
        )

        assert should_scan is False
        assert reason == "unchanged"


class TestComputeContentHash:
    """Tests for content hash computation."""

    @pytest.fixture
    def service(self):
        return _make_service()

    def test_computes_sha256_hash(self, service):
        """Should compute SHA-256 hash of content."""
        content = b"Hello, World!"
        expected = hashlib.sha256(content).hexdigest()

        result = service.compute_content_hash(content)

        assert result == expected

    def test_different_content_different_hash(self, service):
        """Should return different hash for different content."""
        hash1 = service.compute_content_hash(b"Content A")
        hash2 = service.compute_content_hash(b"Content B")

        assert hash1 != hash2

    def test_handles_empty_content(self, service):
        """Should handle empty bytes."""
        result = service.compute_content_hash(b"")
        expected = hashlib.sha256(b"").hexdigest()

        assert result == expected


class TestUpdateFolderInventory:
    """Tests for updating folder inventory."""

    @pytest.fixture
    def service(self):
        return _make_service()

    async def test_updates_existing_folder(self, service):
        """Should update existing folder found in cache."""
        job_id = uuid4()
        mock_folder = MagicMock()
        mock_folder.folder_path = "/test"
        service._folder_cache["/test"] = mock_folder

        result = await service.update_folder_inventory(
            folder_path="/test",
            adapter="filesystem",
            job_id=job_id,
            file_count=10,
            total_size=1024,
            has_sensitive=True,
            highest_risk="HIGH",
            total_entities=5,
        )

        assert result is mock_folder
        assert mock_folder.file_count == 10
        assert mock_folder.total_size_bytes == 1024
        assert mock_folder.has_sensitive_files is True
        assert mock_folder.highest_risk_tier == "HIGH"
        assert mock_folder.total_entities_found == 5
        assert mock_folder.last_scan_job_id == job_id

    async def test_creates_new_folder(self, service):
        """Should create new folder when not in cache or DB."""
        job_id = uuid4()

        with patch('openlabels.jobs.inventory.FolderInventory') as MockFolderInv:
            mock_new_folder = MagicMock()
            MockFolderInv.return_value = mock_new_folder

            result = await service.update_folder_inventory(
                folder_path="/new/folder",
                adapter="filesystem",
                job_id=job_id,
                file_count=5,
            )

            MockFolderInv.assert_called_once()
            service.session.add.assert_called_once_with(mock_new_folder)
            assert service._folder_cache["/new/folder"] is mock_new_folder

    async def test_sets_last_scanned_at(self, service):
        """Should set last_scanned_at to current time."""
        mock_folder = MagicMock()
        service._folder_cache["/test"] = mock_folder

        before = datetime.now(timezone.utc)
        await service.update_folder_inventory(
            folder_path="/test",
            adapter="filesystem",
            job_id=uuid4(),
        )
        after = datetime.now(timezone.utc)

        assert before <= mock_folder.last_scanned_at <= after


class TestUpdateFileInventory:
    """Tests for updating file inventory."""

    @pytest.fixture
    def service(self):
        return _make_service()

    @pytest.fixture
    def mock_file_info(self):
        """Create a mock FileInfo object."""
        file_info = MagicMock()
        file_info.path = "/test/file.txt"
        file_info.name = "file.txt"
        file_info.adapter = "local"
        file_info.size = 1024
        file_info.modified = datetime.now(timezone.utc)
        return file_info

    @pytest.fixture
    def mock_scan_result(self):
        """Create a mock ScanResult object."""
        result = MagicMock()
        result.risk_score = 75
        result.risk_tier = "HIGH"
        result.entity_counts = {"ssn": 5, "email": 10}
        result.total_entities = 15
        result.exposure_level = "INTERNAL"
        result.owner = "user@example.com"
        result.label_applied = False
        result.current_label_id = None
        result.current_label_name = None
        result.label_applied_at = None
        return result

    async def test_updates_existing_file(self, service, mock_file_info, mock_scan_result):
        """Should update existing file found in cache."""
        job_id = uuid4()
        mock_file_inv = MagicMock()
        mock_file_inv.content_hash = "old_hash"
        mock_file_inv.content_changed_count = 0
        mock_file_inv.scan_count = 1
        service._file_cache[mock_file_info.path] = mock_file_inv

        result = await service.update_file_inventory(
            file_info=mock_file_info,
            scan_result=mock_scan_result,
            content_hash="new_hash",
            job_id=job_id,
        )

        assert result is mock_file_inv
        assert mock_file_inv.content_hash == "new_hash"
        assert mock_file_inv.content_changed_count == 1  # Incremented
        assert mock_file_inv.scan_count == 2  # Incremented
        assert mock_file_inv.needs_rescan is False

    async def test_increments_content_changed_count(self, service, mock_file_info, mock_scan_result):
        """Should increment content_changed_count when hash differs."""
        mock_file_inv = MagicMock()
        mock_file_inv.content_hash = "hash1"
        mock_file_inv.content_changed_count = 5
        mock_file_inv.scan_count = 10
        service._file_cache[mock_file_info.path] = mock_file_inv

        await service.update_file_inventory(
            file_info=mock_file_info,
            scan_result=mock_scan_result,
            content_hash="hash2",  # Different
            job_id=uuid4(),
        )

        assert mock_file_inv.content_changed_count == 6

    async def test_does_not_increment_when_hash_same(self, service, mock_file_info, mock_scan_result):
        """Should not increment content_changed_count when hash matches."""
        mock_file_inv = MagicMock()
        mock_file_inv.content_hash = "same_hash"
        mock_file_inv.content_changed_count = 5
        mock_file_inv.scan_count = 10
        service._file_cache[mock_file_info.path] = mock_file_inv

        await service.update_file_inventory(
            file_info=mock_file_info,
            scan_result=mock_scan_result,
            content_hash="same_hash",  # Same
            job_id=uuid4(),
        )

        assert mock_file_inv.content_changed_count == 5  # Not incremented

    async def test_creates_new_file(self, service, mock_file_info, mock_scan_result):
        """Should create new file when not in cache or DB."""
        job_id = uuid4()

        with patch('openlabels.jobs.inventory.FileInventory') as MockFileInv:
            mock_new_file = MagicMock()
            MockFileInv.return_value = mock_new_file

            result = await service.update_file_inventory(
                file_info=mock_file_info,
                scan_result=mock_scan_result,
                content_hash="abc123",
                job_id=job_id,
            )

            MockFileInv.assert_called_once()
            service.session.add.assert_called_once_with(mock_new_file)
            assert service._file_cache[mock_file_info.path] is mock_new_file

    async def test_updates_label_info_when_applied(self, service, mock_file_info, mock_scan_result):
        """Should update label info when label was applied."""
        mock_scan_result.label_applied = True
        mock_scan_result.current_label_id = uuid4()
        mock_scan_result.current_label_name = "Confidential"
        mock_scan_result.label_applied_at = datetime.now(timezone.utc)

        mock_file_inv = MagicMock()
        mock_file_inv.content_hash = "same"
        mock_file_inv.content_changed_count = 0
        mock_file_inv.scan_count = 0
        service._file_cache[mock_file_info.path] = mock_file_inv

        await service.update_file_inventory(
            file_info=mock_file_info,
            scan_result=mock_scan_result,
            content_hash="same",
            job_id=uuid4(),
        )

        assert mock_file_inv.current_label_id == mock_scan_result.current_label_id
        assert mock_file_inv.current_label_name == "Confidential"
        assert mock_file_inv.label_applied_at == mock_scan_result.label_applied_at


class TestMarkMissingFiles:
    """Tests for marking missing files via DB UPDATE."""

    @pytest.fixture
    def service(self):
        return _make_service()

    async def test_executes_update_and_returns_rowcount(self, service):
        """Should execute UPDATE and return rowcount."""
        mock_result = MagicMock()
        mock_result.rowcount = 5
        service.session.execute = AsyncMock(return_value=mock_result)

        count = await service.mark_missing_files(uuid4())

        assert count == 5
        service.session.execute.assert_awaited_once()

    async def test_returns_zero_when_no_missing(self, service):
        """Should return 0 when no files are missing."""
        mock_result = MagicMock()
        mock_result.rowcount = 0
        service.session.execute = AsyncMock(return_value=mock_result)

        count = await service.mark_missing_files(uuid4())

        assert count == 0

    async def test_only_takes_job_id(self, service):
        """New signature takes only job_id (no seen_paths)."""
        mock_result = MagicMock()
        mock_result.rowcount = 0
        service.session.execute = AsyncMock(return_value=mock_result)

        # Should work with just job_id
        count = await service.mark_missing_files(uuid4())
        assert count == 0


class TestGetInventoryStats:
    """Tests for inventory statistics via DB aggregation."""

    @pytest.fixture
    def service(self):
        return _make_service()

    def _mock_stats_queries(self, service, folder_count=0, file_total=0,
                            total_entities=0, labeled=0, pending_rescan=0,
                            risk_rows=None):
        """Configure mock session to return values for the 5 aggregation queries."""
        if risk_rows is None:
            risk_rows = []

        # Build mock results for each query in order:
        # 1. folder count (scalar)
        # 2. file aggregate (row with .total and .total_entities)
        # 3. labeled count (scalar)
        # 4. pending rescan count (scalar)
        # 5. risk tier breakdown (rows with .risk_tier and .cnt)
        folder_result = MagicMock()
        folder_result.scalar.return_value = folder_count

        file_row = MagicMock()
        file_row.total = file_total
        file_row.total_entities = total_entities
        file_result = MagicMock()
        file_result.one.return_value = file_row

        labeled_result = MagicMock()
        labeled_result.scalar.return_value = labeled

        rescan_result = MagicMock()
        rescan_result.scalar.return_value = pending_rescan

        risk_result = MagicMock()
        risk_result.all.return_value = risk_rows

        service.session.execute = AsyncMock(
            side_effect=[folder_result, file_result, labeled_result,
                         rescan_result, risk_result]
        )

    async def test_returns_folder_count(self, service):
        """Should return correct folder count from DB."""
        self._mock_stats_queries(service, folder_count=3)

        stats = await service.get_inventory_stats()

        assert stats["total_folders"] == 3

    async def test_returns_file_count(self, service):
        """Should return correct sensitive file count from DB."""
        self._mock_stats_queries(service, file_total=5)

        stats = await service.get_inventory_stats()

        assert stats["total_sensitive_files"] == 5

    async def test_counts_risk_tiers(self, service):
        """Should count files by risk tier from DB."""
        risk_rows = [
            MagicMock(risk_tier="CRITICAL", cnt=2),
            MagicMock(risk_tier="HIGH", cnt=1),
            MagicMock(risk_tier="MEDIUM", cnt=1),
            MagicMock(risk_tier="LOW", cnt=1),
            MagicMock(risk_tier="MINIMAL", cnt=1),
        ]
        self._mock_stats_queries(service, file_total=6, risk_rows=risk_rows)

        stats = await service.get_inventory_stats()

        assert stats["risk_tier_breakdown"]["CRITICAL"] == 2
        assert stats["risk_tier_breakdown"]["HIGH"] == 1
        assert stats["risk_tier_breakdown"]["MEDIUM"] == 1
        assert stats["risk_tier_breakdown"]["LOW"] == 1
        assert stats["risk_tier_breakdown"]["MINIMAL"] == 1

    async def test_counts_total_entities(self, service):
        """Should return sum of total entities from DB."""
        self._mock_stats_queries(service, total_entities=35)

        stats = await service.get_inventory_stats()

        assert stats["total_entities"] == 35

    async def test_counts_labeled_files(self, service):
        """Should count files with labels from DB."""
        self._mock_stats_queries(service, labeled=2)

        stats = await service.get_inventory_stats()

        assert stats["labeled_files"] == 2

    async def test_counts_pending_rescan(self, service):
        """Should count files flagged for rescan from DB."""
        self._mock_stats_queries(service, pending_rescan=2)

        stats = await service.get_inventory_stats()

        assert stats["pending_rescan"] == 2

    async def test_handles_empty_inventory(self, service):
        """Should handle empty DB results gracefully."""
        self._mock_stats_queries(service)

        stats = await service.get_inventory_stats()

        assert stats["total_folders"] == 0
        assert stats["total_sensitive_files"] == 0
        assert stats["total_entities"] == 0
        assert stats["labeled_files"] == 0
        assert stats["pending_rescan"] == 0

    async def test_ignores_unknown_risk_tiers(self, service):
        """Should only count known risk tiers."""
        risk_rows = [MagicMock(risk_tier="UNKNOWN_TIER", cnt=3)]
        self._mock_stats_queries(service, file_total=3, risk_rows=risk_rows)

        stats = await service.get_inventory_stats()

        # Unknown tier shouldn't be counted in known tiers
        assert stats["risk_tier_breakdown"]["CRITICAL"] == 0
        assert stats["risk_tier_breakdown"]["HIGH"] == 0
