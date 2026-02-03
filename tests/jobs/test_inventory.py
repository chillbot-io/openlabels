"""
Comprehensive tests for the data inventory service.

Tests focus on:
- Inventory initialization and caching
- Delta scan logic (should_scan_folder, should_scan_file)
- Content hash computation
- Folder and file inventory updates
- Missing file detection
- Inventory statistics
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
)


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


class TestInventoryServiceInit:
    """Tests for InventoryService initialization."""

    def test_init_stores_session(self):
        """Should store the database session."""
        mock_session = AsyncMock()
        tenant_id = uuid4()
        target_id = uuid4()

        service = InventoryService(mock_session, tenant_id, target_id)

        assert service.session is mock_session

    def test_init_stores_tenant_id(self):
        """Should store the tenant ID."""
        mock_session = AsyncMock()
        tenant_id = uuid4()
        target_id = uuid4()

        service = InventoryService(mock_session, tenant_id, target_id)

        assert service.tenant_id == tenant_id

    def test_init_stores_target_id(self):
        """Should store the target ID."""
        mock_session = AsyncMock()
        tenant_id = uuid4()
        target_id = uuid4()

        service = InventoryService(mock_session, tenant_id, target_id)

        assert service.target_id == target_id

    def test_init_creates_empty_folder_cache(self):
        """Should initialize empty folder cache."""
        mock_session = AsyncMock()
        service = InventoryService(mock_session, uuid4(), uuid4())

        assert service._folder_cache == {}

    def test_init_creates_empty_file_cache(self):
        """Should initialize empty file cache."""
        mock_session = AsyncMock()
        service = InventoryService(mock_session, uuid4(), uuid4())

        assert service._file_cache == {}


class TestLoadFolderInventory:
    """Tests for loading folder inventory."""

    @pytest.fixture
    def service(self):
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_loads_folders_into_cache(self, service):
        """Should load folders from DB into cache."""
        mock_folder1 = MagicMock()
        mock_folder1.folder_path = "/path/one"
        mock_folder2 = MagicMock()
        mock_folder2.folder_path = "/path/two"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_folder1, mock_folder2]
        service.session.execute = AsyncMock(return_value=mock_result)

        result = await service.load_folder_inventory()

        assert len(result) == 2
        assert "/path/one" in result
        assert "/path/two" in result

    @pytest.mark.asyncio
    async def test_returns_empty_dict_when_no_folders(self, service):
        """Should return empty dict when no folders exist."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        service.session.execute = AsyncMock(return_value=mock_result)

        result = await service.load_folder_inventory()

        assert result == {}

    @pytest.mark.asyncio
    async def test_updates_internal_cache(self, service):
        """Should update internal _folder_cache."""
        mock_folder = MagicMock()
        mock_folder.folder_path = "/test/path"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_folder]
        service.session.execute = AsyncMock(return_value=mock_result)

        await service.load_folder_inventory()

        assert service._folder_cache["/test/path"] is mock_folder


class TestLoadFileInventory:
    """Tests for loading file inventory."""

    @pytest.fixture
    def service(self):
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_loads_files_into_cache(self, service):
        """Should load files from DB into cache."""
        mock_file1 = MagicMock()
        mock_file1.file_path = "/path/file1.txt"
        mock_file2 = MagicMock()
        mock_file2.file_path = "/path/file2.txt"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_file1, mock_file2]
        service.session.execute = AsyncMock(return_value=mock_result)

        result = await service.load_file_inventory()

        assert len(result) == 2
        assert "/path/file1.txt" in result
        assert "/path/file2.txt" in result

    @pytest.mark.asyncio
    async def test_returns_empty_dict_when_no_files(self, service):
        """Should return empty dict when no files exist."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        service.session.execute = AsyncMock(return_value=mock_result)

        result = await service.load_file_inventory()

        assert result == {}


class TestShouldScanFolder:
    """Tests for should_scan_folder delta logic."""

    @pytest.fixture
    def service(self):
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_returns_true_for_force_full_scan(self, service):
        """Should return True when force_full_scan is True."""
        # Even if folder is in cache
        mock_folder = MagicMock()
        mock_folder.last_scanned_at = datetime.now(timezone.utc)
        mock_folder.has_sensitive_files = False
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test", force_full_scan=True)

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_for_new_folder(self, service):
        """Should return True for folder not in cache."""
        result = await service.should_scan_folder("/new/folder")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_when_never_scanned(self, service):
        """Should return True when folder was never scanned."""
        mock_folder = MagicMock()
        mock_folder.last_scanned_at = None
        mock_folder.has_sensitive_files = False
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test")

        assert result is True

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_returns_true_when_has_sensitive_files(self, service):
        """Should always return True for folders with sensitive files."""
        mock_folder = MagicMock()
        mock_folder.last_scanned_at = datetime.now(timezone.utc)
        mock_folder.folder_modified = None
        mock_folder.has_sensitive_files = True
        service._folder_cache["/test"] = mock_folder

        result = await service.should_scan_folder("/test")

        assert result is True

    @pytest.mark.asyncio
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
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.fixture
    def mock_file_info(self):
        """Create a mock FileInfo object."""
        file_info = MagicMock()
        file_info.path = "/test/file.txt"
        file_info.size = 1024
        file_info.modified = datetime.now(timezone.utc)
        return file_info

    @pytest.mark.asyncio
    async def test_returns_true_for_force_full_scan(self, service, mock_file_info):
        """Should return True with 'full_scan' reason when forced."""
        should_scan, reason = await service.should_scan_file(
            mock_file_info,
            force_full_scan=True
        )

        assert should_scan is True
        assert reason == "full_scan"

    @pytest.mark.asyncio
    async def test_returns_true_for_new_file(self, service, mock_file_info):
        """Should return True with 'new_file' reason for new files."""
        should_scan, reason = await service.should_scan_file(mock_file_info)

        assert should_scan is True
        assert reason == "new_file"

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    def test_computes_sha256_hash(self, service):
        """Should compute SHA-256 hash of content."""
        content = b"Hello, World!"
        expected = hashlib.sha256(content).hexdigest()

        result = service.compute_content_hash(content)

        assert result == expected

    def test_returns_consistent_hash(self, service):
        """Should return same hash for same content."""
        content = b"Test content"

        hash1 = service.compute_content_hash(content)
        hash2 = service.compute_content_hash(content)

        assert hash1 == hash2

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

    def test_hash_is_64_characters(self, service):
        """SHA-256 hex digest should be 64 characters."""
        result = service.compute_content_hash(b"test")

        assert len(result) == 64


class TestUpdateFolderInventory:
    """Tests for updating folder inventory."""

    @pytest.fixture
    def service(self):
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_updates_existing_folder(self, service):
        """Should update existing folder in cache."""
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

    @pytest.mark.asyncio
    async def test_creates_new_folder(self, service):
        """Should create new folder when not in cache."""
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

    @pytest.mark.asyncio
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
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        return InventoryService(mock_session, uuid4(), uuid4())

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

    @pytest.mark.asyncio
    async def test_updates_existing_file(self, service, mock_file_info, mock_scan_result):
        """Should update existing file in cache."""
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_creates_new_file(self, service, mock_file_info, mock_scan_result):
        """Should create new file when not in cache."""
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

    @pytest.mark.asyncio
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
    """Tests for marking missing files."""

    @pytest.fixture
    def service(self):
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_marks_unseen_files_for_rescan(self, service):
        """Should mark files not in seen_paths for rescan."""
        mock_file1 = MagicMock()
        mock_file1.needs_rescan = False
        mock_file2 = MagicMock()
        mock_file2.needs_rescan = False
        mock_file3 = MagicMock()
        mock_file3.needs_rescan = False

        service._file_cache = {
            "/seen/file.txt": mock_file1,
            "/missing/file.txt": mock_file2,
            "/also/missing.txt": mock_file3,
        }

        seen_paths = {"/seen/file.txt"}
        count = await service.mark_missing_files(seen_paths, uuid4())

        assert count == 2
        assert mock_file1.needs_rescan is False
        assert mock_file2.needs_rescan is True
        assert mock_file3.needs_rescan is True

    @pytest.mark.asyncio
    async def test_returns_zero_when_all_seen(self, service):
        """Should return 0 when all files were seen."""
        mock_file = MagicMock()
        mock_file.needs_rescan = False
        service._file_cache = {"/test/file.txt": mock_file}

        count = await service.mark_missing_files({"/test/file.txt"}, uuid4())

        assert count == 0
        assert mock_file.needs_rescan is False

    @pytest.mark.asyncio
    async def test_returns_zero_with_empty_cache(self, service):
        """Should return 0 when cache is empty."""
        count = await service.mark_missing_files({"/some/path"}, uuid4())

        assert count == 0


class TestGetInventoryStats:
    """Tests for inventory statistics."""

    @pytest.fixture
    def service(self):
        """Create an InventoryService instance."""
        mock_session = AsyncMock()
        return InventoryService(mock_session, uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_returns_folder_count(self, service):
        """Should return correct folder count."""
        service._folder_cache = {
            "/a": MagicMock(),
            "/b": MagicMock(),
            "/c": MagicMock(),
        }
        service._file_cache = {}

        stats = await service.get_inventory_stats()

        assert stats["total_folders"] == 3

    @pytest.mark.asyncio
    async def test_returns_file_count(self, service):
        """Should return correct sensitive file count."""
        service._folder_cache = {}

        mock_file = MagicMock()
        mock_file.risk_tier = "LOW"
        mock_file.total_entities = 0
        mock_file.current_label_id = None
        mock_file.needs_rescan = False

        service._file_cache = {
            "/a.txt": mock_file,
            "/b.txt": mock_file,
        }

        stats = await service.get_inventory_stats()

        assert stats["total_sensitive_files"] == 2

    @pytest.mark.asyncio
    async def test_counts_risk_tiers(self, service):
        """Should count files by risk tier."""
        service._folder_cache = {}

        def make_file(tier, entities=0):
            f = MagicMock()
            f.risk_tier = tier
            f.total_entities = entities
            f.current_label_id = None
            f.needs_rescan = False
            return f

        service._file_cache = {
            "/a": make_file("CRITICAL"),
            "/b": make_file("CRITICAL"),
            "/c": make_file("HIGH"),
            "/d": make_file("MEDIUM"),
            "/e": make_file("LOW"),
            "/f": make_file("MINIMAL"),
        }

        stats = await service.get_inventory_stats()

        assert stats["risk_tier_breakdown"]["CRITICAL"] == 2
        assert stats["risk_tier_breakdown"]["HIGH"] == 1
        assert stats["risk_tier_breakdown"]["MEDIUM"] == 1
        assert stats["risk_tier_breakdown"]["LOW"] == 1
        assert stats["risk_tier_breakdown"]["MINIMAL"] == 1

    @pytest.mark.asyncio
    async def test_counts_total_entities(self, service):
        """Should sum total entities across files."""
        service._folder_cache = {}

        def make_file(entities):
            f = MagicMock()
            f.risk_tier = "LOW"
            f.total_entities = entities
            f.current_label_id = None
            f.needs_rescan = False
            return f

        service._file_cache = {
            "/a": make_file(10),
            "/b": make_file(20),
            "/c": make_file(5),
        }

        stats = await service.get_inventory_stats()

        assert stats["total_entities"] == 35

    @pytest.mark.asyncio
    async def test_counts_labeled_files(self, service):
        """Should count files with labels applied."""
        service._folder_cache = {}

        def make_file(label_id):
            f = MagicMock()
            f.risk_tier = "LOW"
            f.total_entities = 0
            f.current_label_id = label_id
            f.needs_rescan = False
            return f

        service._file_cache = {
            "/a": make_file(uuid4()),
            "/b": make_file(uuid4()),
            "/c": make_file(None),  # Not labeled
        }

        stats = await service.get_inventory_stats()

        assert stats["labeled_files"] == 2

    @pytest.mark.asyncio
    async def test_counts_pending_rescan(self, service):
        """Should count files flagged for rescan."""
        service._folder_cache = {}

        def make_file(needs_rescan):
            f = MagicMock()
            f.risk_tier = "LOW"
            f.total_entities = 0
            f.current_label_id = None
            f.needs_rescan = needs_rescan
            return f

        service._file_cache = {
            "/a": make_file(True),
            "/b": make_file(True),
            "/c": make_file(False),
        }

        stats = await service.get_inventory_stats()

        assert stats["pending_rescan"] == 2

    @pytest.mark.asyncio
    async def test_handles_empty_inventory(self, service):
        """Should handle empty caches gracefully."""
        stats = await service.get_inventory_stats()

        assert stats["total_folders"] == 0
        assert stats["total_sensitive_files"] == 0
        assert stats["total_entities"] == 0
        assert stats["labeled_files"] == 0
        assert stats["pending_rescan"] == 0

    @pytest.mark.asyncio
    async def test_ignores_unknown_risk_tiers(self, service):
        """Should only count known risk tiers."""
        service._folder_cache = {}

        mock_file = MagicMock()
        mock_file.risk_tier = "UNKNOWN_TIER"
        mock_file.total_entities = 0
        mock_file.current_label_id = None
        mock_file.needs_rescan = False
        service._file_cache = {"/a": mock_file}

        stats = await service.get_inventory_stats()

        # Unknown tier shouldn't be counted
        assert stats["risk_tier_breakdown"]["CRITICAL"] == 0
        assert stats["risk_tier_breakdown"]["HIGH"] == 0
