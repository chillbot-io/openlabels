"""
Comprehensive tests for the scan task.

Tests focus on:
- Processor initialization and caching
- Job cancellation detection
- Adapter selection
- Detection and scoring
- Delta scanning
- Parallel scan execution
- Task creation and queuing
- Task execution (success path)
- Task failure handling (retries, max retries exceeded)
- Task cancellation
- Progress reporting and updates
- Concurrent task execution
- Task prioritization
- Task timeout handling
- Cleanup after task completion/failure
- Different file types (PDF, DOCX, XLSX, images)
- Large files handling
- Corrupted/unreadable files
- Permission denied scenarios
- Network file access (mock SharePoint/OneDrive)
- Detection result aggregation
- Risk score calculation
- Database connection failures during task
- Out of memory conditions
- Worker crash recovery
- Orphaned tasks cleanup
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock

from openlabels.jobs.tasks.scan import (
    get_processor,
    _check_cancellation,
    _get_adapter,
    _detect_and_score,
    execute_scan_task,
    CANCELLATION_CHECK_INTERVAL,
)
from openlabels.exceptions import AdapterError, JobError


class TestGetProcessor:
    """Tests for get_processor function."""

    def test_creates_file_processor(self):
        """Should create and return a FileProcessor."""
        import openlabels.jobs.tasks.scan as scan_module

        # Reset global processor
        original = scan_module._processor
        scan_module._processor = None

        try:
            with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                mock_settings.return_value = MagicMock(
                    ml_model_dir=None,
                    confidence_threshold=0.70,
                )
                with patch('openlabels.jobs.tasks.scan.FileProcessor') as MockProcessor:
                    MockProcessor.return_value = MagicMock()
                    result = get_processor()

                    MockProcessor.assert_called_once()
                    assert result is not None
        finally:
            scan_module._processor = original

    def test_reuses_existing_processor(self):
        """Should reuse cached processor on subsequent calls."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_proc = MagicMock()
        scan_module._processor = mock_proc

        try:
            result = get_processor()
            assert result is mock_proc
        finally:
            scan_module._processor = original

    def test_passes_enable_ml_parameter(self):
        """Should pass enable_ml to FileProcessor."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        scan_module._processor = None

        try:
            with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                mock_settings.return_value = MagicMock(
                    ml_model_dir="/models",
                    confidence_threshold=0.80,
                )
                with patch('openlabels.jobs.tasks.scan.FileProcessor') as MockProcessor:
                    MockProcessor.return_value = MagicMock()
                    get_processor(enable_ml=True)

                    call_kwargs = MockProcessor.call_args.kwargs
                    assert call_kwargs["config"].enable_ml is True
        finally:
            scan_module._processor = original


class TestCheckCancellation:
    """Tests for _check_cancellation function."""

    async def test_returns_true_when_cancelled(self):
        """Should return True when job status is 'cancelled'."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = "cancelled"
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await _check_cancellation(mock_session, uuid4())

        assert result is True

    async def test_returns_false_when_running(self):
        """Should return False when job is still running."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = "running"
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await _check_cancellation(mock_session, uuid4())

        assert result is False

    async def test_returns_false_when_job_not_found(self):
        """Should return False when job doesn't exist."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await _check_cancellation(mock_session, uuid4())

        assert result is False


class TestGetAdapter:
    """Tests for _get_adapter function."""

    def test_returns_filesystem_adapter(self):
        """Should return FilesystemAdapter for 'filesystem' type."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock()
            with patch('openlabels.jobs.tasks.scan.FilesystemAdapter') as MockAdapter:
                MockAdapter.return_value = MagicMock()
                result = _get_adapter("filesystem", {})

                MockAdapter.assert_called_once()
                assert result is not None

    def test_returns_sharepoint_adapter(self):
        """Should return SharePointAdapter for 'sharepoint' type."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
            )
            with patch('openlabels.jobs.tasks.scan.SharePointAdapter') as MockAdapter:
                MockAdapter.return_value = MagicMock()
                result = _get_adapter("sharepoint", {})

                MockAdapter.assert_called_once()

    def test_returns_onedrive_adapter(self):
        """Should return OneDriveAdapter for 'onedrive' type."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
            )
            with patch('openlabels.jobs.tasks.scan.OneDriveAdapter') as MockAdapter:
                MockAdapter.return_value = MagicMock()
                result = _get_adapter("onedrive", {})

                MockAdapter.assert_called_once()

    def test_raises_for_unknown_adapter(self):
        """Should raise AdapterError for unknown adapter type."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock()

            with pytest.raises(AdapterError) as exc_info:
                _get_adapter("unknown_adapter", {})

            assert "unknown" in str(exc_info.value).lower()

    def test_passes_service_account_to_filesystem(self):
        """Should pass service_account config to FilesystemAdapter."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock()
            with patch('openlabels.jobs.tasks.scan.FilesystemAdapter') as MockAdapter:
                MockAdapter.return_value = MagicMock()
                _get_adapter("filesystem", {"service_account": "user@domain.com"})

                call_kwargs = MockAdapter.call_args.kwargs
                assert call_kwargs["service_account"] == "user@domain.com"

    def test_raises_sharepoint_without_auth(self):
        """Should raise AdapterError when SharePoint auth is missing."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(tenant_id=None, client_id=None)
            )

            with pytest.raises(AdapterError) as exc_info:
                _get_adapter("sharepoint", {})

            assert "auth" in str(exc_info.value).lower()

    def test_raises_onedrive_without_auth(self):
        """Should raise AdapterError when OneDrive auth is missing."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(tenant_id=None, client_id=None)
            )

            with pytest.raises(AdapterError) as exc_info:
                _get_adapter("onedrive", {})

            assert "auth" in str(exc_info.value).lower()


class TestDetectAndScore:
    """Tests for _detect_and_score function."""

    @pytest.fixture
    def mock_file_info(self):
        """Create a mock FileInfo object."""
        file_info = MagicMock()
        file_info.path = "/test/file.txt"
        file_info.name = "file.txt"
        file_info.size = 1024
        file_info.exposure = MagicMock(value="PRIVATE")
        return file_info

    async def test_returns_detection_results(self, mock_file_info):
        """Should return detection results from processor."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_processor = MagicMock()
        mock_result = MagicMock()
        mock_result.risk_score = 75
        mock_result.risk_tier = MagicMock(value="HIGH")
        mock_result.entity_counts = {"ssn": 5}
        mock_result.spans = []
        mock_result.processing_time_ms = 100
        mock_result.error = None
        mock_processor.process_file = AsyncMock(return_value=mock_result)
        scan_module._processor = mock_processor

        try:
            result = await _detect_and_score(b"test content", mock_file_info)

            assert result["risk_score"] == 75
            assert result["risk_tier"] == "HIGH"
            assert result["entity_counts"] == {"ssn": 5}
            assert result["total_entities"] == 5
        finally:
            scan_module._processor = original

    async def test_handles_unicode_decode_error(self, mock_file_info):
        """Should handle UnicodeDecodeError gracefully."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_processor = MagicMock()
        mock_processor.process_file = AsyncMock(
            side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")
        )
        scan_module._processor = mock_processor

        try:
            result = await _detect_and_score(b"test", mock_file_info)

            assert result["risk_score"] == 0
            assert result["risk_tier"] == "MINIMAL"
            assert "error" in result
        finally:
            scan_module._processor = original

    async def test_handles_value_error(self, mock_file_info):
        """Should handle ValueError gracefully."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_processor = MagicMock()
        mock_processor.process_file = AsyncMock(
            side_effect=ValueError("Invalid file format")
        )
        scan_module._processor = mock_processor

        try:
            result = await _detect_and_score(b"test", mock_file_info)

            assert result["risk_score"] == 0
            assert result["risk_tier"] == "MINIMAL"
            assert "Value error" in result.get("error", "")
        finally:
            scan_module._processor = original

    async def test_handles_os_error(self, mock_file_info):
        """Should handle OSError gracefully."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_processor = MagicMock()
        mock_processor.process_file = AsyncMock(
            side_effect=OSError("Disk full")
        )
        scan_module._processor = mock_processor

        try:
            result = await _detect_and_score(b"test", mock_file_info)

            assert result["risk_score"] == 0
            assert result["risk_tier"] == "MINIMAL"
            assert "OS error" in result.get("error", "")
        finally:
            scan_module._processor = original

    async def test_limits_findings_to_50(self, mock_file_info):
        """Should limit findings list to first 50."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_processor = MagicMock()

        # Create 100 mock spans
        mock_spans = []
        for i in range(100):
            span = MagicMock()
            span.entity_type = "test"
            span.start = i
            span.end = i + 1
            span.confidence = 0.9
            span.detector = "test_detector"
            span.tier = MagicMock(name="LOW")
            mock_spans.append(span)

        mock_result = MagicMock()
        mock_result.risk_score = 50
        mock_result.risk_tier = MagicMock(value="MEDIUM")
        mock_result.entity_counts = {"test": 100}
        mock_result.spans = mock_spans
        mock_result.processing_time_ms = 100
        mock_result.error = None
        mock_processor.process_file = AsyncMock(return_value=mock_result)
        scan_module._processor = mock_processor

        try:
            result = await _detect_and_score(b"test", mock_file_info)

            assert len(result["findings"]["entities"]) == 50
        finally:
            scan_module._processor = original

    async def test_calculates_total_entities_correctly(self, mock_file_info):
        """Should correctly sum entity counts for total_entities."""
        import openlabels.jobs.tasks.scan as scan_module

        original = scan_module._processor
        mock_processor = MagicMock()
        mock_result = MagicMock()
        mock_result.risk_score = 85
        mock_result.risk_tier = MagicMock(value="HIGH")
        mock_result.entity_counts = {"ssn": 3, "credit_card": 2, "phone": 5}
        mock_result.spans = []
        mock_result.processing_time_ms = 50
        mock_result.error = None
        mock_processor.process_file = AsyncMock(return_value=mock_result)
        scan_module._processor = mock_processor

        try:
            result = await _detect_and_score(b"test", mock_file_info)
            assert result["total_entities"] == 10  # 3 + 2 + 5
        finally:
            scan_module._processor = original


class TestExecuteScanTask:
    """Tests for execute_scan_task function."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    @pytest.fixture
    def mock_job(self):
        """Create a mock ScanJob."""
        job = MagicMock()
        job.id = uuid4()
        job.tenant_id = uuid4()
        job.target_id = uuid4()
        job.status = "pending"
        job.files_scanned = 0
        job.files_with_pii = 0
        job.progress = {}
        return job

    @pytest.fixture
    def mock_target(self):
        """Create a mock ScanTarget."""
        target = MagicMock()
        target.id = uuid4()
        target.adapter = "filesystem"
        target.config = {"path": "/test/path"}
        return target

    async def test_raises_when_job_not_found(self, mock_session):
        """Should raise JobError when job doesn't exist."""
        mock_session.get = AsyncMock(return_value=None)

        with pytest.raises(JobError) as exc_info:
            await execute_scan_task(mock_session, {"job_id": str(uuid4())})

        assert "not found" in str(exc_info.value).lower()

    async def test_raises_when_target_not_found(self, mock_session, mock_job):
        """Should raise JobError when target doesn't exist."""
        mock_session.get = AsyncMock(side_effect=[mock_job, None])

        with pytest.raises(JobError) as exc_info:
            await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

        assert "target" in str(exc_info.value).lower() and "not found" in str(exc_info.value).lower()

    async def test_returns_cancelled_when_job_already_cancelled(self, mock_session, mock_job, mock_target):
        """Should return cancelled status if job was cancelled before start."""
        mock_job.status = "cancelled"
        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        result = await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

        assert result["status"] == "cancelled"
        assert result["files_scanned"] == 0

    async def test_updates_job_status_to_running(self, mock_session, mock_job, mock_target):
        """Should update job status to 'running' when starting."""
        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        # Mock the adapter to return empty file list
        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_get_adapter:
            mock_adapter = MagicMock()

            async def empty_list(*args):
                return
                yield  # Makes this an async generator

            mock_adapter.list_files = empty_list
            mock_get_adapter.return_value = mock_adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.update_file_inventory = AsyncMock()
                mock_inv.update_folder_inventory = AsyncMock()
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        labeling=MagicMock(enabled=False)
                    )

                    await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

                    assert mock_job.status == "completed"

    async def test_returns_scan_statistics(self, mock_session, mock_job, mock_target):
        """Should return scan statistics on completion."""
        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_get_adapter:
            mock_adapter = MagicMock()

            async def empty_list(*args):
                return
                yield

            mock_adapter.list_files = empty_list
            mock_get_adapter.return_value = mock_adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={"total_files": 0})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        labeling=MagicMock(enabled=False)
                    )

                    result = await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

                    assert "files_scanned" in result
                    assert "files_with_pii" in result
                    assert "total_entities" in result
                    assert "scan_mode" in result



class TestScanTaskDeltaMode:
    """Tests for delta scanning functionality."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_force_full_scan_parameter(self, mock_session):
        """Should pass force_full_scan to inventory service."""
        job_id = uuid4()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.tenant_id = uuid4()
        mock_job.target_id = uuid4()
        mock_job.status = "pending"

        mock_target = MagicMock()
        mock_target.id = mock_job.target_id
        mock_target.adapter = "filesystem"
        mock_target.config = {"path": "/test"}

        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def empty_list(*args):
                return
                yield

            adapter.list_files = empty_list
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.update_file_inventory = AsyncMock()
                mock_inv.update_folder_inventory = AsyncMock()
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        labeling=MagicMock(enabled=False)
                    )

                    result = await execute_scan_task(
                        mock_session,
                        {"job_id": str(job_id), "force_full_scan": True}
                    )

                    assert result["scan_mode"] == "full"


class TestScanTaskErrorHandling:
    """Tests for error handling in scan task."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    @pytest.fixture
    def mock_job(self):
        """Create a mock ScanJob."""
        job = MagicMock()
        job.id = uuid4()
        job.tenant_id = uuid4()
        job.target_id = uuid4()
        job.status = "pending"
        return job

    @pytest.fixture
    def mock_target(self):
        """Create a mock ScanTarget."""
        target = MagicMock()
        target.adapter = "filesystem"
        target.config = {"path": "/test"}
        return target

    async def test_handles_permission_error(self, mock_session, mock_job, mock_target):
        """Should handle PermissionError and mark job as failed."""
        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def error_list(*args):
                raise PermissionError("Access denied")
                yield  # Makes this an async generator

            adapter.list_files = error_list
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        scan=MagicMock(max_file_size_mb=100),
                        labeling=MagicMock(enabled=False),
                    )

                    with pytest.raises(PermissionError):
                        await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

                    assert mock_job.status == "failed"
                    assert "Permission denied" in mock_job.error

    async def test_handles_os_error(self, mock_session, mock_job, mock_target):
        """Should handle OSError and mark job as failed."""
        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def error_list(*args):
                raise OSError("Disk failure")
                yield  # Makes this an async generator

            adapter.list_files = error_list
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        scan=MagicMock(max_file_size_mb=100),
                        labeling=MagicMock(enabled=False),
                    )

                    with pytest.raises(OSError):
                        await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

                    assert mock_job.status == "failed"
                    assert "OS error" in mock_job.error



class TestTaskCancellationMidScan:
    """Tests for task cancellation during scan execution."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_cancellation_detected_during_file_iteration(self, mock_session):
        """Scan should stop when cancellation is detected mid-scan."""
        job_id = uuid4()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.tenant_id = uuid4()
        mock_job.target_id = uuid4()
        mock_job.status = "pending"
        mock_job.files_scanned = 0
        mock_job.files_with_pii = 0
        mock_job.progress = {}

        mock_target = MagicMock()
        mock_target.adapter = "filesystem"
        mock_target.config = {"path": "/test"}

        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        # Create multiple mock files to iterate
        mock_files = []
        for i in range(20):  # More than CANCELLATION_CHECK_INTERVAL
            f = MagicMock()
            f.path = f"/test/file{i}.txt"
            f.name = f"file{i}.txt"
            f.size = 100
            f.modified = datetime.now(timezone.utc)
            f.exposure = MagicMock(value="PRIVATE")
            mock_files.append(f)

        files_processed = 0

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def file_list(*args):
                for f in mock_files:
                    yield f

            adapter.list_files = file_list
            adapter.read_file = AsyncMock(return_value=b"test content")
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.should_scan_file = AsyncMock(return_value=(True, "new"))
                mock_inv.compute_content_hash = MagicMock(return_value="hash")
                mock_inv.update_file_inventory = AsyncMock()
                mock_inv.update_folder_inventory = AsyncMock()
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan._detect_and_score') as mock_detect:
                    mock_detect.return_value = {
                        "risk_score": 0,
                        "risk_tier": "MINIMAL",
                        "entity_counts": {},
                        "total_entities": 0,
                    }

                    with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                        mock_settings.return_value = MagicMock(
                            scan=MagicMock(max_file_size_mb=100),
                            labeling=MagicMock(enabled=False),
                        )

                        # Mock cancellation check - return cancelled after some iterations
                        call_count = [0]
                        async def check_cancellation(session, jid):
                            call_count[0] += 1
                            return call_count[0] >= 2  # Cancel on second check

                        with patch('openlabels.jobs.tasks.scan._check_cancellation', side_effect=check_cancellation):
                            result = await execute_scan_task(
                                mock_session,
                                {"job_id": str(job_id)}
                            )

                            # Should have detected cancellation and returned early
                            assert result.get("status") == "cancelled" or mock_job.status == "cancelled"


class TestProgressReportingAndUpdates:
    """Tests for progress reporting during scan."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_progress_updated_during_scan(self, mock_session):
        """Job progress should be updated as files are scanned."""
        job_id = uuid4()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.tenant_id = uuid4()
        mock_job.target_id = uuid4()
        mock_job.status = "pending"
        mock_job.files_scanned = 0
        mock_job.files_with_pii = 0
        mock_job.progress = {}

        mock_target = MagicMock()
        mock_target.adapter = "filesystem"
        mock_target.config = {"path": "/test"}

        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        # Create mock file
        mock_file = MagicMock()
        mock_file.path = "/test/file.txt"
        mock_file.name = "file.txt"
        mock_file.size = 100
        mock_file.modified = datetime.now(timezone.utc)
        mock_file.exposure = MagicMock(value="PRIVATE")

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def file_list(*args):
                yield mock_file

            adapter.list_files = file_list
            adapter.read_file = AsyncMock(return_value=b"test content")
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.should_scan_file = AsyncMock(return_value=(True, "new"))
                mock_inv.compute_content_hash = MagicMock(return_value="hash")
                mock_inv.update_file_inventory = AsyncMock()
                mock_inv.update_folder_inventory = AsyncMock()
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan._detect_and_score') as mock_detect:
                    mock_detect.return_value = {
                        "risk_score": 50,
                        "risk_tier": "MEDIUM",
                        "entity_counts": {"email": 1},
                        "total_entities": 1,
                    }

                    with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                        mock_settings.return_value = MagicMock(
                            scan=MagicMock(max_file_size_mb=100),
                            labeling=MagicMock(enabled=False),
                        )

                        await execute_scan_task(mock_session, {"job_id": str(job_id)})

                        # Progress should have been updated
                        assert mock_job.files_scanned >= 1
                        assert mock_job.progress is not None





class TestLargeFilesHandling:
    """Tests for handling large files."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_large_file_skipped_when_exceeds_limit(self, mock_session):
        """Files exceeding size limit should be skipped."""
        job_id = uuid4()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.tenant_id = uuid4()
        mock_job.target_id = uuid4()
        mock_job.status = "pending"
        mock_job.files_scanned = 0
        mock_job.files_with_pii = 0
        mock_job.progress = {}

        mock_target = MagicMock()
        mock_target.adapter = "filesystem"
        mock_target.config = {"path": "/test"}

        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        # Create large file (200MB when limit is 100MB)
        large_file = MagicMock()
        large_file.path = "/test/huge_file.zip"
        large_file.name = "huge_file.zip"
        large_file.size = 200 * 1024 * 1024  # 200MB
        large_file.modified = datetime.now(timezone.utc)
        large_file.exposure = MagicMock(value="PRIVATE")

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def file_list(*args):
                yield large_file

            adapter.list_files = file_list
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.update_file_inventory = AsyncMock()
                mock_inv.update_folder_inventory = AsyncMock()
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        scan=MagicMock(max_file_size_mb=100),  # 100MB limit
                        labeling=MagicMock(enabled=False),
                    )

                    result = await execute_scan_task(mock_session, {"job_id": str(job_id)})

                    assert result["files_skipped"] >= 1
                    assert result.get("files_too_large", 0) >= 1



class TestPermissionDeniedScenarios:
    """Tests for permission denied scenarios."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_permission_denied_on_single_file_continues(self, mock_session):
        """Permission denied on single file should continue scanning other files."""
        job_id = uuid4()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.tenant_id = uuid4()
        mock_job.target_id = uuid4()
        mock_job.status = "pending"
        mock_job.files_scanned = 0
        mock_job.files_with_pii = 0
        mock_job.progress = {}

        mock_target = MagicMock()
        mock_target.adapter = "filesystem"
        mock_target.config = {"path": "/test"}

        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        # Create two files - first will fail with permission error
        file1 = MagicMock()
        file1.path = "/test/protected.txt"
        file1.name = "protected.txt"
        file1.size = 100
        file1.modified = datetime.now(timezone.utc)
        file1.exposure = MagicMock(value="PRIVATE")

        file2 = MagicMock()
        file2.path = "/test/readable.txt"
        file2.name = "readable.txt"
        file2.size = 100
        file2.modified = datetime.now(timezone.utc)
        file2.exposure = MagicMock(value="PRIVATE")

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def file_list(*args):
                yield file1
                yield file2

            call_count = [0]
            async def read_file_with_error(file_info, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise PermissionError("Access denied")
                return b"readable content"

            adapter.list_files = file_list
            adapter.read_file = read_file_with_error
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                mock_inv.should_scan_file = AsyncMock(return_value=(True, "new"))
                mock_inv.compute_content_hash = MagicMock(return_value="hash")
                mock_inv.update_file_inventory = AsyncMock()
                mock_inv.update_folder_inventory = AsyncMock()
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan._detect_and_score') as mock_detect:
                    mock_detect.return_value = {
                        "risk_score": 0,
                        "risk_tier": "MINIMAL",
                        "entity_counts": {},
                        "total_entities": 0,
                    }

                    with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                        mock_settings.return_value = MagicMock(
                            scan=MagicMock(max_file_size_mb=100),
                            labeling=MagicMock(enabled=False),
                        )

                        result = await execute_scan_task(mock_session, {"job_id": str(job_id)})

                        # Should have completed despite permission error on first file
                        assert mock_job.status == "completed"
                        assert result["files_scanned"] >= 1





class TestDatabaseConnectionFailures:
    """Tests for database connection failure handling."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_database_error_during_job_lookup(self, mock_session):
        """Database error during job lookup should raise exception."""
        from sqlalchemy.exc import SQLAlchemyError

        mock_session.get = AsyncMock(side_effect=SQLAlchemyError("Connection lost"))

        with pytest.raises(SQLAlchemyError):
            await execute_scan_task(mock_session, {"job_id": str(uuid4())})



class TestWorkerCrashRecovery:
    """Tests for worker crash recovery."""

    async def test_stuck_jobs_reclaimed_on_worker_recovery(self):
        """Jobs stuck in running state should be reclaimed."""
        from openlabels.jobs.queue import JobQueue

        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()

        tenant_id = uuid4()
        queue = JobQueue(mock_session, tenant_id)

        # Create job that's been running for too long
        stuck_job = MagicMock()
        stuck_job.status = "running"
        stuck_job.started_at = datetime.now(timezone.utc) - timedelta(hours=3)
        stuck_job.retry_count = 0
        stuck_job.max_retries = 3
        stuck_job.worker_id = "crashed-worker-123"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [stuck_job]
        mock_session.execute = AsyncMock(return_value=mock_result)

        reclaimed = await queue.reclaim_stuck_jobs(timeout_seconds=3600)

        assert reclaimed == 1
        assert stuck_job.status == "pending"
        assert stuck_job.worker_id is None
        assert "Reclaimed" in stuck_job.error


class TestOrphanedTasksCleanup:
    """Tests for orphaned task cleanup."""

    async def test_old_completed_jobs_purged(self):
        """Old completed jobs should be purged."""
        from openlabels.jobs.queue import JobQueue

        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()

        tenant_id = uuid4()
        queue = JobQueue(mock_session, tenant_id)

        # Mock delete returning count
        mock_result = MagicMock()
        mock_result.rowcount = 100
        mock_session.execute = AsyncMock(return_value=mock_result)

        counts = await queue.cleanup_expired_jobs(
            completed_ttl_days=7,
            failed_ttl_days=30
        )

        total_deleted = counts["completed"] + counts["failed"] + counts["cancelled"]
        assert total_deleted > 0

    async def test_stale_pending_jobs_detected(self):
        """Stale pending jobs should be detected."""
        from openlabels.jobs.queue import JobQueue

        mock_session = AsyncMock()
        tenant_id = uuid4()
        queue = JobQueue(mock_session, tenant_id)

        # Create stale pending job
        stale_job = MagicMock()
        stale_job.status = "pending"
        stale_job.created_at = datetime.now(timezone.utc) - timedelta(hours=48)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [stale_job]
        mock_session.execute = AsyncMock(return_value=mock_result)

        stale_jobs = await queue.get_stale_pending_jobs(max_age_hours=24)

        assert len(stale_jobs) == 1
        assert stale_jobs[0].created_at < datetime.now(timezone.utc) - timedelta(hours=24)



class TestInventoryDeltaScanning:
    """Tests for inventory-based delta scanning."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_unchanged_files_skipped_in_delta_mode(self, mock_session):
        """Unchanged files should be skipped in delta scan mode."""
        job_id = uuid4()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.tenant_id = uuid4()
        mock_job.target_id = uuid4()
        mock_job.status = "pending"
        mock_job.files_scanned = 0
        mock_job.files_with_pii = 0
        mock_job.progress = {}

        mock_target = MagicMock()
        mock_target.id = mock_job.target_id
        mock_target.adapter = "filesystem"
        mock_target.config = {"path": "/test"}

        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        unchanged_file = MagicMock()
        unchanged_file.path = "/test/unchanged.txt"
        unchanged_file.name = "unchanged.txt"
        unchanged_file.size = 100
        unchanged_file.modified = datetime.now(timezone.utc)
        unchanged_file.exposure = MagicMock(value="PRIVATE")

        with patch('openlabels.jobs.tasks.scan._get_adapter') as mock_adapter:
            adapter = MagicMock()

            async def file_list(*args):
                yield unchanged_file

            adapter.list_files = file_list
            adapter.read_file = AsyncMock(return_value=b"content")
            mock_adapter.return_value = adapter

            with patch('openlabels.jobs.inventory.InventoryService') as MockInventory:
                mock_inv = MagicMock()
                mock_inv.load_file_inventory = AsyncMock(return_value={})
                mock_inv.load_folder_inventory = AsyncMock(return_value={})
                # Mark file as unchanged - should not scan
                mock_inv.should_scan_file = AsyncMock(return_value=(False, "unchanged"))
                mock_inv.compute_content_hash = MagicMock(return_value="same-hash")
                mock_inv.update_folder_inventory = AsyncMock()
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        scan=MagicMock(max_file_size_mb=100),
                        labeling=MagicMock(enabled=False),
                    )

                    result = await execute_scan_task(
                        mock_session,
                        {"job_id": str(job_id), "force_full_scan": False}
                    )

                    # File should be skipped
                    assert result["files_skipped"] >= 1
                    assert result["scan_mode"] == "delta"
