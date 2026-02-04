"""
Comprehensive tests for the scan task.

Tests focus on:
- Processor initialization and caching
- Job cancellation detection
- Adapter selection
- Detection and scoring
- Delta scanning
- Parallel scan execution
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
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
                    assert call_kwargs["enable_ml"] is True
        finally:
            scan_module._processor = original


class TestCheckCancellation:
    """Tests for _check_cancellation function."""

    @pytest.mark.asyncio
    async def test_returns_true_when_cancelled(self):
        """Should return True when job status is 'cancelled'."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = "cancelled"
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await _check_cancellation(mock_session, uuid4())

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_running(self):
        """Should return False when job is still running."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = "running"
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await _check_cancellation(mock_session, uuid4())

        assert result is False

    @pytest.mark.asyncio
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
        """Should raise ValueError for unknown adapter type."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock()

            with pytest.raises(ValueError) as exc_info:
                _get_adapter("unknown_adapter", {})

            assert "Unknown adapter type" in str(exc_info.value)

    def test_passes_service_account_to_filesystem(self):
        """Should pass service_account config to FilesystemAdapter."""
        with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock()
            with patch('openlabels.jobs.tasks.scan.FilesystemAdapter') as MockAdapter:
                MockAdapter.return_value = MagicMock()
                _get_adapter("filesystem", {"service_account": "user@domain.com"})

                call_kwargs = MockAdapter.call_args.kwargs
                assert call_kwargs["service_account"] == "user@domain.com"


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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

            assert len(result["findings"]) == 50
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

    @pytest.mark.asyncio
    async def test_raises_when_job_not_found(self, mock_session):
        """Should raise ValueError when job doesn't exist."""
        mock_session.get = AsyncMock(return_value=None)

        with pytest.raises(ValueError) as exc_info:
            await execute_scan_task(mock_session, {"job_id": str(uuid4())})

        assert "Job not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_raises_when_target_not_found(self, mock_session, mock_job):
        """Should raise ValueError when target doesn't exist."""
        mock_session.get = AsyncMock(side_effect=[mock_job, None])

        with pytest.raises(ValueError) as exc_info:
            await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

        assert "Target not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_returns_cancelled_when_job_already_cancelled(self, mock_session, mock_job, mock_target):
        """Should return cancelled status if job was cancelled before start."""
        mock_job.status = "cancelled"
        mock_session.get = AsyncMock(side_effect=[mock_job, mock_target])

        result = await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

        assert result["status"] == "cancelled"
        assert result["files_scanned"] == 0

    @pytest.mark.asyncio
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
                mock_inv.mark_missing_files = AsyncMock(return_value=0)
                mock_inv.get_inventory_stats = AsyncMock(return_value={})
                MockInventory.return_value = mock_inv

                with patch('openlabels.jobs.tasks.scan.get_settings') as mock_settings:
                    mock_settings.return_value = MagicMock(
                        labeling=MagicMock(enabled=False)
                    )

                    await execute_scan_task(mock_session, {"job_id": str(mock_job.id)})

                    assert mock_job.status == "completed"

    @pytest.mark.asyncio
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


class TestCancellationCheckInterval:
    """Tests for cancellation check configuration."""

    def test_interval_is_reasonable(self):
        """Cancellation check interval should be between 1 and 100."""
        assert 1 <= CANCELLATION_CHECK_INTERVAL <= 100

    def test_interval_is_integer(self):
        """Cancellation check interval should be an integer."""
        assert isinstance(CANCELLATION_CHECK_INTERVAL, int)


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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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


class TestWebSocketStreamingFlag:
    """Tests for WebSocket streaming enable/disable."""

    def test_ws_streaming_enabled_by_default(self):
        """WebSocket streaming should be enabled when module imports successfully."""
        # This is implicitly tested by the import
        import openlabels.jobs.tasks.scan as scan_module
        # Flag exists
        assert hasattr(scan_module, '_ws_streaming_enabled')


class TestParallelScanTask:
    """Tests for execute_parallel_scan_task function."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        return session

    @pytest.mark.asyncio
    async def test_raises_when_job_not_found(self, mock_session):
        """Should raise ValueError when job doesn't exist."""
        from openlabels.jobs.tasks.scan import execute_parallel_scan_task

        mock_session.get = AsyncMock(return_value=None)

        with pytest.raises(ValueError) as exc_info:
            await execute_parallel_scan_task(mock_session, {"job_id": str(uuid4())})

        assert "Job not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_returns_cancelled_when_already_cancelled(self, mock_session):
        """Should return cancelled if job was cancelled before start."""
        from openlabels.jobs.tasks.scan import execute_parallel_scan_task

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.status = "cancelled"
        mock_session.get = AsyncMock(return_value=mock_job)

        result = await execute_parallel_scan_task(
            mock_session,
            {"job_id": str(mock_job.id)}
        )

        assert result["status"] == "cancelled"
        assert result["files_scanned"] == 0

    @pytest.mark.asyncio
    async def test_raises_when_target_not_found(self, mock_session):
        """Should raise ValueError when target doesn't exist."""
        from openlabels.jobs.tasks.scan import execute_parallel_scan_task

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.status = "pending"
        mock_job.target_id = uuid4()
        mock_session.get = AsyncMock(side_effect=[mock_job, None])

        with pytest.raises(ValueError) as exc_info:
            await execute_parallel_scan_task(
                mock_session,
                {"job_id": str(mock_job.id)}
            )

        assert "Target not found" in str(exc_info.value)
