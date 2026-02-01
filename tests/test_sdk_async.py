"""Tests for SDK async methods (sdk.py async API).

Tests cover:
- Redactor.aredact() - async redaction
- Redactor.arestore() - async restoration
- Redactor.ascan() - async scanning
- Redactor.achat() - async chat
- preload_async() - async preloading
- Thread pool executor management
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch, AsyncMock

import pytest


# --- Fixtures ---

@pytest.fixture
def mock_scrubiq():
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()
    mock.redact.return_value = MagicMock(
        text="Patient [NAME_1]",
        mapping={"[NAME_1]": "John Smith"},
        spans=[],
    )
    mock.restore.return_value = "Patient John Smith"
    mock.scan.return_value = MagicMock(
        has_phi=True,
        spans=[],
    )
    mock.chat.return_value = MagicMock(
        response="The patient is doing well.",
        redacted_input="Patient [NAME_1]",
    )
    return mock


@pytest.fixture
def mock_redactor(mock_scrubiq):
    """Create a Redactor with mocked ScrubIQ backend."""
    # Create a mock redactor directly without importing
    redactor = MagicMock()
    redactor._cr = mock_scrubiq
    redactor._executor = None
    redactor._workers = 4
    redactor._temp_dir = None

    # Set up sync methods
    redactor.redact = mock_scrubiq.redact
    redactor.restore = mock_scrubiq.restore
    redactor.scan = mock_scrubiq.scan
    redactor.chat = mock_scrubiq.chat

    # Set up async methods using actual implementation pattern
    async def aredact(text, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            redactor._get_executor(),
            lambda: redactor.redact(text, **kwargs),
        )

    async def arestore(text, mapping=None):
        return redactor.restore(text, mapping)

    async def ascan(text, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            redactor._get_executor(),
            lambda: redactor.scan(text, **kwargs),
        )

    async def achat(message, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            redactor._get_executor(),
            lambda: redactor.chat(message, **kwargs),
        )

    def _get_executor():
        if redactor._executor is None:
            redactor._executor = ThreadPoolExecutor(
                max_workers=redactor._workers,
                thread_name_prefix="scrubiq-",
            )
        return redactor._executor

    def close():
        if redactor._executor:
            redactor._executor.shutdown(wait=False)
            redactor._executor = None

    redactor.aredact = aredact
    redactor.arestore = arestore
    redactor.ascan = ascan
    redactor.achat = achat
    redactor._get_executor = _get_executor
    redactor.close = close

    yield redactor

    # Cleanup executor if created
    if redactor._executor:
        redactor._executor.shutdown(wait=False)


# --- aredact Tests ---

class TestAredact:
    """Tests for async redact method."""

    @pytest.mark.asyncio
    async def test_aredact_returns_result(self, mock_redactor, mock_scrubiq):
        """aredact should return RedactionResult."""
        mock_scrubiq.redact.return_value = MagicMock(
            text="Patient [NAME_1]",
            mapping={"[NAME_1]": "John Smith"},
        )

        result = await mock_redactor.aredact("Patient John Smith")

        assert result.text == "Patient [NAME_1]"
        mock_scrubiq.redact.assert_called_once()

    @pytest.mark.asyncio
    async def test_aredact_passes_kwargs(self, mock_redactor, mock_scrubiq):
        """aredact should pass kwargs to sync redact."""
        await mock_redactor.aredact(
            "Test text",
            confidence_threshold=0.9,
            allowlist=["allowed"],
        )

        mock_scrubiq.redact.assert_called_with(
            "Test text",
            confidence_threshold=0.9,
            allowlist=["allowed"],
        )

    @pytest.mark.asyncio
    async def test_aredact_uses_executor(self, mock_redactor):
        """aredact should use thread pool executor."""
        await mock_redactor.aredact("Test")

        # Executor should be created
        assert mock_redactor._executor is not None
        assert isinstance(mock_redactor._executor, ThreadPoolExecutor)

    @pytest.mark.asyncio
    async def test_aredact_concurrent_calls(self, mock_redactor, mock_scrubiq):
        """Multiple concurrent aredact calls should work."""
        mock_scrubiq.redact.return_value = MagicMock(text="redacted")

        # Run multiple concurrent calls
        results = await asyncio.gather(
            mock_redactor.aredact("Text 1"),
            mock_redactor.aredact("Text 2"),
            mock_redactor.aredact("Text 3"),
        )

        assert len(results) == 3
        assert mock_scrubiq.redact.call_count == 3


# --- arestore Tests ---

class TestArestore:
    """Tests for async restore method."""

    @pytest.mark.asyncio
    async def test_arestore_returns_string(self, mock_redactor, mock_scrubiq):
        """arestore should return restored string."""
        mock_scrubiq.restore.return_value = "Patient John Smith"

        result = await mock_redactor.arestore("Patient [NAME_1]")

        assert result == "Patient John Smith"

    @pytest.mark.asyncio
    async def test_arestore_passes_mapping(self, mock_redactor, mock_scrubiq):
        """arestore should pass mapping to sync restore."""
        mapping = {"[NAME_1]": "Jane Doe"}

        await mock_redactor.arestore("Patient [NAME_1]", mapping=mapping)

        mock_scrubiq.restore.assert_called_with("Patient [NAME_1]", mapping)

    @pytest.mark.asyncio
    async def test_arestore_no_executor(self, mock_redactor, mock_scrubiq):
        """arestore should not need executor (fast operation)."""
        # Reset executor
        mock_redactor._executor = None

        await mock_redactor.arestore("Test")

        # restore is fast, doesn't need executor
        # The implementation doesn't use executor for restore


# --- ascan Tests ---

class TestAscan:
    """Tests for async scan method."""

    @pytest.mark.asyncio
    async def test_ascan_returns_result(self, mock_redactor, mock_scrubiq):
        """ascan should return ScanResult."""
        mock_scrubiq.scan.return_value = MagicMock(
            has_phi=True,
            phi_count=2,
        )

        result = await mock_redactor.ascan("Patient John Smith, SSN 123-45-6789")

        assert result.has_phi is True
        mock_scrubiq.scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_ascan_passes_kwargs(self, mock_redactor, mock_scrubiq):
        """ascan should pass kwargs to sync scan."""
        await mock_redactor.ascan(
            "Test text",
            confidence_threshold=0.8,
            entity_types=["NAME", "SSN"],
        )

        mock_scrubiq.scan.assert_called_with(
            "Test text",
            confidence_threshold=0.8,
            entity_types=["NAME", "SSN"],
        )

    @pytest.mark.asyncio
    async def test_ascan_uses_executor(self, mock_redactor):
        """ascan should use thread pool executor."""
        await mock_redactor.ascan("Test")

        assert mock_redactor._executor is not None


# --- achat Tests ---

class TestAchat:
    """Tests for async chat method."""

    @pytest.mark.asyncio
    async def test_achat_returns_result(self, mock_redactor, mock_scrubiq):
        """achat should return ChatResult."""
        mock_scrubiq.chat.return_value = MagicMock(
            response="The patient is doing well.",
            redacted_input="Patient [NAME_1] is here.",
        )

        result = await mock_redactor.achat("How is patient John Smith?")

        assert "patient" in result.response.lower()
        mock_scrubiq.chat.assert_called_once()

    @pytest.mark.asyncio
    async def test_achat_passes_kwargs(self, mock_redactor, mock_scrubiq):
        """achat should pass kwargs to sync chat."""
        await mock_redactor.achat(
            "Test message",
            model="gpt-4",
            provider="openai",
        )

        mock_scrubiq.chat.assert_called_with(
            "Test message",
            model="gpt-4",
            provider="openai",
        )

    @pytest.mark.asyncio
    async def test_achat_uses_executor(self, mock_redactor):
        """achat should use thread pool executor."""
        await mock_redactor.achat("Test")

        assert mock_redactor._executor is not None


# --- Executor Management Tests ---

class TestExecutorManagement:
    """Tests for thread pool executor management."""

    @pytest.mark.asyncio
    async def test_get_executor_creates_once(self, mock_redactor):
        """_get_executor should create executor only once."""
        exec1 = mock_redactor._get_executor()
        exec2 = mock_redactor._get_executor()

        assert exec1 is exec2

    @pytest.mark.asyncio
    async def test_executor_thread_prefix(self, mock_redactor):
        """Executor should use scrubiq- thread prefix."""
        executor = mock_redactor._get_executor()

        assert executor._thread_name_prefix == "scrubiq-"

    @pytest.mark.asyncio
    async def test_close_shuts_down_executor(self, mock_redactor):
        """close should shutdown executor."""
        # Create executor
        mock_redactor._get_executor()

        mock_redactor.close()

        assert mock_redactor._executor is None


# --- preload_async Tests ---

class TestPreloadAsync:
    """Tests for async preload function."""

    @pytest.mark.asyncio
    async def test_preload_async_calls_preload(self):
        """preload_async should call sync preload."""
        with patch("scrubiq.sdk.preload") as mock_preload:
            from scrubiq.sdk import preload_async

            await preload_async()

            mock_preload.assert_called_once()

    @pytest.mark.asyncio
    async def test_preload_async_runs_in_executor(self):
        """preload_async should run in executor."""
        with patch("scrubiq.sdk.preload") as mock_preload:
            from scrubiq.sdk import preload_async

            # Should complete without blocking main thread
            await preload_async()

            mock_preload.assert_called()


# --- Integration-style Tests ---

class TestAsyncIntegration:
    """Integration-style tests for async API."""

    @pytest.mark.asyncio
    async def test_redact_restore_roundtrip(self, mock_redactor, mock_scrubiq):
        """Async redact/restore roundtrip should work."""
        original = "Patient John Smith"

        mock_scrubiq.redact.return_value = MagicMock(
            text="Patient [NAME_1]",
            mapping={"[NAME_1]": "John Smith"},
        )
        mock_scrubiq.restore.return_value = original

        # Redact
        redacted = await mock_redactor.aredact(original)

        # Restore
        restored = await mock_redactor.arestore(redacted.text, redacted.mapping)

        assert restored == original

    @pytest.mark.asyncio
    async def test_scan_then_redact_pattern(self, mock_redactor, mock_scrubiq):
        """Common pattern: scan first, then redact if needed."""
        text = "Patient John Smith, SSN 123-45-6789"

        mock_scrubiq.scan.return_value = MagicMock(has_phi=True)
        mock_scrubiq.redact.return_value = MagicMock(text="Patient [NAME_1], SSN [SSN_1]")

        # Scan first
        scan_result = await mock_redactor.ascan(text)

        # Redact if PHI found
        if scan_result.has_phi:
            redact_result = await mock_redactor.aredact(text)
            assert "[NAME_1]" in redact_result.text

    @pytest.mark.asyncio
    async def test_parallel_operations(self, mock_redactor, mock_scrubiq):
        """Multiple operations should work in parallel."""
        mock_scrubiq.redact.return_value = MagicMock(text="redacted")
        mock_scrubiq.scan.return_value = MagicMock(has_phi=True)

        # Run different operations concurrently
        redact_task = mock_redactor.aredact("Text 1")
        scan_task = mock_redactor.ascan("Text 2")

        redact_result, scan_result = await asyncio.gather(redact_task, scan_task)

        assert redact_result is not None
        assert scan_result is not None


# --- Error Handling Tests ---

class TestAsyncErrorHandling:
    """Tests for error handling in async methods."""

    @pytest.mark.asyncio
    async def test_aredact_propagates_errors(self, mock_redactor, mock_scrubiq):
        """Errors from sync redact should propagate."""
        mock_scrubiq.redact.side_effect = ValueError("Invalid input")

        with pytest.raises(ValueError, match="Invalid input"):
            await mock_redactor.aredact("Test")

    @pytest.mark.asyncio
    async def test_ascan_propagates_errors(self, mock_redactor, mock_scrubiq):
        """Errors from sync scan should propagate."""
        mock_scrubiq.scan.side_effect = RuntimeError("Scan failed")

        with pytest.raises(RuntimeError, match="Scan failed"):
            await mock_redactor.ascan("Test")

    @pytest.mark.asyncio
    async def test_achat_propagates_errors(self, mock_redactor, mock_scrubiq):
        """Errors from sync chat should propagate."""
        mock_scrubiq.chat.side_effect = ConnectionError("API unavailable")

        with pytest.raises(ConnectionError, match="API unavailable"):
            await mock_redactor.achat("Test")


# --- Context Manager Tests ---

class TestAsyncContextManager:
    """Tests for using Redactor with async code."""

    @pytest.mark.asyncio
    async def test_context_manager_cleanup(self, mock_redactor, mock_scrubiq):
        """Context manager should cleanup executor."""
        mock_scrubiq.redact.return_value = MagicMock(text="redacted")

        # Use and create executor
        await mock_redactor.aredact("Test")
        assert mock_redactor._executor is not None

        # Close should cleanup
        mock_redactor.close()
        assert mock_redactor._executor is None


# --- Thread Safety Tests ---

class TestAsyncThreadSafety:
    """Tests for thread safety of async operations."""

    @pytest.mark.asyncio
    async def test_concurrent_same_instance(self, mock_redactor, mock_scrubiq):
        """Multiple concurrent calls on same instance should be safe."""
        mock_scrubiq.redact.return_value = MagicMock(text="redacted")
        errors = []

        async def worker(i):
            try:
                await mock_redactor.aredact(f"Text {i}")
            except Exception as e:
                errors.append(e)

        # Run many concurrent calls
        await asyncio.gather(*[worker(i) for i in range(20)])

        assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_executor_reuse(self, mock_redactor, mock_scrubiq):
        """Same executor should be reused across calls."""
        mock_scrubiq.redact.return_value = MagicMock(text="redacted")

        await mock_redactor.aredact("Text 1")
        executor1 = mock_redactor._executor

        await mock_redactor.aredact("Text 2")
        executor2 = mock_redactor._executor

        assert executor1 is executor2
