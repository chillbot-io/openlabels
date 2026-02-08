"""
End-to-end tests for the Phase F unified scan pipeline.

Tests the ScanOrchestrator with:
- Mock adapter (ChangeProvider + ReadAdapter)
- Mock agent pool (bypassed — we test the orchestrator logic,
  not the multiprocessing classification agents)
- DB verification of persisted results
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from openlabels.adapters.base import ExposureLevel, FileInfo
from openlabels.core.agents.pool import AgentPoolConfig, FileResult, ScanOrchestrator
from openlabels.core.agents.worker import AgentResult, EntityMatch, WorkItem
from openlabels.core.change_providers import ChangeProvider, FullWalkProvider


# ── Fixtures / helpers ──────────────────────────────────────────────


def _make_file_info(
    path: str = "/tmp/test.txt",
    name: str = "test.txt",
    size: int = 100,
    exposure: ExposureLevel = ExposureLevel.PRIVATE,
    owner: str = "alice",
) -> FileInfo:
    return FileInfo(
        path=path,
        name=name,
        size=size,
        modified=datetime(2026, 1, 1, tzinfo=timezone.utc),
        owner=owner,
        exposure=exposure,
        adapter="filesystem",
    )


class MockChangeProvider:
    """Yields a fixed list of FileInfo objects."""

    def __init__(self, files: list[FileInfo]):
        self._files = files

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        for f in self._files:
            yield f


class MockAdapter:
    """Adapter that returns preset content for each file."""

    def __init__(self, contents: dict[str, bytes] | None = None):
        self._contents = contents or {}

    async def list_files(self, target, **kwargs):
        # Not used directly when ChangeProvider is supplied
        return
        yield  # make it an async generator

    async def read_file(self, file_info, **kwargs) -> bytes:
        return self._contents.get(file_info.path, b"sample text content")


class MockInventory:
    """Inventory service that says every file should be scanned."""

    def __init__(self, *, skip_paths: set[str] | None = None):
        self._skip = skip_paths or set()

    def compute_content_hash(self, content: bytes) -> str:
        import hashlib
        return hashlib.sha256(content).hexdigest()

    async def should_scan_file(self, file_info, content_hash, force):
        if file_info.path in self._skip:
            return False, "unchanged"
        return True, "new_file"

    async def update_file_inventory(self, **kwargs):
        pass

    async def update_folder_inventory(self, **kwargs):
        pass

    async def load_file_inventory(self):
        pass

    async def load_folder_inventory(self):
        pass


# ── ChangeProvider tests ────────────────────────────────────────────

class TestChangeProvider:
    """Tests for the ChangeProvider protocol and FullWalkProvider."""

    def test_protocol_check(self):
        """MockChangeProvider satisfies the ChangeProvider protocol."""
        provider = MockChangeProvider([])
        assert isinstance(provider, ChangeProvider)

    @pytest.mark.asyncio
    async def test_mock_provider_yields_files(self):
        files = [_make_file_info(f"/tmp/f{i}.txt", f"f{i}.txt") for i in range(3)]
        provider = MockChangeProvider(files)

        collected = []
        async for f in provider.changed_files():
            collected.append(f)

        assert len(collected) == 3
        assert collected[0].path == "/tmp/f0.txt"

    @pytest.mark.asyncio
    async def test_full_walk_provider_wraps_adapter(self):
        """FullWalkProvider delegates to adapter.list_files."""
        file = _make_file_info()

        mock_adapter = MagicMock()

        async def _fake_list_files(target, **kwargs):
            yield file

        mock_adapter.list_files = _fake_list_files

        provider = FullWalkProvider(mock_adapter, "/scan/target")
        assert isinstance(provider, ChangeProvider)

        collected = []
        async for f in provider.changed_files():
            collected.append(f)

        assert len(collected) == 1
        assert collected[0].path == file.path


# ── ScanOrchestrator unit tests ─────────────────────────────────────

class TestScanOrchestratorRiskScoring:
    """Test the _compute_risk static method."""

    def test_minimal_risk(self):
        score, tier = ScanOrchestrator._compute_risk({}, 0, "PRIVATE")
        assert tier == "MINIMAL"
        assert score == 0

    def test_low_risk(self):
        score, tier = ScanOrchestrator._compute_risk({"SSN": 2}, 2, "PRIVATE")
        assert tier == "LOW"
        assert score == 20

    def test_high_risk_with_exposure(self):
        # 7 entities * 10 = 70 base, * 1.5 ORG_WIDE = 100 (capped)
        score, tier = ScanOrchestrator._compute_risk({"SSN": 7}, 7, "ORG_WIDE")
        assert tier == "CRITICAL"
        assert score == 100

    def test_medium_risk(self):
        score, tier = ScanOrchestrator._compute_risk({"EMAIL": 4}, 4, "PRIVATE")
        assert tier == "MEDIUM"
        assert score == 40

    def test_public_exposure_multiplier(self):
        # 3 entities * 10 = 30 base, * 2.0 PUBLIC = 60
        score, tier = ScanOrchestrator._compute_risk({"SSN": 3}, 3, "PUBLIC")
        assert tier == "HIGH"
        assert score == 60


class TestScanOrchestratorDeltaCheck:
    """Test the orchestrator respects inventory delta checks."""

    @pytest.mark.asyncio
    async def test_skipped_files_counted(self):
        """Files that inventory says are unchanged should be skipped."""
        files = [
            _make_file_info("/tmp/changed.txt", "changed.txt"),
            _make_file_info("/tmp/unchanged.txt", "unchanged.txt"),
        ]
        adapter = MockAdapter()
        provider = MockChangeProvider(files)
        inventory = MockInventory(skip_paths={"/tmp/unchanged.txt"})

        orchestrator = ScanOrchestrator(
            adapter=adapter,
            change_provider=provider,
            inventory=inventory,
        )

        # Run just the walker + extractor stages (without actual agent pool)
        # to verify delta check logic
        await orchestrator._walk_files()
        await orchestrator._extract_queue.put(None)

        # The extractor should process only the changed file
        # and skip the unchanged one
        with patch("openlabels.core.extractors.extract_text") as mock_extract:
            mock_result = MagicMock()
            mock_result.text = "Some text with SSN 123-45-6789"
            mock_extract.return_value = mock_result

            with patch("openlabels.core.pipeline.chunking.TextChunker") as MockChunker:
                mock_chunker = MagicMock()
                mock_chunk = MagicMock()
                mock_chunk.text = "Some text"
                mock_chunker.chunk.return_value = [mock_chunk]
                MockChunker.return_value = mock_chunker

                mock_pool = MagicMock()
                mock_pool.submit = AsyncMock()

                await orchestrator._extract_and_submit(mock_pool)

        assert orchestrator.stats["files_skipped"] == 1
        # One file submitted (the changed one)
        assert mock_pool.submit.call_count == 1


class TestScanOrchestratorMetadata:
    """Test that adapter metadata flows through WorkItem.metadata."""

    @pytest.mark.asyncio
    async def test_metadata_attached_to_work_item(self):
        """WorkItem.metadata should contain exposure_level, owner, adapter."""
        file = _make_file_info(
            exposure=ExposureLevel.ORG_WIDE,
            owner="bob",
        )
        adapter = MockAdapter()
        provider = MockChangeProvider([file])
        inventory = MockInventory()

        orchestrator = ScanOrchestrator(
            adapter=adapter,
            change_provider=provider,
            inventory=inventory,
        )

        await orchestrator._walk_files()
        await orchestrator._extract_queue.put(None)

        submitted_items: list[WorkItem] = []

        with patch("openlabels.core.extractors.extract_text") as mock_extract:
            mock_result = MagicMock()
            mock_result.text = "Test text"
            mock_extract.return_value = mock_result

            with patch("openlabels.core.pipeline.chunking.TextChunker") as MockChunker:
                mock_chunker = MagicMock()
                mock_chunk = MagicMock()
                mock_chunk.text = "Test text"
                mock_chunker.chunk.return_value = [mock_chunk]
                MockChunker.return_value = mock_chunker

                mock_pool = MagicMock()

                async def capture_submit(item):
                    submitted_items.append(item)

                mock_pool.submit = capture_submit

                await orchestrator._extract_and_submit(mock_pool)

        assert len(submitted_items) == 1
        meta = submitted_items[0].metadata
        assert meta["exposure_level"] == "ORG_WIDE"
        assert meta["owner"] == "bob"
        assert meta["adapter"] == "filesystem"


class TestScanOrchestratorPersistUnified:
    """Test the unified result pipeline (_persist_unified)."""

    @pytest.mark.asyncio
    async def test_persist_creates_scan_result(self):
        """_persist_unified should add a ScanResult to the session."""
        job = MagicMock()
        job.tenant_id = uuid4()
        job.id = uuid4()
        job.files_scanned = 0
        job.files_with_pii = 0
        job.progress = {}

        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()

        file_info = _make_file_info()
        inventory = MockInventory()

        orchestrator = ScanOrchestrator(
            session=session,
            job=job,
            inventory=inventory,
        )

        # Pre-populate metadata as if extractor ran
        orchestrator._file_metadata["/tmp/test.txt"] = {
            "exposure_level": "PRIVATE",
            "owner": "alice",
            "permissions": None,
            "adapter": "filesystem",
            "item_id": None,
            "content_hash": "abc123",
            "file_info": file_info,
        }

        file_result = FileResult(
            file_path="/tmp/test.txt",
            entity_counts={"SSN": 3, "EMAIL": 1},
            total_entities=4,
            total_processing_ms=100.0,
            chunk_count=1,
            errors=[],
        )

        with patch("openlabels.jobs.inventory.get_folder_path", return_value="/tmp") as mock_gfp, \
             patch("openlabels.server.models.ScanResult") as MockScanResult:
            mock_sr = MagicMock()
            MockScanResult.return_value = mock_sr
            await orchestrator._persist_unified([file_result])

        # Verify a ScanResult was added
        session.add.assert_called_once()
        # Check the kwargs passed to ScanResult(...)
        call_kwargs = MockScanResult.call_args[1]
        assert call_kwargs["risk_tier"] == "MEDIUM"  # 4 entities * 10 = 40 → MEDIUM
        assert call_kwargs["total_entities"] == 4
        assert call_kwargs["exposure_level"] == "PRIVATE"
        assert call_kwargs["owner"] == "alice"
        assert call_kwargs["content_hash"] == "abc123"

        # Stats updated
        assert orchestrator.stats["files_scanned"] == 1
        assert orchestrator.stats["files_with_pii"] == 1
        assert orchestrator.stats["total_entities"] == 4

    @pytest.mark.asyncio
    async def test_persist_with_public_exposure_increases_risk(self):
        """Public exposure should bump the risk tier."""
        job = MagicMock()
        job.tenant_id = uuid4()
        job.id = uuid4()
        job.files_scanned = 0
        job.files_with_pii = 0
        job.progress = {}

        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()

        file_info = _make_file_info(exposure=ExposureLevel.PUBLIC)

        orchestrator = ScanOrchestrator(session=session, job=job)
        orchestrator._file_metadata["/tmp/test.txt"] = {
            "exposure_level": "PUBLIC",
            "owner": "alice",
            "permissions": None,
            "adapter": "filesystem",
            "item_id": None,
            "content_hash": None,
            "file_info": file_info,
        }

        # 3 entities * 10 = 30 base, * 2.0 PUBLIC = 60 → HIGH
        file_result = FileResult(
            file_path="/tmp/test.txt",
            entity_counts={"SSN": 3},
            total_entities=3,
            total_processing_ms=50.0,
            chunk_count=1,
            errors=[],
        )

        with patch("openlabels.jobs.inventory.get_folder_path", return_value="/tmp") as mock_gfp, \
             patch("openlabels.server.models.ScanResult") as MockScanResult:
            mock_sr = MagicMock()
            MockScanResult.return_value = mock_sr
            await orchestrator._persist_unified([file_result])

        call_kwargs = MockScanResult.call_args[1]
        assert call_kwargs["risk_tier"] == "HIGH"
        assert call_kwargs["risk_score"] == 60


class TestScanOrchestratorLegacy:
    """Test backward compatibility with legacy scan_directory API."""

    @pytest.mark.asyncio
    async def test_legacy_result_handler_called(self):
        """When using legacy API, result_handler callback should be called."""
        handler_called = []

        async def fake_handler(results):
            handler_called.extend(results)

        orchestrator = ScanOrchestrator(
            result_handler=fake_handler,
        )

        # Simulate a completed file result arriving
        file_result = FileResult(
            file_path="/tmp/test.txt",
            entity_counts={"SSN": 1},
            total_entities=1,
            total_processing_ms=10.0,
            chunk_count=1,
            errors=[],
        )

        await orchestrator._persist_batch([file_result])
        assert len(handler_called) == 1
        assert handler_called[0].file_path == "/tmp/test.txt"
