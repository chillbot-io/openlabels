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
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({}, 0, "PRIVATE")
        assert tier == "MINIMAL"
        assert score == 0
        assert content_score == 0
        assert mult == 1.0

    def test_low_risk(self):
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({"SSN": 2}, 2, "PRIVATE")
        assert tier == "LOW"
        assert score == 20
        assert content_score == 20
        assert mult == 1.0

    def test_high_risk_with_exposure(self):
        # 7 entities * 10 = 70 base, * 1.5 ORG_WIDE = 105 → capped at 100
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({"SSN": 7}, 7, "ORG_WIDE")
        assert tier == "CRITICAL"
        assert score == 100
        assert content_score == 70  # base score before multiplier
        assert mult == 1.5

    def test_medium_risk(self):
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({"EMAIL": 4}, 4, "PRIVATE")
        assert tier == "MEDIUM"
        assert score == 40
        assert content_score == 40

    def test_public_exposure_multiplier(self):
        # 3 entities * 10 = 30 base, * 2.0 PUBLIC = 60
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({"SSN": 3}, 3, "PUBLIC")
        assert tier == "HIGH"
        assert score == 60
        assert content_score == 30  # base before multiplier
        assert mult == 2.0

    def test_internal_exposure_multiplier(self):
        # 5 entities * 10 = 50 base, * 1.2 INTERNAL = 60
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({"EMAIL": 5}, 5, "INTERNAL")
        assert tier == "HIGH"
        assert score == 60
        assert content_score == 50
        assert mult == 1.2

    def test_unknown_exposure_defaults_to_1(self):
        score, tier, content_score, mult = ScanOrchestrator._compute_risk({"SSN": 3}, 3, "UNKNOWN")
        assert mult == 1.0
        assert score == 30


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
        assert call_kwargs["risk_score"] == 40
        assert call_kwargs["total_entities"] == 4
        assert call_kwargs["exposure_level"] == "PRIVATE"
        assert call_kwargs["owner"] == "alice"
        assert call_kwargs["content_hash"] == "abc123"
        # content_score should be base score (before multiplier)
        assert call_kwargs["content_score"] == 40.0
        # exposure_multiplier should be 1.0 for PRIVATE
        assert call_kwargs["exposure_multiplier"] == 1.0

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
        # content_score = base score 30, exposure_multiplier = 2.0
        assert call_kwargs["content_score"] == 30.0
        assert call_kwargs["exposure_multiplier"] == 2.0


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


# ── TextChunker tests ─────────────────────────────────────────────

class TestTextChunker:
    """Tests for the TextChunker module."""

    def test_empty_text(self):
        from openlabels.core.pipeline.chunking import TextChunker
        chunker = TextChunker()
        assert chunker.chunk("") == []

    def test_short_text_single_chunk(self):
        from openlabels.core.pipeline.chunking import TextChunker
        chunker = TextChunker(max_chunk_size=100)
        chunks = chunker.chunk("Hello world")
        assert len(chunks) == 1
        assert chunks[0].text == "Hello world"
        assert chunks[0].start == 0
        assert chunks[0].end == 11

    def test_exact_boundary(self):
        from openlabels.core.pipeline.chunking import TextChunker
        text = "a" * 100
        chunker = TextChunker(max_chunk_size=100, overlap=10)
        chunks = chunker.chunk(text)
        assert len(chunks) == 1  # exactly at boundary

    def test_long_text_multiple_chunks(self):
        from openlabels.core.pipeline.chunking import TextChunker
        # 10 words of ~11 chars each = 110 chars
        text = " ".join(["word"] * 30)  # 149 chars
        chunker = TextChunker(max_chunk_size=50, overlap=10)
        chunks = chunker.chunk(text)
        assert len(chunks) > 1
        # First chunk starts at 0
        assert chunks[0].start == 0
        # All text is covered
        assert chunks[-1].end == len(text)

    def test_overlap_between_chunks(self):
        from openlabels.core.pipeline.chunking import TextChunker
        text = " ".join(["word"] * 50)  # ~249 chars
        chunker = TextChunker(max_chunk_size=80, overlap=20)
        chunks = chunker.chunk(text)
        # Consecutive chunks should overlap
        for i in range(len(chunks) - 1):
            assert chunks[i + 1].start < chunks[i].end, (
                f"Chunks {i} and {i+1} don't overlap"
            )

    def test_whitespace_boundary_splitting(self):
        from openlabels.core.pipeline.chunking import TextChunker
        # Create text where the split should prefer whitespace
        text = "a" * 45 + " " + "b" * 45 + " " + "c" * 45
        chunker = TextChunker(max_chunk_size=50, overlap=5)
        chunks = chunker.chunk(text)
        # The first chunk should break at a space, not mid-word
        assert chunks[0].text.endswith(" ") or chunks[0].text.endswith("a")


# ── Aggregate file results test ────────────────────────────────────

class TestAggregateFileResults:
    """Test the _aggregate_file_results method."""

    def test_single_chunk_aggregation(self):
        orchestrator = ScanOrchestrator()
        orchestrator._file_results["/tmp/test.txt"] = [
            AgentResult(
                work_id="test:0",
                file_path="/tmp/test.txt",
                chunk_index=0,
                entities=[
                    EntityMatch(entity_type="SSN", value="123-45-6789", start=0, end=11, confidence=0.99, source="checksum"),
                    EntityMatch(entity_type="EMAIL", value="a@b.com", start=20, end=27, confidence=0.95, source="regex"),
                ],
                processing_time_ms=50.0,
                agent_id=0,
                error=None,
            ),
        ]
        result = orchestrator._aggregate_file_results("/tmp/test.txt")
        assert result.file_path == "/tmp/test.txt"
        assert result.entity_counts == {"SSN": 1, "EMAIL": 1}
        assert result.total_entities == 2
        assert result.chunk_count == 1
        assert result.errors == []

    def test_multi_chunk_aggregation(self):
        orchestrator = ScanOrchestrator()
        orchestrator._file_results["/tmp/big.txt"] = [
            AgentResult(
                work_id="big:0",
                file_path="/tmp/big.txt",
                chunk_index=0,
                entities=[
                    EntityMatch(entity_type="SSN", value="123-45-6789", start=0, end=11, confidence=0.99, source="checksum"),
                ],
                processing_time_ms=30.0,
                agent_id=0,
                error=None,
            ),
            AgentResult(
                work_id="big:1",
                file_path="/tmp/big.txt",
                chunk_index=1,
                entities=[
                    EntityMatch(entity_type="SSN", value="987-65-4321", start=0, end=11, confidence=0.98, source="checksum"),
                    EntityMatch(entity_type="CREDIT_CARD", value="4111111111111111", start=15, end=31, confidence=0.97, source="checksum"),
                ],
                processing_time_ms=45.0,
                agent_id=0,
                error=None,
            ),
        ]
        result = orchestrator._aggregate_file_results("/tmp/big.txt")
        assert result.entity_counts == {"SSN": 2, "CREDIT_CARD": 1}
        assert result.total_entities == 3
        assert result.chunk_count == 2
        assert result.total_processing_ms == 75.0

    def test_aggregation_with_errors(self):
        orchestrator = ScanOrchestrator()
        orchestrator._file_results["/tmp/err.txt"] = [
            AgentResult(
                work_id="err:0",
                file_path="/tmp/err.txt",
                chunk_index=0,
                entities=[],
                processing_time_ms=10.0,
                agent_id=0,
                error="Model timeout",
            ),
        ]
        result = orchestrator._aggregate_file_results("/tmp/err.txt")
        assert result.has_errors
        assert "Chunk 0: Model timeout" in result.errors


# ── Seen file paths test ───────────────────────────────────────────

class TestSeenFilePaths:
    """Test that the orchestrator tracks all seen file paths."""

    @pytest.mark.asyncio
    async def test_seen_paths_includes_all_walked_files(self):
        """All files from ChangeProvider should be in _seen_file_paths."""
        files = [
            _make_file_info("/tmp/a.txt", "a.txt"),
            _make_file_info("/tmp/b.txt", "b.txt"),
            _make_file_info("/tmp/c.txt", "c.txt"),
        ]
        provider = MockChangeProvider(files)
        orchestrator = ScanOrchestrator(change_provider=provider)

        await orchestrator._walk_files()

        assert orchestrator._seen_file_paths == {"/tmp/a.txt", "/tmp/b.txt", "/tmp/c.txt"}

    @pytest.mark.asyncio
    async def test_seen_paths_includes_oversized_files(self):
        """Even oversized files that are skipped should be in _seen_file_paths."""
        files = [
            _make_file_info("/tmp/small.txt", "small.txt", size=100),
            _make_file_info("/tmp/big.txt", "big.txt", size=999999999),
        ]
        provider = MockChangeProvider(files)

        settings = MagicMock()
        settings.scan.max_file_size_mb = 1  # 1 MB limit

        orchestrator = ScanOrchestrator(
            change_provider=provider,
            settings=settings,
        )

        await orchestrator._walk_files()

        # Both files seen, but big one was skipped
        assert "/tmp/small.txt" in orchestrator._seen_file_paths
        assert "/tmp/big.txt" in orchestrator._seen_file_paths
        assert orchestrator.stats["files_skipped"] == 1
