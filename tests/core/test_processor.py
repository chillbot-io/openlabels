"""Tests for file processor."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestFileProcessor:
    """Tests for FileProcessor class."""

    def test_processor_creation(self):
        """Test creating file processor."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()
        assert processor is not None

    def test_processor_with_options(self):
        """Test processor with configuration options."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(
            enable_ml=False,
            enable_ocr=False,
            confidence_threshold=0.8,
            max_file_size=10 * 1024 * 1024,
        )

        assert processor.max_file_size == 10 * 1024 * 1024

    def test_can_process_txt(self):
        """Test can_process for text files."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()

        assert processor.can_process("test.txt", 1024) is True
        assert processor.can_process("test.md", 1024) is True
        assert processor.can_process("test.csv", 1024) is True

    def test_can_process_office(self):
        """Test can_process for office files."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()

        assert processor.can_process("test.docx", 1024) is True
        assert processor.can_process("test.xlsx", 1024) is True
        assert processor.can_process("test.pdf", 1024) is True

    def test_can_process_images(self):
        """Test can_process for image files."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()

        assert processor.can_process("test.png", 1024) is True
        assert processor.can_process("test.jpg", 1024) is True

    def test_can_process_respects_size_limit(self):
        """Test can_process respects size limit."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(max_file_size=1024)

        assert processor.can_process("test.txt", 500) is True
        assert processor.can_process("test.txt", 2000) is False

    def test_can_process_rejects_unknown(self):
        """Test can_process rejects unknown extensions."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()

        assert processor.can_process("test.xyz", 1024) is False
        assert processor.can_process("test.bin", 1024) is False

    async def test_process_text_file(self):
        """Test processing a text file."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False, enable_ocr=False)

        result = await processor.process_file(
            file_path="test.txt",
            content="Hello, my SSN is 123-45-6789",
            exposure_level="PRIVATE",
        )

        assert result is not None
        assert result.file_path == "test.txt"

    async def test_process_empty_file(self):
        """Test processing an empty file."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False, enable_ocr=False)

        result = await processor.process_file(
            file_path="empty.txt",
            content="",
            exposure_level="PRIVATE",
        )

        assert result is not None
        assert result.entity_counts == {}

    async def test_process_bytes_content(self):
        """Test processing bytes content."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False, enable_ocr=False)

        result = await processor.process_file(
            file_path="test.txt",
            content=b"Test content with email: test@example.com",
            exposure_level="PRIVATE",
        )

        assert result is not None


class TestFileClassification:
    """Tests for FileClassification dataclass."""

    def test_classification_creation(self):
        """Test creating file classification."""
        from openlabels.core.processor import FileClassification
        from openlabels.core.types import RiskTier

        classification = FileClassification(
            file_path="/path/to/file.txt",
            file_name="file.txt",
            file_size=1024,
            mime_type="text/plain",
            exposure_level="PRIVATE",
        )

        assert classification.file_path == "/path/to/file.txt"
        assert classification.risk_tier == RiskTier.MINIMAL

    def test_classification_to_dict(self):
        """Test classification to_dict method."""
        from openlabels.core.processor import FileClassification
        from openlabels.core.types import RiskTier

        classification = FileClassification(
            file_path="/test.txt",
            file_name="test.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            risk_score=50,
            risk_tier=RiskTier.MEDIUM,
            entity_counts={"EMAIL": 5},
        )

        d = classification.to_dict()

        assert d["file_path"] == "/test.txt"
        assert d["risk_score"] == 50
        assert d["entity_counts"]["EMAIL"] == 5


class TestProcessFileBatch:
    """Tests for batch file processing."""

    async def test_process_batch(self):
        """Test processing multiple files."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False, enable_ocr=False)

        files = [
            {"path": "file1.txt", "content": "Content 1", "exposure": "PRIVATE"},
            {"path": "file2.txt", "content": "Content 2", "exposure": "INTERNAL"},
        ]

        results = []
        async for result in processor.process_batch(files):
            results.append(result)

        assert len(results) == 2

    async def test_process_batch_with_concurrency(self):
        """Test batch processing respects concurrency limit."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False, enable_ocr=False)

        files = [
            {"path": f"file{i}.txt", "content": f"Content {i}", "exposure": "PRIVATE"}
            for i in range(10)
        ]

        results = []
        async for result in processor.process_batch(files, concurrency=2):
            results.append(result)

        assert len(results) == 10


class TestTextExtensions:
    """Tests for text extension constants."""

    def test_text_extensions_defined(self):
        """Test TEXT_EXTENSIONS is defined."""
        from openlabels.core.processor import TEXT_EXTENSIONS

        assert ".txt" in TEXT_EXTENSIONS
        assert ".md" in TEXT_EXTENSIONS
        assert ".py" in TEXT_EXTENSIONS

    def test_office_extensions_defined(self):
        """Test OFFICE_EXTENSIONS is defined."""
        from openlabels.core.processor import OFFICE_EXTENSIONS

        assert ".docx" in OFFICE_EXTENSIONS
        assert ".xlsx" in OFFICE_EXTENSIONS

    def test_pdf_extensions_defined(self):
        """Test PDF_EXTENSIONS is defined."""
        from openlabels.core.processor import PDF_EXTENSIONS

        assert ".pdf" in PDF_EXTENSIONS

    def test_image_extensions_defined(self):
        """Test IMAGE_EXTENSIONS is defined."""
        from openlabels.core.processor import IMAGE_EXTENSIONS

        assert ".png" in IMAGE_EXTENSIONS
        assert ".jpg" in IMAGE_EXTENSIONS
