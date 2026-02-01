"""
File processor for classification pipeline.

Integrates adapters (filesystem, SharePoint, OneDrive) with detection engine
to scan files and produce classification results.

Pipeline:
    1. Fetch file content via adapter
    2. Extract text (based on file type)
    3. Run detection engine
    4. Score entities
    5. Return classification result
"""

import asyncio
import logging
import mimetypes
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, AsyncIterator, Union

from .types import Span, DetectionResult, ScoringResult, RiskTier
from .detectors.orchestrator import DetectorOrchestrator
from .scoring.scorer import score

logger = logging.getLogger(__name__)


# Supported text-based file extensions
TEXT_EXTENSIONS: Set[str] = frozenset({
    ".txt", ".md", ".markdown", ".rst", ".csv", ".tsv",
    ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".log", ".sql", ".html", ".htm", ".css", ".js", ".ts",
    ".py", ".rb", ".go", ".java", ".c", ".cpp", ".h", ".hpp",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
})

# Office document extensions (require extraction libraries)
OFFICE_EXTENSIONS: Set[str] = frozenset({
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf",
})

# PDF extension
PDF_EXTENSIONS: Set[str] = frozenset({".pdf"})


@dataclass
class FileClassification:
    """Classification result for a single file."""
    file_path: str
    file_name: str
    file_size: int
    mime_type: Optional[str]
    exposure_level: str

    # Detection results
    spans: List[Span] = field(default_factory=list)
    entity_counts: Dict[str, int] = field(default_factory=dict)

    # Scoring results
    risk_score: int = 0
    risk_tier: RiskTier = RiskTier.MINIMAL

    # Metadata
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "exposure_level": self.exposure_level,
            "entity_counts": self.entity_counts,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier.value,
            "processed_at": self.processed_at.isoformat(),
            "processing_time_ms": self.processing_time_ms,
            "error": self.error,
        }


class FileProcessor:
    """
    Processes files through the classification pipeline.

    Usage:
        processor = FileProcessor()

        # Process a single file
        result = await processor.process_file(file_path, content, exposure)

        # Process multiple files
        async for result in processor.process_batch(files):
            print(f"{result.file_path}: {result.risk_tier}")
    """

    def __init__(
        self,
        enable_ml: bool = False,
        ml_model_dir: Optional[Path] = None,
        confidence_threshold: float = 0.70,
        max_file_size: int = 50 * 1024 * 1024,  # 50 MB
    ):
        """
        Initialize the processor.

        Args:
            enable_ml: Enable ML-based detectors
            ml_model_dir: Path to ML model files
            confidence_threshold: Minimum detection confidence
            max_file_size: Maximum file size to process (bytes)
        """
        self.max_file_size = max_file_size
        self._orchestrator = DetectorOrchestrator(
            enable_ml=enable_ml,
            ml_model_dir=ml_model_dir,
            confidence_threshold=confidence_threshold,
        )

    async def process_file(
        self,
        file_path: str,
        content: Union[str, bytes],
        exposure_level: str = "PRIVATE",
        file_size: Optional[int] = None,
    ) -> FileClassification:
        """
        Process a single file.

        Args:
            file_path: Path or identifier for the file
            content: File content (text or bytes)
            exposure_level: File exposure (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)
            file_size: File size in bytes (for reporting)

        Returns:
            FileClassification with detection and scoring results
        """
        import time
        start_time = time.time()

        file_name = Path(file_path).name
        mime_type, _ = mimetypes.guess_type(file_path)

        # Initialize result
        result = FileClassification(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size or len(content),
            mime_type=mime_type,
            exposure_level=exposure_level,
        )

        try:
            # Extract text if bytes
            if isinstance(content, bytes):
                text = await self._extract_text(content, file_path)
            else:
                text = content

            if not text or not text.strip():
                result.processing_time_ms = (time.time() - start_time) * 1000
                return result

            # Run detection
            detection_result = self._orchestrator.detect(text)
            result.spans = detection_result.spans
            result.entity_counts = detection_result.entity_counts

            # Score entities
            if detection_result.entity_counts:
                score_result = score(
                    entities=detection_result.entity_counts,
                    exposure=exposure_level,
                )
                result.risk_score = score_result.score
                result.risk_tier = score_result.tier

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            result.error = str(e)

        result.processing_time_ms = (time.time() - start_time) * 1000
        return result

    async def process_batch(
        self,
        files: List[Dict],
        concurrency: int = 4,
    ) -> AsyncIterator[FileClassification]:
        """
        Process multiple files concurrently.

        Args:
            files: List of file dicts with keys: path, content, exposure, size
            concurrency: Maximum concurrent file processing

        Yields:
            FileClassification for each processed file
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def process_one(file_info: Dict) -> FileClassification:
            async with semaphore:
                return await self.process_file(
                    file_path=file_info["path"],
                    content=file_info["content"],
                    exposure_level=file_info.get("exposure", "PRIVATE"),
                    file_size=file_info.get("size"),
                )

        tasks = [process_one(f) for f in files]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result

    async def _extract_text(self, content: bytes, file_path: str) -> str:
        """
        Extract text from file content.

        Args:
            content: Raw file bytes
            file_path: File path for type detection

        Returns:
            Extracted text
        """
        ext = Path(file_path).suffix.lower()

        # Plain text files
        if ext in TEXT_EXTENSIONS:
            return await self._decode_text(content)

        # Office documents
        if ext in OFFICE_EXTENSIONS:
            return await self._extract_office(content, ext)

        # PDFs
        if ext in PDF_EXTENSIONS:
            return await self._extract_pdf(content)

        # Unknown - try as text
        return await self._decode_text(content)

    async def _decode_text(self, content: bytes) -> str:
        """Decode bytes to text with encoding detection."""
        # Try common encodings
        for encoding in ["utf-8", "utf-16", "latin-1", "cp1252"]:
            try:
                return content.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue

        # Last resort: decode with errors replaced
        return content.decode("utf-8", errors="replace")

    async def _extract_office(self, content: bytes, ext: str) -> str:
        """
        Extract text from Office documents.

        TODO: Implement with python-docx, openpyxl, python-pptx
        """
        logger.warning(f"Office extraction not implemented for {ext}")
        return ""

    async def _extract_pdf(self, content: bytes) -> str:
        """
        Extract text from PDF.

        TODO: Implement with pdfplumber or PyMuPDF
        """
        logger.warning("PDF extraction not implemented")
        return ""

    def can_process(self, file_path: str, file_size: int) -> bool:
        """
        Check if a file can be processed.

        Args:
            file_path: Path to the file
            file_size: Size in bytes

        Returns:
            True if file can be processed
        """
        if file_size > self.max_file_size:
            return False

        ext = Path(file_path).suffix.lower()
        supported = TEXT_EXTENSIONS | OFFICE_EXTENSIONS | PDF_EXTENSIONS

        return ext in supported


async def process_file(
    file_path: str,
    content: Union[str, bytes],
    exposure_level: str = "PRIVATE",
    **kwargs,
) -> FileClassification:
    """
    Convenience function to process a single file.

    Args:
        file_path: Path to the file
        content: File content
        exposure_level: File exposure level
        **kwargs: Passed to FileProcessor

    Returns:
        FileClassification result
    """
    processor = FileProcessor(**kwargs)
    return await processor.process_file(file_path, content, exposure_level)
