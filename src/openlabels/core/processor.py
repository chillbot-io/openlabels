"""
File processor for classification pipeline.

Integrates adapters (filesystem, SharePoint, OneDrive) with detection engine
to scan files and produce classification results.

Pipeline:
    1. Fetch file content via adapter
    2. Extract text (based on file type) - with decompression bomb protection
    3. Run detection engine
    4. Score entities
    5. Return classification result
"""

import asyncio
import logging
import mimetypes
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from openlabels.exceptions import DetectionError, ExtractionError, SecurityError

from .constants import DEFAULT_MODELS_DIR
from .detectors.config import DetectionConfig
from .detectors.orchestrator import DetectorOrchestrator
from .extractors import extract_text as _extract_text_from_file
from .scoring.scorer import score
from .types import RiskTier, Span

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

# Image extensions (require OCR)
IMAGE_EXTENSIONS: Set[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".gif", ".webp",
})


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
    content_score: float = 0.0
    exposure_multiplier: float = 1.0
    co_occurrence_rules: List[str] = field(default_factory=list)

    # Metadata
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "exposure_level": self.exposure_level,
            "entity_counts": self.entity_counts,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier.value,
            "content_score": self.content_score,
            "exposure_multiplier": self.exposure_multiplier,
            "co_occurrence_rules": self.co_occurrence_rules,
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
        config: DetectionConfig | None = None,
        enable_ocr: bool = True,
        max_file_size: int = 50 * 1024 * 1024,  # 50 MB
    ):
        """
        Initialize the processor.

        Args:
            config: Detection configuration (defaults to patterns-only)
            enable_ocr: Enable OCR for images and scanned PDFs
            max_file_size: Maximum file size to process (bytes)
        """
        self.config = config or DetectionConfig()
        self.max_file_size = max_file_size
        self.enable_ocr = enable_ocr
        self._ocr_engine = None
        self._ml_model_dir = self.config.ml_model_dir or DEFAULT_MODELS_DIR
        self._orchestrator = DetectorOrchestrator(config=self.config)

        # Lazily initialize OCR engine when needed
        if enable_ocr:
            self._init_ocr_engine()

    def _init_ocr_engine(self) -> None:
        """Initialize OCR engine lazily."""
        try:
            from .ocr import OCREngine
            self._ocr_engine = OCREngine(models_dir=self._ml_model_dir)
            if self._ocr_engine.is_available:
                # Start loading in background for faster first use
                self._ocr_engine.start_loading()
            else:
                logger.info("OCR not available - rapidocr-onnxruntime not installed")
                self._ocr_engine = None
        except ImportError:
            logger.debug("OCR module not available")
            self._ocr_engine = None

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

        Security:
            Files exceeding max_file_size are rejected to prevent DoS attacks.
        """
        import time
        start_time = time.time()

        file_name = Path(file_path).name
        mime_type, _ = mimetypes.guess_type(file_path)

        # Security: Calculate actual content size for DoS protection
        actual_size = file_size if file_size is not None else len(content)

        # Initialize result
        result = FileClassification(
            file_path=file_path,
            file_name=file_name,
            file_size=actual_size,
            mime_type=mime_type,
            exposure_level=exposure_level,
        )

        # Security: Reject files that exceed max_file_size to prevent DoS
        if actual_size > self.max_file_size:
            result.error = f"File size ({actual_size:,} bytes) exceeds limit ({self.max_file_size:,} bytes)"
            result.processing_time_ms = (time.time() - start_time) * 1000
            logger.warning(f"Rejected oversized file: {file_path} ({actual_size:,} bytes)")
            return result

        try:
            # Extract text if bytes
            if isinstance(content, bytes):
                text = await self._extract_text(content, file_path)
            else:
                text = content

            if not text or not text.strip():
                result.processing_time_ms = (time.time() - start_time) * 1000
                return result

            # Run detection (async — delegates to thread pool)
            detection_result = await self._orchestrator.detect(text)
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
                result.content_score = score_result.content_score
                result.exposure_multiplier = score_result.exposure_multiplier
                result.co_occurrence_rules = score_result.co_occurrence_rules

        except (DetectionError, ExtractionError, SecurityError) as e:
            # Domain-specific errors - log with full context
            logger.error(f"Processing error for {file_path}: {e}")
            result.error = str(e)
        except UnicodeDecodeError as e:
            # Encoding issue during text extraction
            error_msg = f"Failed to decode file content: encoding error at position {e.start}"
            logger.warning(f"{file_path}: {error_msg}")
            result.error = error_msg
        except MemoryError:
            # File too large to process in memory
            error_msg = f"Insufficient memory to process file ({actual_size:,} bytes)"
            logger.error(f"{file_path}: {error_msg}")
            result.error = error_msg
        except OSError as e:
            # Filesystem or IO error
            error_msg = f"IO error while processing file: {type(e).__name__}: {e}"
            logger.error(f"{file_path}: {error_msg}")
            result.error = error_msg
        except ValueError as e:
            # Invalid data or security violation (e.g., decompression bomb)
            logger.error(f"Value/Security error processing {file_path}: {e}")
            result.error = str(e)
        except RuntimeError as e:
            # Unexpected runtime issue
            error_msg = f"Runtime error during processing: {type(e).__name__}: {e}"
            logger.error(f"{file_path}: {error_msg}")
            result.error = error_msg

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
        Extract text from file content using secure extractors.

        Features:
        - Decompression bomb protection for DOCX/XLSX
        - Page limits for PDFs to prevent DoS
        - OCR fallback for scanned documents

        Args:
            content: Raw file bytes
            file_path: File path for type detection

        Returns:
            Extracted text
        """
        ext = Path(file_path).suffix.lower()

        # Plain text files - handle directly (fast path)
        if ext in TEXT_EXTENSIONS:
            return await self._decode_text(content)

        # Use secure extractors for all other formats (CPU-bound, offload to thread)
        try:
            result = await asyncio.to_thread(
                _extract_text_from_file,
                content=content,
                filename=file_path,
                ocr_engine=self._ocr_engine,
            )

            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"{file_path}: {warning}")

            return result.text

        except ValueError as e:
            # Decompression bomb or other security issue
            logger.error(f"Security error extracting {file_path}: {e}")
            raise
        except ImportError as e:
            # Missing library - try fallback
            logger.warning(f"Missing library for {file_path}: {e}")
            return await self._decode_text(content)
        except (OSError, RuntimeError, MemoryError) as e:
            # Log extraction failures - may indicate unsupported format or corrupt file
            logger.warning(f"Extraction failed for {file_path}: {type(e).__name__}: {e}")
            # Fall back to trying as text
            return await self._decode_text(content)
        except Exception as e:  # noqa: BLE001 — catch-all for third-party extraction libraries
            logger.warning(f"Unexpected extraction error for {file_path}: {type(e).__name__}: {e}")
            return await self._decode_text(content)

    def _extract_image_sync(self, content: bytes) -> str:
        """Synchronous image OCR -- all CPU-bound work in one call."""
        import io

        import numpy as np
        from PIL import Image

        image = Image.open(io.BytesIO(content))
        if image.mode != "RGB":
            image = image.convert("RGB")
        image_array = np.array(image)
        return self._ocr_engine.extract_text(image_array)

    async def _extract_image(self, content: bytes) -> str:
        """
        Extract text from image using OCR.

        Args:
            content: Raw image bytes

        Returns:
            Extracted text or empty string if OCR unavailable
        """
        if not self._ocr_engine:
            logger.warning("OCR not available for image extraction")
            return ""

        try:
            return await asyncio.to_thread(self._extract_image_sync, content)
        except ImportError as e:
            logger.warning(f"Image processing library not installed: {e}")
            return ""
        except (OSError, ValueError, RuntimeError, MemoryError) as e:
            logger.warning(f"Error extracting text from image: {type(e).__name__}: {e}")
            return ""

    async def _decode_text(self, content: bytes) -> str:
        """Decode bytes to text with encoding detection."""
        # Try common encodings - decode errors are expected for wrong encodings
        for encoding in ["utf-8", "utf-16", "latin-1", "cp1252"]:
            try:
                return content.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                # This encoding doesn't work - try next one
                continue

        # Last resort: decode with errors replaced
        return content.decode("utf-8", errors="replace")

    # NOTE: Legacy extraction methods (_extract_office, _extract_docx, _extract_xlsx,
    # _extract_pptx, _extract_odf, _extract_rtf, _extract_legacy_office, _extract_pdf,
    # _extract_pdf_with_ocr) have been removed. All extraction is now handled by
    # the secure extractors in openlabels.core.extractors module via _extract_text_from_file.

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
        supported = TEXT_EXTENSIONS | OFFICE_EXTENSIONS | PDF_EXTENSIONS | IMAGE_EXTENSIONS

        return ext in supported

    def cleanup(self) -> None:
        """
        Release resources held by the processor.

        This should be called during graceful shutdown to free ML models
        and other heavy resources (typically 200-500MB for ML models).
        """
        # Clear OCR engine
        if self._ocr_engine is not None:
            try:
                # OCR engines may have cleanup methods
                if hasattr(self._ocr_engine, 'cleanup'):
                    self._ocr_engine.cleanup()
            except (RuntimeError, OSError, AttributeError) as e:
                logger.debug(f"Error cleaning up OCR engine: {e}")
            self._ocr_engine = None

        # Clear detectors in orchestrator (releases ML model memory)
        if self._orchestrator is not None:
            try:
                # Clear detector list to release references to ML models
                self._orchestrator.detectors.clear()
                # Clear pipeline components
                self._orchestrator._coref_resolver = None
                self._orchestrator._context_enhancer = None
            except (RuntimeError, AttributeError) as e:
                logger.debug(f"Error cleaning up orchestrator: {e}")
            self._orchestrator = None

        logger.info("FileProcessor resources released")


async def process_file(
    file_path: str,
    content: Union[str, bytes],
    exposure_level: str = "PRIVATE",
    config: DetectionConfig | None = None,
) -> FileClassification:
    """
    Convenience function to process a single file.

    Args:
        file_path: Path to the file
        content: File content
        exposure_level: File exposure level
        config: Detection configuration

    Returns:
        FileClassification result
    """
    processor = FileProcessor(config=config)
    return await processor.process_file(file_path, content, exposure_level)
