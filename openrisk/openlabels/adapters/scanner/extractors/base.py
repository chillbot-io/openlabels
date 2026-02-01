"""Base extractor classes and result types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ocr import OCRResult


@dataclass
class PageInfo:
    """Information about a single extracted page."""
    page_num: int
    text: str
    is_scanned: bool
    ocr_result: Optional["OCRResult"] = None
    temp_image_path: Optional[str] = None


@dataclass
class ExtractionResult:
    """Result of text extraction from a file."""
    text: str
    pages: int = 1
    needs_ocr: bool = False
    ocr_pages: List[int] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    confidence: float = 1.0
    ocr_results: List["OCRResult"] = field(default_factory=list)
    page_infos: List[PageInfo] = field(default_factory=list)
    temp_dir_path: Optional[str] = None
    document_type: Optional[str] = None
    is_id_document: bool = False
    phi_fields: Optional[Dict[str, Any]] = None
    enhanced_text: Optional[str] = None
    enhancements_applied: List[str] = field(default_factory=list)

    @property
    def has_scanned_pages(self) -> bool:
        return any(p.is_scanned for p in self.page_infos)

    @property
    def scanned_page_count(self) -> int:
        return sum(1 for p in self.page_infos if p.is_scanned)

    @property
    def best_text(self) -> str:
        return self.enhanced_text if self.enhanced_text else self.text


class BaseExtractor(ABC):
    """Base class for format-specific extractors."""

    @abstractmethod
    def can_handle(self, content_type: str, extension: str) -> bool:
        """Check if this extractor handles the file type."""
        ...

    @abstractmethod
    def extract(self, content: bytes, filename: str) -> ExtractionResult:
        """Extract text from file content."""
        ...
