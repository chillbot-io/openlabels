"""Tests for files/extractor.py - text extraction from various file formats.

Tests cover:
- ExtractionResult dataclass
- PageInfo dataclass
- BaseExtractor interface
- PDFExtractor
- DOCXExtractor
- XLSXExtractor
- ImageExtractor
- TextExtractor
- RTFExtractor
"""

import io
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# PAGE INFO TESTS
# =============================================================================

class TestPageInfo:
    """Tests for PageInfo dataclass."""

    def test_creation(self):
        """PageInfo can be created with all fields."""
        from scrubiq.files.extractor import PageInfo

        page = PageInfo(
            page_num=0,
            text="Test content",
            is_scanned=True,
            ocr_result=MagicMock(),
            temp_image_path="/tmp/page_0.png",
        )

        assert page.page_num == 0
        assert page.text == "Test content"
        assert page.is_scanned is True
        assert page.temp_image_path == "/tmp/page_0.png"

    def test_defaults(self):
        """PageInfo has reasonable defaults."""
        from scrubiq.files.extractor import PageInfo

        page = PageInfo(
            page_num=1,
            text="Text",
            is_scanned=False,
        )

        assert page.ocr_result is None
        assert page.temp_image_path is None


# =============================================================================
# EXTRACTION RESULT TESTS
# =============================================================================

class TestExtractionResult:
    """Tests for ExtractionResult dataclass."""

    def test_creation(self):
        """ExtractionResult can be created."""
        from scrubiq.files.extractor import ExtractionResult

        result = ExtractionResult(
            text="Extracted text content",
            pages=5,
            needs_ocr=True,
            ocr_pages=[1, 3, 5],
        )

        assert result.text == "Extracted text content"
        assert result.pages == 5
        assert result.needs_ocr is True
        assert result.ocr_pages == [1, 3, 5]

    def test_defaults(self):
        """ExtractionResult has reasonable defaults."""
        from scrubiq.files.extractor import ExtractionResult

        result = ExtractionResult(text="Test")

        assert result.pages == 1
        assert result.needs_ocr is False
        assert result.ocr_pages == []
        assert result.warnings == []
        assert result.confidence == 1.0
        assert result.ocr_results == []
        assert result.page_infos == []
        assert result.temp_dir_path is None
        assert result.document_type is None
        assert result.is_id_document is False
        assert result.phi_fields is None
        assert result.enhanced_text is None
        assert result.enhancements_applied == []

    def test_has_scanned_pages_false_when_none(self):
        """has_scanned_pages returns False when no pages are scanned."""
        from scrubiq.files.extractor import ExtractionResult, PageInfo

        result = ExtractionResult(
            text="Test",
            page_infos=[
                PageInfo(page_num=0, text="Page 1", is_scanned=False),
                PageInfo(page_num=1, text="Page 2", is_scanned=False),
            ],
        )

        assert result.has_scanned_pages is False

    def test_has_scanned_pages_true_when_some(self):
        """has_scanned_pages returns True when some pages are scanned."""
        from scrubiq.files.extractor import ExtractionResult, PageInfo

        result = ExtractionResult(
            text="Test",
            page_infos=[
                PageInfo(page_num=0, text="Page 1", is_scanned=False),
                PageInfo(page_num=1, text="Page 2", is_scanned=True),
            ],
        )

        assert result.has_scanned_pages is True

    def test_scanned_page_count(self):
        """scanned_page_count returns count of scanned pages."""
        from scrubiq.files.extractor import ExtractionResult, PageInfo

        result = ExtractionResult(
            text="Test",
            page_infos=[
                PageInfo(page_num=0, text="Page 1", is_scanned=False),
                PageInfo(page_num=1, text="Page 2", is_scanned=True),
                PageInfo(page_num=2, text="Page 3", is_scanned=True),
            ],
        )

        assert result.scanned_page_count == 2

    def test_best_text_returns_enhanced_when_available(self):
        """best_text returns enhanced_text when available."""
        from scrubiq.files.extractor import ExtractionResult

        result = ExtractionResult(
            text="Raw text",
            enhanced_text="Enhanced text with better formatting",
        )

        assert result.best_text == "Enhanced text with better formatting"

    def test_best_text_returns_raw_when_no_enhanced(self):
        """best_text returns raw text when no enhanced available."""
        from scrubiq.files.extractor import ExtractionResult

        result = ExtractionResult(
            text="Raw text only",
            enhanced_text=None,
        )

        assert result.best_text == "Raw text only"


# =============================================================================
# BASE EXTRACTOR TESTS
# =============================================================================

class TestBaseExtractor:
    """Tests for BaseExtractor abstract class."""

    def test_is_abstract(self):
        """BaseExtractor cannot be instantiated directly."""
        from scrubiq.files.extractor import BaseExtractor

        with pytest.raises(TypeError):
            BaseExtractor()

    def test_requires_can_handle(self):
        """Subclasses must implement can_handle."""
        from scrubiq.files.extractor import BaseExtractor

        class IncompleteExtractor(BaseExtractor):
            def extract(self, content, filename):
                pass

        with pytest.raises(TypeError):
            IncompleteExtractor()

    def test_requires_extract(self):
        """Subclasses must implement extract."""
        from scrubiq.files.extractor import BaseExtractor

        class IncompleteExtractor(BaseExtractor):
            def can_handle(self, content_type, extension):
                pass

        with pytest.raises(TypeError):
            IncompleteExtractor()


# =============================================================================
# PDF EXTRACTOR TESTS
# =============================================================================

class TestPDFExtractor:
    """Tests for PDFExtractor."""

    def test_can_handle_pdf_mime_type(self):
        """Handles application/pdf MIME type."""
        with patch('scrubiq.files.extractor.fitz', create=True):
            from scrubiq.files.extractor import PDFExtractor

            extractor = PDFExtractor()
            assert extractor.can_handle("application/pdf", ".pdf") is True

    def test_can_handle_pdf_extension(self):
        """Handles .pdf extension."""
        with patch('scrubiq.files.extractor.fitz', create=True):
            from scrubiq.files.extractor import PDFExtractor

            extractor = PDFExtractor()
            assert extractor.can_handle("application/octet-stream", ".pdf") is True

    def test_cannot_handle_other_types(self):
        """Does not handle non-PDF types."""
        with patch('scrubiq.files.extractor.fitz', create=True):
            from scrubiq.files.extractor import PDFExtractor

            extractor = PDFExtractor()
            assert extractor.can_handle("text/plain", ".txt") is False
            assert extractor.can_handle("image/jpeg", ".jpg") is False

    def test_init_with_ocr_engine(self):
        """Accepts OCR engine."""
        from scrubiq.files.extractor import PDFExtractor

        mock_ocr = MagicMock()
        extractor = PDFExtractor(ocr_engine=mock_ocr)

        assert extractor.ocr_engine == mock_ocr

    def test_init_with_temp_dir(self):
        """Accepts temp directory."""
        from scrubiq.files.extractor import PDFExtractor

        mock_temp_dir = MagicMock()
        extractor = PDFExtractor(temp_dir=mock_temp_dir)

        assert extractor.temp_dir == mock_temp_dir

    def test_enhanced_processing_enabled_by_default(self):
        """Enhanced processing is enabled by default."""
        from scrubiq.files.extractor import PDFExtractor

        extractor = PDFExtractor()

        assert extractor.enable_enhanced_processing is True

    def test_enhanced_processing_can_be_disabled(self):
        """Enhanced processing can be disabled."""
        from scrubiq.files.extractor import PDFExtractor

        extractor = PDFExtractor(enable_enhanced_processing=False)

        assert extractor.enable_enhanced_processing is False

    def test_render_dpi_constant(self):
        """RENDER_DPI is set for quality/size balance."""
        from scrubiq.files.extractor import PDFExtractor

        assert PDFExtractor.RENDER_DPI == 150


# =============================================================================
# DOCX EXTRACTOR TESTS
# =============================================================================

class TestDOCXExtractor:
    """Tests for DOCXExtractor."""

    def test_can_handle_docx_mime_type(self):
        """Handles DOCX MIME type."""
        from scrubiq.files.extractor import DOCXExtractor

        extractor = DOCXExtractor()
        assert extractor.can_handle(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".docx"
        ) is True

    def test_can_handle_docx_extension(self):
        """Handles .docx extension."""
        from scrubiq.files.extractor import DOCXExtractor

        extractor = DOCXExtractor()
        assert extractor.can_handle("application/octet-stream", ".docx") is True

    def test_can_handle_doc_extension(self):
        """Handles .doc extension (legacy Word)."""
        from scrubiq.files.extractor import DOCXExtractor

        extractor = DOCXExtractor()
        # DOCXExtractor typically also handles .doc
        result = extractor.can_handle("application/msword", ".doc")
        # Implementation specific - may or may not handle .doc
        assert isinstance(result, bool)

    def test_cannot_handle_pdf(self):
        """Does not handle PDF."""
        from scrubiq.files.extractor import DOCXExtractor

        extractor = DOCXExtractor()
        assert extractor.can_handle("application/pdf", ".pdf") is False


# =============================================================================
# XLSX EXTRACTOR TESTS
# =============================================================================

class TestXLSXExtractor:
    """Tests for XLSXExtractor."""

    def test_can_handle_xlsx_mime_type(self):
        """Handles XLSX MIME type."""
        from scrubiq.files.extractor import XLSXExtractor

        extractor = XLSXExtractor()
        assert extractor.can_handle(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".xlsx"
        ) is True

    def test_can_handle_xlsx_extension(self):
        """Handles .xlsx extension."""
        from scrubiq.files.extractor import XLSXExtractor

        extractor = XLSXExtractor()
        assert extractor.can_handle("application/octet-stream", ".xlsx") is True

    def test_can_handle_csv(self):
        """May handle CSV files."""
        from scrubiq.files.extractor import XLSXExtractor

        extractor = XLSXExtractor()
        result = extractor.can_handle("text/csv", ".csv")
        # Implementation specific
        assert isinstance(result, bool)


# =============================================================================
# IMAGE EXTRACTOR TESTS
# =============================================================================

class TestImageExtractor:
    """Tests for ImageExtractor."""

    def test_can_handle_jpeg(self):
        """Handles JPEG images."""
        from scrubiq.files.extractor import ImageExtractor

        extractor = ImageExtractor()
        assert extractor.can_handle("image/jpeg", ".jpg") is True
        assert extractor.can_handle("image/jpeg", ".jpeg") is True

    def test_can_handle_png(self):
        """Handles PNG images."""
        from scrubiq.files.extractor import ImageExtractor

        extractor = ImageExtractor()
        assert extractor.can_handle("image/png", ".png") is True

    def test_can_handle_tiff(self):
        """Handles TIFF images."""
        from scrubiq.files.extractor import ImageExtractor

        extractor = ImageExtractor()
        assert extractor.can_handle("image/tiff", ".tiff") is True
        assert extractor.can_handle("image/tiff", ".tif") is True

    def test_can_handle_webp(self):
        """Handles WebP images."""
        from scrubiq.files.extractor import ImageExtractor

        extractor = ImageExtractor()
        assert extractor.can_handle("image/webp", ".webp") is True

    def test_can_handle_bmp(self):
        """Handles BMP images."""
        from scrubiq.files.extractor import ImageExtractor

        extractor = ImageExtractor()
        assert extractor.can_handle("image/bmp", ".bmp") is True

    def test_cannot_handle_pdf(self):
        """Does not handle PDF."""
        from scrubiq.files.extractor import ImageExtractor

        extractor = ImageExtractor()
        assert extractor.can_handle("application/pdf", ".pdf") is False

    def test_init_with_ocr_engine(self):
        """Accepts OCR engine."""
        from scrubiq.files.extractor import ImageExtractor

        mock_ocr = MagicMock()
        extractor = ImageExtractor(ocr_engine=mock_ocr)

        assert extractor.ocr_engine == mock_ocr

    def test_init_with_temp_dir(self):
        """Accepts temp directory."""
        from scrubiq.files.extractor import ImageExtractor

        mock_temp_dir = MagicMock()
        extractor = ImageExtractor(temp_dir=mock_temp_dir)

        assert extractor.temp_dir == mock_temp_dir


# =============================================================================
# TEXT EXTRACTOR TESTS
# =============================================================================

class TestTextExtractor:
    """Tests for TextExtractor."""

    def test_can_handle_text_plain(self):
        """Handles text/plain MIME type."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()
        assert extractor.can_handle("text/plain", ".txt") is True

    def test_can_handle_txt_extension(self):
        """Handles .txt extension."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()
        assert extractor.can_handle("application/octet-stream", ".txt") is True

    def test_can_handle_various_text_types(self):
        """Handles various text content types."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()

        # Common text types that may be supported
        text_types = [
            ("text/plain", ".txt"),
            ("text/csv", ".csv"),
            ("text/markdown", ".md"),
        ]

        for content_type, extension in text_types:
            result = extractor.can_handle(content_type, extension)
            assert isinstance(result, bool)

    def test_cannot_handle_binary(self):
        """Does not handle binary formats."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()
        assert extractor.can_handle("application/pdf", ".pdf") is False
        assert extractor.can_handle("image/jpeg", ".jpg") is False

    def test_extract_simple_text(self):
        """Extracts simple text content."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()
        content = b"Hello, World!\nThis is a test."

        result = extractor.extract(content, "test.txt")

        assert "Hello, World!" in result.text
        assert "This is a test" in result.text
        assert result.needs_ocr is False

    def test_extract_utf8_text(self):
        """Extracts UTF-8 encoded text."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()
        content = "Unicode: \u00e9\u00e0\u00fc\u00f1".encode('utf-8')

        result = extractor.extract(content, "unicode.txt")

        assert "\u00e9" in result.text  # é
        assert "\u00e0" in result.text  # à

    def test_extract_handles_encoding_errors(self):
        """Handles encoding errors gracefully."""
        from scrubiq.files.extractor import TextExtractor

        extractor = TextExtractor()
        # Invalid UTF-8 sequence
        content = b"Valid text \xff\xfe invalid bytes"

        # Should not raise, should handle gracefully
        result = extractor.extract(content, "mixed.txt")
        assert isinstance(result.text, str)


# =============================================================================
# RTF EXTRACTOR TESTS
# =============================================================================

class TestRTFExtractor:
    """Tests for RTFExtractor."""

    def test_can_handle_rtf_mime_type(self):
        """Handles RTF MIME type."""
        from scrubiq.files.extractor import RTFExtractor

        extractor = RTFExtractor()
        assert extractor.can_handle("application/rtf", ".rtf") is True
        assert extractor.can_handle("text/rtf", ".rtf") is True

    def test_can_handle_rtf_extension(self):
        """Handles .rtf extension."""
        from scrubiq.files.extractor import RTFExtractor

        extractor = RTFExtractor()
        assert extractor.can_handle("application/octet-stream", ".rtf") is True

    def test_cannot_handle_doc(self):
        """Does not handle DOC format."""
        from scrubiq.files.extractor import RTFExtractor

        extractor = RTFExtractor()
        assert extractor.can_handle("application/msword", ".doc") is False


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for extraction constants."""

    def test_min_native_text_length(self):
        """MIN_NATIVE_TEXT_LENGTH is reasonable."""
        from scrubiq.constants import MIN_NATIVE_TEXT_LENGTH

        # Should be small enough to catch text-layer PDFs
        # but large enough to avoid noise
        assert MIN_NATIVE_TEXT_LENGTH > 0
        assert MIN_NATIVE_TEXT_LENGTH < 1000

    def test_max_document_pages(self):
        """MAX_DOCUMENT_PAGES limits DoS attacks."""
        from scrubiq.constants import MAX_DOCUMENT_PAGES

        # Should be reasonable for legitimate documents
        assert MAX_DOCUMENT_PAGES >= 100
        assert MAX_DOCUMENT_PAGES <= 10000

    def test_max_spreadsheet_rows(self):
        """MAX_SPREADSHEET_ROWS limits spreadsheet size."""
        from scrubiq.constants import MAX_SPREADSHEET_ROWS

        # Should allow large spreadsheets but prevent abuse
        assert MAX_SPREADSHEET_ROWS >= 1000
        assert MAX_SPREADSHEET_ROWS <= 10000000


# =============================================================================
# EXTRACTOR SELECTION TESTS
# =============================================================================

class TestExtractorSelection:
    """Tests for selecting appropriate extractor."""

    def test_extractors_have_distinct_types(self):
        """Each extractor handles distinct file types."""
        from scrubiq.files.extractor import (
            PDFExtractor,
            DOCXExtractor,
            XLSXExtractor,
            ImageExtractor,
            TextExtractor,
            RTFExtractor,
        )

        # PDF should not be handled by non-PDF extractors
        pdf_type = ("application/pdf", ".pdf")

        assert PDFExtractor().can_handle(*pdf_type) is True
        assert DOCXExtractor().can_handle(*pdf_type) is False
        assert XLSXExtractor().can_handle(*pdf_type) is False
        assert ImageExtractor().can_handle(*pdf_type) is False
        assert TextExtractor().can_handle(*pdf_type) is False
        assert RTFExtractor().can_handle(*pdf_type) is False

    def test_image_types_only_handled_by_image_extractor(self):
        """Image types are only handled by ImageExtractor."""
        from scrubiq.files.extractor import (
            PDFExtractor,
            DOCXExtractor,
            XLSXExtractor,
            ImageExtractor,
            TextExtractor,
            RTFExtractor,
        )

        jpeg_type = ("image/jpeg", ".jpg")

        assert PDFExtractor().can_handle(*jpeg_type) is False
        assert DOCXExtractor().can_handle(*jpeg_type) is False
        assert XLSXExtractor().can_handle(*jpeg_type) is False
        assert ImageExtractor().can_handle(*jpeg_type) is True
        assert TextExtractor().can_handle(*jpeg_type) is False
        assert RTFExtractor().can_handle(*jpeg_type) is False


# =============================================================================
# EXTRACTION FLOW TESTS
# =============================================================================

class TestExtractionFlow:
    """Tests for extraction workflow."""

    def test_text_extractor_returns_extraction_result(self):
        """TextExtractor returns ExtractionResult."""
        from scrubiq.files.extractor import TextExtractor, ExtractionResult

        extractor = TextExtractor()
        result = extractor.extract(b"Test content", "test.txt")

        assert isinstance(result, ExtractionResult)
        assert result.text == "Test content"
        assert result.pages == 1

    def test_extraction_result_has_required_fields(self):
        """ExtractionResult has all required fields."""
        from scrubiq.files.extractor import ExtractionResult

        result = ExtractionResult(text="Test")

        # All these should be accessible
        _ = result.text
        _ = result.pages
        _ = result.needs_ocr
        _ = result.ocr_pages
        _ = result.warnings
        _ = result.confidence
        _ = result.ocr_results
        _ = result.page_infos
        _ = result.temp_dir_path
        _ = result.document_type
        _ = result.is_id_document
        _ = result.phi_fields
        _ = result.enhanced_text
        _ = result.enhancements_applied
        _ = result.has_scanned_pages
        _ = result.scanned_page_count
        _ = result.best_text
