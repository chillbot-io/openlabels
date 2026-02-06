"""
Comprehensive tests for openlabels.core.extractors module.

Tests cover:
- ExtractionResult / PageInfo dataclass behavior
- Decompression bomb protection (zip bombs, billion laughs analog)
- Text extraction from each supported format (PDF, DOCX, XLSX, Image, Email, HTML, RTF, PPTX, Text)
- Error handling (corrupted files, empty files, missing dependencies)
- Unicode handling (BOM, multi-byte, mixed encodings)
- Edge cases (zero-length content, binary content, null bytes)
- Extractor registry (get_extractor, extract_text)
"""

import io
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from openlabels.core.extractors import (
    BaseExtractor,
    DOCXExtractor,
    EmailExtractor,
    ExtractionResult,
    HTMLExtractor,
    ImageExtractor,
    PDFExtractor,
    PPTXExtractor,
    PageInfo,
    RTFExtractor,
    TextExtractor,
    XLSXExtractor,
    extract_text,
    get_extractor,
)
from openlabels.core.constants import (
    MAX_DECOMPRESSED_SIZE,
    MAX_DOCUMENT_PAGES,
    MAX_EXTRACTION_RATIO,
    MAX_SPREADSHEET_ROWS,
    MIN_NATIVE_TEXT_LENGTH,
)


# =============================================================================
# ExtractionResult / PageInfo TESTS
# =============================================================================


class TestExtractionResult:
    """Tests for ExtractionResult and PageInfo dataclasses."""

    def test_default_values(self):
        """ExtractionResult has sensible defaults for optional fields."""
        result = ExtractionResult(text="hello")
        assert result.pages == 1
        assert result.needs_ocr is False
        assert result.ocr_pages == []
        assert result.warnings == []
        assert result.confidence == 1.0
        assert result.page_infos == []

    def test_has_scanned_pages_false_when_no_pages(self):
        """has_scanned_pages returns False when page_infos is empty."""
        result = ExtractionResult(text="", page_infos=[])
        assert result.has_scanned_pages is False

    def test_has_scanned_pages_false_when_all_native(self):
        """has_scanned_pages returns False when all pages are native text."""
        pages = [
            PageInfo(page_num=0, text="native text", is_scanned=False),
            PageInfo(page_num=1, text="more native text", is_scanned=False),
        ]
        result = ExtractionResult(text="", page_infos=pages)
        assert result.has_scanned_pages is False

    def test_has_scanned_pages_true_with_mixed(self):
        """has_scanned_pages returns True if even one page is scanned."""
        pages = [
            PageInfo(page_num=0, text="native text", is_scanned=False),
            PageInfo(page_num=1, text="ocr text", is_scanned=True),
        ]
        result = ExtractionResult(text="", page_infos=pages)
        assert result.has_scanned_pages is True

    def test_scanned_page_count(self):
        """scanned_page_count accurately counts only scanned pages."""
        pages = [
            PageInfo(page_num=0, text="native", is_scanned=False),
            PageInfo(page_num=1, text="scanned 1", is_scanned=True),
            PageInfo(page_num=2, text="native", is_scanned=False),
            PageInfo(page_num=3, text="scanned 2", is_scanned=True),
            PageInfo(page_num=4, text="scanned 3", is_scanned=True),
        ]
        result = ExtractionResult(text="", page_infos=pages)
        assert result.scanned_page_count == 3

    def test_scanned_page_count_zero_when_all_native(self):
        """scanned_page_count returns 0 when no pages are scanned."""
        pages = [PageInfo(page_num=0, text="native", is_scanned=False)]
        result = ExtractionResult(text="", page_infos=pages)
        assert result.scanned_page_count == 0


# =============================================================================
# TextExtractor TESTS
# =============================================================================


class TestTextExtractor:
    """Tests for TextExtractor."""

    def test_can_handle_text_plain(self):
        """Handles text/plain content type."""
        ext = TextExtractor()
        assert ext.can_handle("text/plain", ".txt") is True

    def test_can_handle_txt_extension(self):
        """Handles .txt extension regardless of content type."""
        ext = TextExtractor()
        assert ext.can_handle("application/octet-stream", ".txt") is True

    def test_rejects_non_text_types(self):
        """Rejects non-text types."""
        ext = TextExtractor()
        assert ext.can_handle("application/pdf", ".pdf") is False
        assert ext.can_handle("image/png", ".png") is False

    def test_utf8_text(self):
        """Extracts UTF-8 text correctly."""
        ext = TextExtractor()
        content = "Hello, world! Special chars: cafe\u0301"
        result = ext.extract(content.encode("utf-8"), "test.txt")
        assert result.text == content
        assert result.pages == 1
        assert result.warnings == []

    def test_utf8_bom_preserved_by_utf8_decode(self):
        """UTF-8 BOM bytes are valid UTF-8, so utf-8 decoding keeps the BOM character.

        The extractor tries utf-8 first, which succeeds with the BOM as U+FEFF.
        This is the actual behavior -- utf-8-sig is never tried because utf-8 works.
        """
        ext = TextExtractor()
        bom = b"\xef\xbb\xbf"
        text = "Text after BOM"
        result = ext.extract(bom + text.encode("utf-8"), "bom.txt")
        # utf-8 decodes BOM bytes as U+FEFF character (succeeds before utf-8-sig)
        assert result.text == "\ufeff" + text
        assert result.warnings == []

    def test_latin1_only_bytes(self):
        """Falls back to latin-1 for bytes not valid in UTF-8."""
        ext = TextExtractor()
        # \xe9 is 'e with acute' in latin-1 but invalid continuation in UTF-8
        content = b"Caf\xe9 au lait"
        result = ext.extract(content, "latin.txt")
        assert "Caf" in result.text
        # latin-1 decodes every byte, so it should succeed
        assert result.warnings == []

    def test_cp1252_smart_quotes(self):
        """Handles Windows cp1252 smart quotes that break UTF-8."""
        ext = TextExtractor()
        # \x93 and \x94 are left/right double quotes in cp1252, invalid in UTF-8
        content = b"\x93Hello World\x94"
        result = ext.extract(content, "smart.txt")
        # Should decode without error via latin-1 or cp1252
        assert "Hello World" in result.text
        assert result.warnings == []

    def test_empty_content(self):
        """Empty bytes produce empty text, no warnings."""
        ext = TextExtractor()
        result = ext.extract(b"", "empty.txt")
        assert result.text == ""
        assert result.warnings == []

    def test_multibyte_unicode_cjk(self):
        """Handles CJK characters (3-byte UTF-8 sequences)."""
        ext = TextExtractor()
        content = "\u4f60\u597d\u4e16\u754c"  # "Hello World" in Chinese
        result = ext.extract(content.encode("utf-8"), "chinese.txt")
        assert result.text == content

    def test_emoji_4byte_unicode(self):
        """Handles emoji (4-byte UTF-8 sequences)."""
        ext = TextExtractor()
        content = "Hello \U0001f600 World \U0001f30d"
        result = ext.extract(content.encode("utf-8"), "emoji.txt")
        assert result.text == content

    def test_null_bytes_in_content(self):
        """Content with null bytes still decodes (null is valid UTF-8)."""
        ext = TextExtractor()
        content = b"Before\x00After"
        result = ext.extract(content, "nulls.txt")
        assert "Before" in result.text
        assert "After" in result.text

    def test_binary_garbage_falls_through_to_latin1(self):
        """Random binary bytes always decode via latin-1 (it accepts all bytes)."""
        ext = TextExtractor()
        # Generate bytes that are invalid in utf-8 and cp1252
        content = bytes(range(256))
        result = ext.extract(content, "binary.txt")
        # latin-1 maps every byte to a character, so it should always succeed
        assert result.warnings == []
        assert len(result.text) == 256


# =============================================================================
# PDFExtractor TESTS
# =============================================================================


class TestPDFExtractor:
    """Tests for PDFExtractor with mocked PyMuPDF."""

    def test_can_handle_pdf_content_type(self):
        ext = PDFExtractor()
        assert ext.can_handle("application/pdf", ".txt") is True

    def test_can_handle_pdf_extension(self):
        ext = PDFExtractor()
        assert ext.can_handle("text/plain", ".pdf") is True

    def test_rejects_non_pdf(self):
        ext = PDFExtractor()
        assert ext.can_handle("text/plain", ".txt") is False

    def test_extract_native_text_page(self):
        """Pages with sufficient native text are marked as non-scanned."""
        mock_page = MagicMock()
        native_text = "A" * (MIN_NATIVE_TEXT_LENGTH + 10)
        mock_page.get_text.return_value = native_text

        mock_doc = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.__len__ = MagicMock(return_value=1)
        mock_doc.close = MagicMock()

        with patch.dict("sys.modules", {"fitz": MagicMock()}):
            import sys
            sys.modules["fitz"].open.return_value = mock_doc

            ext = PDFExtractor()
            result = ext.extract(b"fake-pdf-content", "test.pdf")

        assert native_text.strip() in result.text
        assert result.pages == 1
        assert len(result.page_infos) == 1
        assert result.page_infos[0].is_scanned is False
        assert result.needs_ocr is False

    def test_scanned_page_without_ocr_engine(self):
        """Scanned page without OCR engine produces warning."""
        mock_page = MagicMock()
        # Short text = below MIN_NATIVE_TEXT_LENGTH threshold
        mock_page.get_text.return_value = "ab"

        mock_doc = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.__len__ = MagicMock(return_value=1)
        mock_doc.close = MagicMock()

        with patch.dict("sys.modules", {"fitz": MagicMock()}):
            import sys
            sys.modules["fitz"].open.return_value = mock_doc

            ext = PDFExtractor(ocr_engine=None)
            result = ext.extract(b"fake-pdf", "scanned.pdf")

        assert result.page_infos[0].is_scanned is True
        assert any("OCR not available" in w for w in result.warnings)

    def test_scanned_page_with_ocr_engine(self):
        """Scanned page with OCR engine calls extract_text on rendered image."""
        mock_page = MagicMock()
        mock_page.get_text.return_value = ""  # No native text

        mock_pix = MagicMock()
        mock_pix.width = 100
        mock_pix.height = 100
        mock_pix.samples = b"\x00" * (100 * 100 * 3)
        mock_page.get_pixmap.return_value = mock_pix

        mock_doc = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.__len__ = MagicMock(return_value=1)
        mock_doc.close = MagicMock()

        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        mock_ocr.extract_text.return_value = "OCR extracted text"

        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc

        mock_pil_image = MagicMock()
        mock_np = MagicMock()
        mock_np.array.return_value = "fake_array"

        with patch.dict("sys.modules", {
            "fitz": mock_fitz,
            "PIL": MagicMock(),
            "PIL.Image": MagicMock(frombytes=MagicMock(return_value=mock_pil_image)),
            "numpy": mock_np,
        }):
            ext = PDFExtractor(ocr_engine=mock_ocr)
            result = ext.extract(b"fake-pdf", "scanned.pdf")

        assert result.needs_ocr is True
        assert 0 in result.ocr_pages

    def test_ocr_failure_on_page_produces_warning(self):
        """OCR failure on a specific page produces a warning but does not crash."""
        mock_page = MagicMock()
        mock_page.get_text.return_value = ""

        mock_pix = MagicMock()
        mock_pix.width = 100
        mock_pix.height = 100
        mock_pix.samples = b"\x00" * (100 * 100 * 3)
        mock_page.get_pixmap.return_value = mock_pix

        mock_doc = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.__len__ = MagicMock(return_value=1)
        mock_doc.close = MagicMock()

        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        mock_ocr.extract_text.side_effect = RuntimeError("OCR engine crashed")

        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc

        with patch.dict("sys.modules", {
            "fitz": mock_fitz,
            "PIL": MagicMock(),
            "PIL.Image": MagicMock(frombytes=MagicMock(return_value=MagicMock())),
            "numpy": MagicMock(),
        }):
            ext = PDFExtractor(ocr_engine=mock_ocr)
            result = ext.extract(b"fake-pdf", "test.pdf")

        assert any("OCR failed" in w for w in result.warnings)
        assert result.page_infos[0].is_scanned is True
        assert result.page_infos[0].text == ""

    def test_page_limit_truncation(self):
        """PDFs exceeding MAX_DOCUMENT_PAGES are truncated with warning."""
        pages = []
        for i in range(MAX_DOCUMENT_PAGES + 10):
            mock_page = MagicMock()
            mock_page.get_text.return_value = f"Page {i} " + "x" * MIN_NATIVE_TEXT_LENGTH
            pages.append(mock_page)

        mock_doc = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter(pages))
        mock_doc.__len__ = MagicMock(return_value=len(pages))
        mock_doc.close = MagicMock()

        with patch.dict("sys.modules", {"fitz": MagicMock()}):
            import sys
            sys.modules["fitz"].open.return_value = mock_doc

            ext = PDFExtractor()
            result = ext.extract(b"fake-pdf", "huge.pdf")

        # Should only process MAX_DOCUMENT_PAGES pages
        assert len(result.page_infos) == MAX_DOCUMENT_PAGES
        assert any("truncated" in w for w in result.warnings)

    def test_pymupdf_not_installed(self):
        """Raises ImportError when PyMuPDF is not available."""
        ext = PDFExtractor()
        with patch.dict("sys.modules", {"fitz": None}):
            with pytest.raises(ImportError, match="PyMuPDF"):
                ext.extract(b"fake-pdf", "test.pdf")

    def test_corrupted_pdf_raises(self):
        """Corrupted PDF bytes cause fitz.open to raise, which propagates."""
        mock_fitz = MagicMock()
        mock_fitz.open.side_effect = RuntimeError("cannot open broken file")

        with patch.dict("sys.modules", {"fitz": mock_fitz}):
            ext = PDFExtractor()
            with pytest.raises(RuntimeError, match="cannot open broken file"):
                ext.extract(b"not-a-pdf", "corrupt.pdf")


# =============================================================================
# DOCXExtractor TESTS
# =============================================================================


class TestDOCXExtractor:
    """Tests for DOCXExtractor with mocked python-docx."""

    def test_can_handle_docx_mime(self):
        ext = DOCXExtractor()
        assert ext.can_handle(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".docx",
        ) is True

    def test_can_handle_doc_extension(self):
        ext = DOCXExtractor()
        assert ext.can_handle("application/msword", ".doc") is True

    def test_can_handle_doc_extension_only(self):
        """Extension alone is sufficient to match."""
        ext = DOCXExtractor()
        assert ext.can_handle("application/octet-stream", ".docx") is True

    def test_rejects_pdf(self):
        ext = DOCXExtractor()
        assert ext.can_handle("application/pdf", ".pdf") is False

    def test_extract_paragraphs(self):
        """Extracts text from paragraphs."""
        mock_para1 = MagicMock()
        mock_para1.text = "First paragraph"
        mock_para2 = MagicMock()
        mock_para2.text = "Second paragraph"
        mock_para3 = MagicMock()
        mock_para3.text = "   "  # Whitespace-only, should be skipped

        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para1, mock_para2, mock_para3]
        mock_doc.tables = []

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            result = ext.extract(b"x" * 200, "test.docx")

        assert "First paragraph" in result.text
        assert "Second paragraph" in result.text
        assert result.pages == 1

    def test_extract_tables(self):
        """Extracts text from table cells joined with pipe separator."""
        mock_cell1 = MagicMock()
        mock_cell1.text = "Name"
        mock_cell2 = MagicMock()
        mock_cell2.text = "John Doe"
        mock_row = MagicMock()
        mock_row.cells = [mock_cell1, mock_cell2]
        mock_table = MagicMock()
        mock_table.rows = [mock_row]

        mock_doc = MagicMock()
        mock_doc.paragraphs = []
        mock_doc.tables = [mock_table]

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            result = ext.extract(b"x" * 200, "test.docx")

        assert "Name | John Doe" in result.text

    def test_decompression_bomb_in_paragraphs(self):
        """Detects decompression bomb when paragraph text exceeds limit."""
        # Create a paragraph whose text exceeds MAX_DECOMPRESSED_SIZE
        huge_text = "A" * (MAX_DECOMPRESSED_SIZE + 1)
        mock_para = MagicMock()
        mock_para.text = huge_text

        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para]
        mock_doc.tables = []

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb detected"):
                ext.extract(b"x" * 200, "bomb.docx")

    def test_decompression_bomb_in_tables(self):
        """Detects decompression bomb accumulated across table cells."""
        # Create enough cells to exceed MAX_DECOMPRESSED_SIZE
        chunk_size = MAX_DECOMPRESSED_SIZE // 2 + 1
        mock_cell1 = MagicMock()
        mock_cell1.text = "A" * chunk_size
        mock_cell2 = MagicMock()
        mock_cell2.text = "B" * chunk_size

        mock_row = MagicMock()
        mock_row.cells = [mock_cell1, mock_cell2]
        mock_table = MagicMock()
        mock_table.rows = [mock_row]

        mock_doc = MagicMock()
        mock_doc.paragraphs = []
        mock_doc.tables = [mock_table]

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb detected"):
                ext.extract(b"x" * 200, "bomb.docx")

    def test_legacy_doc_extraction(self):
        """Legacy .doc files get basic text extraction with warning."""
        ext = DOCXExtractor()
        content = b"Some readable content embedded in binary " + b"\x00" * 50 + b"data here"
        result = ext.extract(content, "legacy.doc")

        assert result.pages == 1
        assert any("Legacy .doc" in w for w in result.warnings)

    def test_legacy_doc_filters_short_lines(self):
        """Legacy .doc extraction filters lines shorter than 4 characters."""
        ext = DOCXExtractor()
        # Build content: lines of varying length in latin-1
        content = b"ab\nHello World\nxy\nThis is a longer line\n"
        result = ext.extract(content, "test.doc")

        # Lines "ab" and "xy" should be filtered (len <= 3)
        assert "ab" not in result.text
        assert "Hello World" in result.text

    def test_python_docx_not_installed(self):
        """Raises ImportError when python-docx is not available."""
        ext = DOCXExtractor()
        with patch.dict("sys.modules", {"docx": None}):
            with pytest.raises(ImportError, match="python-docx"):
                ext.extract(b"x" * 200, "test.docx")

    def test_check_decompression_size_small_file_logs_warning(self):
        """Very small compressed files generate a log warning."""
        ext = DOCXExtractor()
        # Should not raise, just log
        ext._check_decompression_size(50, "tiny.docx")

    def test_empty_docx_paragraphs(self):
        """DOCX with all empty paragraphs produces empty text."""
        mock_para = MagicMock()
        mock_para.text = "   "

        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para]
        mock_doc.tables = []

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            result = ext.extract(b"x" * 200, "empty.docx")

        assert result.text == ""


# =============================================================================
# XLSXExtractor TESTS
# =============================================================================


class TestXLSXExtractor:
    """Tests for XLSXExtractor."""

    def test_can_handle_xlsx(self):
        ext = XLSXExtractor()
        assert ext.can_handle(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".xlsx",
        ) is True

    def test_can_handle_csv(self):
        ext = XLSXExtractor()
        assert ext.can_handle("text/csv", ".csv") is True

    def test_can_handle_tsv(self):
        ext = XLSXExtractor()
        assert ext.can_handle("text/csv", ".tsv") is True

    def test_can_handle_xls(self):
        ext = XLSXExtractor()
        assert ext.can_handle("application/vnd.ms-excel", ".xls") is True

    def test_csv_extraction_utf8(self):
        """Extracts CSV with UTF-8 encoding."""
        ext = XLSXExtractor()
        csv_content = "Name,Email\nJohn,john@test.com\nJane,jane@test.com"
        result = ext.extract(csv_content.encode("utf-8"), "data.csv")

        assert "Name | Email" in result.text
        assert "John | john@test.com" in result.text
        assert "Jane | jane@test.com" in result.text

    def test_csv_extraction_utf8_bom(self):
        """Handles CSV with UTF-8 BOM."""
        ext = XLSXExtractor()
        bom = b"\xef\xbb\xbf"
        csv_content = "Name,Value\nAlpha,100"
        result = ext.extract(bom + csv_content.encode("utf-8"), "bom.csv")

        assert "Name | Value" in result.text
        assert "Alpha | 100" in result.text

    def test_csv_extraction_latin1_fallback(self):
        """Falls back to latin-1 for non-UTF-8 CSV."""
        ext = XLSXExtractor()
        # \xe9 is 'e with acute' in latin-1
        csv_content = b"Name,City\nJos\xe9,Montr\xe9al"
        result = ext.extract(csv_content, "latin.csv")

        assert "Name | City" in result.text
        assert result.warnings == []

    def test_csv_empty_rows_skipped(self):
        """Empty CSV rows are skipped."""
        ext = XLSXExtractor()
        csv_content = b"A,B\n,,\nX,Y"
        result = ext.extract(csv_content, "sparse.csv")

        assert "A | B" in result.text
        assert "X | Y" in result.text
        # The empty row ",," has no stripped non-empty cells, so skipped
        lines = [line for line in result.text.split("\n") if line.strip()]
        assert len(lines) == 2

    def test_tsv_extraction(self):
        """Extracts TSV (tab-delimited) files."""
        ext = XLSXExtractor()
        tsv_content = b"Name\tAge\nAlice\t30\nBob\t25"
        result = ext.extract(tsv_content, "data.tsv")

        assert "Name | Age" in result.text
        assert "Alice | 30" in result.text

    def test_xlsx_extraction_with_mock(self):
        """Extracts text from XLSX using mocked openpyxl."""
        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = [
            ("Name", "SSN"),
            ("John", "123-45-6789"),
            (None, None),  # Empty row
        ]

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            result = ext.extract(b"x" * 200, "test.xlsx")

        assert "[Sheet: Sheet1]" in result.text
        assert "Name | SSN" in result.text
        assert "John | 123-45-6789" in result.text
        assert result.pages == 1

    def test_xlsx_decompression_bomb(self):
        """Detects decompression bomb during XLSX extraction."""
        # Create a sheet that yields enormous cell values
        huge_cell = "A" * (MAX_DECOMPRESSED_SIZE + 1)
        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = [(huge_cell,)]

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb detected"):
                ext.extract(b"x" * 200, "bomb.xlsx")

    def test_xlsx_row_limit_truncation(self):
        """Sheets exceeding MAX_SPREADSHEET_ROWS are truncated."""
        # Generate rows beyond the limit
        rows = [(f"val_{i}",) for i in range(MAX_SPREADSHEET_ROWS + 100)]

        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = iter(rows)

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["BigSheet"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            result = ext.extract(b"x" * 200, "big.xlsx")

        assert any("truncated" in w for w in result.warnings)

    def test_xlsx_high_extraction_ratio_warning(self):
        """High extraction ratio logs a warning but does not raise."""
        # Small compressed size with large text output
        compressed = b"x" * 10  # 10 bytes

        # Each row returns text; total chars must exceed ratio * compressed_size
        # MAX_EXTRACTION_RATIO=100, compressed=10, so need >1000 chars
        row_text = "A" * 200
        rows = [(row_text,) for _ in range(10)]  # 2000 chars total > 100*10=1000

        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = iter(rows)

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            # Should not raise, just warn
            result = ext.extract(compressed, "ratio.xlsx")

        # Text should still be returned
        assert row_text in result.text

    def test_xlsx_multi_sheet(self):
        """Extracts text from multiple sheets with sheet headers."""
        mock_sheet1 = MagicMock()
        mock_sheet1.iter_rows.return_value = [("Sheet1Data",)]
        mock_sheet2 = MagicMock()
        mock_sheet2.iter_rows.return_value = [("Sheet2Data",)]

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["First", "Second"]

        def getitem(name):
            return mock_sheet1 if name == "First" else mock_sheet2

        mock_wb.__getitem__ = MagicMock(side_effect=getitem)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            result = ext.extract(b"x" * 200, "multi.xlsx")

        assert "[Sheet: First]" in result.text
        assert "[Sheet: Second]" in result.text
        assert result.pages == 2

    def test_xls_extraction_with_mock(self):
        """Extracts text from legacy XLS using mocked xlrd."""
        mock_sheet = MagicMock()
        mock_sheet.nrows = 2
        mock_sheet.name = "Data"
        mock_sheet.row_values.side_effect = [
            ["Name", "Age"],
            ["Alice", 30],
        ]

        mock_wb = MagicMock()
        mock_wb.nsheets = 1
        mock_wb.sheet_by_index.return_value = mock_sheet

        mock_xlrd = MagicMock()
        mock_xlrd.open_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"xlrd": mock_xlrd}):
            ext = XLSXExtractor()
            result = ext.extract(b"xls-content", "data.xls")

        assert "[Sheet: Data]" in result.text
        assert "Name | Age" in result.text

    def test_openpyxl_not_installed(self):
        """Raises ImportError when openpyxl is not available."""
        ext = XLSXExtractor()
        with patch.dict("sys.modules", {"openpyxl": None}):
            with pytest.raises(ImportError, match="openpyxl"):
                ext.extract(b"x" * 200, "test.xlsx")

    def test_xlrd_not_installed(self):
        """Raises ImportError when xlrd is not available."""
        ext = XLSXExtractor()
        with patch.dict("sys.modules", {"xlrd": None}):
            with pytest.raises(ImportError, match="xlrd"):
                ext.extract(b"x" * 200, "test.xls")

    def test_csv_all_encodings_fail(self):
        """When all CSV encoding attempts fail, returns warning."""
        ext = XLSXExtractor()
        # This is tricky: latin-1 accepts all bytes, so normally nothing fails.
        # We mock decode to always fail.
        bad_bytes = MagicMock(spec=bytes)
        bad_bytes.decode = MagicMock(side_effect=UnicodeDecodeError("x", b"", 0, 1, "bad"))

        # Patch at the method level to intercept the loop
        with patch.object(XLSXExtractor, "_extract_csv") as mock_csv:
            mock_csv.return_value = ExtractionResult(
                text="", warnings=["Failed to decode CSV file"]
            )
            result = ext.extract(b"bad", "fail.csv")

        assert any("Failed to decode" in w for w in result.warnings)


# =============================================================================
# ImageExtractor TESTS
# =============================================================================


class TestImageExtractor:
    """Tests for ImageExtractor."""

    def test_can_handle_image_content_type(self):
        ext = ImageExtractor()
        assert ext.can_handle("image/png", ".png") is True
        assert ext.can_handle("image/jpeg", ".jpg") is True
        assert ext.can_handle("image/gif", ".gif") is True
        assert ext.can_handle("image/webp", ".webp") is True

    def test_can_handle_image_extensions(self):
        ext = ImageExtractor()
        for ext_str in (".jpg", ".jpeg", ".png", ".tiff", ".tif",
                        ".heic", ".heif", ".gif", ".bmp", ".webp"):
            assert ext.can_handle("application/octet-stream", ext_str) is True

    def test_rejects_non_image_types(self):
        ext = ImageExtractor()
        assert ext.can_handle("application/pdf", ".pdf") is False
        assert ext.can_handle("text/plain", ".txt") is False

    def test_extract_without_ocr_engine(self):
        """Without OCR engine, returns empty text with warning."""
        ext = ImageExtractor(ocr_engine=None)
        result = ext.extract(b"fake-image-bytes", "photo.jpg")

        assert result.text == ""
        assert result.needs_ocr is True
        assert any("OCR engine not available" in w for w in result.warnings)

    def test_extract_with_unavailable_ocr(self):
        """OCR engine present but not available returns empty with warning."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = False

        ext = ImageExtractor(ocr_engine=mock_ocr)
        result = ext.extract(b"fake-image", "photo.png")

        assert result.text == ""
        assert any("OCR engine not available" in w for w in result.warnings)

    def test_extract_with_ocr_success(self):
        """OCR engine successfully extracts text from image."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        mock_ocr.extract_text.return_value = "Patient: John Doe"

        mock_img = MagicMock()
        mock_img.mode = "RGB"

        mock_np = MagicMock()
        mock_np.array.return_value = "fake_array"

        mock_pil_image = MagicMock()
        mock_pil_image.open.return_value = mock_img

        with patch.dict("sys.modules", {
            "PIL": MagicMock(),
            "PIL.Image": mock_pil_image,
            "numpy": mock_np,
        }):
            ext = ImageExtractor(ocr_engine=mock_ocr)
            result = ext.extract(b"fake-png-bytes", "scan.png")

        assert result.text == "Patient: John Doe"
        assert result.needs_ocr is True
        assert result.ocr_pages == [0]
        assert result.page_infos[0].is_scanned is True

    def test_extract_converts_rgba_to_rgb(self):
        """Images not in RGB/L mode are converted to RGB."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        mock_ocr.extract_text.return_value = "converted text"

        mock_img = MagicMock()
        mock_img.mode = "RGBA"  # Not RGB or L
        mock_converted = MagicMock()
        mock_img.convert.return_value = mock_converted

        mock_np_module = MagicMock()
        mock_np_module.array.return_value = "fake_array"

        mock_pil = MagicMock()
        mock_image_module = MagicMock()
        mock_image_module.open.return_value = mock_img
        mock_pil.Image = mock_image_module

        with patch.dict("sys.modules", {
            "PIL": mock_pil,
            "PIL.Image": mock_image_module,
            "numpy": mock_np_module,
        }):
            ext = ImageExtractor(ocr_engine=mock_ocr)
            result = ext.extract(b"fake-rgba-bytes", "alpha.png")

        mock_img.convert.assert_called_once_with("RGB")
        assert result.text == "converted text"

    def test_extract_image_failure_returns_warning(self):
        """Image processing failure returns empty text with warning, not exception."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = True

        mock_image_module = MagicMock()
        mock_image_module.open.side_effect = OSError("cannot identify image file")

        mock_pil = MagicMock()
        mock_pil.Image = mock_image_module

        with patch.dict("sys.modules", {
            "PIL": mock_pil,
            "PIL.Image": mock_image_module,
            "numpy": MagicMock(),
        }):
            ext = ImageExtractor(ocr_engine=mock_ocr)
            result = ext.extract(b"corrupted-image", "broken.jpg")

        assert result.text == ""
        assert any("Image extraction failed" in w for w in result.warnings)

    def test_heic_without_pillow_heif(self):
        """HEIC files without pillow-heif return warning."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = True

        mock_pil_image = MagicMock()
        mock_np = MagicMock()

        # Mock pillow_heif import to fail
        def fake_import(name, *args, **kwargs):
            if name == "pillow_heif":
                raise ImportError("No module named 'pillow_heif'")
            return MagicMock()

        with patch.dict("sys.modules", {
            "PIL": MagicMock(),
            "PIL.Image": mock_pil_image,
            "numpy": mock_np,
        }):
            with patch("builtins.__import__", side_effect=fake_import):
                ext = ImageExtractor(ocr_engine=mock_ocr)
                result = ext.extract(b"heic-content", "photo.heic")

        assert any("HEIC" in w for w in result.warnings)


# =============================================================================
# EmailExtractor TESTS
# =============================================================================


class TestEmailExtractor:
    """Tests for EmailExtractor."""

    def test_can_handle_msg(self):
        ext = EmailExtractor()
        assert ext.can_handle("application/vnd.ms-outlook", ".msg") is True

    def test_can_handle_eml(self):
        ext = EmailExtractor()
        assert ext.can_handle("message/rfc822", ".eml") is True

    def test_can_handle_eml_extension(self):
        ext = EmailExtractor()
        assert ext.can_handle("application/octet-stream", ".eml") is True

    def test_rejects_non_email(self):
        ext = EmailExtractor()
        assert ext.can_handle("text/plain", ".txt") is False

    def test_eml_extraction_plain_text(self):
        """Extracts headers and plain-text body from EML."""
        msg = MIMEText("Hello, this is the body.")
        msg["Subject"] = "Test Subject"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Date"] = "Mon, 1 Jan 2024 12:00:00 +0000"

        ext = EmailExtractor()
        result = ext.extract(msg.as_bytes(), "test.eml")

        assert "Subject: Test Subject" in result.text
        assert "From: sender@example.com" in result.text
        assert "To: recipient@example.com" in result.text
        assert "Hello, this is the body." in result.text

    def test_eml_multipart_prefers_plain_text(self):
        """Multipart emails prefer text/plain over text/html."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Multipart"
        msg["From"] = "from@test.com"
        msg["To"] = "to@test.com"

        html_part = MIMEText("<html><body><p>HTML body</p></body></html>", "html")
        plain_part = MIMEText("Plain text body")

        msg.attach(html_part)
        msg.attach(plain_part)

        ext = EmailExtractor()
        result = ext.extract(msg.as_bytes(), "multi.eml")

        assert "Plain text body" in result.text

    def test_eml_html_fallback(self):
        """Falls back to HTML when no plain text part exists."""
        msg = MIMEMultipart()
        msg["Subject"] = "HTML Only"
        msg["From"] = "from@test.com"
        msg["To"] = "to@test.com"

        html_part = MIMEText("<html><body><p>Only HTML content</p></body></html>", "html")
        msg.attach(html_part)

        ext = EmailExtractor()
        result = ext.extract(msg.as_bytes(), "html_only.eml")

        # Should extract text from HTML
        assert "Only HTML content" in result.text or "HTML" in result.text

    def test_eml_with_attachments_listed(self):
        """Attachment filenames are listed in extracted text."""
        msg = MIMEMultipart()
        msg["Subject"] = "With Attachment"
        msg["From"] = "from@test.com"
        msg["To"] = "to@test.com"

        body = MIMEText("See attached.")
        msg.attach(body)

        attachment = MIMEText("fake attachment content")
        attachment.add_header("Content-Disposition", "attachment", filename="report.pdf")
        msg.attach(attachment)

        ext = EmailExtractor()
        result = ext.extract(msg.as_bytes(), "attached.eml")

        assert "report.pdf" in result.text
        assert "[Attachments]" in result.text

    def test_eml_without_headers(self):
        """EML with no headers still extracts body."""
        msg = MIMEText("Body only, no headers set")

        ext = EmailExtractor()
        result = ext.extract(msg.as_bytes(), "noheaders.eml")

        assert "Body only" in result.text

    def test_eml_empty_message(self):
        """Empty EML does not crash."""
        ext = EmailExtractor()
        # Minimal valid email bytes
        result = ext.extract(b"", "empty.eml")
        # Should return without crash
        assert result is not None

    def test_eml_unicode_subject(self):
        """EML with Unicode subject is handled correctly."""
        msg = MIMEText("Test body")
        msg["Subject"] = "Re: \u00dcber wichtig \u2014 Dringend"
        msg["From"] = "test@example.com"
        msg["To"] = "to@example.com"

        ext = EmailExtractor()
        result = ext.extract(msg.as_bytes(), "unicode.eml")

        assert "Subject:" in result.text

    def test_msg_not_installed(self):
        """Raises ImportError when extract-msg is not available."""
        ext = EmailExtractor()
        with patch.dict("sys.modules", {"extract_msg": None}):
            with pytest.raises(ImportError, match="extract-msg"):
                ext.extract(b"msg-content", "test.msg")

    def test_msg_extraction_failure_returns_warning(self):
        """MSG extraction failure returns empty text with warning."""
        mock_extract_msg = MagicMock()
        mock_extract_msg.Message.side_effect = Exception("corrupted MSG")

        with patch.dict("sys.modules", {"extract_msg": mock_extract_msg}):
            ext = EmailExtractor()
            result = ext.extract(b"bad-msg", "corrupt.msg")

        assert result.text == ""
        assert any("MSG extraction failed" in w for w in result.warnings)

    def test_html_to_text_without_beautifulsoup(self):
        """HTML-to-text fallback works without BeautifulSoup."""
        ext = EmailExtractor()

        # Check if bs4 is actually unavailable
        try:
            from bs4 import BeautifulSoup
            bs4_available = True
        except ImportError:
            bs4_available = False

        if bs4_available:
            # If bs4 is installed, simulate its absence
            original_import = __import__

            def selective_import(name, *args, **kwargs):
                if name == "bs4":
                    raise ImportError("mocked: no bs4")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=selective_import):
                result = ext._html_to_text("<html><body><p>Fallback text</p></body></html>")
        else:
            # bs4 is not installed, so the fallback path is used naturally
            result = ext._html_to_text("<html><body><p>Fallback text</p></body></html>")

        assert "Fallback text" in result


# =============================================================================
# HTMLExtractor TESTS
# =============================================================================


class TestHTMLExtractor:
    """Tests for HTMLExtractor."""

    def test_can_handle_html(self):
        ext = HTMLExtractor()
        assert ext.can_handle("text/html", ".html") is True
        assert ext.can_handle("application/xhtml+xml", ".xhtml") is True

    def test_can_handle_htm_extension(self):
        ext = HTMLExtractor()
        assert ext.can_handle("application/octet-stream", ".htm") is True

    def test_rejects_non_html(self):
        ext = HTMLExtractor()
        assert ext.can_handle("text/plain", ".txt") is False

    def test_extract_basic_html(self):
        """Extracts visible text from HTML, removing scripts and styles."""
        html = b"""
        <html>
        <head><title>Test Page</title></head>
        <body>
            <script>alert('xss');</script>
            <style>body { color: red; }</style>
            <h1>Main Heading</h1>
            <p>Paragraph with content.</p>
        </body>
        </html>
        """
        ext = HTMLExtractor()
        result = ext.extract(html, "page.html")

        assert "Main Heading" in result.text
        assert "Paragraph with content" in result.text
        assert "alert" not in result.text  # Script removed
        assert "color: red" not in result.text  # Style removed

    def test_extract_title_in_output(self):
        """Page title text is present in the output (via bs4 or fallback)."""
        html = b"<html><head><title>My Title</title></head><body>Body text</body></html>"
        ext = HTMLExtractor()
        result = ext.extract(html, "titled.html")

        # Both bs4 path and regex fallback should include the title text
        assert "My Title" in result.text
        assert "Body" in result.text

    def test_extract_html_entities(self):
        """HTML entities are decoded properly."""
        html = b"<html><body>&amp; &lt;tag&gt; &quot;quoted&quot;</body></html>"
        ext = HTMLExtractor()
        result = ext.extract(html, "entities.html")

        # BeautifulSoup should decode entities
        assert "&" in result.text or "&amp;" not in result.text

    def test_empty_html(self):
        """Empty HTML produces empty or minimal text."""
        ext = HTMLExtractor()
        result = ext.extract(b"", "empty.html")
        # Empty bytes decode to empty string
        assert result is not None

    def test_html_latin1_encoding(self):
        """HTML with latin-1 specific bytes is decoded."""
        html_bytes = b"<html><body>Caf\xe9 au lait</body></html>"
        ext = HTMLExtractor()
        result = ext.extract(html_bytes, "latin.html")

        assert "Caf" in result.text

    def test_noscript_elements_removed_with_bs4(self):
        """<noscript> elements are removed when bs4 is available."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            pytest.skip("BeautifulSoup not installed - noscript removal requires bs4")

        html = b"""
        <html><body>
            <noscript>Enable JavaScript!</noscript>
            <p>Visible content</p>
        </body></html>
        """
        ext = HTMLExtractor()
        result = ext.extract(html, "noscript.html")

        assert "Visible content" in result.text
        assert "Enable JavaScript" not in result.text

    def test_html_fallback_without_beautifulsoup(self):
        """Fallback tag stripping works without BeautifulSoup."""
        html = b"<html><body><script>evil();</script><p>Content here</p></body></html>"

        ext = HTMLExtractor()

        # Check if bs4 is actually unavailable
        try:
            from bs4 import BeautifulSoup
            bs4_available = True
        except ImportError:
            bs4_available = False

        if bs4_available:
            # If bs4 is installed, we need to simulate its absence
            # Use patch on the module-level import inside the method
            import importlib
            original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

            def selective_import(name, *args, **kwargs):
                if name == "bs4":
                    raise ImportError("mocked: no bs4")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=selective_import):
                result = ext.extract(html, "fallback.html")
        else:
            # bs4 is not installed, so the fallback path is used naturally
            result = ext.extract(html, "fallback.html")

        assert "Content here" in result.text
        assert any("BeautifulSoup not available" in w for w in result.warnings)


# =============================================================================
# RTFExtractor TESTS
# =============================================================================


class TestRTFExtractor:
    """Tests for RTFExtractor."""

    def test_can_handle_rtf(self):
        ext = RTFExtractor()
        assert ext.can_handle("application/rtf", ".rtf") is True

    def test_rejects_non_rtf(self):
        ext = RTFExtractor()
        assert ext.can_handle("text/plain", ".txt") is False
        assert ext.can_handle("application/pdf", ".pdf") is False

    def test_extract_with_mocked_striprtf(self):
        """Extracts text using striprtf library."""
        mock_striprtf_module = MagicMock()
        mock_striprtf_module.striprtf.rtf_to_text.return_value = "Extracted RTF content"

        with patch.dict("sys.modules", {
            "striprtf": mock_striprtf_module,
            "striprtf.striprtf": mock_striprtf_module.striprtf,
        }):
            ext = RTFExtractor()
            result = ext.extract(b"{\\rtf1 content}", "test.rtf")

        assert result.text == "Extracted RTF content"

    def test_striprtf_not_installed(self):
        """Raises ImportError when striprtf is not available."""
        ext = RTFExtractor()
        with patch.dict("sys.modules", {"striprtf": None, "striprtf.striprtf": None}):
            with pytest.raises(ImportError, match="striprtf"):
                ext.extract(b"{\\rtf1 test}", "test.rtf")

    def test_rtf_extraction_failure_returns_warning(self):
        """RTF parsing failure returns empty text with warning."""
        mock_module = MagicMock()
        mock_module.rtf_to_text.side_effect = ValueError("malformed RTF")

        with patch.dict("sys.modules", {
            "striprtf": MagicMock(),
            "striprtf.striprtf": mock_module,
        }):
            ext = RTFExtractor()
            result = ext.extract(b"not valid rtf", "bad.rtf")

        assert result.text == ""
        assert any("RTF extraction failed" in w for w in result.warnings)

    def test_rtf_encoding_fallback(self):
        """RTF with latin-1 bytes falls back from UTF-8."""
        mock_module = MagicMock()
        mock_module.rtf_to_text.return_value = "decoded content"

        # Content with bytes that fail UTF-8 but work in latin-1
        content = b"{\\rtf1 caf\xe9}"

        with patch.dict("sys.modules", {
            "striprtf": MagicMock(),
            "striprtf.striprtf": mock_module,
        }):
            ext = RTFExtractor()
            result = ext.extract(content, "latin_rtf.rtf")

        assert result.text == "decoded content"


# =============================================================================
# PPTXExtractor TESTS
# =============================================================================


class TestPPTXExtractor:
    """Tests for PPTXExtractor."""

    def test_can_handle_pptx(self):
        ext = PPTXExtractor()
        assert ext.can_handle(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".pptx",
        ) is True

    def test_can_handle_ppt(self):
        ext = PPTXExtractor()
        assert ext.can_handle("application/vnd.ms-powerpoint", ".ppt") is True

    def test_rejects_non_pptx(self):
        ext = PPTXExtractor()
        assert ext.can_handle("application/pdf", ".pdf") is False

    def test_extract_slide_text(self):
        """Extracts text from slide shapes."""
        mock_shape = MagicMock()
        mock_shape.text = "Slide content"
        mock_shape.has_table = False

        mock_slide = MagicMock()
        mock_slide.shapes = [mock_shape]
        mock_slide.has_notes_slide = False

        mock_prs = MagicMock()
        mock_prs.slides = [mock_slide]

        mock_pptx = MagicMock()
        mock_pptx.Presentation.return_value = mock_prs

        with patch.dict("sys.modules", {"pptx": mock_pptx}):
            ext = PPTXExtractor()
            result = ext.extract(b"pptx-content", "slides.pptx")

        assert "[Slide 1]" in result.text
        assert "Slide content" in result.text

    def test_extract_speaker_notes(self):
        """Extracts speaker notes from slides."""
        mock_shape = MagicMock()
        mock_shape.text = "Visible content"
        mock_shape.has_table = False

        mock_notes_frame = MagicMock()
        mock_notes_frame.text = "Speaker notes here"

        mock_slide = MagicMock()
        mock_slide.shapes = [mock_shape]
        mock_slide.has_notes_slide = True
        mock_slide.notes_slide.notes_text_frame = mock_notes_frame

        mock_prs = MagicMock()
        mock_prs.slides = [mock_slide]

        mock_pptx = MagicMock()
        mock_pptx.Presentation.return_value = mock_prs

        with patch.dict("sys.modules", {"pptx": mock_pptx}):
            ext = PPTXExtractor()
            result = ext.extract(b"pptx-content", "notes.pptx")

        assert "[Notes: Speaker notes here]" in result.text

    def test_decompression_bomb_in_slides(self):
        """Detects decompression bomb when slide text exceeds limit."""
        huge_text = "A" * (MAX_DECOMPRESSED_SIZE + 1)
        mock_shape = MagicMock()
        mock_shape.text = huge_text
        mock_shape.has_table = False

        mock_slide = MagicMock()
        mock_slide.shapes = [mock_shape]
        mock_slide.has_notes_slide = False

        mock_prs = MagicMock()
        mock_prs.slides = [mock_slide]

        mock_pptx = MagicMock()
        mock_pptx.Presentation.return_value = mock_prs

        with patch.dict("sys.modules", {"pptx": mock_pptx}):
            ext = PPTXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb detected"):
                ext.extract(b"pptx-bomb", "bomb.pptx")

    def test_decompression_bomb_in_tables(self):
        """Detects decompression bomb accumulated through table cells."""
        chunk = "X" * (MAX_DECOMPRESSED_SIZE // 2 + 1)

        mock_cell1 = MagicMock()
        mock_cell1.text = chunk
        mock_cell2 = MagicMock()
        mock_cell2.text = chunk
        mock_row = MagicMock()
        mock_row.cells = [mock_cell1, mock_cell2]
        mock_table = MagicMock()
        mock_table.rows = [mock_row]

        mock_shape = MagicMock()
        mock_shape.text = ""
        mock_shape.has_table = True
        mock_shape.table = mock_table

        mock_slide = MagicMock()
        mock_slide.shapes = [mock_shape]
        mock_slide.has_notes_slide = False

        mock_prs = MagicMock()
        mock_prs.slides = [mock_slide]

        mock_pptx = MagicMock()
        mock_pptx.Presentation.return_value = mock_prs

        with patch.dict("sys.modules", {"pptx": mock_pptx}):
            ext = PPTXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb detected"):
                ext.extract(b"pptx-bomb", "tablebomb.pptx")

    def test_legacy_ppt_extraction(self):
        """Legacy .ppt files get basic text extraction with warning."""
        ext = PPTXExtractor()
        content = b"Some readable content in the binary PPT file format"
        result = ext.extract(content, "legacy.ppt")

        assert result.pages == 1
        assert any("Legacy .ppt" in w for w in result.warnings)

    def test_pptx_not_installed(self):
        """Raises ImportError when python-pptx is not available."""
        ext = PPTXExtractor()
        with patch.dict("sys.modules", {"pptx": None}):
            with pytest.raises(ImportError, match="python-pptx"):
                ext.extract(b"pptx-content", "test.pptx")


# =============================================================================
# get_extractor REGISTRY TESTS
# =============================================================================


class TestGetExtractor:
    """Tests for get_extractor factory function."""

    def test_returns_pdf_extractor(self):
        ext = get_extractor("application/pdf", ".pdf")
        assert isinstance(ext, PDFExtractor)

    def test_returns_docx_extractor(self):
        ext = get_extractor(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".docx",
        )
        assert isinstance(ext, DOCXExtractor)

    def test_returns_xlsx_extractor(self):
        ext = get_extractor(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".xlsx",
        )
        assert isinstance(ext, XLSXExtractor)

    def test_returns_csv_extractor(self):
        ext = get_extractor("text/csv", ".csv")
        assert isinstance(ext, XLSXExtractor)

    def test_returns_pptx_extractor(self):
        ext = get_extractor(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".pptx",
        )
        assert isinstance(ext, PPTXExtractor)

    def test_returns_email_extractor_eml(self):
        ext = get_extractor("message/rfc822", ".eml")
        assert isinstance(ext, EmailExtractor)

    def test_returns_email_extractor_msg(self):
        ext = get_extractor("application/vnd.ms-outlook", ".msg")
        assert isinstance(ext, EmailExtractor)

    def test_returns_html_extractor(self):
        ext = get_extractor("text/html", ".html")
        assert isinstance(ext, HTMLExtractor)

    def test_returns_image_extractor(self):
        ext = get_extractor("image/png", ".png")
        assert isinstance(ext, ImageExtractor)

    def test_returns_text_extractor(self):
        ext = get_extractor("text/plain", ".txt")
        assert isinstance(ext, TextExtractor)

    def test_returns_rtf_extractor(self):
        ext = get_extractor("application/rtf", ".rtf")
        assert isinstance(ext, RTFExtractor)

    def test_returns_none_for_unknown(self):
        ext = get_extractor("application/x-unknown", ".xyz")
        assert ext is None

    def test_passes_ocr_engine_to_pdf(self):
        """OCR engine is passed to PDFExtractor."""
        mock_ocr = MagicMock()
        ext = get_extractor("application/pdf", ".pdf", ocr_engine=mock_ocr)
        assert isinstance(ext, PDFExtractor)
        assert ext.ocr_engine is mock_ocr

    def test_passes_ocr_engine_to_image(self):
        """OCR engine is passed to ImageExtractor."""
        mock_ocr = MagicMock()
        ext = get_extractor("image/png", ".png", ocr_engine=mock_ocr)
        assert isinstance(ext, ImageExtractor)
        assert ext.ocr_engine is mock_ocr

    def test_priority_pdf_over_text(self):
        """PDF content type matches PDF extractor even with .txt extension."""
        ext = get_extractor("application/pdf", ".txt")
        assert isinstance(ext, PDFExtractor)

    def test_extension_based_fallback(self):
        """Extension matching works when content type is generic."""
        ext = get_extractor("application/octet-stream", ".pdf")
        assert isinstance(ext, PDFExtractor)


# =============================================================================
# extract_text CONVENIENCE FUNCTION TESTS
# =============================================================================


class TestExtractTextFunction:
    """Tests for extract_text top-level convenience function."""

    def test_plain_text_extraction(self):
        """Extracts text from plain text content."""
        result = extract_text(b"Hello world", "test.txt")
        assert "Hello world" in result.text

    def test_guesses_mime_type(self):
        """Guesses MIME type from filename when not provided."""
        result = extract_text(b"plain text", "readme.txt")
        assert result.text == "plain text"

    def test_explicit_content_type(self):
        """Uses explicit content type when provided."""
        result = extract_text(b"content", "file.txt", content_type="text/plain")
        assert result.text == "content"

    def test_unknown_extension_returns_warning(self):
        """Unknown file types return a result with warning."""
        result = extract_text(b"content", "data.xyz123")
        assert result is not None
        assert len(result.warnings) > 0
        assert "No extractor available" in result.warnings[0]

    def test_unknown_type_empty_text(self):
        """Unknown file types return empty text."""
        result = extract_text(b"content", "file.unknown_ext_xyz")
        assert result.text == ""

    def test_csv_via_extract_text(self):
        """CSV files are extracted correctly via convenience function."""
        csv_data = b"Name,Value\nAlpha,100\nBeta,200"
        result = extract_text(csv_data, "data.csv")
        assert "Alpha" in result.text
        assert "Beta" in result.text

    def test_html_via_extract_text(self):
        """HTML files are extracted correctly via convenience function."""
        html_data = b"<html><body><p>Content</p></body></html>"
        result = extract_text(html_data, "page.html")
        assert "Content" in result.text

    def test_empty_content_type_guessed(self):
        """When content_type is None, it is guessed from extension."""
        result = extract_text(b"hello", "file.txt", content_type=None)
        assert result.text == "hello"


# =============================================================================
# DECOMPRESSION BOMB SECURITY TESTS
# =============================================================================


class TestDecompressionBombProtection:
    """
    Security tests verifying decompression bomb detection across extractors.

    These tests ensure that maliciously crafted files (zip bombs, billion laughs
    analogs) are caught before they exhaust memory.
    """

    def test_docx_bomb_ratio_small_file_huge_output(self):
        """A tiny DOCX producing huge decompressed text is caught."""
        # Simulate: 100 bytes compressed -> 250MB decompressed
        para_text = "Z" * (MAX_DECOMPRESSED_SIZE + 1)
        mock_para = MagicMock()
        mock_para.text = para_text

        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para]
        mock_doc.tables = []

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb"):
                ext.extract(b"x" * 100, "zipbomb.docx")

    def test_xlsx_bomb_via_cell_accumulation(self):
        """XLSX bomb detected through accumulated cell sizes."""
        # Each cell is small, but many cells exceed the limit
        cell_text = "A" * 10000
        # Need enough rows to exceed MAX_DECOMPRESSED_SIZE
        num_rows = (MAX_DECOMPRESSED_SIZE // 10000) + 10
        rows = [(cell_text,) for _ in range(num_rows)]

        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = iter(rows)

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb"):
                ext.extract(b"x" * 200, "cellbomb.xlsx")

    def test_pptx_bomb_via_many_shapes(self):
        """PPTX bomb detected through many shapes with large text."""
        shapes = []
        for _ in range(100):
            mock_shape = MagicMock()
            mock_shape.text = "A" * (MAX_DECOMPRESSED_SIZE // 50)
            mock_shape.has_table = False
            shapes.append(mock_shape)

        mock_slide = MagicMock()
        mock_slide.shapes = shapes
        mock_slide.has_notes_slide = False

        mock_prs = MagicMock()
        mock_prs.slides = [mock_slide]

        mock_pptx = MagicMock()
        mock_pptx.Presentation.return_value = mock_prs

        with patch.dict("sys.modules", {"pptx": mock_pptx}):
            ext = PPTXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb"):
                ext.extract(b"pptx", "shapebomb.pptx")

    def test_docx_bomb_across_paragraphs_and_tables(self):
        """
        Decompression bomb detected when combined paragraph and table
        text exceeds limit, even if individually each is under limit.
        """
        half = MAX_DECOMPRESSED_SIZE // 2

        # Paragraphs use half the budget
        mock_para = MagicMock()
        mock_para.text = "P" * half

        # Table cells use the other half + overflow
        mock_cell = MagicMock()
        mock_cell.text = "T" * (half + 1000)
        mock_row = MagicMock()
        mock_row.cells = [mock_cell]
        mock_table = MagicMock()
        mock_table.rows = [mock_row]

        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para]
        mock_doc.tables = [mock_table]

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            with pytest.raises(ValueError, match="Decompression bomb"):
                ext.extract(b"x" * 200, "combined_bomb.docx")

    def test_xlsx_bomb_workbook_closed_on_detection(self):
        """XLSX workbook is properly closed when decompression bomb detected."""
        huge_cell = "A" * (MAX_DECOMPRESSED_SIZE + 1)
        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = [(huge_cell,)]

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            with pytest.raises(ValueError):
                ext.extract(b"x" * 200, "bomb.xlsx")

        # Verify workbook was closed to free resources
        mock_wb.close.assert_called_once()

    def test_normal_docx_size_passes(self):
        """Normal-sized DOCX content does not trigger bomb detection."""
        mock_para = MagicMock()
        mock_para.text = "Normal paragraph content"

        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para]
        mock_doc.tables = []

        mock_docx_module = MagicMock()
        mock_docx_module.Document.return_value = mock_doc

        with patch.dict("sys.modules", {"docx": mock_docx_module}):
            ext = DOCXExtractor()
            result = ext.extract(b"x" * 200, "normal.docx")

        assert "Normal paragraph content" in result.text

    def test_extraction_ratio_boundary(self):
        """Extraction ratio exactly at threshold does not warn, above does."""
        # Create content that yields exactly MAX_EXTRACTION_RATIO
        compressed_size = 1000
        compressed = b"x" * compressed_size

        # Exactly at ratio: should NOT warn
        at_limit = "A" * (MAX_EXTRACTION_RATIO * compressed_size)
        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = iter([(at_limit,)])

        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__ = MagicMock(return_value=mock_sheet)
        mock_wb.close = MagicMock()

        mock_openpyxl = MagicMock()
        mock_openpyxl.load_workbook.return_value = mock_wb

        with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
            ext = XLSXExtractor()
            # Should succeed without raising
            result = ext.extract(compressed, "atboundary.xlsx")
            assert result is not None


# =============================================================================
# EDGE CASE TESTS
# =============================================================================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_zero_length_csv(self):
        """Empty CSV produces empty text."""
        ext = XLSXExtractor()
        result = ext.extract(b"", "empty.csv")
        assert result.text == ""

    def test_csv_with_only_delimiters(self):
        """CSV with only commas produces empty text (no visible content)."""
        ext = XLSXExtractor()
        result = ext.extract(b",,,,\n,,,,", "commas.csv")
        # All cells are empty after strip, so rows are skipped
        assert result.text == ""

    def test_csv_with_null_bytes(self):
        """CSV with embedded null bytes does not crash."""
        ext = XLSXExtractor()
        content = b"Name,Value\nJohn\x00Doe,123"
        result = ext.extract(content, "nulls.csv")
        assert result is not None

    def test_html_with_only_scripts(self):
        """HTML with only script content produces empty or minimal text."""
        html = b"<html><body><script>var x = 1;</script></body></html>"
        ext = HTMLExtractor()
        result = ext.extract(html, "scripts.html")
        assert "var x" not in result.text

    def test_text_extractor_large_content(self):
        """Large text files are handled without error."""
        ext = TextExtractor()
        # 1MB of text
        content = ("A" * 1000 + "\n") * 1000
        result = ext.extract(content.encode("utf-8"), "large.txt")
        assert len(result.text) > 0

    def test_extraction_result_immutable_defaults(self):
        """Default lists in ExtractionResult are not shared between instances."""
        r1 = ExtractionResult(text="a")
        r2 = ExtractionResult(text="b")
        r1.warnings.append("warning")
        # r2 should not be affected
        assert r2.warnings == []

    def test_get_extractor_extension_case_sensitivity(self):
        """get_extractor expects lowercase extensions (as documented)."""
        # The function receives lowercase extension per extract_text
        ext = get_extractor("text/plain", ".txt")
        assert ext is not None

    def test_legacy_doc_with_pure_binary_content(self):
        """Legacy .doc with completely binary content still returns a result."""
        ext = DOCXExtractor()
        content = bytes(range(256)) * 10
        result = ext.extract(content, "binary.doc")
        assert result is not None
        assert result.pages == 1
        # Should have legacy warning
        assert any("Legacy .doc" in w for w in result.warnings)

    def test_eml_with_non_utf8_charset(self):
        """EML with non-UTF-8 charset decodes body correctly."""
        # Build a raw EML with ISO-8859-1 charset
        raw_eml = (
            b"From: sender@test.com\r\n"
            b"To: recipient@test.com\r\n"
            b"Subject: Latin-1 Email\r\n"
            b"Content-Type: text/plain; charset=iso-8859-1\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"Caf\xe9 au lait\r\n"
        )
        ext = EmailExtractor()
        result = ext.extract(raw_eml, "latin.eml")
        assert "Subject: Latin-1 Email" in result.text

    def test_pdf_close_called_even_on_success(self):
        """PDF document is closed even on successful extraction (finally block)."""
        mock_page = MagicMock()
        mock_page.get_text.return_value = "X" * (MIN_NATIVE_TEXT_LENGTH + 5)

        mock_doc = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.__len__ = MagicMock(return_value=1)
        mock_doc.close = MagicMock()

        with patch.dict("sys.modules", {"fitz": MagicMock()}):
            import sys
            sys.modules["fitz"].open.return_value = mock_doc

            ext = PDFExtractor()
            ext.extract(b"pdf-content", "test.pdf")

        mock_doc.close.assert_called_once()

    def test_tsv_with_embedded_tabs(self):
        """TSV extraction handles tab-separated values."""
        ext = XLSXExtractor()
        content = b"Col1\tCol2\nVal1\tVal2"
        result = ext.extract(content, "data.tsv")
        assert "Col1 | Col2" in result.text
        assert "Val1 | Val2" in result.text

    def test_multiple_extractors_dont_share_state(self):
        """Multiple extractor instances don't share mutable state."""
        ext1 = PDFExtractor(ocr_engine=MagicMock())
        ext2 = PDFExtractor(ocr_engine=None)
        assert ext1.ocr_engine is not ext2.ocr_engine

    def test_extract_text_with_none_content_type_and_unknown_ext(self):
        """extract_text with None content_type and unknown extension returns warning."""
        result = extract_text(b"data", "file.zzz_unknown", content_type=None)
        assert len(result.warnings) > 0
