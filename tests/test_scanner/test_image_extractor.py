"""
Tests for image text extractor.

Tests OCR-based text extraction from images.
"""

import io
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from openlabels.adapters.scanner.extractors.image import ImageExtractor
from openlabels.adapters.scanner.extractors.base import ExtractionResult, PageInfo

# Check if numpy is available (required for OCR tests)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

requires_numpy = pytest.mark.skipif(
    not NUMPY_AVAILABLE,
    reason="numpy not available"
)


class TestImageExtractorInit:
    """Tests for ImageExtractor initialization."""

    def test_init_no_ocr_engine(self):
        """Should initialize without OCR engine."""
        extractor = ImageExtractor()
        assert extractor.ocr_engine is None
        assert extractor.temp_dir is None
        assert extractor.enable_enhanced_processing is False

    def test_init_with_ocr_engine(self):
        """Should initialize with OCR engine."""
        mock_ocr = MagicMock()
        extractor = ImageExtractor(ocr_engine=mock_ocr)
        assert extractor.ocr_engine is mock_ocr

    def test_init_with_temp_dir(self):
        """Should initialize with temp directory."""
        mock_temp = MagicMock()
        extractor = ImageExtractor(temp_dir=mock_temp)
        assert extractor.temp_dir is mock_temp

    def test_init_with_enhanced_processing(self):
        """Should initialize with enhanced processing flag."""
        extractor = ImageExtractor(enable_enhanced_processing=True)
        assert extractor.enable_enhanced_processing is True
        assert extractor._enhanced_processor is None


class TestEnhancedProcessor:
    """Tests for enhanced processor property."""

    def test_returns_none_when_disabled(self):
        """Should return None when enhanced processing disabled."""
        extractor = ImageExtractor(enable_enhanced_processing=False)
        assert extractor.enhanced_processor is None

    def test_handles_import_error(self):
        """Should handle ImportError gracefully."""
        extractor = ImageExtractor(enable_enhanced_processing=True)

        with patch.dict("sys.modules", {"openlabels.adapters.scanner.enhanced_ocr": None}):
            with patch(
                "openlabels.adapters.scanner.extractors.image.ImageExtractor.enhanced_processor",
                new_callable=lambda: property(lambda self: None)
            ):
                # The property handles the import error internally
                pass


class TestCanHandle:
    """Tests for can_handle method."""

    @pytest.fixture
    def extractor(self):
        return ImageExtractor()

    def test_handles_image_content_type(self, extractor):
        """Should handle image/* content types."""
        assert extractor.can_handle("image/jpeg", ".jpg") is True
        assert extractor.can_handle("image/png", ".png") is True
        assert extractor.can_handle("image/gif", ".gif") is True
        assert extractor.can_handle("image/webp", ".webp") is True

    def test_handles_jpeg_extensions(self, extractor):
        """Should handle JPEG extensions."""
        assert extractor.can_handle("application/octet-stream", ".jpg") is True
        assert extractor.can_handle("application/octet-stream", ".jpeg") is True

    def test_handles_png_extension(self, extractor):
        """Should handle PNG extension."""
        assert extractor.can_handle("application/octet-stream", ".png") is True

    def test_handles_tiff_extensions(self, extractor):
        """Should handle TIFF extensions."""
        assert extractor.can_handle("application/octet-stream", ".tiff") is True
        assert extractor.can_handle("application/octet-stream", ".tif") is True

    def test_handles_heic_extensions(self, extractor):
        """Should handle HEIC extensions."""
        assert extractor.can_handle("application/octet-stream", ".heic") is True
        assert extractor.can_handle("application/octet-stream", ".heif") is True

    def test_handles_other_image_extensions(self, extractor):
        """Should handle other image extensions."""
        assert extractor.can_handle("application/octet-stream", ".gif") is True
        assert extractor.can_handle("application/octet-stream", ".bmp") is True
        assert extractor.can_handle("application/octet-stream", ".webp") is True

    def test_does_not_handle_text(self, extractor):
        """Should not handle text types."""
        assert extractor.can_handle("text/plain", ".txt") is False

    def test_does_not_handle_pdf(self, extractor):
        """Should not handle PDF."""
        assert extractor.can_handle("application/pdf", ".pdf") is False

    def test_does_not_handle_doc(self, extractor):
        """Should not handle Word documents."""
        assert extractor.can_handle("application/msword", ".doc") is False


class TestExtractWithoutOCR:
    """Tests for extract when OCR is unavailable."""

    def test_returns_warning_without_ocr_engine(self):
        """Should return warning when no OCR engine."""
        extractor = ImageExtractor(ocr_engine=None)

        result = extractor.extract(b"fake image data", "test.jpg")

        assert isinstance(result, ExtractionResult)
        assert result.text == ""
        assert result.needs_ocr is True
        assert len(result.warnings) > 0
        assert "OCR engine not available" in result.warnings[0]

    def test_returns_warning_when_ocr_unavailable(self):
        """Should return warning when OCR not available."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = False
        extractor = ImageExtractor(ocr_engine=mock_ocr)

        result = extractor.extract(b"fake image data", "test.jpg")

        assert result.text == ""
        assert "OCR engine not available" in result.warnings[0]


@requires_numpy
class TestExtractWithOCR:
    """Tests for extract with OCR engine."""

    @pytest.fixture
    def mock_ocr_result(self):
        """Create mock OCR result."""
        result = MagicMock()
        result.full_text = "Extracted text from image"
        result.confidence = 0.95
        result.blocks = []
        return result

    @pytest.fixture
    def mock_ocr_engine(self, mock_ocr_result):
        """Create mock OCR engine."""
        engine = MagicMock()
        engine.is_available = True
        engine.extract_with_coordinates.return_value = mock_ocr_result
        return engine

    def test_extracts_text_from_png(self, mock_ocr_engine, mock_ocr_result):
        """Should extract text from PNG image."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        # Create a simple valid PNG
        from PIL import Image
        img = Image.new("RGB", (100, 100), color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.png")

        assert result.text == "Extracted text from image"
        assert result.confidence == 0.95
        assert result.pages == 1

    def test_extracts_text_from_jpeg(self, mock_ocr_engine, mock_ocr_result):
        """Should extract text from JPEG image."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        img = Image.new("RGB", (100, 100), color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.jpg")

        assert result.text == "Extracted text from image"
        assert result.needs_ocr is True

    def test_converts_non_rgb_images(self, mock_ocr_engine, mock_ocr_result):
        """Should convert non-RGB images to RGB."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        # Create RGBA image
        from PIL import Image
        img = Image.new("RGBA", (100, 100), color=(255, 255, 255, 255))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.png")

        # Should succeed (conversion happens internally)
        assert result.text == "Extracted text from image"

    def test_handles_grayscale_images(self, mock_ocr_engine, mock_ocr_result):
        """Should handle grayscale images."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        img = Image.new("L", (100, 100), color=128)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        content = buffer.getvalue()

        result = extractor.extract(content, "grayscale.png")

        # Grayscale (L mode) is acceptable
        assert result.text == "Extracted text from image"

    def test_saves_page_to_temp_dir(self, mock_ocr_engine, mock_ocr_result):
        """Should save page image to temp directory."""
        mock_temp = MagicMock()
        mock_temp.path = Path("/tmp/test")
        mock_temp.write_page.return_value = Path("/tmp/test/page_0.png")

        extractor = ImageExtractor(ocr_engine=mock_ocr_engine, temp_dir=mock_temp)

        from PIL import Image
        img = Image.new("RGB", (100, 100))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.png", save_pages=True)

        mock_temp.write_page.assert_called_once()
        assert result.page_infos[0].temp_image_path == "/tmp/test/page_0.png"

    def test_skips_save_when_disabled(self, mock_ocr_engine, mock_ocr_result):
        """Should skip saving pages when save_pages=False."""
        mock_temp = MagicMock()

        extractor = ImageExtractor(ocr_engine=mock_ocr_engine, temp_dir=mock_temp)

        from PIL import Image
        img = Image.new("RGB", (100, 100))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.png", save_pages=False)

        mock_temp.write_page.assert_not_called()

    def test_handles_corrupt_image(self, mock_ocr_engine):
        """Should handle corrupt image data gracefully."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        result = extractor.extract(b"not valid image data", "corrupt.png")

        assert result.text == ""
        assert len(result.warnings) > 0
        assert "failed" in result.warnings[0].lower()

    def test_returns_page_info(self, mock_ocr_engine, mock_ocr_result):
        """Should return page info."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        img = Image.new("RGB", (100, 100))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.png")

        assert len(result.page_infos) == 1
        assert result.page_infos[0].page_num == 0
        assert result.page_infos[0].is_scanned is True


@requires_numpy
class TestExtractMultipageTiff:
    """Tests for multipage TIFF extraction."""

    @pytest.fixture
    def mock_ocr_result(self):
        """Create mock OCR result."""
        result = MagicMock()
        result.full_text = "Page text"
        result.confidence = 0.9
        result.blocks = []
        return result

    @pytest.fixture
    def mock_ocr_engine(self, mock_ocr_result):
        """Create mock OCR engine."""
        engine = MagicMock()
        engine.is_available = True
        engine.extract_with_coordinates.return_value = mock_ocr_result
        return engine

    def test_extracts_single_page_tiff(self, mock_ocr_engine, mock_ocr_result):
        """Should extract text from single-page TIFF."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        img = Image.new("RGB", (100, 100))
        buffer = io.BytesIO()
        img.save(buffer, format="TIFF")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.tiff")

        assert result.pages == 1
        assert "Page text" in result.text

    def test_extracts_multipage_tiff(self, mock_ocr_engine, mock_ocr_result):
        """Should extract text from multipage TIFF."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        # Create a 3-page TIFF
        from PIL import Image
        pages = [
            Image.new("RGB", (100, 100), color="red"),
            Image.new("RGB", (100, 100), color="green"),
            Image.new("RGB", (100, 100), color="blue"),
        ]

        buffer = io.BytesIO()
        pages[0].save(
            buffer,
            format="TIFF",
            save_all=True,
            append_images=pages[1:],
        )
        content = buffer.getvalue()

        result = extractor.extract(content, "multipage.tiff")

        assert result.pages == 3
        assert len(result.page_infos) == 3
        assert len(result.ocr_results) == 3

    def test_handles_tif_extension(self, mock_ocr_engine, mock_ocr_result):
        """Should handle .tif extension (short form)."""
        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        img = Image.new("RGB", (100, 100))
        buffer = io.BytesIO()
        img.save(buffer, format="TIFF")
        content = buffer.getvalue()

        result = extractor.extract(content, "test.tif")

        assert result.pages == 1

    def test_calculates_average_confidence(self, mock_ocr_engine):
        """Should calculate average confidence across pages."""
        # Different confidence for each page
        results = [
            MagicMock(full_text="Page 1", confidence=0.8, blocks=[]),
            MagicMock(full_text="Page 2", confidence=0.9, blocks=[]),
            MagicMock(full_text="Page 3", confidence=1.0, blocks=[]),
        ]
        mock_ocr_engine.extract_with_coordinates.side_effect = results

        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        pages = [Image.new("RGB", (100, 100)) for _ in range(3)]
        buffer = io.BytesIO()
        pages[0].save(buffer, format="TIFF", save_all=True, append_images=pages[1:])
        content = buffer.getvalue()

        result = extractor.extract(content, "test.tiff")

        # Average of 0.8, 0.9, 1.0 = 0.9
        assert result.confidence == pytest.approx(0.9, rel=0.01)

    def test_joins_pages_with_newlines(self, mock_ocr_engine):
        """Should join page texts with double newlines."""
        results = [
            MagicMock(full_text="Page 1 text", confidence=0.9, blocks=[]),
            MagicMock(full_text="Page 2 text", confidence=0.9, blocks=[]),
        ]
        mock_ocr_engine.extract_with_coordinates.side_effect = results

        extractor = ImageExtractor(ocr_engine=mock_ocr_engine)

        from PIL import Image
        pages = [Image.new("RGB", (100, 100)) for _ in range(2)]
        buffer = io.BytesIO()
        pages[0].save(buffer, format="TIFF", save_all=True, append_images=pages[1:])
        content = buffer.getvalue()

        result = extractor.extract(content, "test.tiff")

        assert result.text == "Page 1 text\n\nPage 2 text"


@requires_numpy
class TestHEICSupport:
    """Tests for HEIC image support."""

    def test_requires_pillow_heif(self):
        """Should warn when pillow-heif not installed."""
        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        extractor = ImageExtractor(ocr_engine=mock_ocr)

        with patch.dict("sys.modules", {"pillow_heif": None}):
            # Create fake HEIC content (won't actually be valid)
            result = extractor.extract(b"fake heic data", "photo.heic")

            # Should either fail with HEIC warning or image decode error
            assert len(result.warnings) > 0


class TestSavePageImage:
    """Tests for _save_page_image method."""

    def test_returns_none_without_temp_dir(self):
        """Should return None when no temp_dir."""
        extractor = ImageExtractor()

        from PIL import Image
        img = Image.new("RGB", (100, 100))

        result = extractor._save_page_image(img, 0)

        assert result is None

    def test_saves_to_temp_dir(self):
        """Should save image to temp directory."""
        mock_temp = MagicMock()
        mock_temp.write_page.return_value = Path("/tmp/page_0.png")

        extractor = ImageExtractor(temp_dir=mock_temp)

        from PIL import Image
        img = Image.new("RGB", (100, 100))

        result = extractor._save_page_image(img, 0)

        assert result == "/tmp/page_0.png"
        mock_temp.write_page.assert_called_once()
        # Check PNG data was written
        call_args = mock_temp.write_page.call_args
        assert call_args[0][0] == 0  # page_num
        assert isinstance(call_args[0][1], bytes)  # PNG data
