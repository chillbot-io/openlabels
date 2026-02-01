"""Tests for metadata stripping module.

Tests for file type detection, metadata field classes, and metadata stripping.
"""

import io
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from scrubiq.image_protection.metadata_stripper import (
    FileType,
    MetadataField,
    MetadataStrippingResult,
    detect_file_type,
    MetadataStripper,
    SENSITIVE_EXIF_TAGS,
    SENSITIVE_XMP_FIELDS,
    SENSITIVE_OFFICE_FIELDS,
)


# =============================================================================
# FILETYPE ENUM TESTS
# =============================================================================

class TestFileType:
    """Tests for FileType enum."""

    def test_all_types_defined(self):
        """All expected file types are defined."""
        assert FileType.JPEG.value == "jpeg"
        assert FileType.PNG.value == "png"
        assert FileType.TIFF.value == "tiff"
        assert FileType.WEBP.value == "webp"
        assert FileType.GIF.value == "gif"
        assert FileType.BMP.value == "bmp"
        assert FileType.PDF.value == "pdf"
        assert FileType.DOCX.value == "docx"
        assert FileType.XLSX.value == "xlsx"
        assert FileType.PPTX.value == "pptx"
        assert FileType.DICOM.value == "dicom"
        assert FileType.UNKNOWN.value == "unknown"


# =============================================================================
# METADATAFIELD TESTS
# =============================================================================

class TestMetadataField:
    """Tests for MetadataField dataclass."""

    def test_create_field(self):
        """MetadataField stores all properties."""
        field = MetadataField(
            category="EXIF",
            name="GPSLatitude",
            is_sensitive=True,
        )

        assert field.category == "EXIF"
        assert field.name == "GPSLatitude"
        assert field.is_sensitive is True

    def test_str_representation(self):
        """MetadataField has string representation."""
        field = MetadataField("XMP", "creator", True)

        assert str(field) == "XMP:creator"

    def test_non_sensitive_field(self):
        """MetadataField can be non-sensitive."""
        field = MetadataField("EXIF", "ColorSpace", False)

        assert field.is_sensitive is False


# =============================================================================
# METADATASTRIPPINGRESULT TESTS
# =============================================================================

class TestMetadataStrippingResult:
    """Tests for MetadataStrippingResult dataclass."""

    def test_create_result(self):
        """MetadataStrippingResult stores all properties."""
        result = MetadataStrippingResult(
            original_hash="abc123",
            stripped_hash="def456",
            file_type=FileType.JPEG,
            fields_removed=[],
            processing_time_ms=10.5,
        )

        assert result.original_hash == "abc123"
        assert result.stripped_hash == "def456"
        assert result.file_type == FileType.JPEG
        assert result.processing_time_ms == 10.5

    def test_default_flags_are_false(self):
        """Default flags are False."""
        result = MetadataStrippingResult(
            original_hash="a",
            stripped_hash="b",
            file_type=FileType.PNG,
            fields_removed=[],
            processing_time_ms=1.0,
        )

        assert result.had_thumbnail is False
        assert result.had_gps is False
        assert result.had_device_id is False
        assert result.had_author is False
        assert result.had_timestamps is False

    def test_total_fields_removed_property(self):
        """total_fields_removed counts fields."""
        result = MetadataStrippingResult(
            original_hash="a",
            stripped_hash="b",
            file_type=FileType.JPEG,
            fields_removed=[
                MetadataField("EXIF", "Make", True),
                MetadataField("EXIF", "Model", True),
                MetadataField("EXIF", "DateTime", True),
            ],
            processing_time_ms=1.0,
        )

        assert result.total_fields_removed == 3

    def test_sensitive_fields_removed_property(self):
        """sensitive_fields_removed counts only sensitive fields."""
        result = MetadataStrippingResult(
            original_hash="a",
            stripped_hash="b",
            file_type=FileType.JPEG,
            fields_removed=[
                MetadataField("EXIF", "GPSLatitude", True),
                MetadataField("EXIF", "ColorSpace", False),
                MetadataField("EXIF", "Author", True),
            ],
            processing_time_ms=1.0,
        )

        assert result.sensitive_fields_removed == 2

    def test_to_audit_dict(self):
        """to_audit_dict returns proper dict."""
        result = MetadataStrippingResult(
            original_hash="abc123",
            stripped_hash="def456",
            file_type=FileType.PNG,
            fields_removed=[MetadataField("tEXt", "Author", True)],
            processing_time_ms=5.123,
            had_gps=True,
            had_author=True,
            warnings=["Test warning"],
        )

        audit_dict = result.to_audit_dict()

        assert audit_dict["original_hash"] == "abc123"
        assert audit_dict["stripped_hash"] == "def456"
        assert audit_dict["file_type"] == "png"
        assert audit_dict["total_fields_removed"] == 1
        assert audit_dict["sensitive_fields_removed"] == 1
        assert audit_dict["had_gps"] is True
        assert audit_dict["had_author"] is True
        assert audit_dict["processing_time_ms"] == 5.1  # rounded
        assert audit_dict["warnings"] == ["Test warning"]


# =============================================================================
# DETECT_FILE_TYPE TESTS
# =============================================================================

class TestDetectFileType:
    """Tests for detect_file_type function."""

    def test_detect_jpeg(self):
        """Detects JPEG from magic bytes."""
        # JPEG starts with FF D8 FF
        data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

        assert detect_file_type(data) == FileType.JPEG

    def test_detect_png(self):
        """Detects PNG from magic bytes."""
        # PNG signature: 89 50 4E 47 0D 0A 1A 0A
        data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100

        assert detect_file_type(data) == FileType.PNG

    def test_detect_tiff_little_endian(self):
        """Detects TIFF (little-endian) from magic bytes."""
        data = b'II*\x00' + b'\x00' * 100

        assert detect_file_type(data) == FileType.TIFF

    def test_detect_tiff_big_endian(self):
        """Detects TIFF (big-endian) from magic bytes."""
        data = b'MM\x00*' + b'\x00' * 100

        assert detect_file_type(data) == FileType.TIFF

    def test_detect_webp(self):
        """Detects WebP from magic bytes."""
        # RIFF....WEBP
        data = b'RIFF' + b'\x00\x00\x00\x00' + b'WEBP' + b'\x00' * 100

        assert detect_file_type(data) == FileType.WEBP

    def test_detect_gif87a(self):
        """Detects GIF87a from magic bytes."""
        data = b'GIF87a' + b'\x00' * 100

        assert detect_file_type(data) == FileType.GIF

    def test_detect_gif89a(self):
        """Detects GIF89a from magic bytes."""
        data = b'GIF89a' + b'\x00' * 100

        assert detect_file_type(data) == FileType.GIF

    def test_detect_bmp(self):
        """Detects BMP from magic bytes."""
        data = b'BM' + b'\x00' * 100

        assert detect_file_type(data) == FileType.BMP

    def test_detect_pdf(self):
        """Detects PDF from magic bytes."""
        data = b'%PDF-1.4\n' + b'\x00' * 100

        assert detect_file_type(data) == FileType.PDF

    def test_detect_dicom(self):
        """Detects DICOM from magic bytes."""
        # DICM at offset 128
        data = b'\x00' * 128 + b'DICM' + b'\x00' * 100

        assert detect_file_type(data) == FileType.DICOM

    def test_detect_docx(self):
        """Detects DOCX from ZIP contents."""
        # Create a minimal DOCX (ZIP with word/ folder)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr('word/document.xml', '<document/>')
        data = buffer.getvalue()

        assert detect_file_type(data) == FileType.DOCX

    def test_detect_xlsx(self):
        """Detects XLSX from ZIP contents."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr('xl/workbook.xml', '<workbook/>')
        data = buffer.getvalue()

        assert detect_file_type(data) == FileType.XLSX

    def test_detect_pptx(self):
        """Detects PPTX from ZIP contents."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr('ppt/presentation.xml', '<presentation/>')
        data = buffer.getvalue()

        assert detect_file_type(data) == FileType.PPTX

    def test_unknown_file_type(self):
        """Returns UNKNOWN for unrecognized files."""
        data = b'random data that is not a known format' * 10

        assert detect_file_type(data) == FileType.UNKNOWN

    def test_too_short_data(self):
        """Returns UNKNOWN for data shorter than 12 bytes."""
        data = b'short'

        assert detect_file_type(data) == FileType.UNKNOWN

    def test_empty_data(self):
        """Returns UNKNOWN for empty data."""
        assert detect_file_type(b'') == FileType.UNKNOWN


# =============================================================================
# SENSITIVE FIELD CONSTANTS TESTS
# =============================================================================

class TestSensitiveFieldConstants:
    """Tests for sensitive field constant sets."""

    def test_sensitive_exif_tags_includes_gps(self):
        """SENSITIVE_EXIF_TAGS includes GPS tags."""
        assert "GPSInfo" in SENSITIVE_EXIF_TAGS
        assert "GPSLatitude" in SENSITIVE_EXIF_TAGS
        assert "GPSLongitude" in SENSITIVE_EXIF_TAGS

    def test_sensitive_exif_tags_includes_device_ids(self):
        """SENSITIVE_EXIF_TAGS includes device identifiers."""
        assert "Make" in SENSITIVE_EXIF_TAGS
        assert "Model" in SENSITIVE_EXIF_TAGS
        assert "BodySerialNumber" in SENSITIVE_EXIF_TAGS
        assert "SerialNumber" in SENSITIVE_EXIF_TAGS

    def test_sensitive_exif_tags_includes_author(self):
        """SENSITIVE_EXIF_TAGS includes author fields."""
        assert "Artist" in SENSITIVE_EXIF_TAGS
        assert "Copyright" in SENSITIVE_EXIF_TAGS
        assert "CameraOwnerName" in SENSITIVE_EXIF_TAGS

    def test_sensitive_exif_tags_includes_thumbnail(self):
        """SENSITIVE_EXIF_TAGS includes thumbnail tags."""
        assert "ThumbnailImage" in SENSITIVE_EXIF_TAGS
        assert "JPEGThumbnail" in SENSITIVE_EXIF_TAGS

    def test_sensitive_xmp_fields(self):
        """SENSITIVE_XMP_FIELDS includes expected fields."""
        assert "creator" in SENSITIVE_XMP_FIELDS
        assert "author" in SENSITIVE_XMP_FIELDS
        assert "gps" in SENSITIVE_XMP_FIELDS
        assert "location" in SENSITIVE_XMP_FIELDS

    def test_sensitive_office_fields(self):
        """SENSITIVE_OFFICE_FIELDS includes expected fields."""
        assert "creator" in SENSITIVE_OFFICE_FIELDS
        assert "lastmodifiedby" in SENSITIVE_OFFICE_FIELDS
        assert "company" in SENSITIVE_OFFICE_FIELDS
        assert "author" in SENSITIVE_OFFICE_FIELDS


# =============================================================================
# METADATASTRIPPER INIT TESTS
# =============================================================================

class TestMetadataStripperInit:
    """Tests for MetadataStripper initialization."""

    def test_default_init(self):
        """Default initialization doesn't preserve color profiles."""
        stripper = MetadataStripper()

        assert stripper.preserve_color_profile is False

    def test_preserve_color_profile(self):
        """Can initialize with color profile preservation."""
        stripper = MetadataStripper(preserve_color_profile=True)

        assert stripper.preserve_color_profile is True


# =============================================================================
# METADATASTRIPPER STRIP TESTS
# =============================================================================

class TestMetadataStripperStrip:
    """Tests for MetadataStripper.strip method."""

    def test_strip_returns_tuple(self):
        """strip returns (bytes, result) tuple."""
        stripper = MetadataStripper()

        # Minimal valid PNG
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # Signature
            b'\x00\x00\x00\rIHDR'  # IHDR chunk
            b'\x00\x00\x00\x01\x00\x00\x00\x01'  # 1x1
            b'\x08\x02'  # 8-bit RGB
            b'\x00\x00\x00'  # compression, filter, interlace
            b'\x90wS\xde'  # CRC
            b'\x00\x00\x00\x00IEND\xaeB`\x82'  # IEND
        )

        result = stripper.strip(png_data, "test.png")

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bytes)
        assert isinstance(result[1], MetadataStrippingResult)

    def test_strip_unknown_type_returns_original(self):
        """Unknown file types return original data with warning."""
        stripper = MetadataStripper()
        data = b'random unknown data' * 100

        stripped, result = stripper.strip(data, "unknown.bin")

        assert stripped == data
        assert result.file_type == FileType.UNKNOWN
        assert len(result.warnings) > 0
        assert "SECURITY WARNING" in result.warnings[0]

    def test_strip_dicom_returns_with_warning(self):
        """DICOM files return with warning about specialized handling."""
        stripper = MetadataStripper()
        # DICOM magic: DICM at offset 128
        data = b'\x00' * 128 + b'DICM' + b'\x00' * 100

        stripped, result = stripper.strip(data, "image.dcm")

        assert stripped == data
        assert result.file_type == FileType.DICOM
        assert len(result.warnings) > 0
        assert "DICOM" in result.warnings[0]

    def test_strip_calculates_hashes(self):
        """strip calculates original and stripped hashes."""
        stripper = MetadataStripper()
        data = b'random data' * 100

        _, result = stripper.strip(data)

        assert result.original_hash is not None
        assert result.stripped_hash is not None
        assert len(result.original_hash) == 16  # First 16 chars of sha256
        assert len(result.stripped_hash) == 16

    def test_strip_records_processing_time(self):
        """strip records processing time."""
        stripper = MetadataStripper()
        data = b'random data' * 100

        _, result = stripper.strip(data)

        assert result.processing_time_ms >= 0

    @patch('scrubiq.image_protection.metadata_stripper.MetadataStripper._strip_jpeg')
    def test_strip_routes_jpeg(self, mock_strip_jpeg):
        """strip routes JPEG to _strip_jpeg handler."""
        mock_strip_jpeg.return_value = (b'stripped', [])
        stripper = MetadataStripper()
        jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

        stripper.strip(jpeg_data, "test.jpg")

        mock_strip_jpeg.assert_called_once_with(jpeg_data)

    @patch('scrubiq.image_protection.metadata_stripper.MetadataStripper._strip_png')
    def test_strip_routes_png(self, mock_strip_png):
        """strip routes PNG to _strip_png handler."""
        mock_strip_png.return_value = (b'stripped', [])
        stripper = MetadataStripper()
        png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100

        stripper.strip(png_data, "test.png")

        mock_strip_png.assert_called_once_with(png_data)

    @patch('scrubiq.image_protection.metadata_stripper.MetadataStripper._strip_pdf')
    def test_strip_routes_pdf(self, mock_strip_pdf):
        """strip routes PDF to _strip_pdf handler."""
        mock_strip_pdf.return_value = (b'stripped', [])
        stripper = MetadataStripper()
        pdf_data = b'%PDF-1.4\n' + b'\x00' * 100

        stripper.strip(pdf_data, "test.pdf")

        mock_strip_pdf.assert_called_once_with(pdf_data)


# =============================================================================
# RESULT FLAG DETECTION TESTS
# =============================================================================

class TestResultFlagDetection:
    """Tests for detecting sensitive field flags in results."""

    def test_detects_thumbnail_flag(self):
        """Result correctly sets had_thumbnail flag."""
        stripper = MetadataStripper()

        # Mock strip to return fields with thumbnail
        with patch.object(stripper, '_strip_jpeg') as mock:
            mock.return_value = (b'stripped', [
                MetadataField("EXIF", "ThumbnailImage", True),
            ])
            jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

            _, result = stripper.strip(jpeg_data)

            assert result.had_thumbnail is True

    def test_detects_gps_flag(self):
        """Result correctly sets had_gps flag."""
        stripper = MetadataStripper()

        with patch.object(stripper, '_strip_jpeg') as mock:
            mock.return_value = (b'stripped', [
                MetadataField("EXIF", "GPSLatitude", True),
            ])
            jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

            _, result = stripper.strip(jpeg_data)

            assert result.had_gps is True

    def test_detects_device_id_flag(self):
        """Result correctly sets had_device_id flag."""
        stripper = MetadataStripper()

        with patch.object(stripper, '_strip_jpeg') as mock:
            mock.return_value = (b'stripped', [
                MetadataField("EXIF", "Make", True),
                MetadataField("EXIF", "Model", True),
            ])
            jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

            _, result = stripper.strip(jpeg_data)

            assert result.had_device_id is True

    def test_detects_author_flag(self):
        """Result correctly sets had_author flag."""
        stripper = MetadataStripper()

        with patch.object(stripper, '_strip_jpeg') as mock:
            mock.return_value = (b'stripped', [
                MetadataField("EXIF", "Artist", True),
            ])
            jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

            _, result = stripper.strip(jpeg_data)

            assert result.had_author is True

    def test_detects_timestamps_flag(self):
        """Result correctly sets had_timestamps flag."""
        stripper = MetadataStripper()

        with patch.object(stripper, '_strip_jpeg') as mock:
            mock.return_value = (b'stripped', [
                MetadataField("EXIF", "DateTime", True),
            ])
            jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100

            _, result = stripper.strip(jpeg_data)

            assert result.had_timestamps is True


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_filename(self):
        """Handles empty filename."""
        stripper = MetadataStripper()
        data = b'random' * 100

        # Should not raise
        _, result = stripper.strip(data, "")

        assert result is not None

    def test_no_filename(self):
        """Handles no filename provided."""
        stripper = MetadataStripper()
        data = b'random' * 100

        # Should not raise
        _, result = stripper.strip(data)

        assert result is not None

    def test_warnings_list_exists(self):
        """Result always has warnings list."""
        stripper = MetadataStripper()
        # Valid PNG to not trigger warnings
        png_data = (
            b'\x89PNG\r\n\x1a\n'
            b'\x00\x00\x00\rIHDR'
            b'\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00'
            b'\x90wS\xde'
            b'\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        _, result = stripper.strip(png_data)

        assert isinstance(result.warnings, list)


# =============================================================================
# ZIP-BASED OFFICE DETECTION TESTS
# =============================================================================

class TestZipBasedOfficeDetection:
    """Tests for ZIP-based Office file detection edge cases."""

    def test_invalid_zip_returns_unknown(self):
        """Invalid ZIP with PK header returns UNKNOWN."""
        # PK header but invalid ZIP content
        data = b'PK\x03\x04' + b'\x00' * 100

        assert detect_file_type(data) == FileType.UNKNOWN

    def test_empty_zip_returns_unknown(self):
        """Empty ZIP without Office folders returns UNKNOWN."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr('random.txt', 'content')
        data = buffer.getvalue()

        assert detect_file_type(data) == FileType.UNKNOWN
