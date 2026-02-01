"""Comprehensive tests for files module to improve coverage to 80%+.

Tests for validators.py, temp_storage.py, and other file processing utilities.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# VALIDATORS TESTS
# =============================================================================

class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_empty_filename(self):
        """Empty filename returns 'unknown'."""
        from scrubiq.files.validators import sanitize_filename

        assert sanitize_filename("") == "unknown"
        assert sanitize_filename(None) == "unknown"

    def test_removes_path_components(self):
        """Path components are removed."""
        from scrubiq.files.validators import sanitize_filename

        assert sanitize_filename("/etc/passwd") == "passwd"
        assert sanitize_filename("../../../etc/passwd") == "passwd"
        assert sanitize_filename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"

    def test_removes_null_bytes(self):
        """Null bytes are removed."""
        from scrubiq.files.validators import sanitize_filename

        assert "file\x00.txt" != sanitize_filename("file\x00.txt")
        assert "\x00" not in sanitize_filename("file\x00name.txt")

    def test_removes_control_characters(self):
        """Control characters are replaced."""
        from scrubiq.files.validators import sanitize_filename

        result = sanitize_filename("file\x1fname.txt")
        assert "\x1f" not in result

    def test_removes_dangerous_characters(self):
        """Dangerous characters are replaced."""
        from scrubiq.files.validators import sanitize_filename

        result = sanitize_filename("file<script>.txt")
        assert "<" not in result
        assert ">" not in result

        result = sanitize_filename("file|cmd.txt")
        assert "|" not in result

    def test_collapses_multiple_underscores(self):
        """Multiple underscores are collapsed."""
        from scrubiq.files.validators import sanitize_filename

        result = sanitize_filename("file___name.txt")
        assert "___" not in result

    def test_collapses_multiple_dots(self):
        """Multiple dots are collapsed."""
        from scrubiq.files.validators import sanitize_filename

        result = sanitize_filename("file...txt")
        assert "..." not in result

    def test_strips_leading_trailing(self):
        """Leading/trailing dots and underscores are stripped."""
        from scrubiq.files.validators import sanitize_filename

        result = sanitize_filename("...file.txt...")
        assert not result.startswith(".")
        assert not result.endswith(".")

    def test_length_limit(self):
        """Very long filenames are truncated."""
        from scrubiq.files.validators import sanitize_filename
        from scrubiq.constants import MAX_FILENAME_LENGTH

        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)

        assert len(result) <= MAX_FILENAME_LENGTH
        assert result.endswith(".txt")

    def test_preserves_valid_filenames(self):
        """Valid filenames are preserved."""
        from scrubiq.files.validators import sanitize_filename

        assert sanitize_filename("document.pdf") == "document.pdf"
        assert sanitize_filename("my_file_2024.txt") == "my_file_2024.txt"


class TestMagicByteDetection:
    """Tests for magic byte detection."""

    def test_detect_pdf(self):
        """PDF files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        pdf_content = b"%PDF-1.4\n" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(pdf_content) == "application/pdf"

    def test_detect_jpeg(self):
        """JPEG files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        jpeg_content = b"\xFF\xD8\xFF\xE0" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(jpeg_content) == "image/jpeg"

    def test_detect_png(self):
        """PNG files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        png_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(png_content) == "image/png"

    def test_detect_gif87a(self):
        """GIF87a files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        gif_content = b"GIF87a" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(gif_content) == "image/gif"

    def test_detect_gif89a(self):
        """GIF89a files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        gif_content = b"GIF89a" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(gif_content) == "image/gif"

    def test_detect_tiff_little_endian(self):
        """Little-endian TIFF files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        tiff_content = b"II\x2A\x00" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(tiff_content) == "image/tiff"

    def test_detect_tiff_big_endian(self):
        """Big-endian TIFF files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        tiff_content = b"MM\x00\x2A" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(tiff_content) == "image/tiff"

    def test_detect_bmp(self):
        """BMP files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        bmp_content = b"BM" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(bmp_content) == "image/bmp"

    def test_detect_docx(self):
        """DOCX (ZIP) files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        docx_content = b"PK\x03\x04" + b"\x00" * 100
        result = detect_mime_from_magic_bytes(docx_content)
        # Could be docx or xlsx since both are ZIP
        assert result in [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ]

    def test_detect_ole(self):
        """OLE (DOC/XLS) files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        ole_content = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 100
        result = detect_mime_from_magic_bytes(ole_content)
        assert result in ["application/msword", "application/vnd.ms-excel"]

    def test_detect_rtf(self):
        """RTF files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        rtf_content = b"{\\rtf1\\ansi" + b"\x00" * 100
        assert detect_mime_from_magic_bytes(rtf_content) == "application/rtf"

    def test_detect_text(self):
        """Text files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        text_content = b"Hello, this is plain text content."
        assert detect_mime_from_magic_bytes(text_content) == "text/plain"

    def test_detect_empty_returns_none(self):
        """Empty content returns None."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        assert detect_mime_from_magic_bytes(b"") is None

    def test_detect_unknown_returns_none(self):
        """Unknown binary returns None."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        # Binary content with null bytes that isn't any known type
        binary_content = b"\x00\x01\x02\x03\x04\x05" * 20
        assert detect_mime_from_magic_bytes(binary_content) is None


class TestValidateMagicBytes:
    """Tests for validate_magic_bytes function."""

    def test_validate_pdf_content(self):
        """PDF content validates correctly."""
        from scrubiq.files.validators import validate_magic_bytes

        pdf_content = b"%PDF-1.4\n" + b"x" * 100
        assert validate_magic_bytes("application/pdf", file_content=pdf_content) is True

    def test_validate_jpeg_content(self):
        """JPEG content validates correctly."""
        from scrubiq.files.validators import validate_magic_bytes

        jpeg_content = b"\xFF\xD8\xFF" + b"x" * 100
        assert validate_magic_bytes("image/jpeg", file_content=jpeg_content) is True

    def test_validate_mismatch(self):
        """Mismatched content returns False."""
        from scrubiq.files.validators import validate_magic_bytes

        pdf_content = b"%PDF-1.4\n"
        assert validate_magic_bytes("image/jpeg", file_content=pdf_content) is False

    def test_validate_from_file(self):
        """Can validate from file path."""
        from scrubiq.files.validators import validate_magic_bytes

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"%PDF-1.4\n" + b"x" * 100)
            f.flush()
            try:
                assert validate_magic_bytes("application/pdf", file_path=f.name) is True
            finally:
                os.unlink(f.name)

    def test_validate_file_not_found(self):
        """FileValidationError for missing file."""
        from scrubiq.files.validators import validate_magic_bytes, FileValidationError

        with pytest.raises(FileValidationError, match="not found"):
            validate_magic_bytes("application/pdf", file_path="/nonexistent/path.pdf")

    def test_validate_no_input_raises(self):
        """ValueError when neither path nor content provided."""
        from scrubiq.files.validators import validate_magic_bytes

        with pytest.raises(ValueError, match="Must provide"):
            validate_magic_bytes("application/pdf")

    def test_validate_empty_file(self):
        """Empty file raises error."""
        from scrubiq.files.validators import validate_magic_bytes, FileValidationError

        with pytest.raises(FileValidationError, match="empty"):
            validate_magic_bytes("application/pdf", file_content=b"")

    def test_validate_unknown_mime_allows(self):
        """Unknown MIME type is allowed (fail-open)."""
        from scrubiq.files.validators import validate_magic_bytes

        content = b"unknown content"
        assert validate_magic_bytes("application/x-unknown", file_content=content) is True

    def test_validate_text_plain(self):
        """text/plain validates text content."""
        from scrubiq.files.validators import validate_magic_bytes

        text_content = b"Hello, world!"
        assert validate_magic_bytes("text/plain", file_content=text_content) is True

    def test_validate_text_csv(self):
        """text/csv validates CSV content."""
        from scrubiq.files.validators import validate_magic_bytes

        csv_content = b"name,age\nJohn,30\nJane,25"
        assert validate_magic_bytes("text/csv", file_content=csv_content) is True

    def test_validate_binary_as_text_fails(self):
        """Binary content fails text validation."""
        from scrubiq.files.validators import validate_magic_bytes

        binary_content = b"\x00\x01\x02\x03" * 100
        assert validate_magic_bytes("text/plain", file_content=binary_content) is False


class TestValidateTextContent:
    """Tests for text content validation."""

    def test_valid_utf8(self):
        """Valid UTF-8 passes."""
        from scrubiq.files.validators import _validate_text_content

        text = "Hello, world! \u00e9\u00e8\u00ea"
        assert _validate_text_content(text.encode("utf-8")) is True

    def test_valid_ascii(self):
        """Valid ASCII passes."""
        from scrubiq.files.validators import _validate_text_content

        text = b"Hello, world!"
        assert _validate_text_content(text) is True

    def test_null_bytes_fail(self):
        """Content with null bytes fails."""
        from scrubiq.files.validators import _validate_text_content

        content = b"Hello\x00world"
        assert _validate_text_content(content) is False

    def test_empty_content_passes(self):
        """Empty content passes."""
        from scrubiq.files.validators import _validate_text_content

        assert _validate_text_content(b"") is True

    def test_high_non_printable_fails(self):
        """High ratio of non-printable characters fails."""
        from scrubiq.files.validators import _validate_text_content

        # Create content with many non-printable characters
        content = bytes(range(1, 32)) * 10
        assert _validate_text_content(content) is False


class TestFileTypeHelpers:
    """Tests for file type helper functions."""

    def test_get_extension(self):
        """get_extension returns lowercase extension."""
        from scrubiq.files.validators import get_extension

        assert get_extension("file.PDF") == ".pdf"
        assert get_extension("file.txt") == ".txt"
        assert get_extension("file") == ""
        assert get_extension("file.tar.gz") == ".gz"

    def test_is_allowed_extension(self):
        """is_allowed_extension checks whitelist."""
        from scrubiq.files.validators import is_allowed_extension

        assert is_allowed_extension("file.pdf") is True
        assert is_allowed_extension("file.docx") is True
        assert is_allowed_extension("file.jpg") is True
        assert is_allowed_extension("file.exe") is False
        assert is_allowed_extension("file.php") is False

    def test_is_allowed_mime(self):
        """is_allowed_mime checks whitelist."""
        from scrubiq.files.validators import is_allowed_mime

        assert is_allowed_mime("application/pdf") is True
        assert is_allowed_mime("image/jpeg") is True
        assert is_allowed_mime("application/x-executable") is False

    def test_is_allowed_mime_with_charset(self):
        """is_allowed_mime handles charset suffix."""
        from scrubiq.files.validators import is_allowed_mime

        assert is_allowed_mime("text/plain; charset=utf-8") is True

    def test_get_max_size_bytes(self):
        """get_max_size_bytes returns correct limits."""
        from scrubiq.files.validators import get_max_size_bytes

        # PDF max is 50MB
        assert get_max_size_bytes("application/pdf") == 50 * 1024 * 1024

        # Text max is 5MB
        assert get_max_size_bytes("text/plain") == 5 * 1024 * 1024

        # Unknown uses default
        assert get_max_size_bytes("application/unknown") == 50 * 1024 * 1024

    def test_is_image(self):
        """is_image checks content type."""
        from scrubiq.files.validators import is_image

        assert is_image("image/jpeg") is True
        assert is_image("image/png") is True
        assert is_image("application/pdf") is False

    def test_is_pdf(self):
        """is_pdf checks content type."""
        from scrubiq.files.validators import is_pdf

        assert is_pdf("application/pdf") is True
        assert is_pdf("image/jpeg") is False

    def test_is_spreadsheet(self):
        """is_spreadsheet checks content type."""
        from scrubiq.files.validators import is_spreadsheet

        assert is_spreadsheet("text/csv") is True
        assert is_spreadsheet("application/vnd.ms-excel") is True
        assert is_spreadsheet("application/pdf") is False

    def test_is_document(self):
        """is_document checks content type."""
        from scrubiq.files.validators import is_document

        assert is_document("application/msword") is True
        assert is_document("text/plain") is True
        assert is_document("image/jpeg") is False

    def test_infer_content_type(self):
        """infer_content_type works from extension."""
        from scrubiq.files.validators import infer_content_type

        assert infer_content_type("file.pdf") == "application/pdf"
        assert infer_content_type("file.jpg") == "image/jpeg"
        assert infer_content_type("file.unknown") is None


class TestValidateFile:
    """Tests for main validate_file function."""

    def test_validate_valid_pdf(self):
        """Valid PDF passes validation."""
        from scrubiq.files.validators import validate_file

        pdf_content = b"%PDF-1.4\n" + b"x" * 1000

        result = validate_file(
            filename="document.pdf",
            content_type="application/pdf",
            size_bytes=len(pdf_content),
            file_content=pdf_content,
        )

        assert result == "application/pdf"

    def test_validate_no_extension_fails(self):
        """File without extension fails."""
        from scrubiq.files.validators import validate_file, FileValidationError

        with pytest.raises(FileValidationError, match="no extension"):
            validate_file(
                filename="document",
                content_type="application/pdf",
                size_bytes=1000,
            )

    def test_validate_disallowed_extension_fails(self):
        """Disallowed extension fails."""
        from scrubiq.files.validators import validate_file, FileValidationError

        with pytest.raises(FileValidationError, match="not allowed"):
            validate_file(
                filename="malware.exe",
                content_type="application/x-executable",
                size_bytes=1000,
            )

    def test_validate_mime_mismatch_fails(self):
        """MIME/extension mismatch fails."""
        from scrubiq.files.validators import validate_file, FileValidationError

        with pytest.raises(FileValidationError, match="does not match"):
            validate_file(
                filename="document.pdf",
                content_type="image/jpeg",
                size_bytes=1000,
            )

    def test_validate_too_large_fails(self):
        """File exceeding size limit fails."""
        from scrubiq.files.validators import validate_file, FileValidationError

        with pytest.raises(FileValidationError, match="too large"):
            validate_file(
                filename="document.txt",
                content_type="text/plain",
                size_bytes=100 * 1024 * 1024,  # 100MB > 5MB limit
            )

    def test_validate_empty_file_fails(self):
        """Empty file fails."""
        from scrubiq.files.validators import validate_file, FileValidationError

        with pytest.raises(FileValidationError, match="empty"):
            validate_file(
                filename="document.pdf",
                content_type="application/pdf",
                size_bytes=0,
            )

    def test_validate_magic_byte_mismatch_fails(self):
        """Magic byte mismatch fails."""
        from scrubiq.files.validators import validate_file, FileValidationError

        # PDF extension/MIME but JPEG content
        jpeg_content = b"\xFF\xD8\xFF" + b"x" * 100

        with pytest.raises(FileValidationError, match="spoofing"):
            validate_file(
                filename="document.pdf",
                content_type="application/pdf",
                size_bytes=len(jpeg_content),
                file_content=jpeg_content,
            )

    def test_validate_without_content_type(self):
        """Validation works without Content-Type (inferred from extension)."""
        from scrubiq.files.validators import validate_file

        pdf_content = b"%PDF-1.4\n" + b"x" * 1000

        result = validate_file(
            filename="document.pdf",
            content_type=None,
            size_bytes=len(pdf_content),
            file_content=pdf_content,
        )

        assert result == "application/pdf"


# =============================================================================
# TEMP STORAGE TESTS
# =============================================================================

class TestSecureTempDir:
    """Tests for SecureTempDir class."""

    def test_context_manager_creates_and_cleans(self):
        """Context manager creates and cleans up directory."""
        from scrubiq.files.temp_storage import SecureTempDir

        with SecureTempDir("test_job") as temp_dir:
            assert temp_dir.exists()
            assert temp_dir.is_dir()
            saved_path = temp_dir

        # Should be cleaned up after context
        assert not saved_path.exists()

    def test_create_returns_path(self):
        """create() returns Path object."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")

        try:
            path = temp.create()
            assert isinstance(path, Path)
            assert path.exists()
        finally:
            temp.cleanup()

    def test_cleanup_idempotent(self):
        """cleanup() is safe to call multiple times."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        temp.create()

        temp.cleanup()
        temp.cleanup()  # Should not raise

    def test_path_property(self):
        """path property returns None before create."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        assert temp.path is None

        try:
            temp.create()
            assert temp.path is not None
        finally:
            temp.cleanup()

    def test_write_page(self):
        """write_page() creates page file."""
        from scrubiq.files.temp_storage import SecureTempDir

        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            data = b"fake image data"
            path = temp.write_page(0, data)

            assert path.exists()
            assert path.read_bytes() == data

    def test_write_page_not_created_raises(self):
        """write_page() raises if directory not created."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")

        with pytest.raises(RuntimeError, match="not created"):
            temp.write_page(0, b"data")

    def test_read_page(self):
        """read_page() reads page file."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        try:
            temp.create()

            data = b"test data"
            temp.write_page(0, data)

            result = temp.read_page(0)
            assert result == data
        finally:
            temp.cleanup()

    def test_read_page_not_created_raises(self):
        """read_page() raises if directory not created."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")

        with pytest.raises(RuntimeError, match="not created"):
            temp.read_page(0)

    def test_page_path(self):
        """page_path() returns correct path."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        try:
            temp.create()

            path = temp.page_path(5)
            assert path.name == "page_0005.png"
        finally:
            temp.cleanup()

    def test_page_path_not_created_raises(self):
        """page_path() raises if directory not created."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")

        with pytest.raises(RuntimeError, match="not created"):
            temp.page_path(0)

    def test_list_pages(self):
        """list_pages() returns sorted list."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        try:
            temp.create()

            # Write pages out of order
            temp.write_page(2, b"page 2")
            temp.write_page(0, b"page 0")
            temp.write_page(1, b"page 1")

            pages = temp.list_pages()

            assert len(pages) == 3
            assert pages[0].name == "page_0000.png"
            assert pages[1].name == "page_0001.png"
            assert pages[2].name == "page_0002.png"
        finally:
            temp.cleanup()

    def test_list_pages_empty(self):
        """list_pages() returns empty list if no pages."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        try:
            temp.create()
            assert temp.list_pages() == []
        finally:
            temp.cleanup()

    def test_list_pages_not_exists(self):
        """list_pages() returns empty list if directory gone."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        assert temp.list_pages() == []

    def test_iter_pages(self):
        """iter_pages() yields page contents."""
        from scrubiq.files.temp_storage import SecureTempDir

        temp = SecureTempDir("test_job")
        try:
            temp.create()

            temp.write_page(0, b"page 0")
            temp.write_page(1, b"page 1")

            contents = list(temp.iter_pages())

            assert len(contents) == 2
            assert contents[0] == b"page 0"
            assert contents[1] == b"page 1"
        finally:
            temp.cleanup()

    def test_custom_base_dir(self):
        """Can specify custom base directory."""
        from scrubiq.files.temp_storage import SecureTempDir

        with tempfile.TemporaryDirectory() as base:
            temp = SecureTempDir("test_job", base_dir=Path(base))
            try:
                path = temp.create()
                assert str(path).startswith(base)
            finally:
                temp.cleanup()

    def test_directory_permissions(self):
        """Directory has restricted permissions."""
        from scrubiq.files.temp_storage import SecureTempDir
        import stat

        temp = SecureTempDir("test_job")
        try:
            path = temp.create()

            # Get permissions
            mode = path.stat().st_mode
            # Check it's owner-only (700)
            assert (mode & 0o077) == 0  # No group/other permissions
        finally:
            temp.cleanup()


class TestCleanupOnExit:
    """Tests for cleanup on exit functionality."""

    def test_active_temp_dirs_tracking(self):
        """Temp dirs are tracked for cleanup."""
        from scrubiq.files.temp_storage import SecureTempDir, _active_temp_dirs

        initial_count = len(_active_temp_dirs)

        temp = SecureTempDir("test_job")
        temp.create()

        assert len(_active_temp_dirs) == initial_count + 1

        temp.cleanup()

        assert len(_active_temp_dirs) == initial_count

    def test_cleanup_on_exit_function(self):
        """_cleanup_on_exit() cleans orphaned dirs."""
        from scrubiq.files.temp_storage import SecureTempDir, _cleanup_on_exit, _active_temp_dirs

        temp = SecureTempDir("test_job")
        path = temp.create()

        # Manually call cleanup
        _cleanup_on_exit()

        assert not path.exists()
        assert len(_active_temp_dirs) == 0


# =============================================================================
# FILE VALIDATION ERROR TESTS
# =============================================================================

class TestFileValidationError:
    """Tests for FileValidationError."""

    def test_exception_message(self):
        """FileValidationError has message."""
        from scrubiq.files.validators import FileValidationError

        error = FileValidationError("Test error message")

        assert str(error) == "Test error message"

    def test_exception_inherits_exception(self):
        """FileValidationError inherits from Exception."""
        from scrubiq.files.validators import FileValidationError

        error = FileValidationError("Test")

        assert isinstance(error, Exception)


# =============================================================================
# HEIC DETECTION TESTS
# =============================================================================

class TestHEICDetection:
    """Tests for HEIC/HEIF image detection."""

    def test_detect_heic(self):
        """HEIC files are detected via ftyp box."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        # HEIC has ftyp at offset 4
        heic_content = b"\x00\x00\x00\x18ftyp" + b"heic" + b"\x00" * 100
        result = detect_mime_from_magic_bytes(heic_content)

        assert result == "image/heic"


# =============================================================================
# WEBP DETECTION TESTS
# =============================================================================

class TestWebPDetection:
    """Tests for WebP image detection."""

    def test_detect_webp(self):
        """WebP files are detected."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        # WebP is RIFF container with WEBP at offset 8
        webp_content = b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 100
        result = detect_mime_from_magic_bytes(webp_content)

        assert result == "image/webp"

    def test_riff_not_webp(self):
        """RIFF without WEBP is not detected as WebP."""
        from scrubiq.files.validators import detect_mime_from_magic_bytes

        # RIFF but not WebP (could be AVI, WAV, etc.)
        riff_content = b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 100
        result = detect_mime_from_magic_bytes(riff_content)

        # Should not be WebP
        assert result != "image/webp"
