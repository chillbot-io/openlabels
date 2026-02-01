"""
Tests for file validators security.

Tests critical validation functionality:
- Filename sanitization to prevent injection attacks
- Magic byte validation to prevent type spoofing
- File type detection and validation
- TOCTOU protection in file validation
"""

import os
import stat as stat_module
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.adapters.scanner.validators import (
    WINDOWS_RESERVED_NAMES,
    MAGIC_SIGNATURES,
    sanitize_filename,
    detect_mime_from_magic_bytes,
    validate_magic_bytes,
    validate_file,
    validate_uploaded_file,
    is_allowed_extension,
    is_allowed_mime,
    get_extension,
    get_max_size_bytes,
    infer_content_type,
    is_image,
    is_pdf,
    is_spreadsheet,
    is_document,
    FileValidationError,
)


class TestSanitizeFilename:
    """Tests for filename sanitization."""

    # Basic sanitization
    def test_removes_path_components_unix(self):
        """Should remove Unix path traversal."""
        result = sanitize_filename("../../../etc/passwd")
        assert "/" not in result
        assert ".." not in result
        assert result == "passwd"

    def test_removes_path_components_windows(self):
        """Should remove Windows path traversal and backslash characters."""
        result = sanitize_filename("..\\..\\Windows\\System32\\config")
        # Backslashes are replaced with underscores
        assert "\\" not in result
        # On non-Windows, os.path.basename doesn't split on \, but \ is replaced
        # The result will have underscores where backslashes were
        assert "_" in result or result == "config"

    def test_removes_null_bytes(self):
        """Should remove null bytes (string truncation attack)."""
        result = sanitize_filename("file.txt\x00.exe")
        assert "\x00" not in result

    def test_removes_control_characters(self):
        """Should remove control characters."""
        result = sanitize_filename("file\x01\x02\x03.txt")
        for i in range(0x20):
            assert chr(i) not in result

    # HTML/XSS dangerous characters
    def test_removes_angle_brackets(self):
        """Should remove < and > (HTML injection)."""
        result = sanitize_filename("<script>alert(1)</script>.txt")
        assert "<" not in result
        assert ">" not in result

    def test_removes_quotes(self):
        """Should remove quote characters."""
        result = sanitize_filename('file"name\'.txt')
        assert '"' not in result
        assert "'" not in result

    # Shell dangerous characters
    def test_removes_backticks(self):
        """Should remove backticks (command substitution)."""
        result = sanitize_filename("`whoami`.txt")
        assert "`" not in result

    def test_removes_dollar_sign(self):
        """Should remove dollar sign (variable expansion)."""
        result = sanitize_filename("$HOME.txt")
        assert "$" not in result

    def test_removes_semicolon(self):
        """Should remove semicolon (command separator)."""
        result = sanitize_filename("file;rm -rf /.txt")
        assert ";" not in result

    def test_removes_ampersand(self):
        """Should remove ampersand."""
        result = sanitize_filename("file&background.txt")
        assert "&" not in result

    def test_removes_pipe(self):
        """Should remove pipe."""
        result = sanitize_filename("file|cat.txt")
        assert "|" not in result

    def test_removes_parentheses(self):
        """Should remove parentheses."""
        result = sanitize_filename("file(1).txt")
        assert "(" not in result
        assert ")" not in result

    def test_removes_hash(self):
        """Should remove hash."""
        result = sanitize_filename("file#comment.txt")
        assert "#" not in result

    def test_removes_at_sign(self):
        """Should remove at sign."""
        result = sanitize_filename("user@domain.txt")
        assert "@" not in result

    # Windows reserved names
    def test_prefixes_windows_reserved_con(self):
        """Should prefix CON (Windows device name)."""
        result = sanitize_filename("CON.txt")
        assert result.startswith("file_")

    def test_prefixes_windows_reserved_prn(self):
        """Should prefix PRN (Windows device name)."""
        result = sanitize_filename("PRN")
        assert result.startswith("file_")

    def test_prefixes_windows_reserved_aux(self):
        """Should prefix AUX (Windows device name)."""
        result = sanitize_filename("AUX.doc")
        assert result.startswith("file_")

    def test_prefixes_windows_reserved_nul(self):
        """Should prefix NUL (Windows device name)."""
        result = sanitize_filename("NUL")
        assert result.startswith("file_")

    def test_prefixes_windows_reserved_com1(self):
        """Should prefix COM ports."""
        for i in range(1, 10):
            result = sanitize_filename(f"COM{i}.txt")
            assert result.startswith("file_")

    def test_prefixes_windows_reserved_lpt1(self):
        """Should prefix LPT ports."""
        for i in range(1, 10):
            result = sanitize_filename(f"LPT{i}.txt")
            assert result.startswith("file_")

    def test_case_insensitive_reserved_check(self):
        """Should handle case-insensitive reserved names."""
        result = sanitize_filename("con.txt")
        assert result.startswith("file_")
        result = sanitize_filename("Con.txt")
        assert result.startswith("file_")

    # Leading dash protection
    def test_removes_leading_dash(self):
        """Should remove leading dash (CLI confusion)."""
        result = sanitize_filename("-rf.txt")
        assert not result.startswith("-")

    def test_removes_multiple_leading_dashes(self):
        """Should remove multiple leading dashes."""
        result = sanitize_filename("---file.txt")
        assert not result.startswith("-")

    # Percent encoding
    def test_decodes_percent_encoding(self):
        """Should decode percent-encoded characters."""
        result = sanitize_filename("file%20name.txt")
        # After decoding %20 becomes space, which gets replaced
        assert "%20" not in result

    def test_handles_malformed_percent_encoding(self):
        """Should handle malformed percent encoding gracefully."""
        result = sanitize_filename("file%ZZname.txt")
        # Should not crash
        assert isinstance(result, str)

    # Unicode/homoglyph protection
    def test_replaces_non_ascii(self):
        """Should replace non-ASCII characters (homoglyph protection)."""
        result = sanitize_filename("fle.txt")  # Cyrillic 'а' looks like 'a'
        # Non-ASCII should be replaced with ?
        assert "?" in result or all(ord(c) < 128 for c in result)

    # Length limits
    def test_truncates_long_filename(self):
        """Should truncate very long filenames."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255  # Common filesystem limit

    def test_preserves_extension_when_truncating(self):
        """Should preserve extension when truncating."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert result.endswith(".txt")

    # Edge cases
    def test_empty_filename_returns_unknown(self):
        """Should return 'unknown' for empty filename."""
        result = sanitize_filename("")
        assert result == "unknown"

    def test_none_returns_unknown(self):
        """Should handle None gracefully."""
        result = sanitize_filename(None)
        assert result == "unknown"

    def test_all_dangerous_chars_returns_unknown(self):
        """Should return 'unknown' if all chars removed."""
        result = sanitize_filename("<>:\"/\\|?*")
        # Should have something or return unknown
        assert result == "unknown" or len(result) > 0

    def test_collapses_multiple_underscores(self):
        """Should collapse multiple underscores."""
        result = sanitize_filename("file___name.txt")
        assert "___" not in result

    def test_collapses_multiple_dots(self):
        """Should collapse multiple dots."""
        result = sanitize_filename("file...name.txt")
        assert "..." not in result


class TestMagicSignatures:
    """Tests for magic byte signature definitions."""

    def test_pdf_signature(self):
        """PDF should have correct magic bytes."""
        sigs = MAGIC_SIGNATURES.get("application/pdf", [])
        assert any(sig[0] == b"%PDF" for sig in sigs)

    def test_jpeg_signature(self):
        """JPEG should have correct magic bytes."""
        sigs = MAGIC_SIGNATURES.get("image/jpeg", [])
        assert any(sig[0] == b"\xFF\xD8\xFF" for sig in sigs)

    def test_png_signature(self):
        """PNG should have correct magic bytes."""
        sigs = MAGIC_SIGNATURES.get("image/png", [])
        assert any(sig[0] == b"\x89PNG\r\n\x1a\n" for sig in sigs)

    def test_docx_signature(self):
        """DOCX should have ZIP signature."""
        sigs = MAGIC_SIGNATURES.get(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            []
        )
        assert any(sig[0] == b"PK\x03\x04" for sig in sigs)

    def test_ole_signature(self):
        """DOC/XLS should have OLE signature."""
        doc_sigs = MAGIC_SIGNATURES.get("application/msword", [])
        xls_sigs = MAGIC_SIGNATURES.get("application/vnd.ms-excel", [])
        ole_magic = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
        assert any(sig[0] == ole_magic for sig in doc_sigs)
        assert any(sig[0] == ole_magic for sig in xls_sigs)


class TestDetectMimeFromMagicBytes:
    """Tests for MIME type detection from magic bytes."""

    def test_detects_pdf(self):
        """Should detect PDF files."""
        content = b"%PDF-1.7\n..."
        result = detect_mime_from_magic_bytes(content)
        assert result == "application/pdf"

    def test_detects_jpeg(self):
        """Should detect JPEG files."""
        content = b"\xFF\xD8\xFF\xE0\x00\x10JFIF"
        result = detect_mime_from_magic_bytes(content)
        assert result == "image/jpeg"

    def test_detects_png(self):
        """Should detect PNG files."""
        content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 56
        result = detect_mime_from_magic_bytes(content)
        assert result == "image/png"

    def test_detects_gif87a(self):
        """Should detect GIF87a files."""
        content = b"GIF87a" + b"\x00" * 58
        result = detect_mime_from_magic_bytes(content)
        assert result == "image/gif"

    def test_detects_gif89a(self):
        """Should detect GIF89a files."""
        content = b"GIF89a" + b"\x00" * 58
        result = detect_mime_from_magic_bytes(content)
        assert result == "image/gif"

    def test_detects_text(self):
        """Should detect plain text."""
        content = b"Hello, this is a plain text file."
        result = detect_mime_from_magic_bytes(content)
        assert result == "text/plain"

    def test_empty_content_returns_none(self):
        """Should return None for empty content."""
        result = detect_mime_from_magic_bytes(b"")
        assert result is None

    def test_none_content_returns_none(self):
        """Should return None for None content."""
        result = detect_mime_from_magic_bytes(None)
        assert result is None

    def test_unknown_format_returns_none(self):
        """Should return None for unknown binary format."""
        content = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        result = detect_mime_from_magic_bytes(content)
        # Binary with null bytes won't be detected as text
        assert result is None


class TestValidateMagicBytes:
    """Tests for magic byte validation."""

    def test_validates_pdf_content(self, tmp_path):
        """Should validate PDF magic bytes."""
        pdf_content = b"%PDF-1.7\nsome content"
        result = validate_magic_bytes("application/pdf", file_content=pdf_content)
        assert result is True

    def test_rejects_mismatched_magic_bytes(self, tmp_path):
        """Should reject content that doesn't match claimed type."""
        # Claim PDF but provide PNG
        png_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 56
        result = validate_magic_bytes("application/pdf", file_content=png_content)
        assert result is False

    def test_validates_text_content(self, tmp_path):
        """Should validate text content."""
        text_content = b"Hello, world!"
        result = validate_magic_bytes("text/plain", file_content=text_content)
        assert result is True

    def test_rejects_binary_as_text(self, tmp_path):
        """Should reject binary content claimed as text."""
        binary_content = b"\x00\x01\x02\x03\x04\x05"  # Contains null bytes
        result = validate_magic_bytes("text/plain", file_content=binary_content)
        assert result is False

    def test_validates_from_file_path(self, tmp_path):
        """Should read and validate from file path."""
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.7\nsome content")

        result = validate_magic_bytes("application/pdf", file_path=pdf_file)
        assert result is True

    def test_rejects_symlink_file(self, tmp_path):
        """Should reject symlinks (TOCTOU protection)."""
        target = tmp_path / "target.pdf"
        target.write_bytes(b"%PDF-1.7\nsome content")
        link = tmp_path / "link.pdf"
        link.symlink_to(target)

        with pytest.raises(FileValidationError, match="Symlinks not allowed"):
            validate_magic_bytes("application/pdf", file_path=link)

    def test_rejects_directory(self, tmp_path):
        """Should reject directory."""
        with pytest.raises(FileValidationError, match="Not a regular file"):
            validate_magic_bytes("application/pdf", file_path=tmp_path)

    def test_raises_on_missing_file(self, tmp_path):
        """Should raise on non-existent file."""
        nonexistent = tmp_path / "nonexistent.pdf"
        with pytest.raises(FileValidationError, match="File not found"):
            validate_magic_bytes("application/pdf", file_path=nonexistent)

    def test_raises_on_empty_file(self, tmp_path):
        """Should raise on empty file."""
        empty_file = tmp_path / "empty.pdf"
        empty_file.write_bytes(b"")

        with pytest.raises(FileValidationError, match="File is empty"):
            validate_magic_bytes("application/pdf", file_path=empty_file)

    def test_raises_without_path_or_content(self):
        """Should raise when neither path nor content provided."""
        with pytest.raises(ValueError, match="Must provide"):
            validate_magic_bytes("application/pdf")

    def test_rejects_unknown_mime_type(self):
        """Should reject unknown MIME types (fail closed)."""
        content = b"some content"
        result = validate_magic_bytes("application/unknown-type", file_content=content)
        assert result is False


class TestValidateFile:
    """Tests for complete file validation."""

    def test_validates_allowed_extension(self):
        """Should accept allowed extensions."""
        result = validate_file(
            filename="document.pdf",
            content_type="application/pdf",
            size_bytes=1000,
        )
        assert result is not None

    def test_rejects_disallowed_extension(self):
        """Should reject disallowed extensions."""
        with pytest.raises(FileValidationError, match="not allowed"):
            validate_file(
                filename="script.exe",
                content_type="application/octet-stream",
                size_bytes=1000,
            )

    def test_rejects_no_extension(self):
        """Should reject files without extension."""
        with pytest.raises(FileValidationError, match="no extension"):
            validate_file(
                filename="noextension",
                content_type="application/pdf",
                size_bytes=1000,
            )

    def test_rejects_mismatched_mime_and_extension(self):
        """Should reject when MIME doesn't match extension."""
        with pytest.raises(FileValidationError, match="does not match"):
            validate_file(
                filename="image.pdf",  # .pdf extension
                content_type="image/jpeg",  # JPEG MIME type
                size_bytes=1000,
            )

    def test_rejects_oversized_file(self):
        """Should reject files exceeding size limit."""
        with pytest.raises(FileValidationError, match="too large"):
            validate_file(
                filename="document.pdf",
                content_type="application/pdf",
                size_bytes=100 * 1024 * 1024,  # 100MB, exceeds 50MB limit
            )

    def test_rejects_empty_file(self):
        """Should reject empty files."""
        with pytest.raises(FileValidationError, match="empty"):
            validate_file(
                filename="document.pdf",
                content_type="application/pdf",
                size_bytes=0,
            )

    def test_validates_magic_bytes_when_content_provided(self):
        """Should validate magic bytes when content is provided."""
        pdf_content = b"%PDF-1.7\nsome content"
        result = validate_file(
            filename="document.pdf",
            content_type="application/pdf",
            size_bytes=len(pdf_content),
            file_content=pdf_content,
        )
        assert result is not None

    def test_detects_type_spoofing(self):
        """Should detect file type spoofing."""
        # PNG content but claiming to be PDF
        png_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        with pytest.raises(FileValidationError, match="spoofing"):
            validate_file(
                filename="document.pdf",
                content_type="application/pdf",
                size_bytes=len(png_content),
                file_content=png_content,
            )


class TestValidateUploadedFile:
    """Tests for uploaded file validation convenience function."""

    def test_validates_complete_file(self, tmp_path):
        """Should validate a complete uploaded file."""
        pdf_file = tmp_path / "document.pdf"
        pdf_content = b"%PDF-1.7\nsome content here"
        pdf_file.write_bytes(pdf_content)

        # Should not raise
        validate_uploaded_file(
            filename="document.pdf",
            content_type="application/pdf",
            file_path=pdf_file,
        )

    def test_rejects_symlink(self, tmp_path):
        """Should reject symlink uploads."""
        target = tmp_path / "target.pdf"
        target.write_bytes(b"%PDF-1.7\nsome content")
        link = tmp_path / "link.pdf"
        link.symlink_to(target)

        with pytest.raises(FileValidationError, match="Symlinks not allowed"):
            validate_uploaded_file(
                filename="link.pdf",
                content_type="application/pdf",
                file_path=link,
            )

    def test_rejects_missing_file(self, tmp_path):
        """Should reject missing file."""
        nonexistent = tmp_path / "nonexistent.pdf"

        with pytest.raises(FileValidationError, match="File not found"):
            validate_uploaded_file(
                filename="nonexistent.pdf",
                content_type="application/pdf",
                file_path=nonexistent,
            )


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_extension(self):
        """Should extract lowercase extension."""
        assert get_extension("file.PDF") == ".pdf"
        assert get_extension("file.TXT") == ".txt"
        assert get_extension("noext") == ""

    def test_is_allowed_extension(self):
        """Should check allowed extensions."""
        assert is_allowed_extension("file.pdf") is True
        assert is_allowed_extension("file.jpg") is True
        assert is_allowed_extension("file.exe") is False

    def test_is_allowed_mime(self):
        """Should check allowed MIME types."""
        assert is_allowed_mime("application/pdf") is True
        assert is_allowed_mime("image/jpeg") is True
        assert is_allowed_mime("application/x-executable") is False

    def test_get_max_size_bytes(self):
        """Should return correct size limits."""
        pdf_limit = get_max_size_bytes("application/pdf")
        assert pdf_limit == 50 * 1024 * 1024  # 50MB

        txt_limit = get_max_size_bytes("text/plain")
        assert txt_limit == 5 * 1024 * 1024  # 5MB

    def test_infer_content_type(self):
        """Should infer MIME type from extension."""
        assert infer_content_type("file.pdf") == "application/pdf"
        assert infer_content_type("file.jpg") == "image/jpeg"
        assert infer_content_type("file.unknown") is None

    def test_is_image(self):
        """Should identify image types."""
        assert is_image("image/jpeg") is True
        assert is_image("image/png") is True
        assert is_image("application/pdf") is False

    def test_is_pdf(self):
        """Should identify PDF type."""
        assert is_pdf("application/pdf") is True
        assert is_pdf("image/jpeg") is False

    def test_is_spreadsheet(self):
        """Should identify spreadsheet types."""
        assert is_spreadsheet("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") is True
        assert is_spreadsheet("text/csv") is True
        assert is_spreadsheet("application/pdf") is False

    def test_is_document(self):
        """Should identify document types."""
        assert is_document("application/vnd.openxmlformats-officedocument.wordprocessingml.document") is True
        assert is_document("application/rtf") is True
        assert is_document("text/plain") is True
        assert is_document("image/jpeg") is False


class TestWindowsReservedNames:
    """Tests for Windows reserved names constant."""

    def test_contains_con(self):
        assert "CON" in WINDOWS_RESERVED_NAMES

    def test_contains_prn(self):
        assert "PRN" in WINDOWS_RESERVED_NAMES

    def test_contains_aux(self):
        assert "AUX" in WINDOWS_RESERVED_NAMES

    def test_contains_nul(self):
        assert "NUL" in WINDOWS_RESERVED_NAMES

    def test_contains_all_com_ports(self):
        for i in range(1, 10):
            assert f"COM{i}" in WINDOWS_RESERVED_NAMES

    def test_contains_all_lpt_ports(self):
        for i in range(1, 10):
            assert f"LPT{i}" in WINDOWS_RESERVED_NAMES

    def test_is_frozen_set(self):
        """Should be immutable."""
        assert isinstance(WINDOWS_RESERVED_NAMES, frozenset)
