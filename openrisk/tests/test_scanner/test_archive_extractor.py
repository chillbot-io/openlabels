"""Tests for archive extractor (ZIP, TAR, GZ, 7Z)."""

import gzip
import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from openlabels.adapters.scanner.extractors.archive import (
    ArchiveExtractor,
    ArchiveSecurityError,
    GzipExtractor,
    TarExtractor,
    ZipExtractor,
    SevenZipExtractor,
    _is_safe_path,
    _get_extension,
    MAX_ARCHIVE_NESTING_DEPTH,
    MAX_FILES_PER_ARCHIVE,
)
from openlabels.adapters.scanner.extractors import extract_text


class TestPathSafety:
    """Test path traversal prevention."""

    def test_safe_paths(self):
        """Normal paths should be allowed."""
        assert _is_safe_path("file.txt") is True
        assert _is_safe_path("dir/file.txt") is True
        assert _is_safe_path("a/b/c/file.txt") is True
        assert _is_safe_path("Documents/report.pdf") is True

    def test_path_traversal_blocked(self):
        """Parent directory references should be blocked."""
        assert _is_safe_path("../file.txt") is False
        assert _is_safe_path("dir/../file.txt") is False
        assert _is_safe_path("a/b/../../c/file.txt") is False
        assert _is_safe_path("..") is False

    def test_absolute_paths_blocked(self):
        """Absolute paths should be blocked."""
        assert _is_safe_path("/etc/passwd") is False
        assert _is_safe_path("/home/user/file.txt") is False
        assert _is_safe_path("C:\\Windows\\System32") is False

    def test_null_bytes_blocked(self):
        """Null bytes in paths should be blocked."""
        assert _is_safe_path("file\x00.txt") is False
        assert _is_safe_path("dir/file\x00name.txt") is False

    def test_windows_reserved_names_blocked(self):
        """Windows reserved device names should be blocked."""
        assert _is_safe_path("CON") is False
        assert _is_safe_path("PRN.txt") is False
        assert _is_safe_path("dir/NUL") is False
        assert _is_safe_path("COM1") is False
        assert _is_safe_path("LPT1.txt") is False

    def test_empty_path_blocked(self):
        """Empty paths should be blocked."""
        assert _is_safe_path("") is False
        assert _is_safe_path(None) is False


class TestExtensionDetection:
    """Test file extension detection."""

    def test_simple_extensions(self):
        """Simple extensions should be detected correctly."""
        assert _get_extension("file.txt") == ".txt"
        assert _get_extension("file.zip") == ".zip"
        assert _get_extension("file.PDF") == ".pdf"

    def test_compound_extensions(self):
        """Compound extensions like .tar.gz should be detected."""
        assert _get_extension("archive.tar.gz") == ".tar.gz"
        assert _get_extension("archive.tar.bz2") == ".tar.bz2"
        assert _get_extension("archive.tar.xz") == ".tar.xz"
        assert _get_extension("ARCHIVE.TAR.GZ") == ".tar.gz"

    def test_no_extension(self):
        """Files without extensions should return empty string."""
        assert _get_extension("README") == ""
        assert _get_extension("Makefile") == ""


class TestZipExtractor:
    """Tests for ZIP archive extraction."""

    def test_can_handle_by_magic_bytes(self):
        """ZIP files should be detected by magic bytes."""
        zip_magic = b'PK\x03\x04' + b'\x00' * 100
        assert ZipExtractor.can_handle(zip_magic, ".dat") is True

    def test_can_handle_by_extension(self):
        """ZIP files should be detected by extension."""
        assert ZipExtractor.can_handle(b'', ".zip") is True
        assert ZipExtractor.can_handle(b'', ".txt") is False

    def test_extract_simple_zip(self):
        """Extract files from a simple ZIP archive."""
        # Create a ZIP with text files
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("file1.txt", "Hello World")
            zf.writestr("dir/file2.txt", "Nested file content")

        buffer.seek(0)
        content = buffer.read()

        files = list(ZipExtractor.extract_files(content))
        assert len(files) == 2

        paths = {f.path for f in files}
        assert "file1.txt" in paths
        assert "dir/file2.txt" in paths

    def test_extract_zip_with_path_traversal(self):
        """Malicious paths in ZIP should be skipped."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr("safe.txt", "Safe content")
            # Manually create entry with malicious path
            info = zipfile.ZipInfo("../etc/passwd")
            zf.writestr(info, "malicious")

        buffer.seek(0)
        content = buffer.read()

        files = list(ZipExtractor.extract_files(content))
        # Only safe file should be extracted
        assert len(files) == 1
        assert files[0].path == "safe.txt"

    def test_zip_file_count_limit(self):
        """ZIP with too many files should raise error."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            for i in range(100):
                zf.writestr(f"file{i}.txt", f"content {i}")

        buffer.seek(0)
        content = buffer.read()

        # Should raise when limit is low
        with pytest.raises(ArchiveSecurityError, match="exceeds limit"):
            list(ZipExtractor.extract_files(content, max_files=50))

    def test_nested_archive_detection(self):
        """Nested archives should be flagged."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr("normal.txt", "Normal file")
            zf.writestr("nested.zip", b"PK\x03\x04fake")
            zf.writestr("nested.tar.gz", b"\x1f\x8bfake")

        buffer.seek(0)
        content = buffer.read()

        files = list(ZipExtractor.extract_files(content))
        nested = [f for f in files if f.is_archive]
        assert len(nested) == 2


class TestTarExtractor:
    """Tests for TAR archive extraction."""

    def test_can_handle_by_extension(self):
        """TAR files should be detected by extension."""
        assert TarExtractor.can_handle(b'', ".tar") is True
        assert TarExtractor.can_handle(b'', ".tar.gz") is True
        assert TarExtractor.can_handle(b'', ".tgz") is True
        assert TarExtractor.can_handle(b'', ".tar.bz2") is True
        assert TarExtractor.can_handle(b'', ".txt") is False

    def test_extract_simple_tar(self):
        """Extract files from a simple TAR archive."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tf:
            # Add a file
            data = b"Hello from TAR"
            info = tarfile.TarInfo(name="hello.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        files = list(TarExtractor.extract_files(content))
        assert len(files) == 1
        assert files[0].path == "hello.txt"
        assert files[0].content == b"Hello from TAR"

    def test_extract_tar_gz(self):
        """Extract files from a .tar.gz archive."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
            data = b"Compressed content"
            info = tarfile.TarInfo(name="compressed.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        files = list(TarExtractor.extract_files(content))
        assert len(files) == 1
        assert files[0].content == b"Compressed content"

    def test_tar_path_traversal_blocked(self):
        """Path traversal attempts in TAR should be blocked."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tf:
            # Safe file
            data = b"safe"
            info = tarfile.TarInfo(name="safe.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            # Malicious path
            data = b"evil"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        files = list(TarExtractor.extract_files(content))
        assert len(files) == 1
        assert files[0].path == "safe.txt"

    def test_tar_skips_directories_and_links(self):
        """TAR extraction should skip directories and symbolic links."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tf:
            # Directory
            dir_info = tarfile.TarInfo(name="mydir")
            dir_info.type = tarfile.DIRTYPE
            tf.addfile(dir_info)

            # Regular file
            data = b"file content"
            file_info = tarfile.TarInfo(name="mydir/file.txt")
            file_info.size = len(data)
            tf.addfile(file_info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        files = list(TarExtractor.extract_files(content))
        # Only the regular file should be extracted
        assert len(files) == 1
        assert files[0].path == "mydir/file.txt"


class TestGzipExtractor:
    """Tests for GZIP extraction."""

    def test_can_handle_by_magic_bytes(self):
        """GZIP files should be detected by magic bytes."""
        gz_magic = b'\x1f\x8b' + b'\x00' * 100
        assert GzipExtractor.can_handle(gz_magic, ".gz") is True
        assert GzipExtractor.can_handle(gz_magic, ".dat") is True

    def test_can_handle_excludes_tar_gz(self):
        """GZIP handler should not claim .tar.gz files."""
        gz_magic = b'\x1f\x8b' + b'\x00' * 100
        assert GzipExtractor.can_handle(gz_magic, ".tar.gz") is False
        assert GzipExtractor.can_handle(gz_magic, ".tgz") is False

    def test_extract_gzip(self):
        """Extract content from GZIP file."""
        original = b"This is the original uncompressed content"
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
            gz.write(original)

        buffer.seek(0)
        content = buffer.read()

        files = list(GzipExtractor.extract_files(content, "data.txt.gz"))
        assert len(files) == 1
        assert files[0].path == "data.txt"
        assert files[0].content == original

    def test_gzip_size_limit(self):
        """GZIP decompression should respect size limits."""
        # Create a large compressed file
        original = b"X" * (1024 * 1024)  # 1MB
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
            gz.write(original)

        buffer.seek(0)
        content = buffer.read()

        # Should raise when limit is low
        with pytest.raises(ArchiveSecurityError, match="exceeds"):
            list(GzipExtractor.extract_files(content, "big.txt.gz", max_size=1000))


class TestSevenZipExtractor:
    """Tests for 7Z extraction (when py7zr is available)."""

    def test_can_handle_by_magic_bytes(self):
        """7Z files should be detected by magic bytes."""
        sz_magic = b'7z\xbc\xaf\x27\x1c' + b'\x00' * 100
        assert SevenZipExtractor.can_handle(sz_magic, ".dat") is True

    def test_can_handle_by_extension(self):
        """7Z files should be detected by extension."""
        assert SevenZipExtractor.can_handle(b'', ".7z") is True
        assert SevenZipExtractor.can_handle(b'', ".zip") is False

    @pytest.mark.skipif(
        not SevenZipExtractor.is_available(),
        reason="py7zr not installed"
    )
    def test_extract_7z(self):
        """Extract files from a 7Z archive (requires py7zr)."""
        import py7zr

        buffer = io.BytesIO()
        with py7zr.SevenZipFile(buffer, 'w') as sz:
            sz.writestr(b"Seven zip content", "file.txt")

        buffer.seek(0)
        content = buffer.read()

        files = list(SevenZipExtractor.extract_files(content))
        assert len(files) == 1
        assert files[0].path == "file.txt"


class TestArchiveExtractor:
    """Tests for the unified ArchiveExtractor."""

    def test_can_handle_zip(self):
        """ArchiveExtractor should handle ZIP files."""
        extractor = ArchiveExtractor()
        assert extractor.can_handle("application/zip", ".zip") is True
        assert extractor.can_handle("application/x-zip-compressed", ".zip") is True

    def test_can_handle_tar(self):
        """ArchiveExtractor should handle TAR files."""
        extractor = ArchiveExtractor()
        assert extractor.can_handle("application/x-tar", ".tar") is True
        assert extractor.can_handle("application/gzip", ".tar.gz") is True
        assert extractor.can_handle("application/gzip", ".tgz") is True

    def test_can_handle_gzip(self):
        """ArchiveExtractor should handle GZIP files."""
        extractor = ArchiveExtractor()
        assert extractor.can_handle("application/gzip", ".gz") is True

    def test_can_handle_7z(self):
        """ArchiveExtractor should handle 7Z files."""
        extractor = ArchiveExtractor()
        assert extractor.can_handle("application/x-7z-compressed", ".7z") is True

    def test_extract_zip_with_text_files(self):
        """Extract text from files within a ZIP archive."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr("readme.txt", "This is the readme content.")
            zf.writestr("data/notes.txt", "Some notes here.")

        buffer.seek(0)
        content = buffer.read()

        extractor = ArchiveExtractor()
        result = extractor.extract(content, "archive.zip")

        assert "readme content" in result.text
        assert "Some notes" in result.text
        assert result.pages == 2  # Two files processed

    def test_extract_nested_zip(self):
        """Extract text from nested ZIP archives."""
        # Create inner ZIP
        inner_buffer = io.BytesIO()
        with zipfile.ZipFile(inner_buffer, 'w') as inner_zf:
            inner_zf.writestr("inner.txt", "Inner archive content")

        # Create outer ZIP containing inner ZIP
        outer_buffer = io.BytesIO()
        with zipfile.ZipFile(outer_buffer, 'w') as outer_zf:
            outer_zf.writestr("outer.txt", "Outer archive content")
            outer_zf.writestr("nested.zip", inner_buffer.getvalue())

        outer_buffer.seek(0)
        content = outer_buffer.read()

        extractor = ArchiveExtractor()
        result = extractor.extract(content, "outer.zip")

        assert "Outer archive content" in result.text
        assert "Inner archive content" in result.text

    def test_nesting_depth_limit(self):
        """Deeply nested archives should be stopped at max depth."""

        def create_nested_zip(depth: int) -> bytes:
            if depth == 0:
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w') as zf:
                    zf.writestr("deepest.txt", f"Depth {depth}")
                return buffer.getvalue()
            else:
                inner = create_nested_zip(depth - 1)
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w') as zf:
                    zf.writestr("level.txt", f"Depth {depth}")
                    zf.writestr("inner.zip", inner)
                return buffer.getvalue()

        # Create archive nested beyond limit
        content = create_nested_zip(MAX_ARCHIVE_NESTING_DEPTH + 2)

        extractor = ArchiveExtractor()
        result = extractor.extract(content, "deep.zip")

        # Should have warning about nesting depth
        assert any("depth" in w.lower() for w in result.warnings)


class TestRegistryIntegration:
    """Test that archive extractor is properly integrated with registry."""

    def test_extract_text_handles_zip(self):
        """extract_text() should handle ZIP files."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr("document.txt", "Document content from ZIP")

        buffer.seek(0)
        content = buffer.read()

        result = extract_text(content, "archive.zip")
        assert "Document content from ZIP" in result.text

    def test_extract_text_handles_tar_gz(self):
        """extract_text() should handle .tar.gz files."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
            data = b"Content from tarball"
            info = tarfile.TarInfo(name="file.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        result = extract_text(content, "archive.tar.gz")
        assert "Content from tarball" in result.text


class TestSecurityEdgeCases:
    """Test security edge cases and attack vectors."""

    def test_zip_bomb_ratio_detection(self):
        """High compression ratio (zip bomb) should be detected."""
        # Create a file that compresses extremely well
        highly_compressible = b'\x00' * (10 * 1024 * 1024)  # 10MB of zeros

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.bin", highly_compressible)

        buffer.seek(0)
        content = buffer.read()

        # The compression ratio will be very high
        # Our extractor should detect this
        files = list(ZipExtractor.extract_files(
            content,
            max_total_size=5 * 1024 * 1024,  # 5MB limit
        ))

        # File should be skipped due to size or ratio
        assert len(files) == 0 or files[0].size <= 5 * 1024 * 1024

    def test_symlink_in_tar_ignored(self):
        """Symbolic links in TAR should be ignored."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tf:
            # Add a symlink
            link_info = tarfile.TarInfo(name="link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tf.addfile(link_info)

            # Add a regular file
            data = b"regular file"
            file_info = tarfile.TarInfo(name="regular.txt")
            file_info.size = len(data)
            tf.addfile(file_info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        files = list(TarExtractor.extract_files(content))
        # Only regular file should be extracted
        assert len(files) == 1
        assert files[0].path == "regular.txt"

    def test_hardlink_in_tar_ignored(self):
        """Hard links in TAR should be ignored."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tf:
            # Add a hardlink
            link_info = tarfile.TarInfo(name="hardlink")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "target"
            tf.addfile(link_info)

            # Add a regular file
            data = b"content"
            file_info = tarfile.TarInfo(name="regular.txt")
            file_info.size = len(data)
            tf.addfile(file_info, io.BytesIO(data))

        buffer.seek(0)
        content = buffer.read()

        files = list(TarExtractor.extract_files(content))
        assert len(files) == 1
        assert files[0].path == "regular.txt"

    def test_empty_archive(self):
        """Empty archives should be handled gracefully."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            pass  # Empty archive

        buffer.seek(0)
        content = buffer.read()

        extractor = ArchiveExtractor()
        result = extractor.extract(content, "empty.zip")

        assert result.text == ""
        assert result.pages == 0


class TestMixedContent:
    """Test archives with mixed content types."""

    def test_archive_with_binary_and_text(self):
        """Archives with mixed binary and text files."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr("readme.txt", "Text content here")
            zf.writestr("image.png", b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
            zf.writestr("data.bin", bytes(range(256)))

        buffer.seek(0)
        content = buffer.read()

        extractor = ArchiveExtractor()
        result = extractor.extract(content, "mixed.zip")

        # Text file should be extracted
        assert "Text content" in result.text
        # Binary files may or may not contribute depending on extractors
        assert result.pages >= 1
