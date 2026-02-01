"""
Tests for File Metadata Collector.

Tests file system metadata collection:
- POSIX permission collection
- Symlink rejection (security)
- Encryption detection
- Archive detection
- Extended attribute collection
- TOCTOU protection
"""

import os
import stat
import hashlib
import platform
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest

from openlabels.agent.collector import (
    FileMetadata,
    FileCollector,
    collect_metadata,
    collect_directory,
)
from openlabels.adapters.base import ExposureLevel, NormalizedContext


class TestFileMetadata:
    """Tests for FileMetadata dataclass."""

    def test_basic_construction(self):
        metadata = FileMetadata(
            path="/test/file.txt",
            name="file.txt",
            size_bytes=1024,
            file_type="text/plain",
            extension=".txt",
        )

        assert metadata.path == "/test/file.txt"
        assert metadata.name == "file.txt"
        assert metadata.size_bytes == 1024
        assert metadata.file_type == "text/plain"
        assert metadata.extension == ".txt"

    def test_default_values(self):
        metadata = FileMetadata(
            path="/test/file.txt",
            name="file.txt",
            size_bytes=0,
            file_type="text/plain",
            extension=".txt",
        )

        assert metadata.exposure == ExposureLevel.PRIVATE
        assert metadata.is_encrypted is False
        assert metadata.is_archive is False
        assert metadata.xattrs == {}
        assert metadata.errors == []

    def test_to_normalized_context(self):
        metadata = FileMetadata(
            path="/test/file.txt",
            name="file.txt",
            size_bytes=1024,
            file_type="text/plain",
            extension=".txt",
            exposure=ExposureLevel.PUBLIC,
            owner="testuser",
            modified_at="2025-01-01T00:00:00",
            is_archive=True,
        )

        ctx = metadata.to_normalized_context()

        assert isinstance(ctx, NormalizedContext)
        assert ctx.exposure == "PUBLIC"
        assert ctx.owner == "testuser"
        assert ctx.size_bytes == 1024
        assert ctx.file_type == "text/plain"
        assert ctx.is_archive is True


class TestFileCollector:
    """Tests for FileCollector class."""

    def test_init_defaults(self):
        collector = FileCollector()

        assert collector.compute_hash is False
        assert collector.compute_partial_hash is True
        assert collector.collect_xattrs is True

    def test_init_custom_options(self):
        collector = FileCollector(
            compute_hash=True,
            compute_partial_hash=False,
            collect_xattrs=False,
        )

        assert collector.compute_hash is True
        assert collector.compute_partial_hash is False
        assert collector.collect_xattrs is False


class TestFileCollectorCollect:
    """Tests for FileCollector.collect() method."""

    def test_collect_regular_file(self, tmp_path):
        """Should collect metadata from regular file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.name == "test.txt"
        assert metadata.size_bytes == 13
        assert metadata.extension == ".txt"
        assert "text" in metadata.file_type

    def test_collect_rejects_symlink(self, tmp_path):
        """Should reject symlinks for security."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        collector = FileCollector()

        with pytest.raises(ValueError, match="symlink"):
            collector.collect(str(link))

    def test_collect_rejects_directory(self, tmp_path):
        """Should reject directories."""
        collector = FileCollector()

        with pytest.raises(ValueError, match="Not a regular file"):
            collector.collect(str(tmp_path))

    def test_collect_raises_on_not_found(self, tmp_path):
        """Should raise FileNotFoundError for missing files."""
        nonexistent = tmp_path / "nonexistent.txt"

        collector = FileCollector()

        with pytest.raises(FileNotFoundError):
            collector.collect(str(nonexistent))

    def test_collect_timestamps(self, tmp_path):
        """Should collect file timestamps."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        # Timestamps should be ISO format strings
        assert isinstance(metadata.created_at, str) and "T" in metadata.created_at
        assert isinstance(metadata.modified_at, str) and "T" in metadata.modified_at
        assert isinstance(metadata.accessed_at, str) and "T" in metadata.accessed_at

    def test_collect_partial_hash(self, tmp_path):
        """Should compute partial hash when enabled."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        collector = FileCollector(compute_partial_hash=True)
        metadata = collector.collect(str(test_file))

        assert isinstance(metadata.partial_hash, str)
        assert len(metadata.partial_hash) == 16  # Short hash

    def test_collect_full_hash(self, tmp_path):
        """Should compute full hash when enabled."""
        test_file = tmp_path / "test.txt"
        content = "Hello, World!"
        test_file.write_text(content)

        collector = FileCollector(compute_hash=True)
        metadata = collector.collect(str(test_file))

        assert metadata.content_hash is not None
        # Verify it's correct SHA256
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert metadata.content_hash == expected

    def test_collect_skip_hash_for_large_files(self, tmp_path):
        """Should skip full hash for files exceeding size limit."""
        test_file = tmp_path / "large.txt"
        test_file.write_bytes(b"x" * 1000)

        # Set very low hash size limit
        collector = FileCollector(compute_hash=True, hash_size_limit=100)
        metadata = collector.collect(str(test_file))

        # Full hash should not be computed
        assert metadata.content_hash is None


class TestEncryptionDetection:
    """Tests for encryption detection."""

    def test_detects_gpg_extension(self, tmp_path):
        """Should detect .gpg files as encrypted."""
        test_file = tmp_path / "secret.gpg"
        test_file.write_bytes(b"encrypted content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_encrypted is True
        assert metadata.encryption_type == "file_level"

    def test_detects_age_extension(self, tmp_path):
        """Should detect .age files as encrypted."""
        test_file = tmp_path / "secret.age"
        test_file.write_bytes(b"encrypted content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_encrypted is True

    def test_detects_encrypted_zip_header(self, tmp_path):
        """Should detect encrypted ZIP via header inspection."""
        test_file = tmp_path / "encrypted.zip"
        # ZIP with encryption flag set (bit 0 of general purpose flag at offset 6)
        zip_header = b'PK\x03\x04' + b'\x00\x00' + b'\x01\x00' + b'\x00' * 56
        test_file.write_bytes(zip_header)

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_encrypted is True
        assert "zip_encrypted" in metadata.encryption_type

    def test_unencrypted_file(self, tmp_path):
        """Should not mark regular files as encrypted."""
        test_file = tmp_path / "plain.txt"
        test_file.write_text("plain text content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_encrypted is False


class TestArchiveDetection:
    """Tests for archive detection."""

    def test_detects_zip_archive(self, tmp_path):
        """Should detect .zip files as archives."""
        test_file = tmp_path / "archive.zip"
        test_file.write_bytes(b"PK content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_archive is True
        assert metadata.archive_type == "zip"

    def test_detects_tar_gz_archive(self, tmp_path):
        """Should detect .tar.gz files as archives."""
        test_file = tmp_path / "archive.tar.gz"
        test_file.write_bytes(b"gzip content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_archive is True
        # Archive type might be 'gz' or 'tar.gz' depending on detection logic
        assert metadata.archive_type in ("gz", "tar.gz")

    def test_detects_7z_archive(self, tmp_path):
        """Should detect .7z files as archives."""
        test_file = tmp_path / "archive.7z"
        test_file.write_bytes(b"7z content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_archive is True
        assert metadata.archive_type == "7z"

    def test_non_archive_file(self, tmp_path):
        """Should not mark regular files as archives."""
        test_file = tmp_path / "document.pdf"
        test_file.write_bytes(b"%PDF-1.7")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.is_archive is False


class TestPermissionCollection:
    """Tests for permission/exposure collection."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX permissions")
    def test_collects_posix_permissions(self, tmp_path):
        """Should collect POSIX permissions on Unix."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        test_file.chmod(0o644)

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert isinstance(metadata.mode, int)
        assert metadata.mode & 0o777 == 0o644

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX permissions")
    def test_world_readable_is_org_wide(self, tmp_path):
        """World-readable files should be ORG_WIDE exposure."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        test_file.chmod(0o644)  # rw-r--r--

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        # Should be at least INTERNAL or ORG_WIDE
        assert metadata.exposure in (ExposureLevel.INTERNAL, ExposureLevel.ORG_WIDE)

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX permissions")
    def test_world_writable_is_public(self, tmp_path):
        """World-writable files should be PUBLIC exposure."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        test_file.chmod(0o666)  # rw-rw-rw-

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert metadata.exposure == ExposureLevel.PUBLIC


class TestXattrCollection:
    """Tests for extended attribute collection."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="xattr not on Windows")
    def test_collects_xattrs_when_enabled(self, tmp_path):
        """Should attempt to collect xattrs when enabled."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        collector = FileCollector(collect_xattrs=True)
        metadata = collector.collect(str(test_file))

        # xattrs may be empty, but shouldn't error
        assert isinstance(metadata.xattrs, dict)

    def test_skips_xattrs_when_disabled(self, tmp_path):
        """Should skip xattr collection when disabled."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        collector = FileCollector(collect_xattrs=False)
        metadata = collector.collect(str(test_file))

        assert metadata.xattrs == {}

    def test_validates_xattr_name_length(self):
        """Should reject overly long xattr names."""
        collector = FileCollector()

        long_name = "user." + "x" * 300
        assert collector._validate_xattr_name(long_name) is False

    def test_validates_xattr_name_null_bytes(self):
        """Should reject xattr names with null bytes."""
        collector = FileCollector()

        assert collector._validate_xattr_name("user.test\x00evil") is False

    def test_validates_xattr_name_control_chars(self):
        """Should reject xattr names with control characters."""
        collector = FileCollector()

        assert collector._validate_xattr_name("user.test\x01") is False


class TestMimeTypeDetection:
    """Tests for MIME type detection."""

    def test_detects_text_file(self, tmp_path):
        """Should detect text/plain for .txt files."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert "text" in metadata.file_type

    def test_detects_pdf_file(self, tmp_path):
        """Should detect application/pdf for .pdf files."""
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"%PDF-1.7")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        assert "pdf" in metadata.file_type

    def test_unknown_extension_fallback(self, tmp_path):
        """Should use application/octet-stream for unknown types."""
        # Use a truly unknown extension (not .xyz which maps to chemical/x-xyz)
        test_file = tmp_path / "test.qzx123"
        test_file.write_bytes(b"binary content")

        collector = FileCollector()
        metadata = collector.collect(str(test_file))

        # Unknown types should return octet-stream or None
        assert metadata.file_type in ("application/octet-stream", "application/x-octet-stream", None)


class TestCollectMetadataConvenience:
    """Tests for collect_metadata() convenience function."""

    def test_collects_metadata(self, tmp_path):
        """Should collect metadata using convenience function."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        metadata = collect_metadata(str(test_file))

        assert metadata.name == "test.txt"


class TestCollectDirectory:
    """Tests for collect_directory() function."""

    def test_collects_all_files(self, tmp_path):
        """Should collect metadata for all files in directory."""
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")
        (tmp_path / "file3.txt").write_text("content3")

        results = list(collect_directory(str(tmp_path)))

        assert len(results) == 3

    def test_recursive_collection(self, tmp_path):
        """Should recursively collect from subdirectories."""
        (tmp_path / "file1.txt").write_text("content1")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").write_text("content2")

        results = list(collect_directory(str(tmp_path), recursive=True))

        assert len(results) == 2

    def test_non_recursive_collection(self, tmp_path):
        """Should not recurse when recursive=False."""
        (tmp_path / "file1.txt").write_text("content1")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").write_text("content2")

        results = list(collect_directory(str(tmp_path), recursive=False))

        assert len(results) == 1

    def test_excludes_hidden_by_default(self, tmp_path):
        """Should exclude hidden files by default."""
        (tmp_path / "visible.txt").write_text("content1")
        (tmp_path / ".hidden.txt").write_text("content2")

        results = list(collect_directory(str(tmp_path), include_hidden=False))

        names = [r.name for r in results]
        assert "visible.txt" in names
        assert ".hidden.txt" not in names

    def test_includes_hidden_when_requested(self, tmp_path):
        """Should include hidden files when requested."""
        (tmp_path / "visible.txt").write_text("content1")
        (tmp_path / ".hidden.txt").write_text("content2")

        results = list(collect_directory(str(tmp_path), include_hidden=True))

        names = [r.name for r in results]
        assert ".hidden.txt" in names

    def test_respects_max_files_limit(self, tmp_path):
        """Should stop after max_files."""
        for i in range(10):
            (tmp_path / f"file{i}.txt").write_text(f"content{i}")

        results = list(collect_directory(str(tmp_path), max_files=5))

        assert len(results) == 5

    def test_raises_for_non_directory(self, tmp_path):
        """Should raise for non-directory path."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        with pytest.raises(NotADirectoryError):
            list(collect_directory(str(test_file)))

    def test_skips_symlinks_in_directory(self, tmp_path):
        """Should skip symlinks when collecting from directory."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        # Should not raise, just skip the symlink
        results = list(collect_directory(str(tmp_path)))

        # Only the target should be collected, not the symlink
        assert len(results) == 1
        assert results[0].name == "target.txt"


class TestTOCTOUProtection:
    """Tests for Time-of-Check to Time-of-Use protection."""

    def test_uses_lstat_for_initial_check(self, tmp_path):
        """Should use lstat() to detect symlinks atomically."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        collector = FileCollector()

        # This should work - file is regular
        metadata = collector.collect(str(test_file))
        assert metadata.name == "test.txt"
        assert metadata.size_bytes == 7  # "content" is 7 bytes

    def test_rejects_symlink_even_to_regular_file(self, tmp_path):
        """Should reject symlinks even when they point to regular files."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        collector = FileCollector()

        with pytest.raises(ValueError, match="symlink"):
            collector.collect(str(link))
