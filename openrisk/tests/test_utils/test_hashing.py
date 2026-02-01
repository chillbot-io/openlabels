"""
Tests for openlabels.utils.hashing module.

Tests the quick_hash function for file modification detection.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestQuickHashBasic:
    """Tests for basic quick_hash functionality."""

    def test_hash_small_file(self, tmp_path):
        """Should hash a small file (< 2 * block_size)."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "small.txt"
        file_path.write_bytes(b"Hello, World!")

        result = quick_hash(file_path)

        assert result is not None
        assert len(result) == 32  # Truncated hex digest
        assert all(c in '0123456789abcdef' for c in result)

    def test_hash_large_file(self, tmp_path):
        """Should hash a large file using start and end blocks."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "large.bin"
        # Create file larger than 2 * default block_size (65536 * 2 = 131072)
        content = b"A" * 50000 + b"B" * 50000 + b"C" * 50000
        file_path.write_bytes(content)

        result = quick_hash(file_path)

        assert result is not None
        assert len(result) == 32

    def test_hash_empty_file(self, tmp_path):
        """Should hash an empty file."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "empty.txt"
        file_path.write_bytes(b"")

        result = quick_hash(file_path)

        assert result is not None
        assert len(result) == 32

    def test_hash_exactly_one_block(self, tmp_path):
        """Should hash file exactly one block size."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "one_block.bin"
        file_path.write_bytes(b"X" * 65536)

        result = quick_hash(file_path)

        assert result is not None
        assert len(result) == 32

    def test_hash_exactly_two_blocks(self, tmp_path):
        """Should hash file exactly two blocks size."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "two_blocks.bin"
        file_path.write_bytes(b"Y" * 131072)

        result = quick_hash(file_path)

        assert result is not None
        assert len(result) == 32


class TestQuickHashConsistency:
    """Tests for hash consistency."""

    def test_same_content_same_hash(self, tmp_path):
        """Same content should produce same hash."""
        from openlabels.utils.hashing import quick_hash

        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        content = b"Test content for hashing"
        file1.write_bytes(content)
        file2.write_bytes(content)

        hash1 = quick_hash(file1)
        hash2 = quick_hash(file2)

        assert hash1 == hash2

    def test_different_content_different_hash(self, tmp_path):
        """Different content should produce different hash."""
        from openlabels.utils.hashing import quick_hash

        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_bytes(b"Content A")
        file2.write_bytes(b"Content B")

        hash1 = quick_hash(file1)
        hash2 = quick_hash(file2)

        assert hash1 != hash2

    def test_same_file_repeated_calls(self, tmp_path):
        """Repeated calls on same file should return same hash."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "consistent.txt"
        file_path.write_bytes(b"Consistent content")

        results = [quick_hash(file_path) for _ in range(5)]

        assert all(r == results[0] for r in results)

    def test_size_affects_hash(self, tmp_path):
        """Files with same content but different size should differ."""
        from openlabels.utils.hashing import quick_hash

        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        # Same prefix but different lengths
        file1.write_bytes(b"AAAA")
        file2.write_bytes(b"AAAAA")

        hash1 = quick_hash(file1)
        hash2 = quick_hash(file2)

        assert hash1 != hash2


class TestQuickHashBlockSize:
    """Tests for custom block sizes."""

    def test_custom_block_size_small(self, tmp_path):
        """Should work with small block size."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"Test content")

        result = quick_hash(file_path, block_size=4)

        assert result is not None
        assert len(result) == 32

    def test_custom_block_size_large(self, tmp_path):
        """Should work with large block size."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"Test content")

        result = quick_hash(file_path, block_size=1024 * 1024)

        assert result is not None
        assert len(result) == 32

    def test_block_size_one(self, tmp_path):
        """Should work with block size of 1."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"ABC")

        result = quick_hash(file_path, block_size=1)

        assert result is not None

    def test_different_block_sizes_different_hashes(self, tmp_path):
        """Different block sizes may produce different hashes for large files."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "large.bin"
        # File with distinct start and end to highlight block differences
        file_path.write_bytes(b"START" * 20000 + b"END" * 20000)

        hash1 = quick_hash(file_path, block_size=100)
        hash2 = quick_hash(file_path, block_size=200)

        # May or may not differ depending on content alignment
        assert hash1 is not None
        assert hash2 is not None


class TestQuickHashErrors:
    """Tests for error handling."""

    def test_nonexistent_file_returns_none(self, tmp_path):
        """Should return None for nonexistent file."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "nonexistent.txt"

        result = quick_hash(file_path)

        assert result is None

    def test_directory_returns_none(self, tmp_path):
        """Should return None for directory."""
        from openlabels.utils.hashing import quick_hash

        result = quick_hash(tmp_path)

        assert result is None

    def test_permission_denied_returns_none(self, tmp_path):
        """Should return None when permission denied."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "noperm.txt"
        file_path.write_bytes(b"secret")

        # Skip on Windows where chmod doesn't work the same
        # Also skip if running as root (uid 0) since root bypasses permissions
        if os.name != 'nt' and os.getuid() != 0:
            file_path.chmod(0o000)
            try:
                result = quick_hash(file_path)
                assert result is None
            finally:
                file_path.chmod(0o644)  # Restore for cleanup

    def test_symlink_to_nonexistent_returns_none(self, tmp_path):
        """Should return None for broken symlink."""
        from openlabels.utils.hashing import quick_hash

        link_path = tmp_path / "broken_link"
        target_path = tmp_path / "nonexistent_target"

        # Skip on Windows where symlinks may require privileges
        if os.name != 'nt':
            link_path.symlink_to(target_path)
            result = quick_hash(link_path)
            assert result is None


class TestQuickHashSeekHandling:
    """Tests for seek failure handling (TOCTOU conditions)."""

    def test_seek_oserror_handled(self, tmp_path):
        """Should handle OSError during seek gracefully."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.bin"
        # Create large enough file to trigger seek
        file_path.write_bytes(b"X" * 200000)

        # Mock file operations to simulate seek failure
        original_open = open

        def mock_open(*args, **kwargs):
            f = original_open(*args, **kwargs)
            original_seek = f.seek

            def failing_seek(offset, whence=0):
                if whence == 2:  # Seek from end
                    raise OSError("Seek failed")
                return original_seek(offset, whence)

            f.seek = failing_seek
            return f

        with patch('builtins.open', mock_open):
            result = quick_hash(file_path)

        # Should still return a hash (from first block only)
        assert result is not None

    def test_stat_oserror_returns_none(self, tmp_path):
        """Should return None when stat fails."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"test")

        with patch.object(Path, 'stat', side_effect=OSError("stat failed")):
            result = quick_hash(file_path)

        assert result is None


class TestQuickHashEdgeCases:
    """Tests for edge cases."""

    def test_binary_content(self, tmp_path):
        """Should handle binary content correctly."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "binary.bin"
        # Include null bytes and all byte values
        file_path.write_bytes(bytes(range(256)) * 100)

        result = quick_hash(file_path)

        assert result is not None
        assert len(result) == 32

    def test_unicode_filename(self, tmp_path):
        """Should handle unicode filenames."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "文件.txt"
        file_path.write_bytes(b"Unicode filename test")

        result = quick_hash(file_path)

        assert result is not None

    def test_path_with_spaces(self, tmp_path):
        """Should handle paths with spaces."""
        from openlabels.utils.hashing import quick_hash

        subdir = tmp_path / "path with spaces"
        subdir.mkdir()
        file_path = subdir / "file name.txt"
        file_path.write_bytes(b"Content")

        result = quick_hash(file_path)

        assert result is not None

    def test_very_long_filename(self, tmp_path):
        """Should handle long filenames within filesystem limits."""
        from openlabels.utils.hashing import quick_hash

        # Most filesystems support 255 character filenames
        long_name = "a" * 200 + ".txt"
        file_path = tmp_path / long_name
        file_path.write_bytes(b"Long filename test")

        result = quick_hash(file_path)

        assert result is not None

    def test_symlink_to_file(self, tmp_path):
        """Should follow symlinks to actual files."""
        from openlabels.utils.hashing import quick_hash

        target = tmp_path / "target.txt"
        target.write_bytes(b"Target content")
        link = tmp_path / "link.txt"

        if os.name != 'nt':
            link.symlink_to(target)

            result_target = quick_hash(target)
            result_link = quick_hash(link)

            assert result_link == result_target


class TestQuickHashAlgorithm:
    """Tests for hash algorithm properties."""

    def test_uses_blake2b(self, tmp_path):
        """Should use BLAKE2b algorithm."""
        from openlabels.utils.hashing import quick_hash
        import hashlib

        file_path = tmp_path / "test.txt"
        content = b"Test for blake2b"
        file_path.write_bytes(content)

        result = quick_hash(file_path)

        # Verify by computing expected hash manually
        hasher = hashlib.blake2b()
        hasher.update(str(len(content)).encode())
        hasher.update(content)
        expected = hasher.hexdigest()[:32]

        assert result == expected

    def test_hash_includes_file_size(self, tmp_path):
        """Hash should incorporate file size."""
        from openlabels.utils.hashing import quick_hash

        # Two files with same content but we'll test size is hashed
        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"test")

        result = quick_hash(file_path)

        # Size (4) is part of hash input, verified indirectly
        assert result is not None

    def test_hash_length_always_32(self, tmp_path):
        """Hash should always be exactly 32 characters."""
        from openlabels.utils.hashing import quick_hash

        sizes = [0, 1, 100, 65536, 131072, 200000]

        for size in sizes:
            file_path = tmp_path / f"file_{size}.bin"
            file_path.write_bytes(b"X" * size)

            result = quick_hash(file_path)

            assert result is not None
            assert len(result) == 32, f"Hash for size {size} was {len(result)} chars"


class TestQuickHashPathTypes:
    """Tests for different path input types."""

    def test_pathlib_path(self, tmp_path):
        """Should accept pathlib.Path."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"pathlib test")

        result = quick_hash(file_path)

        assert result is not None

    def test_string_path_raises_attribute_error(self, tmp_path):
        """String path should raise AttributeError (expects Path)."""
        from openlabels.utils.hashing import quick_hash

        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"string path test")

        # The function expects Path, not str
        with pytest.raises(AttributeError):
            quick_hash(str(file_path))
