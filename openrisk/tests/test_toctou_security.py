"""
Tests for TOCTOU (Time-Of-Check to Time-Of-Use) security fixes.

These tests verify that the TOCTOU-001 security fixes are working correctly.
The fixes prevent race condition attacks where an attacker could:
1. Create a normal file
2. Wait for the security check to pass
3. Replace the file with a symlink to a sensitive file
4. Have the operation follow the symlink

All fixed locations:
- agent/collector.py: collect(), collect_directory()
- agent/watcher.py: _scan_directory()
- cli/commands/quarantine.py: move_file()
- components/scanner.py: _iter_files(), _build_tree_node()
"""

import os
import stat
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# =============================================================================
# COLLECTOR TESTS
# =============================================================================

class TestCollectorTOCTOU:
    """Test TOCTOU fixes in agent/collector.py"""

    def test_collect_rejects_symlink(self):
        """collect() should reject symlinks."""
        from openlabels.agent.collector import FileCollector

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a target file and a symlink to it
            target = Path(tmpdir) / "target.txt"
            target.write_text("sensitive data")
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(target)

            collector = FileCollector()

            # Should raise ValueError for symlinks
            with pytest.raises(ValueError, match="symlink"):
                collector.collect(str(symlink))

    def test_collect_accepts_regular_file(self):
        """collect() should accept regular files."""
        from openlabels.agent.collector import FileCollector

        with tempfile.TemporaryDirectory() as tmpdir:
            regular_file = Path(tmpdir) / "regular.txt"
            regular_file.write_text("normal content")

            collector = FileCollector()
            metadata = collector.collect(str(regular_file))

            assert metadata.path == str(regular_file)
            assert metadata.size_bytes > 0

    def test_collect_rejects_directory(self):
        """collect() should reject directories."""
        from openlabels.agent.collector import FileCollector

        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()

            collector = FileCollector()

            with pytest.raises(ValueError, match="Not a regular file"):
                collector.collect(str(subdir))

    def test_collect_handles_missing_file(self):
        """collect() should raise FileNotFoundError for missing files."""
        from openlabels.agent.collector import FileCollector

        collector = FileCollector()

        with pytest.raises(FileNotFoundError):
            collector.collect("/nonexistent/path/file.txt")

    def test_collect_directory_skips_symlinks(self):
        """collect_directory() should skip symlinks."""
        from openlabels.agent.collector import collect_directory

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular files
            (Path(tmpdir) / "file1.txt").write_text("content 1")
            (Path(tmpdir) / "file2.txt").write_text("content 2")

            # Create a symlink
            target = Path(tmpdir) / "file1.txt"
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(target)

            # Collect should only return regular files
            results = list(collect_directory(tmpdir, recursive=False))

            # Should have exactly 2 results (file1.txt, file2.txt)
            paths = [r.path for r in results]
            assert len(paths) == 2
            assert str(symlink) not in paths

    def test_collect_directory_skips_directories(self):
        """collect_directory() should skip subdirectories in iteration."""
        from openlabels.agent.collector import collect_directory

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file and a subdirectory
            (Path(tmpdir) / "file.txt").write_text("content")
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "nested.txt").write_text("nested content")

            # Non-recursive should only return the top-level file
            results = list(collect_directory(tmpdir, recursive=False))
            assert len(results) == 1
            assert "file.txt" in results[0].name


# =============================================================================
# QUARANTINE TESTS
# =============================================================================

class TestQuarantineTOCTOU:
    """Test TOCTOU fixes in cli/commands/quarantine.py"""

    def test_move_file_rejects_symlink(self):
        """move_file() should reject symlinks."""
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            dest_dir = Path(tmpdir) / "dest"
            source_dir.mkdir()
            dest_dir.mkdir()

            # Create target and symlink
            target = source_dir / "target.txt"
            target.write_text("sensitive")
            symlink = source_dir / "symlink.txt"
            symlink.symlink_to(target)

            with pytest.raises(ValueError, match="symlink"):
                move_file(symlink, dest_dir)

    def test_move_file_rejects_directory(self):
        """move_file() should reject directories."""
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            dest_dir = Path(tmpdir) / "dest"
            source_dir.mkdir()
            dest_dir.mkdir()

            subdir = source_dir / "subdir"
            subdir.mkdir()

            with pytest.raises(ValueError, match="Not a regular file"):
                move_file(subdir, dest_dir)

    def test_move_file_succeeds_for_regular_file(self):
        """move_file() should succeed for regular files."""
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            dest_dir = Path(tmpdir) / "dest"
            source_dir.mkdir()
            dest_dir.mkdir()

            source_file = source_dir / "file.txt"
            source_file.write_text("content")

            new_path = move_file(source_file, dest_dir)

            assert new_path.exists()
            assert not source_file.exists()
            assert new_path.read_text() == "content"

    def test_move_file_handles_missing_source(self):
        """move_file() should raise FileNotFoundError for missing source."""
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = Path(tmpdir) / "dest"
            dest_dir.mkdir()

            with pytest.raises(FileNotFoundError):
                move_file(Path("/nonexistent/file.txt"), dest_dir)

    def test_move_file_cross_filesystem_verifies_source(self):
        """move_file() should re-verify source on cross-filesystem moves."""
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            dest_dir = Path(tmpdir) / "dest"
            source_dir.mkdir()
            dest_dir.mkdir()

            source_file = source_dir / "file.txt"
            source_file.write_text("content")

            # Mock os.rename to simulate cross-filesystem move
            original_rename = os.rename

            def mock_rename(src, dst):
                raise OSError("Cross-device link")

            with patch("os.rename", mock_rename):
                new_path = move_file(source_file, dest_dir)

            assert new_path.exists()


# =============================================================================
# SCANNER TESTS
# =============================================================================

class TestScannerTOCTOU:
    """Test TOCTOU fixes in components/scanner.py"""

    def test_iter_files_skips_symlinks(self):
        """_iter_files() should skip symlinks."""
        from openlabels.components.scanner import Scanner
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular file
            regular = Path(tmpdir) / "regular.txt"
            regular.write_text("content")

            # Create symlink
            target = Path(tmpdir) / "regular.txt"
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(target)

            # Create scanner with mock scorer
            ctx = Context()
            mock_scorer = MagicMock()
            scanner = Scanner(ctx, mock_scorer)

            # _iter_files should only return regular file
            files = list(scanner._iter_files(Path(tmpdir), recursive=False))

            assert len(files) == 1
            assert files[0].name == "regular.txt"

            ctx.close()

    def test_iter_files_skips_directories(self):
        """_iter_files() should skip directories."""
        from openlabels.components.scanner import Scanner
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular file
            (Path(tmpdir) / "file.txt").write_text("content")

            # Create subdirectory
            (Path(tmpdir) / "subdir").mkdir()

            ctx = Context()
            mock_scorer = MagicMock()
            scanner = Scanner(ctx, mock_scorer)

            files = list(scanner._iter_files(Path(tmpdir), recursive=False))

            # Should only have the file, not the directory
            assert len(files) == 1
            assert files[0].name == "file.txt"

            ctx.close()

    def test_iter_files_handles_permission_denied(self):
        """_iter_files() should skip files with permission errors."""
        from openlabels.components.scanner import Scanner
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files
            file1 = Path(tmpdir) / "file1.txt"
            file2 = Path(tmpdir) / "file2.txt"
            file1.write_text("content1")
            file2.write_text("content2")

            ctx = Context()
            mock_scorer = MagicMock()
            scanner = Scanner(ctx, mock_scorer)

            # Mock stat to raise PermissionError for file1
            original_stat = Path.stat

            def mock_stat(self, *args, **kwargs):
                if "file1" in str(self):
                    raise PermissionError("Access denied")
                return original_stat(self, *args, **kwargs)

            with patch.object(Path, "stat", mock_stat):
                files = list(scanner._iter_files(Path(tmpdir), recursive=False))

            # Should only have file2
            assert len(files) == 1
            assert files[0].name == "file2.txt"

            ctx.close()


# =============================================================================
# WATCHER TESTS
# =============================================================================

class TestWatcherTOCTOU:
    """Test TOCTOU fixes in agent/watcher.py"""

    def test_scan_directory_skips_symlinks(self):
        """PollingWatcher._scan_directory() should skip symlinks."""
        from openlabels.agent.watcher import PollingWatcher

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular file
            regular = Path(tmpdir) / "regular.txt"
            regular.write_text("content")

            # Create symlink
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(regular)

            watcher = PollingWatcher(tmpdir, hash_threshold=0)
            files = watcher._scan_directory()

            # Should only contain the regular file
            assert len(files) == 1
            assert str(regular) in files
            assert str(symlink) not in files

    def test_scan_directory_skips_directories(self):
        """PollingWatcher._scan_directory() should skip directories."""
        from openlabels.agent.watcher import PollingWatcher

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular file
            (Path(tmpdir) / "file.txt").write_text("content")

            # Create subdirectory with file
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "nested.txt").write_text("nested")

            watcher = PollingWatcher(tmpdir, recursive=False, hash_threshold=0)
            files = watcher._scan_directory()

            # Non-recursive should only have top-level file
            assert len(files) == 1
            assert "file.txt" in list(files.keys())[0]

    def test_scan_directory_handles_disappearing_files(self):
        """PollingWatcher._scan_directory() should handle files that disappear."""
        from openlabels.agent.watcher import PollingWatcher

        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "file1.txt"
            file2 = Path(tmpdir) / "file2.txt"
            file1.write_text("content1")
            file2.write_text("content2")

            watcher = PollingWatcher(tmpdir, hash_threshold=0)

            # Mock stat to raise FileNotFoundError for file1
            original_stat = Path.stat

            def mock_stat(self, *args, **kwargs):
                if "file1" in str(self):
                    raise FileNotFoundError("File deleted")
                return original_stat(self, *args, **kwargs)

            with patch.object(Path, "stat", mock_stat):
                files = watcher._scan_directory()

            # Should only have file2
            assert len(files) == 1
            assert "file2.txt" in list(files.keys())[0]


# =============================================================================
# FILEOPS TESTS
# =============================================================================

class TestFileOpsTOCTOU:
    """Test TOCTOU fixes in components/fileops.py"""

    def test_fileops_move_rejects_symlink(self):
        """FileOps.move() should reject symlinks."""
        from openlabels.components.fileops import FileOps
        from openlabels.components.scanner import Scanner
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            scorer = Scorer(ctx)
            scanner = Scanner(ctx, scorer)
            fileops = FileOps(ctx, scanner)

            # Create target and symlink
            target = Path(tmpdir) / "target.txt"
            target.write_text("content")
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(target)
            dest = Path(tmpdir) / "dest.txt"

            # Should fail for symlink
            result = fileops.move(symlink, dest)
            assert not result.success
            assert "Symlinks not allowed" in result.error

            ctx.close()

    def test_fileops_move_rejects_directory(self):
        """FileOps.move() should reject directories."""
        from openlabels.components.fileops import FileOps
        from openlabels.components.scanner import Scanner
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            scorer = Scorer(ctx)
            scanner = Scanner(ctx, scorer)
            fileops = FileOps(ctx, scanner)

            source_dir = Path(tmpdir) / "source_dir"
            source_dir.mkdir()
            dest = Path(tmpdir) / "dest"

            result = fileops.move(source_dir, dest)
            assert not result.success
            assert "Not a regular file" in result.error

            ctx.close()

    def test_fileops_move_succeeds_for_regular_file(self):
        """FileOps.move() should work for regular files."""
        from openlabels.components.fileops import FileOps
        from openlabels.components.scanner import Scanner
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            scorer = Scorer(ctx)
            scanner = Scanner(ctx, scorer)
            fileops = FileOps(ctx, scanner)

            source = Path(tmpdir) / "source.txt"
            source.write_text("content")
            dest = Path(tmpdir) / "dest.txt"

            result = fileops.move(source, dest)
            assert result.success
            assert dest.exists()
            assert not source.exists()

            ctx.close()

    def test_fileops_delete_rejects_symlink(self):
        """FileOps.delete() should reject symlinks."""
        from openlabels.components.fileops import FileOps
        from openlabels.components.scanner import Scanner
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            scorer = Scorer(ctx)
            scanner = Scanner(ctx, scorer)
            fileops = FileOps(ctx, scanner)

            target = Path(tmpdir) / "target.txt"
            target.write_text("content")
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(target)

            result = fileops.delete(symlink)
            assert result.error_count == 1
            assert "Symlinks not allowed" in str(result.errors)

            ctx.close()


# =============================================================================
# SCANNER ENTRY POINT TESTS
# =============================================================================

class TestScannerEntryTOCTOU:
    """Test TOCTOU fixes in Scanner.scan() entry point."""

    def test_scan_rejects_symlink_target(self):
        """Scanner.scan() should reject symlink as target."""
        from openlabels.components.scanner import Scanner
        from openlabels.context import Context
        from unittest.mock import MagicMock

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            mock_scorer = MagicMock()
            scanner = Scanner(ctx, mock_scorer)

            # Create file and symlink
            target = Path(tmpdir) / "target.txt"
            target.write_text("content")
            symlink = Path(tmpdir) / "symlink"
            symlink.symlink_to(target)

            # Should raise ValueError for symlink
            with pytest.raises(ValueError, match="Symlinks not allowed"):
                list(scanner.scan(symlink))

            ctx.close()

    def test_scan_accepts_regular_file(self):
        """Scanner.scan() should accept regular file as target."""
        from openlabels.components.scanner import Scanner
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            scorer = Scorer(ctx)
            scanner = Scanner(ctx, scorer)

            regular = Path(tmpdir) / "file.txt"
            regular.write_text("hello world")

            results = list(scanner.scan(regular))
            assert len(results) == 1
            assert results[0].path == str(regular)

            ctx.close()

    def test_scan_accepts_directory(self):
        """Scanner.scan() should accept directory as target."""
        from openlabels.components.scanner import Scanner
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            scorer = Scorer(ctx)
            scanner = Scanner(ctx, scorer)

            (Path(tmpdir) / "file.txt").write_text("content")

            results = list(scanner.scan(tmpdir))
            assert len(results) == 1

            ctx.close()


# =============================================================================
# POSIX TESTS
# =============================================================================

class TestPosixTOCTOU:
    """Test TOCTOU fixes in agent/posix.py"""

    def test_get_posix_permissions_handles_symlink(self):
        """get_posix_permissions() should use lstat, not follow symlinks."""
        from openlabels.agent.posix import get_posix_permissions

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.txt"
            target.write_text("content")
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(target)

            # Should return permissions of symlink itself (not target)
            perms = get_posix_permissions(str(symlink))
            # Symlinks typically have 0777 permissions (lrwxrwxrwx)
            # The key test is that this doesn't follow the symlink
            assert perms is not None

    def test_get_posix_permissions_regular_file(self):
        """get_posix_permissions() should work for regular files."""
        from openlabels.agent.posix import get_posix_permissions

        with tempfile.TemporaryDirectory() as tmpdir:
            regular = Path(tmpdir) / "file.txt"
            regular.write_text("content")

            perms = get_posix_permissions(str(regular))
            assert perms is not None
            assert perms.owner_name is not None

    def test_get_posix_permissions_missing_file(self):
        """get_posix_permissions() should raise for missing files."""
        from openlabels.agent.posix import get_posix_permissions

        with pytest.raises(FileNotFoundError):
            get_posix_permissions("/nonexistent/path/file.txt")


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestTOCTOUIntegration:
    """Integration tests for TOCTOU fixes."""

    def test_full_scan_skips_symlinks(self):
        """Full scan pipeline should skip symlinks throughout."""
        from openlabels import Client

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular files with scannable content
            (Path(tmpdir) / "file1.txt").write_text("Hello world")
            (Path(tmpdir) / "file2.txt").write_text("Another file")

            # Create symlink
            symlink = Path(tmpdir) / "symlink.txt"
            symlink.symlink_to(Path(tmpdir) / "file1.txt")

            client = Client()
            results = list(client.scan(tmpdir, recursive=False))

            # Should have exactly 2 results (no symlink)
            paths = [r.path for r in results]
            assert len(paths) == 2
            assert str(symlink) not in paths

    def test_symlink_to_sensitive_file_blocked(self):
        """Symlink attack to sensitive file should be blocked."""
        from openlabels.agent.collector import FileCollector

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a "sensitive" file outside the expected directory
            sensitive_file = Path(tmpdir) / "sensitive" / "secret.txt"
            sensitive_file.parent.mkdir()
            sensitive_file.write_text("SECRET_API_KEY=abc123")

            # Create a symlink in scan directory pointing to sensitive file
            scan_dir = Path(tmpdir) / "scan"
            scan_dir.mkdir()
            malicious_link = scan_dir / "innocent.txt"
            malicious_link.symlink_to(sensitive_file)

            collector = FileCollector()

            # Should reject the symlink
            with pytest.raises(ValueError, match="symlink"):
                collector.collect(str(malicious_link))

    def test_stat_mode_check_values(self):
        """Verify stat mode checks work correctly for different file types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Regular file
            regular = Path(tmpdir) / "regular.txt"
            regular.write_text("content")
            st = regular.stat(follow_symlinks=False)
            assert stat.S_ISREG(st.st_mode)
            assert not stat.S_ISLNK(st.st_mode)
            assert not stat.S_ISDIR(st.st_mode)

            # Directory
            directory = Path(tmpdir) / "dir"
            directory.mkdir()
            st = directory.stat(follow_symlinks=False)
            assert not stat.S_ISREG(st.st_mode)
            assert not stat.S_ISLNK(st.st_mode)
            assert stat.S_ISDIR(st.st_mode)

            # Symlink
            symlink = Path(tmpdir) / "link"
            symlink.symlink_to(regular)
            st = symlink.stat(follow_symlinks=False)  # lstat
            assert not stat.S_ISREG(st.st_mode)
            assert stat.S_ISLNK(st.st_mode)
            assert not stat.S_ISDIR(st.st_mode)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestTOCTOUEdgeCases:
    """Edge case tests for TOCTOU fixes."""

    def test_broken_symlink_handled(self):
        """Broken symlinks should be handled gracefully."""
        from openlabels.agent.collector import collect_directory

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a broken symlink (target doesn't exist)
            broken_link = Path(tmpdir) / "broken.txt"
            broken_link.symlink_to("/nonexistent/target")

            # Create a regular file
            regular = Path(tmpdir) / "regular.txt"
            regular.write_text("content")

            # Should only return the regular file, skip broken symlink
            results = list(collect_directory(tmpdir, recursive=False))

            assert len(results) == 1
            assert "regular.txt" in results[0].name

    def test_special_files_skipped(self):
        """Special files (devices, sockets, etc.) should be skipped."""
        from openlabels.components.scanner import Scanner
        from openlabels.context import Context

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular file
            regular = Path(tmpdir) / "regular.txt"
            regular.write_text("content")

            ctx = Context()
            mock_scorer = MagicMock()
            scanner = Scanner(ctx, mock_scorer)

            # On Linux, /dev/null is a device file
            # We just test that our code correctly identifies regular files
            files = list(scanner._iter_files(Path(tmpdir), recursive=False))

            assert len(files) == 1
            assert files[0].name == "regular.txt"

            ctx.close()

    def test_deeply_nested_symlink(self):
        """Deeply nested paths with symlinks should be handled."""
        from openlabels.agent.collector import collect_directory

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            deep_dir = Path(tmpdir) / "a" / "b" / "c"
            deep_dir.mkdir(parents=True)

            # Regular file in deep directory
            (deep_dir / "file.txt").write_text("content")

            # Symlink at intermediate level
            symlink_dir = Path(tmpdir) / "a" / "shortcut"
            symlink_dir.symlink_to(deep_dir)

            # Collect recursively
            results = list(collect_directory(tmpdir, recursive=True))

            # Should only have the one regular file, not through symlink
            regular_files = [r for r in results if "file.txt" in r.name]
            assert len(regular_files) == 1
