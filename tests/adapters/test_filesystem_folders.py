"""Tests for filesystem adapter list_folders / _collect_folder_info."""

import os
import tempfile
from pathlib import Path

import pytest

from openlabels.adapters.base import FolderInfo
from openlabels.adapters.filesystem import FilesystemAdapter


class TestListFolders:

    async def test_yields_root_directory_first(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            folders = []
            async for f in adapter.list_folders(tmpdir):
                folders.append(f)

            # Empty dir should yield exactly one folder (the root itself)
            assert len(folders) == 1
            assert folders[0].path == str(Path(tmpdir).absolute())
            assert folders[0].adapter == "filesystem"

    async def test_yields_all_subdirectories_recursively(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a").mkdir()
            (Path(tmpdir) / "a" / "b").mkdir()
            (Path(tmpdir) / "c").mkdir()

            folders = []
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders.append(f)

            names = {f.name for f in folders}
            # root + a + b + c
            assert len(folders) == 4
            assert "a" in names
            assert "b" in names
            assert "c" in names

    async def test_non_recursive_yields_only_root(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "child").mkdir()

            folders = []
            async for f in adapter.list_folders(tmpdir, recursive=False):
                folders.append(f)

            assert len(folders) == 1
            assert folders[0].path == str(Path(tmpdir).absolute())

    async def test_inode_is_populated(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            folders = []
            async for f in adapter.list_folders(tmpdir):
                folders.append(f)

            root = folders[0]
            assert root.inode is not None
            assert isinstance(root.inode, int)
            assert root.inode == Path(tmpdir).stat().st_ino

    async def test_parent_inode_is_populated(self):
        """Regression: parent_inode was never set before the fix."""
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "child").mkdir()

            folders = {}
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders[f.name] = f

            child = folders["child"]
            assert child.parent_inode is not None
            assert isinstance(child.parent_inode, int)
            # Child's parent_inode must equal the root's inode
            root_inode = Path(tmpdir).stat().st_ino
            assert child.parent_inode == root_inode

    async def test_parent_inode_differs_from_self_inode(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "sub").mkdir()

            folders = {}
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders[f.name] = f

            sub = folders["sub"]
            assert sub.inode != sub.parent_inode

    async def test_child_counts_are_accurate(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "dir_a").mkdir()
            (Path(tmpdir) / "dir_b").mkdir()
            (Path(tmpdir) / "file1.txt").write_text("x")
            (Path(tmpdir) / "file2.txt").write_text("y")
            (Path(tmpdir) / "file3.txt").write_text("z")

            folders = {}
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders[f.name] = f

            root = [f for f in folders.values() if f.path == str(Path(tmpdir).absolute())][0]
            assert root.child_dir_count == 2
            assert root.child_file_count == 3

    async def test_empty_directory_has_zero_children(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "empty").mkdir()

            folders = {}
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders[f.name] = f

            assert folders["empty"].child_dir_count == 0
            assert folders["empty"].child_file_count == 0

    async def test_modified_timestamp_matches_stat(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            folders = []
            async for f in adapter.list_folders(tmpdir):
                folders.append(f)

            assert folders[0].modified is not None
            # Verify modified time is close to the actual stat mtime
            from datetime import datetime, timezone
            actual_mtime = datetime.fromtimestamp(
                Path(tmpdir).stat().st_mtime, tz=timezone.utc
            )
            assert folders[0].modified == actual_mtime

    async def test_name_is_basename(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "mydir").mkdir()

            folders = {}
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders[f.name] = f

            assert "mydir" in folders
            # name should be just "mydir", not the full path
            assert "/" not in folders["mydir"].name

    async def test_adapter_field_is_filesystem(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            async for f in adapter.list_folders(tmpdir):
                assert f.adapter == "filesystem"

    async def test_raises_on_nonexistent_path(self):
        from openlabels.exceptions import FilesystemError

        adapter = FilesystemAdapter()
        with pytest.raises(FilesystemError, match="does not exist"):
            async for _ in adapter.list_folders("/nonexistent/path/12345"):
                pass

    async def test_raises_on_file_path(self):
        from openlabels.exceptions import FilesystemError

        adapter = FilesystemAdapter()
        with tempfile.NamedTemporaryFile() as f:
            with pytest.raises(FilesystemError, match="not a directory"):
                async for _ in adapter.list_folders(f.name):
                    pass

    async def test_deep_nesting_parent_chain(self):
        """Each directory's parent_inode should match its parent's inode."""
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a" / "b" / "c").mkdir(parents=True)

            folders = {}
            async for f in adapter.list_folders(tmpdir, recursive=True):
                folders[f.path] = f

            a_path = str((Path(tmpdir) / "a").absolute())
            b_path = str((Path(tmpdir) / "a" / "b").absolute())
            c_path = str((Path(tmpdir) / "a" / "b" / "c").absolute())

            # b's parent_inode == a's inode
            assert folders[b_path].parent_inode == folders[a_path].inode
            # c's parent_inode == b's inode
            assert folders[c_path].parent_inode == folders[b_path].inode


class TestCollectFolderInfo:

    def test_child_dirs_returned_separately(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "sub1").mkdir()
            (Path(tmpdir) / "sub2").mkdir()
            (Path(tmpdir) / "file.txt").write_text("x")

            info, child_dirs = adapter._collect_folder_info(Path(tmpdir))

            assert len(child_dirs) == 2
            child_names = {d.name for d in child_dirs}
            assert child_names == {"sub1", "sub2"}

    def test_inode_matches_stat(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            info, _ = adapter._collect_folder_info(Path(tmpdir))
            assert info.inode == Path(tmpdir).stat().st_ino

    def test_parent_inode_matches_parent_stat(self):
        adapter = FilesystemAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            child = Path(tmpdir) / "child"
            child.mkdir()

            info, _ = adapter._collect_folder_info(child)
            assert info.parent_inode == Path(tmpdir).stat().st_ino
