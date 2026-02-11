"""Tests for directory_tree_to_arrow conversion."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from openlabels.analytics.arrow_convert import _uuid_bytes, directory_tree_to_arrow
from openlabels.analytics.schemas import DIRECTORY_TREE_SCHEMA


@dataclass
class FakeDirectoryTree:
    """Minimal mock that quacks like an ORM DirectoryTree."""

    id: UUID
    tenant_id: UUID
    target_id: UUID
    dir_path: str
    dir_name: str
    parent_id: Optional[UUID] = None
    dir_ref: Optional[int] = None
    parent_ref: Optional[int] = None
    sd_hash: Optional[bytes] = None
    share_id: Optional[UUID] = None
    dir_modified: Optional[datetime] = None
    child_dir_count: Optional[int] = None
    child_file_count: Optional[int] = None
    flags: int = 0
    discovered_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


def _make_fake(**overrides) -> FakeDirectoryTree:
    defaults = dict(
        id=uuid4(),
        tenant_id=uuid4(),
        target_id=uuid4(),
        dir_path="/data/test",
        dir_name="test",
        parent_id=uuid4(),
        dir_ref=12345,
        parent_ref=100,
        sd_hash=b"\x00" * 32,
        share_id=None,
        dir_modified=datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc),
        child_dir_count=3,
        child_file_count=10,
        flags=0,
        discovered_at=datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc),
        updated_at=datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return FakeDirectoryTree(**defaults)


class TestDirectoryTreeToArrow:

    def test_basic_conversion(self):
        rows = [_make_fake(), _make_fake(dir_path="/data/other", dir_name="other")]
        table = directory_tree_to_arrow(rows)

        assert isinstance(table, pa.Table)
        assert table.num_rows == 2

    def test_schema_matches(self):
        table = directory_tree_to_arrow([_make_fake()])
        assert table.schema.equals(DIRECTORY_TREE_SCHEMA)

    def test_empty_input(self):
        table = directory_tree_to_arrow([])
        assert table.num_rows == 0
        assert table.schema.equals(DIRECTORY_TREE_SCHEMA)

    def test_uuid_binary_encoding(self):
        uid = uuid4()
        table = directory_tree_to_arrow([_make_fake(id=uid)])

        raw = table.column("id")[0].as_py()
        assert raw == uid.bytes
        assert UUID(bytes=raw) == uid

    def test_nullable_parent_id(self):
        """parent_id can be None (root directories)."""
        table = directory_tree_to_arrow([_make_fake(parent_id=None)])

        assert table.column("parent_id")[0].as_py() is None

    def test_nullable_share_id(self):
        table = directory_tree_to_arrow([_make_fake(share_id=None)])
        assert table.column("share_id")[0].as_py() is None

    def test_share_id_when_set(self):
        sid = uuid4()
        table = directory_tree_to_arrow([_make_fake(share_id=sid)])
        assert UUID(bytes=table.column("share_id")[0].as_py()) == sid

    def test_sd_hash_none(self):
        table = directory_tree_to_arrow([_make_fake(sd_hash=None)])
        assert table.column("sd_hash")[0].as_py() is None

    def test_sd_hash_32_bytes(self):
        h = b"\xab" * 32
        table = directory_tree_to_arrow([_make_fake(sd_hash=h)])
        assert table.column("sd_hash")[0].as_py() == h

    def test_timestamp_timezone_handling(self):
        """Naive datetimes should get UTC attached by _ts()."""
        naive = datetime(2024, 1, 1, 12, 0, 0)
        table = directory_tree_to_arrow([_make_fake(dir_modified=naive)])

        ts = table.column("dir_modified")[0].as_py()
        assert ts.tzinfo is not None

    def test_null_timestamps(self):
        table = directory_tree_to_arrow([
            _make_fake(dir_modified=None, discovered_at=None, updated_at=None)
        ])
        assert table.column("dir_modified")[0].as_py() is None

    def test_integer_fields_preserved(self):
        table = directory_tree_to_arrow([
            _make_fake(dir_ref=99999, parent_ref=88888,
                       child_dir_count=42, child_file_count=100, flags=7)
        ])

        assert table.column("dir_ref")[0].as_py() == 99999
        assert table.column("parent_ref")[0].as_py() == 88888
        assert table.column("child_dir_count")[0].as_py() == 42
        assert table.column("child_file_count")[0].as_py() == 100
        assert table.column("flags")[0].as_py() == 7

    def test_null_integer_fields(self):
        table = directory_tree_to_arrow([
            _make_fake(dir_ref=None, parent_ref=None,
                       child_dir_count=None, child_file_count=None)
        ])
        assert table.column("dir_ref")[0].as_py() is None
        assert table.column("child_dir_count")[0].as_py() is None

    def test_string_fields_preserved(self):
        table = directory_tree_to_arrow([
            _make_fake(dir_path="/long/nested/path", dir_name="path")
        ])
        assert table.column("dir_path")[0].as_py() == "/long/nested/path"
        assert table.column("dir_name")[0].as_py() == "path"

    def test_parquet_roundtrip(self, tmp_path):
        """Write to Parquet and read back — data survives roundtrip."""
        rows = [
            _make_fake(dir_path="/a", dir_name="a", dir_ref=1),
            _make_fake(dir_path="/b", dir_name="b", dir_ref=2, parent_id=None),
        ]
        table = directory_tree_to_arrow(rows)

        path = tmp_path / "dirtree.parquet"
        pq.write_table(table, path)
        loaded = pq.read_table(path)

        assert loaded.num_rows == 2
        assert loaded.column("dir_path")[0].as_py() == "/a"
        assert loaded.column("dir_path")[1].as_py() == "/b"
        assert loaded.column("dir_ref")[0].as_py() == 1
        # parent_id should be None for second row
        assert loaded.column("parent_id")[1].as_py() is None

    def test_multiple_rows_all_fields(self):
        """Stress: 100 rows convert without error."""
        rows = [_make_fake(dir_path=f"/d/{i}", dir_name=str(i)) for i in range(100)]
        table = directory_tree_to_arrow(rows)
        assert table.num_rows == 100
        assert table.schema.equals(DIRECTORY_TREE_SCHEMA)
