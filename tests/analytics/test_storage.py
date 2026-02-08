"""Tests for CatalogStorage protocol and LocalStorage backend."""

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from openlabels.analytics.storage import CatalogStorage, LocalStorage, create_storage


class TestLocalStorage:
    def test_write_and_read_roundtrip(self, storage: LocalStorage):
        table = pa.table({"x": [1, 2, 3], "y": ["a", "b", "c"]})
        storage.write_parquet("test/data.parquet", table)

        result = storage.read_parquet("test/data.parquet")
        assert result.num_rows == 3
        assert result.column("x").to_pylist() == [1, 2, 3]
        assert result.column("y").to_pylist() == ["a", "b", "c"]

    def test_write_creates_parent_dirs(self, storage: LocalStorage):
        table = pa.table({"v": [42]})
        storage.write_parquet("a/b/c/deep.parquet", table)
        assert storage.exists("a/b/c/deep.parquet")

    def test_exists_returns_false_for_missing(self, storage: LocalStorage):
        assert not storage.exists("nonexistent.parquet")

    def test_exists_returns_true_for_file(self, storage: LocalStorage):
        table = pa.table({"v": [1]})
        storage.write_parquet("x.parquet", table)
        assert storage.exists("x.parquet")

    def test_delete_file(self, storage: LocalStorage):
        table = pa.table({"v": [1]})
        storage.write_parquet("del.parquet", table)
        assert storage.exists("del.parquet")
        storage.delete("del.parquet")
        assert not storage.exists("del.parquet")

    def test_delete_directory(self, storage: LocalStorage):
        table = pa.table({"v": [1]})
        storage.write_parquet("dir/a.parquet", table)
        storage.write_parquet("dir/b.parquet", table)
        storage.delete("dir")
        assert not storage.exists("dir")

    def test_list_partitions(self, storage: LocalStorage):
        table = pa.table({"v": [1]})
        storage.write_parquet("root/part_a/data.parquet", table)
        storage.write_parquet("root/part_b/data.parquet", table)
        storage.write_parquet("root/part_c/data.parquet", table)

        parts = storage.list_partitions("root")
        assert parts == ["part_a", "part_b", "part_c"]

    def test_list_partitions_empty(self, storage: LocalStorage):
        assert storage.list_partitions("nonexistent") == []

    def test_root_property(self, storage: LocalStorage):
        assert storage.root  # non-empty string

    def test_compression_zstd(self, storage: LocalStorage):
        table = pa.table({"v": list(range(1000))})
        storage.write_parquet("zstd.parquet", table, compression="zstd")
        result = storage.read_parquet("zstd.parquet")
        assert result.num_rows == 1000

    def test_implements_protocol(self, storage: LocalStorage):
        assert isinstance(storage, CatalogStorage)

    def test_write_and_read_bytes(self, storage: LocalStorage):
        data = b'{"version": 1, "cursor": "2026-02-08T12:00:00"}'
        storage.write_bytes("_metadata/flush_state.json", data)
        result = storage.read_bytes("_metadata/flush_state.json")
        assert result == data

    def test_read_bytes_creates_parents(self, storage: LocalStorage):
        data = b"test"
        storage.write_bytes("deep/nested/dir/file.json", data)
        assert storage.read_bytes("deep/nested/dir/file.json") == data


    def test_read_json_write_json_roundtrip(self, storage: LocalStorage):
        data = {"schema_version": 1, "last_flush": "2026-02-01T12:00:00+00:00"}
        storage.write_json("meta/state.json", data)

        loaded = storage.read_json("meta/state.json")
        assert loaded["schema_version"] == 1
        assert loaded["last_flush"] == "2026-02-01T12:00:00+00:00"

    def test_read_json_nonexistent_raises(self, storage: LocalStorage):
        with pytest.raises(FileNotFoundError):
            storage.read_json("does_not_exist.json")

    def test_write_json_creates_parent_dirs(self, storage: LocalStorage):
        storage.write_json("a/b/c/deep.json", {"key": "val"})
        assert storage.exists("a/b/c/deep.json")
        loaded = storage.read_json("a/b/c/deep.json")
        assert loaded["key"] == "val"

    def test_write_json_overwrite(self, storage: LocalStorage):
        storage.write_json("s.json", {"v": 1})
        storage.write_json("s.json", {"v": 2})
        assert storage.read_json("s.json")["v"] == 2


class TestCreateStorage:
    def test_local_backend(self, catalog_dir):
        class FakeSettings:
            backend = "local"
            local_path = str(catalog_dir)

        s = create_storage(FakeSettings())
        assert isinstance(s, LocalStorage)

    def test_local_backend_no_path_raises(self):
        class FakeSettings:
            backend = "local"
            local_path = ""

        with pytest.raises(ValueError, match="local_path"):
            create_storage(FakeSettings())

    def test_unsupported_backend_raises(self):
        class FakeSettings:
            backend = "gcs"
            local_path = ""

        with pytest.raises(ValueError, match="Unsupported"):
            create_storage(FakeSettings())
