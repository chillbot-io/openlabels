"""Tests for GCSAdapter — metadata round-trip, generation-based conditional write."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from openlabels.adapters.base import FileInfo, ExposureLevel


# ── GCSAdapter unit tests ────────────────────────────────────────────


class TestGCSAdapterProperties:
    def test_adapter_type(self):
        from openlabels.adapters.gcs import GCSAdapter

        adapter = GCSAdapter(bucket="my-bucket")
        assert adapter.adapter_type == "gcs"

    def test_supports_delta_is_false(self):
        from openlabels.adapters.gcs import GCSAdapter

        adapter = GCSAdapter(bucket="my-bucket")
        assert adapter.supports_delta() is False


class TestGCSLabelCompatibility:
    def test_compatible_extensions(self):
        from openlabels.adapters.base import is_label_compatible

        assert is_label_compatible("report.pdf") is True
        assert is_label_compatible("data.csv") is True
        assert is_label_compatible("doc.docx") is True

    def test_incompatible_extensions(self):
        from openlabels.adapters.base import is_label_compatible

        assert is_label_compatible("binary.bin") is False
        assert is_label_compatible("noext") is False


class TestGCSAdapterListFiles:
    @pytest.mark.asyncio
    async def test_list_files_yields_file_infos(self):
        from openlabels.adapters.gcs import GCSAdapter

        now = datetime.now(timezone.utc)

        blob1 = MagicMock()
        blob1.name = "data/report.pdf"
        blob1.size = 2048
        blob1.updated = now
        blob1.generation = 1001

        blob2 = MagicMock()
        blob2.name = "data/notes.txt"
        blob2.size = 256
        blob2.updated = now
        blob2.generation = 1002

        dir_blob = MagicMock()
        dir_blob.name = "data/subdir/"
        dir_blob.size = 0
        dir_blob.updated = now
        dir_blob.generation = 0

        # GCS list_blobs returns an HTTPIterator with .pages attribute
        mock_blob_iter = MagicMock()
        mock_blob_iter.pages = [[blob1, blob2, dir_blob]]  # one page with all blobs

        mock_bucket = MagicMock()
        mock_bucket.list_blobs.return_value = mock_blob_iter

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket", prefix="data")
        adapter._client = mock_client

        files = []
        async for fi in adapter.list_files(""):
            files.append(fi)

        assert len(files) == 2
        assert files[0].name == "report.pdf"
        assert files[0].path == "gs://my-bucket/data/report.pdf"
        assert files[0].size == 2048
        assert files[0].adapter == "gcs"
        assert files[0].item_id == "data/report.pdf"
        assert files[0].permissions["generation"] == 1001


class TestGCSAdapterReadFile:
    @pytest.mark.asyncio
    async def test_read_file_downloads_content(self):
        from openlabels.adapters.gcs import GCSAdapter

        mock_blob = MagicMock()
        mock_blob.download_as_bytes.return_value = b"gcs file content"

        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="gs://my-bucket/test.txt",
            name="test.txt",
            size=16,
            modified=datetime.now(timezone.utc),
            adapter="gcs",
            item_id="test.txt",
        )

        content = await adapter.read_file(fi)
        assert content == b"gcs file content"
        mock_bucket.blob.assert_called_once_with("test.txt")


class TestGCSAdapterGetMetadata:
    @pytest.mark.asyncio
    async def test_get_metadata_refreshes_from_blob(self):
        from openlabels.adapters.gcs import GCSAdapter

        now = datetime.now(timezone.utc)
        mock_blob = MagicMock()
        mock_blob.size = 4096
        mock_blob.updated = now
        mock_blob.generation = 2001
        mock_blob.metadata = {"openlabels-label-id": "label-1"}
        mock_blob.reload.return_value = None

        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="gs://my-bucket/doc.pdf",
            name="doc.pdf",
            size=1024,
            modified=datetime(2025, 1, 1, tzinfo=timezone.utc),
            adapter="gcs",
            item_id="doc.pdf",
        )

        updated = await adapter.get_metadata(fi)
        assert updated.size == 4096
        assert updated.modified == now
        assert updated.permissions["generation"] == 2001
        assert updated.permissions["metadata"]["openlabels-label-id"] == "label-1"


class TestGCSApplyLabelAndSync:
    @pytest.mark.asyncio
    async def test_apply_label_success(self):
        from openlabels.adapters.gcs import GCSAdapter

        mock_blob = MagicMock()
        mock_blob.generation = 1001
        mock_blob.metadata = {"existing-key": "val"}
        mock_blob.content_type = "application/pdf"
        mock_blob.reload.return_value = None
        mock_blob.upload_from_string.return_value = None

        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="gs://my-bucket/doc.pdf",
            name="doc.pdf",
            size=1024,
            modified=datetime.now(timezone.utc),
            adapter="gcs",
            item_id="doc.pdf",
            permissions={"generation": 1001},
        )

        result = await adapter.apply_label_and_sync(
            fi, label_id="label-uuid", label_name="Confidential", content=b"pdf-bytes"
        )

        assert result["success"] is True
        assert result["method"] == "gcs_metadata"

        # Verify metadata was updated
        assert mock_blob.metadata["openlabels-label-id"] == "label-uuid"
        assert mock_blob.metadata["openlabels-label-name"] == "Confidential"
        assert mock_blob.metadata["existing-key"] == "val"

    @pytest.mark.asyncio
    async def test_apply_label_generation_mismatch(self):
        from openlabels.adapters.gcs import GCSAdapter

        mock_blob = MagicMock()
        mock_blob.generation = 2002  # different from expected
        mock_blob.metadata = {}
        mock_blob.reload.return_value = None

        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="gs://my-bucket/test.txt",
            name="test.txt",
            size=100,
            modified=datetime.now(timezone.utc),
            adapter="gcs",
            item_id="test.txt",
            permissions={"generation": 1001},  # original generation
        )

        result = await adapter.apply_label_and_sync(
            fi, label_id="label-uuid", content=b"content"
        )

        assert result["success"] is False
        assert "Generation mismatch" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_label_incompatible_file(self):
        from openlabels.adapters.gcs import GCSAdapter

        adapter = GCSAdapter(bucket="my-bucket")

        fi = FileInfo(
            path="gs://my-bucket/program.exe",
            name="program.exe",
            size=100,
            modified=datetime.now(timezone.utc),
            adapter="gcs",
            item_id="program.exe",
        )

        result = await adapter.apply_label_and_sync(fi, label_id="label-uuid")

        assert result["success"] is False
        assert result["method"] == "skipped"

    @pytest.mark.asyncio
    async def test_apply_label_conditional_upload_failure(self):
        from openlabels.adapters.gcs import GCSAdapter

        mock_blob = MagicMock()
        mock_blob.generation = 1001
        mock_blob.metadata = {}
        mock_blob.content_type = "text/plain"
        mock_blob.reload.return_value = None
        mock_blob.upload_from_string.side_effect = Exception(
            "conditionNotMet: 412 Precondition Failed"
        )

        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="gs://my-bucket/test.csv",
            name="test.csv",
            size=50,
            modified=datetime.now(timezone.utc),
            adapter="gcs",
            item_id="test.csv",
            permissions={"generation": 1001},
        )

        result = await adapter.apply_label_and_sync(
            fi, label_id="label-uuid", content=b"data"
        )

        assert result["success"] is False
        assert "generation mismatch" in result["error"]


class TestGCSGenerationDiff:
    @pytest.mark.asyncio
    async def test_list_blobs_with_generations(self):
        from openlabels.adapters.gcs import GCSAdapter

        blob1 = MagicMock()
        blob1.name = "a.txt"
        blob1.generation = 100

        blob2 = MagicMock()
        blob2.name = "b.txt"
        blob2.generation = 200

        dir_blob = MagicMock()
        dir_blob.name = "subdir/"
        dir_blob.generation = 0

        mock_bucket = MagicMock()
        mock_bucket.list_blobs.return_value = [blob1, blob2, dir_blob]

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="my-bucket")
        adapter._client = mock_client

        result = await adapter.list_blobs_with_generations()
        assert result == {"a.txt": 100, "b.txt": 200}


class TestGCSResolvePrefix:
    def test_resolve_prefix(self):
        from openlabels.adapters.gcs import GCSAdapter

        adapter = GCSAdapter(bucket="b", prefix="root")
        assert adapter._resolve_prefix("sub") == "root/sub"
        assert adapter._resolve_prefix("") == "root"

        adapter2 = GCSAdapter(bucket="b", prefix="")
        assert adapter2._resolve_prefix("sub") == "sub"
        assert adapter2._resolve_prefix("") == ""
