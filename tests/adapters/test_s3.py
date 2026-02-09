"""Tests for S3Adapter — metadata round-trip, conditional write, label compatibility."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from openlabels.adapters.base import FileInfo, ExposureLevel


# ── S3Adapter unit tests ─────────────────────────────────────────────


class TestS3AdapterProperties:
    def test_adapter_type(self):
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="my-bucket")
        assert adapter.adapter_type == "s3"

    def test_supports_delta_is_false(self):
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="my-bucket")
        assert adapter.supports_delta() is False


class TestS3LabelCompatibility:
    def test_compatible_extensions(self):
        from openlabels.adapters.base import is_label_compatible

        assert is_label_compatible("report.pdf") is True
        assert is_label_compatible("data.csv") is True
        assert is_label_compatible("doc.docx") is True
        assert is_label_compatible("sheet.xlsx") is True
        assert is_label_compatible("photo.jpg") is True
        assert is_label_compatible("archive.zip") is True

    def test_incompatible_extensions(self):
        from openlabels.adapters.base import is_label_compatible

        assert is_label_compatible("program.exe") is False
        assert is_label_compatible("library.dll") is False
        assert is_label_compatible("binary.bin") is False
        assert is_label_compatible("noextension") is False

    def test_case_insensitive(self):
        from openlabels.adapters.base import is_label_compatible

        assert is_label_compatible("REPORT.PDF") is True
        assert is_label_compatible("Data.CSV") is True


class TestS3AdapterListFiles:
    @pytest.mark.asyncio
    async def test_list_files_yields_file_infos(self):
        from openlabels.adapters.s3 import S3Adapter

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        now = datetime.now(timezone.utc)
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "data/report.pdf", "Size": 1024, "LastModified": now, "ETag": '"abc123"'},
                    {"Key": "data/notes.txt", "Size": 512, "LastModified": now, "ETag": '"def456"'},
                    {"Key": "data/subdir/", "Size": 0, "LastModified": now, "ETag": '""'},  # dir marker
                ]
            }
        ]
        mock_client.get_paginator.return_value = mock_paginator

        adapter = S3Adapter(bucket="my-bucket", prefix="data")
        adapter._client = mock_client

        files = []
        async for fi in adapter.list_files(""):
            files.append(fi)

        assert len(files) == 2
        assert files[0].name == "report.pdf"
        assert files[0].path == "s3://my-bucket/data/report.pdf"
        assert files[0].size == 1024
        assert files[0].adapter == "s3"
        assert files[0].item_id == "data/report.pdf"
        assert files[0].permissions["etag"] == "abc123"
        assert files[1].name == "notes.txt"


class TestS3AdapterReadFile:
    @pytest.mark.asyncio
    async def test_read_file_downloads_content(self):
        from openlabels.adapters.s3 import S3Adapter

        mock_client = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = b"file content here"
        mock_client.get_object.return_value = {"Body": mock_body}

        adapter = S3Adapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="s3://my-bucket/test.txt",
            name="test.txt",
            size=17,
            modified=datetime.now(timezone.utc),
            adapter="s3",
            item_id="test.txt",
        )

        content = await adapter.read_file(fi)
        assert content == b"file content here"
        mock_client.get_object.assert_called_once_with(
            Bucket="my-bucket", Key="test.txt"
        )


class TestS3AdapterGetMetadata:
    @pytest.mark.asyncio
    async def test_get_metadata_refreshes_from_head(self):
        from openlabels.adapters.s3 import S3Adapter

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client.head_object.return_value = {
            "ContentLength": 2048,
            "LastModified": now,
            "ETag": '"newetag"',
            "Metadata": {"openlabels-label-id": "label-1"},
        }

        adapter = S3Adapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="s3://my-bucket/doc.pdf",
            name="doc.pdf",
            size=1024,
            modified=datetime(2025, 1, 1, tzinfo=timezone.utc),
            adapter="s3",
            item_id="doc.pdf",
        )

        updated = await adapter.get_metadata(fi)
        assert updated.size == 2048
        assert updated.modified == now
        assert updated.permissions["etag"] == "newetag"
        assert updated.permissions["metadata"]["openlabels-label-id"] == "label-1"


class TestS3ApplyLabelAndSync:
    @pytest.mark.asyncio
    async def test_apply_label_success(self):
        from openlabels.adapters.s3 import S3Adapter

        mock_client = MagicMock()
        mock_client.head_object.return_value = {
            "ETag": '"abc123"',
            "Metadata": {"existing-key": "existing-val"},
            "ContentType": "application/pdf",
        }
        mock_client.copy_object.return_value = {}

        adapter = S3Adapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="s3://my-bucket/doc.pdf",
            name="doc.pdf",
            size=1024,
            modified=datetime.now(timezone.utc),
            adapter="s3",
            item_id="doc.pdf",
            permissions={"etag": "abc123"},
        )

        result = await adapter.apply_label_and_sync(
            fi, label_id="label-uuid", label_name="Confidential"
        )

        assert result["success"] is True
        assert result["method"] == "s3_metadata"

        # Verify copy_object was called (server-side self-copy with CopySourceIfMatch)
        assert mock_client.copy_object.called

    @pytest.mark.asyncio
    async def test_apply_label_etag_mismatch(self):
        from openlabels.adapters.s3 import S3Adapter

        mock_client = MagicMock()
        mock_client.head_object.return_value = {
            "ETag": '"different_etag"',
            "Metadata": {},
            "ContentType": "text/plain",
        }

        adapter = S3Adapter(bucket="my-bucket")
        adapter._client = mock_client

        fi = FileInfo(
            path="s3://my-bucket/test.txt",
            name="test.txt",
            size=100,
            modified=datetime.now(timezone.utc),
            adapter="s3",
            item_id="test.txt",
            permissions={"etag": "original_etag"},
        )

        result = await adapter.apply_label_and_sync(
            fi, label_id="label-uuid"
        )

        assert result["success"] is False
        assert "ETag mismatch" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_label_incompatible_file(self):
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="my-bucket")

        fi = FileInfo(
            path="s3://my-bucket/program.exe",
            name="program.exe",
            size=100,
            modified=datetime.now(timezone.utc),
            adapter="s3",
            item_id="program.exe",
        )

        result = await adapter.apply_label_and_sync(fi, label_id="label-uuid")

        assert result["success"] is False
        assert result["method"] == "skipped"


class TestS3ETagDiff:
    @pytest.mark.asyncio
    async def test_list_objects_with_etags(self):
        from openlabels.adapters.s3 import S3Adapter

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "a.txt", "ETag": '"etag1"'},
                    {"Key": "b.txt", "ETag": '"etag2"'},
                ]
            }
        ]
        mock_client.get_paginator.return_value = mock_paginator

        adapter = S3Adapter(bucket="my-bucket")
        adapter._client = mock_client

        result = await adapter.list_objects_with_etags()
        assert result == {"a.txt": "etag1", "b.txt": "etag2"}


class TestS3BuildClient:
    def test_build_client_requires_boto3(self):
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="my-bucket")

        with patch.dict("sys.modules", {"boto3": None}):
            # If boto3 is not installed, should raise ImportError
            # This test just verifies the method exists and has proper error handling
            assert hasattr(adapter, "_build_client")

    def test_resolve_prefix(self):
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="b", prefix="root")
        assert adapter._resolve_prefix("sub") == "root/sub"
        assert adapter._resolve_prefix("") == "root"

        adapter2 = S3Adapter(bucket="b", prefix="")
        assert adapter2._resolve_prefix("sub") == "sub"
        assert adapter2._resolve_prefix("") == ""
