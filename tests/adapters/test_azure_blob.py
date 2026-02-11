"""Tests for AzureBlobAdapter — metadata round-trip, ETag-based conditional write."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from openlabels.adapters.base import FileInfo, ExposureLevel


def _mock_paged_iterator(items):
    """Create a mock that behaves like Azure SDK's ItemPaged.

    Returns an object whose by_page() returns an iterator of pages,
    where each page is the full list of items (single page).
    """
    result = MagicMock()
    result.__iter__ = MagicMock(return_value=iter(items))
    paged = MagicMock()
    paged.__iter__ = MagicMock(return_value=iter([items]))  # one page with all items
    result.by_page.return_value = paged
    return result


# ── AzureBlobAdapter unit tests ─────────────────────────────────────


class TestAzureBlobAdapterProperties:
    def test_adapter_type(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        assert adapter.adapter_type == "azure_blob"

    def test_supports_delta_is_false(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        assert adapter.supports_delta() is False


class TestAzureBlobAdapterListFiles:
    @pytest.mark.asyncio
    async def test_list_files_yields_file_infos(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        now = datetime.now(timezone.utc)

        blob1 = MagicMock()
        blob1.name = "data/report.pdf"
        blob1.size = 2048
        blob1.last_modified = now
        blob1.etag = '"abc123"'

        blob2 = MagicMock()
        blob2.name = "data/notes.txt"
        blob2.size = 512
        blob2.last_modified = now
        blob2.etag = '"def456"'

        dir_blob = MagicMock()
        dir_blob.name = "data/subdir/"
        dir_blob.size = 0
        dir_blob.last_modified = now
        dir_blob.etag = '""'

        mock_container = MagicMock()
        mock_container.list_blobs.return_value = _mock_paged_iterator([blob1, blob2, dir_blob])

        adapter = AzureBlobAdapter(
            storage_account="myaccount", container="mycontainer", prefix="data"
        )
        adapter._container_client = mock_container

        files = []
        async for fi in adapter.list_files(""):
            files.append(fi)

        assert len(files) == 2
        assert files[0].name == "report.pdf"
        assert files[0].path == "https://myaccount.blob.core.windows.net/mycontainer/data/report.pdf"
        assert files[0].size == 2048
        assert files[0].adapter == "azure_blob"
        assert files[0].item_id == "data/report.pdf"
        assert files[0].permissions["etag"] == "abc123"
        assert files[1].name == "notes.txt"

    @pytest.mark.asyncio
    async def test_list_files_non_recursive(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        now = datetime.now(timezone.utc)

        blob1 = MagicMock()
        blob1.name = "file.txt"
        blob1.size = 100
        blob1.last_modified = now
        blob1.etag = '"e1"'

        mock_container = MagicMock()
        mock_container.walk_blobs.return_value = _mock_paged_iterator([blob1])

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        files = []
        async for fi in adapter.list_files("", recursive=False):
            files.append(fi)

        assert len(files) == 1
        assert files[0].name == "file.txt"
        assert files[0].adapter == "azure_blob"
        mock_container.walk_blobs.assert_called_once_with(name_starts_with="", delimiter="/")

    @pytest.mark.asyncio
    async def test_list_files_skips_blob_prefix_objects(self):
        """walk_blobs returns BlobPrefix objects (no .size attr) for directories."""
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        # BlobPrefix objects don't have .size — only .name
        prefix_obj = MagicMock(spec=["name"])
        prefix_obj.name = "subdir/"

        blob = MagicMock()
        blob.name = "file.txt"
        blob.size = 100
        blob.last_modified = datetime.now(timezone.utc)
        blob.etag = '"e1"'

        mock_container = MagicMock()
        mock_container.list_blobs.return_value = _mock_paged_iterator([prefix_obj, blob])

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        files = []
        async for fi in adapter.list_files(""):
            files.append(fi)

        assert len(files) == 1
        assert files[0].name == "file.txt"


class TestAzureBlobAdapterReadFile:
    @pytest.mark.asyncio
    async def test_read_file_downloads_content(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        mock_downloader = MagicMock()
        mock_downloader.readall.return_value = b"azure blob content"

        mock_blob_client = MagicMock()
        mock_blob_client.download_blob.return_value = mock_downloader

        mock_container = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/test.txt",
            name="test.txt",
            size=18,
            modified=datetime.now(timezone.utc),
            adapter="azure_blob",
            item_id="test.txt",
        )

        content = await adapter.read_file(fi)
        assert content == b"azure blob content"
        mock_container.get_blob_client.assert_called_once_with("test.txt")

    @pytest.mark.asyncio
    async def test_read_file_rejects_oversized(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/big.bin",
            name="big.bin",
            size=200 * 1024 * 1024,  # 200 MB
            modified=datetime.now(timezone.utc),
            adapter="azure_blob",
            item_id="big.bin",
        )

        with pytest.raises(ValueError, match="File too large"):
            await adapter.read_file(fi)


class TestAzureBlobAdapterGetMetadata:
    @pytest.mark.asyncio
    async def test_get_metadata_refreshes_from_properties(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        now = datetime.now(timezone.utc)
        mock_props = MagicMock()
        mock_props.size = 4096
        mock_props.last_modified = now
        mock_props.etag = '"newetag"'
        mock_props.metadata = {"openlabels_label_id": "label-1"}

        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.return_value = mock_props

        mock_container = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/doc.pdf",
            name="doc.pdf",
            size=1024,
            modified=datetime(2025, 1, 1, tzinfo=timezone.utc),
            adapter="azure_blob",
            item_id="doc.pdf",
        )

        updated = await adapter.get_metadata(fi)
        assert updated.size == 4096
        assert updated.modified == now
        assert updated.permissions["etag"] == "newetag"
        assert updated.permissions["metadata"]["openlabels_label_id"] == "label-1"


class TestAzureBlobApplyLabelAndSync:
    @pytest.mark.asyncio
    async def test_apply_label_success(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        mock_props = MagicMock()
        mock_props.etag = '"abc123"'
        mock_props.metadata = {"existing-key": "existing-val"}

        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.return_value = mock_props
        mock_blob_client.set_blob_metadata.return_value = None

        mock_container = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/doc.pdf",
            name="doc.pdf",
            size=1024,
            modified=datetime.now(timezone.utc),
            adapter="azure_blob",
            item_id="doc.pdf",
            permissions={"etag": "abc123"},
        )

        with patch("openlabels.adapters.azure_blob.AzureError", Exception):
            result = await adapter.apply_label_and_sync(
                fi, label_id="label-uuid", label_name="Confidential"
            )

        assert result["success"] is True
        assert result["method"] == "azure_metadata"

        # Verify set_blob_metadata was called with correct merged metadata
        mock_blob_client.set_blob_metadata.assert_called_once()
        call_kwargs = mock_blob_client.set_blob_metadata.call_args[1]
        metadata = call_kwargs["metadata"]
        assert metadata["openlabels_label_id"] == "label-uuid"
        assert metadata["openlabels_label_name"] == "Confidential"
        # Existing metadata should be preserved
        assert metadata["existing-key"] == "existing-val"

    @pytest.mark.asyncio
    async def test_apply_label_etag_mismatch(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        mock_props = MagicMock()
        mock_props.etag = '"different_etag"'
        mock_props.metadata = {}

        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.return_value = mock_props

        mock_container = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/test.txt",
            name="test.txt",
            size=100,
            modified=datetime.now(timezone.utc),
            adapter="azure_blob",
            item_id="test.txt",
            permissions={"etag": "original_etag"},
        )

        result = await adapter.apply_label_and_sync(fi, label_id="label-uuid")

        assert result["success"] is False
        assert "ETag mismatch" in result["error"]
        assert not mock_blob_client.set_blob_metadata.called

    @pytest.mark.asyncio
    async def test_apply_label_incompatible_file(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/program.exe",
            name="program.exe",
            size=100,
            modified=datetime.now(timezone.utc),
            adapter="azure_blob",
            item_id="program.exe",
        )

        result = await adapter.apply_label_and_sync(fi, label_id="label-uuid")

        assert result["success"] is False
        assert result["method"] == "skipped"

    @pytest.mark.asyncio
    async def test_apply_label_condition_not_met(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        mock_props = MagicMock()
        mock_props.etag = '"abc123"'
        mock_props.metadata = {}

        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.return_value = mock_props
        mock_blob_client.set_blob_metadata.side_effect = Exception(
            "ConditionNotMet: 412 The condition specified was not met"
        )

        mock_container = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        fi = FileInfo(
            path="https://myaccount.blob.core.windows.net/mycontainer/test.csv",
            name="test.csv",
            size=50,
            modified=datetime.now(timezone.utc),
            adapter="azure_blob",
            item_id="test.csv",
            permissions={"etag": "abc123"},
        )

        with patch("openlabels.adapters.azure_blob.AzureError", Exception):
            result = await adapter.apply_label_and_sync(fi, label_id="label-uuid")

        assert result["success"] is False
        assert "ConditionNotMet" in result["error"]


class TestAzureBlobETagDiff:
    @pytest.mark.asyncio
    async def test_list_blobs_with_etags(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        blob1 = MagicMock()
        blob1.name = "a.txt"
        blob1.etag = '"etag1"'

        blob2 = MagicMock()
        blob2.name = "b.txt"
        blob2.etag = '"etag2"'

        dir_blob = MagicMock()
        dir_blob.name = "subdir/"
        dir_blob.etag = '""'

        mock_container = MagicMock()
        mock_container.list_blobs.return_value = [blob1, blob2, dir_blob]

        adapter = AzureBlobAdapter(storage_account="myaccount", container="mycontainer")
        adapter._container_client = mock_container

        result = await adapter.list_blobs_with_etags()
        assert result == {"a.txt": "etag1", "b.txt": "etag2"}


class TestAzureBlobHelpers:
    def test_resolve_prefix(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(
            storage_account="acct", container="c", prefix="root"
        )
        assert adapter._resolve_prefix("sub") == "root/sub"
        assert adapter._resolve_prefix("") == "root"

        adapter2 = AzureBlobAdapter(
            storage_account="acct", container="c", prefix=""
        )
        assert adapter2._resolve_prefix("sub") == "sub"
        assert adapter2._resolve_prefix("") == ""

    def test_extract_blob_name(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(
            storage_account="acct", container="mycontainer"
        )
        url = "https://acct.blob.core.windows.net/mycontainer/path/to/file.txt"
        assert adapter._extract_blob_name(url) == "path/to/file.txt"

    def test_extract_blob_name_fallback(self):
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(
            storage_account="acct", container="mycontainer"
        )
        # If container name not found in path, return path as-is
        assert adapter._extract_blob_name("some/other/path") == "some/other/path"


class TestAzureBlobBuildClient:
    def test_ensure_container_client_lazy_creates_client(self):
        """_ensure_container_client should build the client on first call."""
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(
            storage_account="acct", container="c"
        )

        mock_service_client = MagicMock()
        mock_container = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container

        with patch.object(adapter, "_build_client", return_value=mock_service_client):
            result = adapter._ensure_container_client()

        assert result is mock_container
        assert adapter._client is mock_service_client
        mock_service_client.get_container_client.assert_called_once_with("c")

    def test_ensure_container_client_reuses_existing(self):
        """_ensure_container_client should return cached client on subsequent calls."""
        from openlabels.adapters.azure_blob import AzureBlobAdapter

        adapter = AzureBlobAdapter(
            storage_account="acct", container="c"
        )

        mock_container = MagicMock()
        adapter._container_client = mock_container

        result = adapter._ensure_container_client()
        assert result is mock_container
