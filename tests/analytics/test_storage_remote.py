"""Tests for remote storage backends (S3, Azure) — mocked.

These tests verify the S3Storage and AzureBlobStorage classes work
correctly with mocked AWS/Azure clients.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch, PropertyMock

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from openlabels.analytics.storage import (
    AzureBlobStorage,
    CatalogStorage,
    S3Storage,
    create_storage,
)


# ── S3Storage tests ──────────────────────────────────────────────────

class TestS3Storage:
    """Tests for the S3 storage backend with mocked boto3."""

    @patch("openlabels.analytics.storage.boto3", create=True)
    def _make_storage(self, mock_boto3):
        """Helper to create an S3Storage with a mocked boto3 client."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        # Need to patch the import inside the module
        import openlabels.analytics.storage as storage_mod
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            s = S3Storage(
                bucket="test-bucket",
                prefix="catalog",
                region="us-east-1",
                access_key="AKID",
                secret_key="SECRET",
            )
        return s, mock_client

    def test_s3_root_uri(self):
        s, _ = self._make_storage()
        assert s.root == "s3://test-bucket/catalog"

    def test_s3_write_parquet(self):
        s, mock_client = self._make_storage()
        table = pa.table({"x": [1, 2, 3]})
        s.write_parquet("data/part.parquet", table)

        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args
        assert call_kwargs.kwargs["Bucket"] == "test-bucket"
        assert call_kwargs.kwargs["Key"] == "catalog/data/part.parquet"

    def test_s3_read_parquet(self):
        s, mock_client = self._make_storage()

        # Create a real Parquet buffer to return
        table = pa.table({"x": [1, 2, 3]})
        buf = io.BytesIO()
        pq.write_table(table, buf)
        buf.seek(0)

        mock_body = MagicMock()
        mock_body.read.return_value = buf.getvalue()
        mock_client.get_object.return_value = {"Body": mock_body}

        result = s.read_parquet("data/part.parquet")
        assert result.num_rows == 3
        assert result.column("x").to_pylist() == [1, 2, 3]

    def test_s3_list_partitions(self):
        s, mock_client = self._make_storage()

        paginator = MagicMock()
        mock_client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "CommonPrefixes": [
                    {"Prefix": "catalog/scan_results/tenant=abc/"},
                    {"Prefix": "catalog/scan_results/tenant=def/"},
                ],
            }
        ]

        result = s.list_partitions("scan_results")
        assert result == ["tenant=abc", "tenant=def"]

    def test_s3_list_files(self):
        s, mock_client = self._make_storage()

        paginator = MagicMock()
        mock_client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "catalog/scan_results/part-001.parquet"},
                    {"Key": "catalog/scan_results/part-002.parquet"},
                    {"Key": "catalog/scan_results/README.md"},
                ],
            }
        ]

        result = s.list_files("scan_results")
        # Only .parquet files, without the README
        assert len(result) == 2
        assert "scan_results/part-001.parquet" in result
        assert "scan_results/part-002.parquet" in result

    def test_s3_write_bytes(self):
        s, mock_client = self._make_storage()
        s.write_bytes("_metadata/flush_state.json", b'{"version": 1}')

        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args
        assert call_kwargs.kwargs["Key"] == "catalog/_metadata/flush_state.json"
        assert call_kwargs.kwargs["Body"] == b'{"version": 1}'

    def test_s3_read_bytes(self):
        s, mock_client = self._make_storage()

        mock_body = MagicMock()
        mock_body.read.return_value = b'{"version": 1}'
        mock_client.get_object.return_value = {"Body": mock_body}

        result = s.read_bytes("_metadata/flush_state.json")
        assert result == b'{"version": 1}'


# ── Config + factory tests ───────────────────────────────────────────

class TestConfigAndFactory:
    """Test CatalogSettings with S3/Azure sub-configs and the factory."""

    def test_s3_config_defaults(self):
        from openlabels.server.config import S3CatalogSettings
        s3 = S3CatalogSettings()
        assert s3.bucket == ""
        assert s3.prefix == "openlabels/catalog"
        assert s3.region == "us-east-1"
        assert s3.endpoint_url is None

    def test_azure_config_defaults(self):
        from openlabels.server.config import AzureCatalogSettings
        az = AzureCatalogSettings()
        assert az.container == ""
        assert az.prefix == "openlabels/catalog"
        assert az.connection_string is None

    def test_catalog_settings_has_s3_azure(self):
        from openlabels.server.config import CatalogSettings
        cat = CatalogSettings()
        assert hasattr(cat, "s3")
        assert hasattr(cat, "azure")
        assert cat.s3.bucket == ""
        assert cat.azure.container == ""

    def test_create_storage_s3_no_bucket_raises(self):
        from openlabels.server.config import CatalogSettings
        cat = CatalogSettings(enabled=True, backend="s3")
        with pytest.raises(ValueError, match="catalog.s3.bucket"):
            create_storage(cat)

    def test_create_storage_azure_no_container_raises(self):
        from openlabels.server.config import CatalogSettings
        cat = CatalogSettings(enabled=True, backend="azure")
        with pytest.raises(ValueError, match="catalog.azure.container"):
            create_storage(cat)


# ── AzureBlobStorage tests ──────────────────────────────────────────

class TestAzureBlobStorage:
    """Tests for the Azure Blob Storage backend with mocked azure SDK."""

    def _make_storage(self):
        """Helper to create an AzureBlobStorage with a mocked SDK."""
        mock_service = MagicMock()
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container

        with patch.dict("sys.modules", {"azure": MagicMock(), "azure.storage": MagicMock(), "azure.storage.blob": MagicMock()}):
            import sys
            blob_mod = sys.modules["azure.storage.blob"]
            blob_mod.BlobServiceClient = MagicMock()
            blob_mod.BlobServiceClient.from_connection_string.return_value = mock_service

            s = AzureBlobStorage(
                container="test-container",
                prefix="catalog",
                connection_string="DefaultEndpointsProtocol=https;AccountName=test",
            )
        return s, mock_container

    def test_azure_root_uri(self):
        s, _ = self._make_storage()
        assert s.root == "az://test-container/catalog"

    def test_azure_write_parquet(self):
        s, mock_container = self._make_storage()
        mock_blob_client = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        table = pa.table({"x": [1, 2, 3]})
        s.write_parquet("data/part.parquet", table)

        mock_container.get_blob_client.assert_called_with("catalog/data/part.parquet")
        mock_blob_client.upload_blob.assert_called_once()

    def test_azure_read_parquet(self):
        s, mock_container = self._make_storage()

        # Create a real Parquet buffer to return
        table = pa.table({"x": [1, 2, 3]})
        buf = io.BytesIO()
        pq.write_table(table, buf)
        buf.seek(0)

        mock_blob_client = MagicMock()
        mock_download = MagicMock()
        mock_download.readall.return_value = buf.getvalue()
        mock_blob_client.download_blob.return_value = mock_download
        mock_container.get_blob_client.return_value = mock_blob_client

        result = s.read_parquet("data/part.parquet")
        assert result.num_rows == 3
        assert result.column("x").to_pylist() == [1, 2, 3]

    def test_azure_list_files(self):
        s, mock_container = self._make_storage()

        mock_blob1 = MagicMock()
        mock_blob1.name = "catalog/scan_results/part-001.parquet"
        mock_blob2 = MagicMock()
        mock_blob2.name = "catalog/scan_results/part-002.parquet"
        mock_blob3 = MagicMock()
        mock_blob3.name = "catalog/scan_results/README.md"
        mock_container.list_blobs.return_value = [mock_blob1, mock_blob2, mock_blob3]

        result = s.list_files("scan_results")
        assert len(result) == 2
        assert "scan_results/part-001.parquet" in result
        assert "scan_results/part-002.parquet" in result

    def test_azure_write_bytes(self):
        s, mock_container = self._make_storage()
        mock_blob_client = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob_client

        s.write_bytes("_metadata/flush_state.json", b'{"version": 1}')
        mock_blob_client.upload_blob.assert_called_once_with(b'{"version": 1}', overwrite=True)

    def test_azure_read_bytes(self):
        s, mock_container = self._make_storage()
        mock_blob_client = MagicMock()
        mock_download = MagicMock()
        mock_download.readall.return_value = b'{"version": 1}'
        mock_blob_client.download_blob.return_value = mock_download
        mock_container.get_blob_client.return_value = mock_blob_client

        result = s.read_bytes("_metadata/flush_state.json")
        assert result == b'{"version": 1}'
