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
