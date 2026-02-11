"""
Tests for S3 adapter partition and estimation features.

Tests cover:
- list_files with PartitionSpec (start_after, end_before)
- list_top_level_prefixes
- estimate_object_count
- Boundary key handling (stop pagination early)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from openlabels.adapters.base import PartitionSpec


class TestS3PartitionListing:
    """Tests for S3 adapter partition-aware list_files."""

    def _make_page(self, keys):
        """Create a mock S3 listing page with given keys."""
        return {
            "Contents": [
                {
                    "Key": k,
                    "Size": 1024,
                    "LastModified": datetime.now(timezone.utc),
                    "ETag": f'"{k}_etag"',
                }
                for k in keys
            ]
        }

    @pytest.mark.asyncio
    async def test_list_files_with_start_after(self):
        """StartAfter should be passed to S3 paginator."""
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="test-bucket")

        pages = [self._make_page(["m_file1.csv", "n_file2.csv", "o_file3.csv"])]

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages

        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        adapter._client = mock_client

        spec = PartitionSpec(start_after="m")

        files = []
        with patch("asyncio.to_thread", side_effect=lambda fn: fn()):
            async for fi in adapter.list_files("", partition=spec):
                files.append(fi)

        # Verify StartAfter was passed
        call_kwargs = mock_paginator.paginate.call_args[1]
        assert call_kwargs.get("StartAfter") == "m"

    @pytest.mark.asyncio
    async def test_list_files_with_end_before(self):
        """Files at or beyond end_before should be excluded."""
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="test-bucket")

        pages = [self._make_page([
            "a_file.csv", "b_file.csv", "m_file.csv", "z_file.csv"
        ])]

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages

        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        adapter._client = mock_client

        spec = PartitionSpec(end_before="m_file.csv")

        files = []
        with patch("asyncio.to_thread", side_effect=lambda fn: fn()):
            async for fi in adapter.list_files("", partition=spec):
                files.append(fi)

        # Should only include keys before "m_file.csv"
        assert len(files) == 2
        assert files[0].name == "a_file.csv"
        assert files[1].name == "b_file.csv"

    @pytest.mark.asyncio
    async def test_list_files_no_partition(self):
        """Without partition, all files are returned."""
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="test-bucket")

        pages = [self._make_page(["a.csv", "b.csv", "c.csv"])]

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages

        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        adapter._client = mock_client

        files = []
        with patch("asyncio.to_thread", side_effect=lambda fn: fn()):
            async for fi in adapter.list_files(""):
                files.append(fi)

        assert len(files) == 3

    @pytest.mark.asyncio
    async def test_list_top_level_prefixes(self):
        """Should return common prefixes from delimiter listing."""
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="test-bucket")

        pages = [{
            "CommonPrefixes": [
                {"Prefix": "data/"},
                {"Prefix": "logs/"},
                {"Prefix": "reports/"},
            ]
        }]

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages

        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        adapter._client = mock_client

        with patch("asyncio.to_thread", side_effect=lambda fn: fn()):
            prefixes = await adapter.list_top_level_prefixes()

        assert prefixes == ["data/", "logs/", "reports/"]

    @pytest.mark.asyncio
    async def test_estimate_object_count(self):
        """Should return count and sampled keys."""
        from openlabels.adapters.s3 import S3Adapter

        adapter = S3Adapter(bucket="test-bucket")

        keys = [f"file_{i:05d}.csv" for i in range(500)]
        pages = [self._make_page(keys)]

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages

        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        adapter._client = mock_client

        with patch("asyncio.to_thread", side_effect=lambda fn: fn()):
            count, sample = await adapter.estimate_object_count()

        assert count == 500
        assert len(sample) == 500
        assert sample[0] == "file_00000.csv"
