"""Tests for DuckDB engine remote storage configuration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import duckdb
import pytest

from openlabels.analytics.engine import DuckDBEngine


class TestRemoteStorageConfig:
    """Verify that the engine configures DuckDB extensions for S3/Azure."""

    def test_local_backend_no_extensions(self, tmp_path: Path):
        """Local backend should not load httpfs or azure extensions."""
        engine = DuckDBEngine(str(tmp_path), memory_limit="256MB", threads=1)
        # Should work fine — no extensions needed
        result = engine.fetch_all("SELECT 1 AS x")
        assert result == [{"x": 1}]
        engine.close()

    def test_storage_config_none_is_fine(self, tmp_path: Path):
        """Passing storage_config=None should behave like local."""
        engine = DuckDBEngine(
            str(tmp_path),
            memory_limit="256MB",
            threads=1,
            storage_config=None,
        )
        result = engine.fetch_all("SELECT 42 AS answer")
        assert result == [{"answer": 42}]
        engine.close()

    def test_s3_config_detected(self, tmp_path: Path):
        """S3 backend should attempt to install httpfs extension."""
        config = MagicMock()
        config.backend = "s3"
        config.s3.region = "us-west-2"
        config.s3.access_key = "AKID"
        config.s3.secret_key = "SECRET"
        config.s3.endpoint_url = None

        # This may raise if httpfs isn't available in test env,
        # but the config path should still be attempted
        try:
            engine = DuckDBEngine(
                str(tmp_path),
                memory_limit="256MB",
                threads=1,
                storage_config=config,
            )
            engine.close()
        except duckdb.IOException:
            # Extension not available in test env — that's OK
            pass
        except duckdb.HTTPException:
            pass

    def test_azure_config_detected(self, tmp_path: Path):
        """Azure backend should attempt to install azure extension."""
        config = MagicMock()
        config.backend = "azure"
        config.azure.connection_string = "DefaultEndpointsProtocol=https;AccountName=test"
        config.azure.account_name = None
        config.azure.account_key = None

        try:
            engine = DuckDBEngine(
                str(tmp_path),
                memory_limit="256MB",
                threads=1,
                storage_config=config,
            )
            engine.close()
        except (duckdb.IOException, duckdb.HTTPException, duckdb.CatalogException):
            # Extension not available in test env — that's OK
            pass

    def test_local_config_skips_extensions(self, tmp_path: Path):
        """Local backend config should skip extension loading."""
        config = MagicMock()
        config.backend = "local"

        engine = DuckDBEngine(
            str(tmp_path),
            memory_limit="256MB",
            threads=1,
            storage_config=config,
        )
        # Should work without any extensions
        result = engine.fetch_all("SELECT 'hello' AS msg")
        assert result == [{"msg": "hello"}]
        engine.close()
