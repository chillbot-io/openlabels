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

    def test_s3_config_calls_httpfs(self, tmp_path: Path):
        """S3 backend should attempt to install and load httpfs extension."""
        config = MagicMock()
        config.backend = "s3"
        config.s3.region = "us-west-2"
        config.s3.access_key = "AKID"
        config.s3.secret_key = "SECRET"
        config.s3.endpoint_url = None

        with patch.object(duckdb.DuckDBPyConnection, "execute", wraps=None) as mock_exec:
            # Allow real connection creation but track execute calls
            try:
                engine = DuckDBEngine(
                    str(tmp_path),
                    memory_limit="256MB",
                    threads=1,
                    storage_config=config,
                )
                engine.close()
            except (duckdb.IOException, duckdb.HTTPException, duckdb.CatalogException):
                # Extension may not be available in test env -- verify SQL was attempted
                pass

        # Verify that httpfs installation and S3 config were attempted
        executed_sql = [str(call) for call in mock_exec.call_args_list]
        sql_text = " ".join(executed_sql)
        assert "httpfs" in sql_text, "Should attempt to install/load httpfs for S3 backend"
        assert "s3_region" in sql_text, "Should configure s3_region"
        assert "s3_access_key_id" in sql_text, "Should configure s3_access_key_id"

    def test_azure_config_calls_azure_extension(self, tmp_path: Path):
        """Azure backend should attempt to install and load azure extension."""
        config = MagicMock()
        config.backend = "azure"
        config.azure.connection_string = "DefaultEndpointsProtocol=https;AccountName=test"
        config.azure.account_name = None
        config.azure.account_key = None

        with patch.object(duckdb.DuckDBPyConnection, "execute", wraps=None) as mock_exec:
            try:
                engine = DuckDBEngine(
                    str(tmp_path),
                    memory_limit="256MB",
                    threads=1,
                    storage_config=config,
                )
                engine.close()
            except (duckdb.IOException, duckdb.HTTPException, duckdb.CatalogException):
                pass

        executed_sql = [str(call) for call in mock_exec.call_args_list]
        sql_text = " ".join(executed_sql)
        assert "azure" in sql_text.lower(), "Should attempt to install/load azure extension"
        assert "azure_storage_connection_string" in sql_text, "Should configure azure connection string"

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
