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
        """S3 backend should execute httpfs install/load and SET s3_* config."""
        config = MagicMock()
        config.backend = "s3"
        config.s3.region = "us-west-2"
        config.s3.access_key = "AKID"
        config.s3.secret_key = "SECRET"
        config.s3.endpoint_url = None

        engine = DuckDBEngine(str(tmp_path), memory_limit="256MB", threads=1)
        mock_db = MagicMock()
        engine._db = mock_db

        engine._configure_remote_storage(config)

        executed_stmts = [str(call.args[0]) for call in mock_db.execute.call_args_list]
        sql_text = " ".join(executed_stmts)
        assert "INSTALL httpfs" in sql_text, "Should install httpfs extension"
        assert "LOAD httpfs" in sql_text, "Should load httpfs extension"
        assert "s3_region" in sql_text, "Should configure s3_region"
        assert "us-west-2" in sql_text, "Should set s3_region to the provided value"
        assert "s3_access_key_id" in sql_text, "Should configure s3_access_key_id"
        assert "AKID" in sql_text, "Should set access key to the provided value"
        assert "s3_secret_access_key" in sql_text, "Should configure s3_secret_access_key"
        engine.close()

    def test_s3_config_with_endpoint_url(self, tmp_path: Path):
        """S3 backend with custom endpoint should configure endpoint and path style."""
        config = MagicMock()
        config.backend = "s3"
        config.s3.region = "us-east-1"
        config.s3.access_key = "KEY"
        config.s3.secret_key = "SECRET"
        config.s3.endpoint_url = "http://localhost:9000"

        engine = DuckDBEngine(str(tmp_path), memory_limit="256MB", threads=1)
        mock_db = MagicMock()
        engine._db = mock_db

        engine._configure_remote_storage(config)

        executed_stmts = [str(call.args[0]) for call in mock_db.execute.call_args_list]
        sql_text = " ".join(executed_stmts)
        assert "s3_endpoint" in sql_text, "Should configure s3_endpoint"
        assert "localhost:9000" in sql_text, "Should strip protocol from endpoint"
        assert "s3_use_ssl = false" in sql_text, "Should disable SSL for http endpoint"
        assert "s3_url_style" in sql_text, "Should set path-style for custom endpoint"
        engine.close()

    def test_azure_config_calls_azure_extension(self, tmp_path: Path):
        """Azure backend should execute azure install/load and SET connection string."""
        config = MagicMock()
        config.backend = "azure"
        config.azure.connection_string = "DefaultEndpointsProtocol=https;AccountName=test"
        config.azure.account_name = None
        config.azure.account_key = None

        engine = DuckDBEngine(str(tmp_path), memory_limit="256MB", threads=1)
        mock_db = MagicMock()
        engine._db = mock_db

        engine._configure_remote_storage(config)

        executed_stmts = [str(call.args[0]) for call in mock_db.execute.call_args_list]
        sql_text = " ".join(executed_stmts)
        assert "INSTALL azure" in sql_text, "Should install azure extension"
        assert "LOAD azure" in sql_text, "Should load azure extension"
        assert "azure_storage_connection_string" in sql_text, "Should configure connection string"
        assert "AccountName=test" in sql_text, "Should use the provided connection string"
        engine.close()

    def test_azure_config_with_account_key(self, tmp_path: Path):
        """Azure backend with account_name + account_key should set those instead."""
        config = MagicMock()
        config.backend = "azure"
        config.azure.connection_string = None
        config.azure.account_name = "myaccount"
        config.azure.account_key = "mykey123"

        engine = DuckDBEngine(str(tmp_path), memory_limit="256MB", threads=1)
        mock_db = MagicMock()
        engine._db = mock_db

        engine._configure_remote_storage(config)

        executed_stmts = [str(call.args[0]) for call in mock_db.execute.call_args_list]
        sql_text = " ".join(executed_stmts)
        assert "azure_account_name" in sql_text, "Should set azure_account_name"
        assert "myaccount" in sql_text, "Should use the provided account name"
        assert "azure_account_key" in sql_text, "Should set azure_account_key"
        assert "mykey123" in sql_text, "Should use the provided account key"
        engine.close()

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
