"""
Functional tests for the catalog CLI command.

Tests catalog rebuild and compact subcommands including:
- Command invocation and argument parsing
- Confirmation prompts
- Pagination/batch processing logic
- Output messages
- Error handling
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


def _mock_analytics_modules():
    """Install mock modules for openlabels.analytics.* into sys.modules.

    The compact command imports from openlabels.analytics at call time,
    and those packages may not be installed in the test environment.
    We pre-inject mock modules so the lazy imports resolve successfully.
    Returns a context manager that cleans up afterward.
    """
    mock_compaction = MagicMock()
    mock_storage = MagicMock()
    mock_server_config = MagicMock()

    mocks = {
        "openlabels.analytics": MagicMock(),
        "openlabels.analytics.compaction": mock_compaction,
        "openlabels.analytics.storage": mock_storage,
        "openlabels.server": MagicMock(),
        "openlabels.server.config": mock_server_config,
    }
    return mocks, mock_compaction, mock_storage, mock_server_config


class TestCatalogHelp:
    """Tests for catalog command help text."""

    def test_catalog_help_shows_subcommands(self, runner):
        """catalog --help should list subcommands."""
        from openlabels.cli.commands.catalog import catalog

        result = runner.invoke(catalog, ["--help"])

        assert result.exit_code == 0
        assert "rebuild" in result.output
        assert "compact" in result.output

    def test_rebuild_help(self, runner):
        """catalog rebuild --help should show options."""
        from openlabels.cli.commands.catalog import catalog

        result = runner.invoke(catalog, ["rebuild", "--help"])

        assert result.exit_code == 0
        assert "--batch-size" in result.output
        assert "--yes" in result.output

    def test_compact_help(self, runner):
        """catalog compact --help should show options."""
        from openlabels.cli.commands.catalog import catalog

        result = runner.invoke(catalog, ["compact", "--help"])

        assert result.exit_code == 0
        assert "--table" in result.output
        assert "--threshold" in result.output
        assert "--yes" in result.output


class TestCatalogRebuild:
    """Tests for catalog rebuild subcommand."""

    def test_rebuild_prompts_for_confirmation(self, runner):
        """catalog rebuild should prompt for confirmation without --yes."""
        from openlabels.cli.commands.catalog import catalog

        # Send 'n' to abort the confirmation
        result = runner.invoke(catalog, ["rebuild"], input="n\n")

        assert result.exit_code == 1  # Aborted
        assert "Aborted" in result.output or "re-export" in result.output

    def test_rebuild_skips_prompt_with_yes(self, runner):
        """catalog rebuild --yes should skip confirmation."""
        from openlabels.cli.commands.catalog import catalog

        with patch("openlabels.cli.commands.catalog._run_rebuild", new_callable=AsyncMock) as mock_rebuild:
            result = runner.invoke(catalog, ["rebuild", "--yes"])

        assert result.exit_code == 0
        assert "Rebuilding" in result.output
        assert "complete" in result.output
        mock_rebuild.assert_called_once_with(10_000)

    def test_rebuild_custom_batch_size(self, runner):
        """catalog rebuild --batch-size should use custom batch size."""
        from openlabels.cli.commands.catalog import catalog

        with patch("openlabels.cli.commands.catalog._run_rebuild", new_callable=AsyncMock) as mock_rebuild:
            result = runner.invoke(catalog, ["rebuild", "--yes", "--batch-size", "5000"])

        assert result.exit_code == 0
        mock_rebuild.assert_called_once_with(5000)

    def test_rebuild_default_batch_size_is_10000(self, runner):
        """catalog rebuild default batch size should be 10000."""
        from openlabels.cli.commands.catalog import catalog

        with patch("openlabels.cli.commands.catalog._run_rebuild", new_callable=AsyncMock) as mock_rebuild:
            result = runner.invoke(catalog, ["rebuild", "--yes"])

        mock_rebuild.assert_called_once_with(10_000)

    def test_rebuild_confirmation_yes(self, runner):
        """catalog rebuild should proceed when user confirms."""
        from openlabels.cli.commands.catalog import catalog

        with patch("openlabels.cli.commands.catalog._run_rebuild", new_callable=AsyncMock):
            result = runner.invoke(catalog, ["rebuild"], input="y\n")

        assert result.exit_code == 0
        assert "Rebuilding" in result.output

    def test_rebuild_output_messages(self, runner):
        """catalog rebuild should show start and complete messages."""
        from openlabels.cli.commands.catalog import catalog

        with patch("openlabels.cli.commands.catalog._run_rebuild", new_callable=AsyncMock):
            result = runner.invoke(catalog, ["rebuild", "--yes"])

        assert "Rebuilding Parquet catalog from PostgreSQL" in result.output
        assert "Catalog rebuild complete" in result.output


class TestCatalogCompact:
    """Tests for catalog compact subcommand."""

    def test_compact_prompts_for_confirmation(self, runner):
        """catalog compact should prompt for confirmation without --yes."""
        from openlabels.cli.commands.catalog import catalog

        result = runner.invoke(catalog, ["compact"], input="n\n")

        assert result.exit_code == 1  # Aborted

    def test_compact_skips_prompt_with_yes(self, runner):
        """catalog compact --yes should skip confirmation."""
        from openlabels.cli.commands.catalog import catalog

        mocks, mock_compaction, mock_storage, mock_server_config = _mock_analytics_modules()
        mock_compaction.compact_catalog.return_value = 5
        mock_server_config.get_settings.return_value = MagicMock()
        mock_storage.create_storage.return_value = MagicMock()

        saved = {}
        for key, val in mocks.items():
            saved[key] = sys.modules.get(key)
            sys.modules[key] = val

        try:
            result = runner.invoke(catalog, ["compact", "--yes"])
        finally:
            for key in mocks:
                if saved[key] is None:
                    sys.modules.pop(key, None)
                else:
                    sys.modules[key] = saved[key]

        assert result.exit_code == 0
        assert "Compacting" in result.output
        assert "5 partitions compacted" in result.output

    def test_compact_custom_table(self, runner):
        """catalog compact --table should compact specific table only."""
        from openlabels.cli.commands.catalog import catalog

        mocks, mock_compaction, mock_storage, mock_server_config = _mock_analytics_modules()
        mock_compaction.compact_catalog.return_value = 2
        mock_server_config.get_settings.return_value = MagicMock()
        mock_storage.create_storage.return_value = MagicMock()

        saved = {}
        for key, val in mocks.items():
            saved[key] = sys.modules.get(key)
            sys.modules[key] = val

        try:
            result = runner.invoke(catalog, ["compact", "--yes", "--table", "scan_results"])
        finally:
            for key in mocks:
                if saved[key] is None:
                    sys.modules.pop(key, None)
                else:
                    sys.modules[key] = saved[key]

        assert result.exit_code == 0
        mock_compaction.compact_catalog.assert_called_once()
        call_args = mock_compaction.compact_catalog.call_args
        tables_arg = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("tables")
        assert tables_arg == ["scan_results"]

    def test_compact_custom_threshold(self, runner):
        """catalog compact --threshold should use custom threshold."""
        from openlabels.cli.commands.catalog import catalog

        mocks, mock_compaction, mock_storage, mock_server_config = _mock_analytics_modules()
        mock_compaction.compact_catalog.return_value = 0
        mock_server_config.get_settings.return_value = MagicMock()
        mock_storage.create_storage.return_value = MagicMock()

        saved = {}
        for key, val in mocks.items():
            saved[key] = sys.modules.get(key)
            sys.modules[key] = val

        try:
            result = runner.invoke(catalog, ["compact", "--yes", "--threshold", "5"])
        finally:
            for key in mocks:
                if saved[key] is None:
                    sys.modules.pop(key, None)
                else:
                    sys.modules[key] = saved[key]

        assert result.exit_code == 0
        call_kwargs = mock_compaction.compact_catalog.call_args
        threshold_val = call_kwargs[1].get("threshold") if call_kwargs[1] else None
        assert threshold_val == 5

    def test_compact_default_compacts_all_tables(self, runner):
        """catalog compact without --table should compact all tables."""
        from openlabels.cli.commands.catalog import catalog

        mocks, mock_compaction, mock_storage, mock_server_config = _mock_analytics_modules()
        mock_compaction.compact_catalog.return_value = 3
        mock_server_config.get_settings.return_value = MagicMock()
        mock_storage.create_storage.return_value = MagicMock()

        saved = {}
        for key, val in mocks.items():
            saved[key] = sys.modules.get(key)
            sys.modules[key] = val

        try:
            result = runner.invoke(catalog, ["compact", "--yes"])
        finally:
            for key in mocks:
                if saved[key] is None:
                    sys.modules.pop(key, None)
                else:
                    sys.modules[key] = saved[key]

        assert result.exit_code == 0
        call_args = mock_compaction.compact_catalog.call_args
        tables_arg = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("tables")
        expected_tables = [
            "scan_results", "file_inventory", "folder_inventory",
            "access_events", "audit_log", "remediation_actions",
        ]
        assert tables_arg == expected_tables

    def test_compact_zero_partitions(self, runner):
        """catalog compact with nothing to compact should show 0."""
        from openlabels.cli.commands.catalog import catalog

        mocks, mock_compaction, mock_storage, mock_server_config = _mock_analytics_modules()
        mock_compaction.compact_catalog.return_value = 0
        mock_server_config.get_settings.return_value = MagicMock()
        mock_storage.create_storage.return_value = MagicMock()

        saved = {}
        for key, val in mocks.items():
            saved[key] = sys.modules.get(key)
            sys.modules[key] = val

        try:
            result = runner.invoke(catalog, ["compact", "--yes"])
        finally:
            for key in mocks:
                if saved[key] is None:
                    sys.modules.pop(key, None)
                else:
                    sys.modules[key] = saved[key]

        assert result.exit_code == 0
        assert "0 partitions compacted" in result.output
