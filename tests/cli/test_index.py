"""
Functional tests for the index CLI command.

Tests index subcommands including:
- build, rebuild, sync, collect-sd, status
- Command invocation and argument parsing
- Error handling for missing targets
- Output messages
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


class TestIndexHelp:
    """Tests for index command help text."""

    def test_index_help_shows_subcommands(self, runner):
        """index --help should list all subcommands."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["--help"])

        assert result.exit_code == 0
        assert "build" in result.output
        assert "rebuild" in result.output
        assert "sync" in result.output
        assert "collect-sd" in result.output
        assert "status" in result.output

    def test_build_help(self, runner):
        """index build --help should show options."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["build", "--help"])

        assert result.exit_code == 0
        assert "TARGET_NAME" in result.output
        assert "--path" in result.output
        assert "--collect-sd" in result.output

    def test_rebuild_help(self, runner):
        """index rebuild --help should show options."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["rebuild", "--help"])

        assert result.exit_code == 0
        assert "TARGET_NAME" in result.output
        assert "--path" in result.output

    def test_sync_help(self, runner):
        """index sync --help should show options."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["sync", "--help"])

        assert result.exit_code == 0
        assert "TARGET_NAME" in result.output
        assert "--path" in result.output

    def test_collect_sd_help(self, runner):
        """index collect-sd --help should show options."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["collect-sd", "--help"])

        assert result.exit_code == 0
        assert "TARGET_NAME" in result.output

    def test_status_help(self, runner):
        """index status --help should show options."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["status", "--help"])

        assert result.exit_code == 0
        assert "TARGET_NAME" in result.output


class TestIndexBuildArguments:
    """Tests for index build argument parsing."""

    def test_build_requires_target_name(self, runner):
        """index build without target_name should fail."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["build"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "TARGET_NAME" in result.output

    def test_rebuild_requires_target_name(self, runner):
        """index rebuild without target_name should fail."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["rebuild"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "TARGET_NAME" in result.output

    def test_sync_requires_target_name(self, runner):
        """index sync without target_name should fail."""
        from openlabels.cli.commands.index import index

        result = runner.invoke(index, ["sync"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "TARGET_NAME" in result.output


class TestIndexBuild:
    """Tests for index build subcommand execution."""

    def test_build_calls_run_bootstrap(self, runner):
        """index build should call _run_bootstrap with correct args."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_bootstrap", new_callable=AsyncMock) as mock_bootstrap:
            result = runner.invoke(index, ["build", "my_target"])

        assert result.exit_code == 0
        mock_bootstrap.assert_called_once_with("my_target", None, rebuild=False, collect_sd=True)

    def test_build_with_path_override(self, runner):
        """index build --path should pass path override."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_bootstrap", new_callable=AsyncMock) as mock_bootstrap:
            result = runner.invoke(index, ["build", "my_target", "--path", "/custom/path"])

        assert result.exit_code == 0
        mock_bootstrap.assert_called_once_with("my_target", "/custom/path", rebuild=False, collect_sd=True)

    def test_build_with_no_collect_sd(self, runner):
        """index build --no-collect-sd should disable SD collection."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_bootstrap", new_callable=AsyncMock) as mock_bootstrap:
            result = runner.invoke(index, ["build", "my_target", "--no-collect-sd"])

        assert result.exit_code == 0
        mock_bootstrap.assert_called_once_with("my_target", None, rebuild=False, collect_sd=False)


class TestIndexRebuild:
    """Tests for index rebuild subcommand execution."""

    def test_rebuild_calls_run_bootstrap_with_rebuild_true(self, runner):
        """index rebuild should call _run_bootstrap with rebuild=True."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_bootstrap", new_callable=AsyncMock) as mock_bootstrap:
            result = runner.invoke(index, ["rebuild", "my_target"])

        assert result.exit_code == 0
        mock_bootstrap.assert_called_once_with("my_target", None, rebuild=True, collect_sd=True)


class TestIndexSync:
    """Tests for index sync subcommand execution."""

    def test_sync_calls_run_sync(self, runner):
        """index sync should call _run_sync with correct args."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_sync", new_callable=AsyncMock) as mock_sync:
            result = runner.invoke(index, ["sync", "my_target"])

        assert result.exit_code == 0
        mock_sync.assert_called_once_with("my_target", None, collect_sd=True)

    def test_sync_with_path_override(self, runner):
        """index sync --path should pass path override."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_sync", new_callable=AsyncMock) as mock_sync:
            result = runner.invoke(index, ["sync", "my_target", "--path", "/scan/path"])

        assert result.exit_code == 0
        mock_sync.assert_called_once_with("my_target", "/scan/path", collect_sd=True)


class TestIndexCollectSD:
    """Tests for index collect-sd subcommand execution."""

    def test_collect_sd_calls_run_collect_sd(self, runner):
        """index collect-sd should call _run_collect_sd."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_collect_sd", new_callable=AsyncMock) as mock_collect:
            result = runner.invoke(index, ["collect-sd", "my_target"])

        assert result.exit_code == 0
        mock_collect.assert_called_once_with("my_target")


class TestIndexStatus:
    """Tests for index status subcommand execution."""

    def test_status_calls_run_status(self, runner):
        """index status should call _run_status."""
        from openlabels.cli.commands.index import index

        with patch("openlabels.cli.commands.index._run_status", new_callable=AsyncMock) as mock_status:
            result = runner.invoke(index, ["status", "my_target"])

        assert result.exit_code == 0
        mock_status.assert_called_once_with("my_target")


class TestResolveTarget:
    """Tests for the _resolve_target helper function."""

    @pytest.mark.asyncio
    async def test_resolve_target_not_found(self):
        """_resolve_target should return error when target not found."""
        from openlabels.cli.commands.index import _resolve_target

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        target, err = await _resolve_target(mock_session, "nonexistent")

        assert target is None
        assert "not found" in err.lower()

    @pytest.mark.asyncio
    async def test_resolve_target_found(self):
        """_resolve_target should return target when found."""
        from openlabels.cli.commands.index import _resolve_target

        mock_target = MagicMock()
        mock_target.name = "my_target"

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_target
        mock_session.execute = AsyncMock(return_value=mock_result)

        target, err = await _resolve_target(mock_session, "my_target")

        assert target is mock_target
        assert err is None


class TestGetScanPath:
    """Tests for the _get_scan_path helper function."""

    def test_path_override_used(self):
        """_get_scan_path should return override path when provided."""
        from openlabels.cli.commands.index import _get_scan_path

        mock_target = MagicMock()
        mock_target.config = {"path": "/default/path"}

        result = _get_scan_path(mock_target, "/override/path")

        assert result == "/override/path"

    def test_config_path_used(self):
        """_get_scan_path should return config path when no override."""
        from openlabels.cli.commands.index import _get_scan_path

        mock_target = MagicMock()
        mock_target.config = {"path": "/config/path"}

        result = _get_scan_path(mock_target, None)

        assert result == "/config/path"

    def test_missing_path_exits(self):
        """_get_scan_path should exit when no path configured."""
        from openlabels.cli.commands.index import _get_scan_path

        mock_target = MagicMock()
        mock_target.name = "test"
        mock_target.config = {}

        with pytest.raises(SystemExit):
            _get_scan_path(mock_target, None)


class TestRunBootstrapErrorHandling:
    """Tests for _run_bootstrap error handling."""

    def test_bootstrap_target_not_found_exits(self, runner):
        """_run_bootstrap should exit when target not found."""
        from openlabels.cli.commands.index import index

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("openlabels.cli.commands.index._init_db", new_callable=AsyncMock), \
             patch("openlabels.server.db.close_db", new_callable=AsyncMock), \
             patch("openlabels.server.db.get_session_context") as mock_ctx:
            mock_ctx.return_value = mock_session

            result = runner.invoke(index, ["build", "nonexistent_target"])

        assert result.exit_code == 1
        assert "Error" in result.output
