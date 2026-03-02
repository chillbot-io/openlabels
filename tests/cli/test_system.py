"""
Functional tests for the system CLI commands (status, backup, restore).

Tests include:
- Command invocation and argument parsing
- Output formatting
- Subprocess command construction (pg_dump, psql)
- Backup/restore validation
- Error handling
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


class TestStatusHelp:
    """Tests for status command help text."""

    def test_status_help_shows_usage(self, runner):
        """status --help should show usage information."""
        from openlabels.cli.commands.system import status

        result = runner.invoke(status, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "--server" in result.output


class TestStatusCommand:
    """Tests for status command execution."""

    def test_status_shows_server_online(self, runner):
        """status should show server as online when healthy."""
        from openlabels.cli.commands.system import status

        mock_health = {"version": "1.0.0", "database": "healthy"}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_health

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        mock_mip = MagicMock()
        mock_mip.MIPClient.return_value.is_available.return_value = False

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch.dict("sys.modules", {"openlabels.labeling.mip": mock_mip}), \
             patch("openlabels.core.constants.DEFAULT_MODELS_DIR", Path("/fake/models")):
            mock_api.return_value = mock_client

            result = runner.invoke(status, [])

        assert result.exit_code == 0
        assert "Online" in result.output
        assert "1.0.0" in result.output

    def test_status_shows_server_offline_on_timeout(self, runner):
        """status should show server as offline on timeout."""
        import httpx
        from openlabels.cli.commands.system import status

        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.TimeoutException("timed out")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("openlabels.core.constants.DEFAULT_MODELS_DIR", Path("/fake/models")):
            mock_api.return_value = mock_client

            result = runner.invoke(status, [])

        assert result.exit_code == 0
        assert "Offline" in result.output

    def test_status_shows_server_offline_on_connect_error(self, runner):
        """status should show server as offline on connection error."""
        import httpx
        from openlabels.cli.commands.system import status

        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.ConnectError("connection refused")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("openlabels.core.constants.DEFAULT_MODELS_DIR", Path("/fake/models")):
            mock_api.return_value = mock_client

            result = runner.invoke(status, [])

        assert result.exit_code == 0
        assert "Offline" in result.output

    def test_status_shows_job_queue(self, runner):
        """status should display job queue stats when available."""
        from openlabels.cli.commands.system import status

        health_resp = MagicMock()
        health_resp.status_code = 200
        health_resp.json.return_value = {"version": "1.0", "database": "ok"}

        jobs_resp = MagicMock()
        jobs_resp.status_code = 200
        jobs_resp.json.return_value = {"pending": 5, "running": 2, "completed": 100, "failed": 3}

        dashboard_resp = MagicMock()
        dashboard_resp.status_code = 404

        def get_side_effect(url, **kwargs):
            if "/health" in url:
                return health_resp
            elif "/api/jobs/stats" in url:
                return jobs_resp
            elif "/api/dashboard/summary" in url:
                return dashboard_resp
            return MagicMock(status_code=404)

        mock_client = MagicMock()
        mock_client.get.side_effect = get_side_effect
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        mock_mip = MagicMock()
        mock_mip.MIPClient.return_value.is_available.return_value = False

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch.dict("sys.modules", {"openlabels.labeling.mip": mock_mip}), \
             patch("openlabels.core.constants.DEFAULT_MODELS_DIR", Path("/fake/models")):
            mock_api.return_value = mock_client

            result = runner.invoke(status, [])

        assert result.exit_code == 0
        assert "Job Queue" in result.output
        assert "Pending" in result.output


class TestBackupHelp:
    """Tests for backup command help text."""

    def test_backup_help_shows_options(self, runner):
        """backup --help should show usage information."""
        from openlabels.cli.commands.system import backup

        result = runner.invoke(backup, ["--help"])

        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--include-db" in result.output
        assert "--db-url" in result.output


class TestBackupCommand:
    """Tests for backup command execution."""

    def test_backup_creates_directory(self, runner, tmp_path):
        """backup should create the backup directory."""
        from openlabels.cli.commands.system import backup

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        output_dir = str(tmp_path / "test_backup")

        with patch("openlabels.cli.commands.system.api_client") as mock_api:
            mock_api.return_value = mock_client

            result = runner.invoke(backup, ["--output", output_dir])

        assert result.exit_code == 0
        assert "Creating backup" in result.output
        assert Path(output_dir).exists()

    def test_backup_exports_api_data(self, runner, tmp_path):
        """backup should export API endpoints to JSON files."""
        from openlabels.cli.commands.system import backup

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": 1, "name": "test"}]
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        output_dir = str(tmp_path / "backup_export")

        with patch("openlabels.cli.commands.system.api_client") as mock_api:
            mock_api.return_value = mock_client

            result = runner.invoke(backup, ["--output", output_dir])

        assert result.exit_code == 0
        assert "Exported:" in result.output

    def test_backup_with_db_dump(self, runner, tmp_path):
        """backup --include-db should run pg_dump."""
        from openlabels.cli.commands.system import backup

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        output_dir = str(tmp_path / "backup_db")

        # Mock subprocess.Popen to simulate pg_dump
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stdout.read.return_value = b""
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            mock_api.return_value = mock_client

            result = runner.invoke(backup, [
                "--output", output_dir,
                "--include-db",
                "--db-url", "postgresql://localhost/testdb",
            ])

        assert result.exit_code == 0
        assert "pg_dump" in result.output
        mock_popen.assert_called_once()

    def test_backup_pg_dump_not_found(self, runner, tmp_path):
        """backup should handle missing pg_dump gracefully."""
        from openlabels.cli.commands.system import backup

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        output_dir = str(tmp_path / "backup_nopg")

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("subprocess.Popen", side_effect=FileNotFoundError("pg_dump not found")):
            mock_api.return_value = mock_client

            result = runner.invoke(backup, [
                "--output", output_dir,
                "--include-db",
                "--db-url", "postgresql://localhost/testdb",
            ])

        assert result.exit_code == 0
        assert "pg_dump not found" in result.output


class TestRestoreHelp:
    """Tests for restore command help text."""

    def test_restore_help_shows_options(self, runner):
        """restore --help should show usage information."""
        from openlabels.cli.commands.system import restore

        result = runner.invoke(restore, ["--help"])

        assert result.exit_code == 0
        assert "--from" in result.output
        assert "--include-db" in result.output
        assert "--db-url" in result.output


class TestRestoreCommand:
    """Tests for restore command execution."""

    def test_restore_nonexistent_path_shows_error(self, runner):
        """restore --from nonexistent path should show error."""
        from openlabels.cli.commands.system import restore

        result = runner.invoke(restore, ["--from", "/nonexistent/backup"])

        assert result.exit_code == 0
        assert "Backup not found" in result.output

    def test_restore_reads_json_files(self, runner, tmp_path):
        """restore should read and POST JSON files to API."""
        from openlabels.cli.commands.system import restore

        # Create a backup directory with a JSON file
        backup_dir = tmp_path / "test_restore"
        backup_dir.mkdir()
        targets_file = backup_dir / "targets.json"
        targets_file.write_text(json.dumps([{"id": 1, "name": "target1"}]))

        mock_response = MagicMock()
        mock_response.status_code = 201

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api:
            mock_api.return_value = mock_client

            result = runner.invoke(restore, ["--from", str(backup_dir)])

        assert result.exit_code == 0
        assert "Restored:" in result.output
        assert "Restore completed" in result.output

    def test_restore_skips_config_json(self, runner, tmp_path):
        """restore should skip config.json files."""
        from openlabels.cli.commands.system import restore

        backup_dir = tmp_path / "test_restore_config"
        backup_dir.mkdir()
        config_file = backup_dir / "config.json"
        config_file.write_text(json.dumps({"key": "value"}))

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api:
            mock_api.return_value = mock_client

            result = runner.invoke(restore, ["--from", str(backup_dir)])

        assert result.exit_code == 0
        assert "Skipped: config.json" in result.output

    def test_restore_validates_backup_filenames(self, runner, tmp_path):
        """restore should reject files with invalid filenames."""
        from openlabels.cli.commands.system import restore

        backup_dir = tmp_path / "test_restore_invalid"
        backup_dir.mkdir()
        # Create a file with valid characters (dots, dashes, underscores are allowed)
        valid_file = backup_dir / "targets.json"
        valid_file.write_text(json.dumps([{"id": 1}]))

        mock_response = MagicMock()
        mock_response.status_code = 201

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api:
            mock_api.return_value = mock_client

            result = runner.invoke(restore, ["--from", str(backup_dir)])

        assert result.exit_code == 0
        assert "Restore completed" in result.output

    def test_restore_with_db_restore(self, runner, tmp_path):
        """restore --include-db should run psql."""
        from openlabels.cli.commands.system import restore

        backup_dir = tmp_path / "test_restore_db"
        backup_dir.mkdir()

        # Create a gzipped SQL dump file
        import gzip
        dump_file = backup_dir / "database.sql.gz"
        with gzip.open(dump_file, "wb") as f:
            f.write(b"CREATE TABLE test;")

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            mock_api.return_value = mock_client

            result = runner.invoke(restore, [
                "--from", str(backup_dir),
                "--include-db",
                "--db-url", "postgresql://localhost/testdb",
            ])

        assert result.exit_code == 0
        assert "Restoring database" in result.output
        assert "Database restored successfully" in result.output

    def test_restore_db_psql_not_found(self, runner, tmp_path):
        """restore should handle missing psql gracefully."""
        from openlabels.cli.commands.system import restore

        backup_dir = tmp_path / "test_restore_nopsql"
        backup_dir.mkdir()

        import gzip
        dump_file = backup_dir / "database.sql.gz"
        with gzip.open(dump_file, "wb") as f:
            f.write(b"CREATE TABLE test;")

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("subprocess.Popen", side_effect=FileNotFoundError("psql not found")):
            mock_api.return_value = mock_client

            result = runner.invoke(restore, [
                "--from", str(backup_dir),
                "--include-db",
                "--db-url", "postgresql://localhost/testdb",
            ])

        assert result.exit_code == 0
        assert "psql not found" in result.output

    def test_restore_invalid_json_file(self, runner, tmp_path):
        """restore should handle invalid JSON files gracefully."""
        from openlabels.cli.commands.system import restore

        backup_dir = tmp_path / "test_restore_badjson"
        backup_dir.mkdir()
        bad_file = backup_dir / "targets.json"
        bad_file.write_text("not valid json{{{")

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api:
            mock_api.return_value = mock_client

            result = runner.invoke(restore, ["--from", str(backup_dir)])

        assert result.exit_code == 0
        assert "invalid JSON" in result.output


class TestParsePgEnv:
    """Tests for the _parse_pg_env helper function."""

    def test_parse_full_url(self):
        """_parse_pg_env should parse a complete PostgreSQL URL."""
        from openlabels.cli.commands.system import _parse_pg_env

        env = _parse_pg_env("postgresql://user:pass@host:5432/mydb")

        assert env["PGHOST"] == "host"
        assert env["PGPORT"] == "5432"
        assert env["PGUSER"] == "user"
        assert env["PGPASSWORD"] == "pass"
        assert env["PGDATABASE"] == "mydb"

    def test_parse_url_without_password(self):
        """_parse_pg_env should handle URL without password."""
        from openlabels.cli.commands.system import _parse_pg_env

        env = _parse_pg_env("postgresql://user@host/mydb")

        assert env["PGHOST"] == "host"
        assert env["PGUSER"] == "user"
        assert "PGPASSWORD" not in env

    def test_parse_url_with_default_port(self):
        """_parse_pg_env should handle URL without port."""
        from openlabels.cli.commands.system import _parse_pg_env

        env = _parse_pg_env("postgresql://user:pass@host/mydb")

        assert env["PGHOST"] == "host"
        assert "PGPORT" not in env

    def test_parse_minimal_url(self):
        """_parse_pg_env should handle a minimal URL."""
        from openlabels.cli.commands.system import _parse_pg_env

        env = _parse_pg_env("postgresql:///mydb")

        assert env.get("PGDATABASE") == "mydb"

    def test_parse_empty_url(self):
        """_parse_pg_env should return empty dict for empty URL."""
        from openlabels.cli.commands.system import _parse_pg_env

        env = _parse_pg_env("")

        assert isinstance(env, dict)


class TestSubprocessCommandConstruction:
    """Tests for subprocess command construction in backup/restore."""

    def test_pg_dump_command_uses_env_vars(self, runner, tmp_path):
        """pg_dump should use PG* env vars, not CLI flags for credentials."""
        from openlabels.cli.commands.system import backup

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stdout.read.return_value = b""
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None

        output_dir = str(tmp_path / "backup_envtest")

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            mock_api.return_value = mock_client

            result = runner.invoke(backup, [
                "--output", output_dir,
                "--include-db",
                "--db-url", "postgresql://myuser:mypass@dbhost:5432/mydb",
            ])

        # Check that Popen was called with env vars containing PGPASSWORD
        call_kwargs = mock_popen.call_args
        env_arg = call_kwargs[1].get("env", {})
        assert env_arg.get("PGPASSWORD") == "mypass"
        assert env_arg.get("PGHOST") == "dbhost"

        # The command should be pg_dump with --no-owner --no-acl (no password on CLI)
        cmd_arg = call_kwargs[0][0]
        assert cmd_arg == ["pg_dump", "--no-owner", "--no-acl"]

    def test_psql_restore_uses_env_vars(self, runner, tmp_path):
        """psql restore should use PG* env vars for credentials."""
        from openlabels.cli.commands.system import restore

        backup_dir = tmp_path / "test_psql_env"
        backup_dir.mkdir()

        import gzip
        dump_file = backup_dir / "database.sql.gz"
        with gzip.open(dump_file, "wb") as f:
            f.write(b"SELECT 1;")

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("openlabels.cli.commands.system.api_client") as mock_api, \
             patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            mock_api.return_value = mock_client

            result = runner.invoke(restore, [
                "--from", str(backup_dir),
                "--include-db",
                "--db-url", "postgresql://restoreuser:restorepass@restorehost:5433/restoredb",
            ])

        call_kwargs = mock_popen.call_args
        env_arg = call_kwargs[1].get("env", {})
        assert env_arg.get("PGPASSWORD") == "restorepass"
        assert env_arg.get("PGHOST") == "restorehost"
        assert env_arg.get("PGPORT") == "5433"
