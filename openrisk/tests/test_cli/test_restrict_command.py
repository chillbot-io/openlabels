"""
Tests for the restrict CLI command.

Tests file permission restriction functionality.
"""

import argparse
import os
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from openlabels.cli.commands.restrict import (
    restrict_posix,
    cmd_restrict,
    add_restrict_parser,
)


class TestRestrictPosix:
    """Tests for restrict_posix function."""

    def test_private_mode_owner_only(self, tmp_path):
        """Private mode should set owner rw only."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        # Start with permissive
        os.chmod(test_file, 0o777)

        result = restrict_posix(test_file, "private")

        assert result is True
        mode = test_file.stat().st_mode
        # Should be rw------- (0600)
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR

    def test_internal_mode_owner_group(self, tmp_path):
        """Internal mode should set owner rw, group r."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        os.chmod(test_file, 0o777)

        result = restrict_posix(test_file, "internal")

        assert result is True
        mode = test_file.stat().st_mode
        # Should be rw-r----- (0640)
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP

    def test_readonly_mode_owner_read(self, tmp_path):
        """Readonly mode should set owner read only."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        os.chmod(test_file, 0o777)

        result = restrict_posix(test_file, "readonly")

        assert result is True
        mode = test_file.stat().st_mode
        # Should be r-------- (0400)
        assert mode & 0o777 == stat.S_IRUSR

    def test_returns_true_on_success(self, tmp_path):
        """Should return True on successful permission change."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = restrict_posix(test_file, "private")

        assert result is True

    def test_returns_false_on_error(self, tmp_path):
        """Should return False when permission change fails."""
        nonexistent = tmp_path / "does_not_exist.txt"

        result = restrict_posix(nonexistent, "private")

        assert result is False

    def test_unknown_mode_no_change(self, tmp_path):
        """Unknown mode should not change permissions."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        os.chmod(test_file, 0o644)
        original_mode = test_file.stat().st_mode

        result = restrict_posix(test_file, "unknown_mode")

        # Should return True (no error), mode unchanged
        assert result is True
        assert test_file.stat().st_mode == original_mode


class TestCmdRestrictValidation:
    """Tests for cmd_restrict command validation."""

    @pytest.fixture
    def mock_args(self):
        """Create mock args object."""
        args = MagicMock()
        args.where = None
        args.acl = None
        args.source = "/tmp/test"
        args.recursive = True
        args.exposure = "PRIVATE"
        args.extensions = None
        args.dry_run = False
        args.force = False
        args.quiet = False
        return args

    def test_requires_where_filter(self, mock_args):
        """Should require --where filter."""
        mock_args.where = None
        mock_args.acl = "private"

        with patch("openlabels.cli.commands.restrict.error"):
            result = cmd_restrict(mock_args)

        assert result == 1

    def test_requires_acl(self, mock_args):
        """Should require --acl."""
        mock_args.where = "score > 50"
        mock_args.acl = None

        with patch("openlabels.cli.commands.restrict.error"):
            result = cmd_restrict(mock_args)

        assert result == 1


class TestCmdRestrictCloudPaths:
    """Tests for cloud path handling."""

    @pytest.fixture
    def mock_args(self):
        """Create mock args for cloud tests."""
        args = MagicMock()
        args.where = "score > 50"
        args.acl = "private"
        args.recursive = True
        args.exposure = "PRIVATE"
        args.extensions = None
        args.dry_run = False
        args.force = False
        args.quiet = False
        return args

    def test_s3_path_shows_aws_cli_help(self, mock_args):
        """S3 paths should show AWS CLI instructions."""
        mock_args.source = "s3://my-bucket/path"

        with patch("openlabels.cli.commands.restrict.info") as mock_info:
            with patch("openlabels.cli.commands.restrict.echo"):
                result = cmd_restrict(mock_args)

        assert result == 1
        mock_info.assert_called()

    def test_gs_path_shows_gsutil_help(self, mock_args):
        """GCS paths should show gsutil instructions."""
        mock_args.source = "gs://my-bucket/path"

        with patch("openlabels.cli.commands.restrict.info") as mock_info:
            with patch("openlabels.cli.commands.restrict.echo"):
                result = cmd_restrict(mock_args)

        assert result == 1
        mock_info.assert_called()

    def test_azure_path_shows_az_help(self, mock_args):
        """Azure paths should show az cli instructions."""
        mock_args.source = "azure://container/path"

        with patch("openlabels.cli.commands.restrict.info") as mock_info:
            with patch("openlabels.cli.commands.restrict.echo"):
                result = cmd_restrict(mock_args)

        assert result == 1
        mock_info.assert_called()


class TestCmdRestrictLocalPath:
    """Tests for local path operations."""

    @pytest.fixture
    def mock_args(self, tmp_path):
        """Create mock args for local path tests."""
        args = MagicMock()
        args.source = str(tmp_path)
        args.where = "score > 50"
        args.acl = "private"
        args.recursive = True
        args.exposure = "PRIVATE"
        args.extensions = None
        args.dry_run = False
        args.force = True  # Skip confirmation
        args.quiet = True
        return args

    def test_nonexistent_source_returns_error(self, mock_args):
        """Should error when source doesn't exist."""
        mock_args.source = "/nonexistent/path/12345"

        with patch("openlabels.cli.commands.restrict.error"):
            result = cmd_restrict(mock_args)

        assert result == 1

    def test_no_matches_returns_zero(self, mock_args, tmp_path):
        """Should return 0 when no files match."""
        mock_args.source = str(tmp_path)

        with patch("openlabels.cli.commands.restrict.find_matching", return_value=[]):
            with patch("openlabels.cli.commands.restrict.echo"):
                result = cmd_restrict(mock_args)

        assert result == 0

    def test_dry_run_does_not_modify(self, mock_args, tmp_path):
        """Dry run should not modify any files."""
        mock_args.source = str(tmp_path)
        mock_args.dry_run = True

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        os.chmod(test_file, 0o644)
        original_mode = test_file.stat().st_mode

        # Mock a matching result
        mock_result = MagicMock()
        mock_result.path = str(test_file)
        mock_result.score = 80

        with patch("openlabels.cli.commands.restrict.find_matching", return_value=[mock_result]):
            with patch("openlabels.cli.commands.restrict.echo"):
                with patch("openlabels.cli.commands.restrict.dim"):
                    result = cmd_restrict(mock_args)

        assert result == 0
        # File permissions should be unchanged
        assert test_file.stat().st_mode == original_mode

    def test_restricts_matching_files(self, mock_args, tmp_path):
        """Should restrict permissions on matching files."""
        mock_args.source = str(tmp_path)

        # Create test file
        test_file = tmp_path / "sensitive.txt"
        test_file.write_text("SSN: 123-45-6789")
        os.chmod(test_file, 0o644)

        # Mock a matching result
        mock_result = MagicMock()
        mock_result.path = str(test_file)
        mock_result.score = 80

        with patch("openlabels.cli.commands.restrict.find_matching", return_value=[mock_result]):
            with patch("openlabels.cli.commands.restrict.echo"):
                with patch("openlabels.cli.commands.restrict.divider"):
                    with patch("openlabels.cli.commands.restrict.success"):
                        with patch("openlabels.cli.commands.restrict.progress") as mock_progress:
                            # Mock progress context manager
                            mock_progress.return_value.__enter__ = MagicMock(return_value=MagicMock())
                            mock_progress.return_value.__exit__ = MagicMock(return_value=False)
                            with patch("openlabels.cli.commands.restrict.audit"):
                                result = cmd_restrict(mock_args)

        assert result == 0
        # File should now be private (0600)
        mode = test_file.stat().st_mode
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR


class TestCmdRestrictConfirmation:
    """Tests for confirmation behavior."""

    @pytest.fixture
    def mock_args(self, tmp_path):
        """Create mock args."""
        args = MagicMock()
        args.source = str(tmp_path)
        args.where = "score > 50"
        args.acl = "private"
        args.recursive = True
        args.exposure = "PRIVATE"
        args.extensions = None
        args.dry_run = False
        args.force = False  # Require confirmation
        args.quiet = False
        return args

    def test_aborts_on_user_decline(self, mock_args, tmp_path):
        """Should abort when user declines confirmation."""
        mock_args.source = str(tmp_path)

        mock_result = MagicMock()
        mock_result.path = str(tmp_path / "test.txt")
        mock_result.score = 80

        with patch("openlabels.cli.commands.restrict.find_matching", return_value=[mock_result]):
            with patch("openlabels.cli.commands.restrict.echo"):
                with patch("openlabels.cli.commands.restrict.confirm", return_value=False):
                    result = cmd_restrict(mock_args)

        assert result == 1

    def test_proceeds_on_user_confirm(self, mock_args, tmp_path):
        """Should proceed when user confirms."""
        mock_args.source = str(tmp_path)

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_result = MagicMock()
        mock_result.path = str(test_file)
        mock_result.score = 80

        with patch("openlabels.cli.commands.restrict.find_matching", return_value=[mock_result]):
            with patch("openlabels.cli.commands.restrict.echo"):
                with patch("openlabels.cli.commands.restrict.confirm", return_value=True):
                    with patch("openlabels.cli.commands.restrict.divider"):
                        with patch("openlabels.cli.commands.restrict.success"):
                            with patch("openlabels.cli.commands.restrict.progress") as mock_progress:
                                mock_progress.return_value.__enter__ = MagicMock(return_value=MagicMock())
                                mock_progress.return_value.__exit__ = MagicMock(return_value=False)
                                with patch("openlabels.cli.commands.restrict.audit"):
                                    result = cmd_restrict(mock_args)

        assert result == 0

    def test_force_skips_confirmation(self, mock_args, tmp_path):
        """--force should skip confirmation."""
        mock_args.source = str(tmp_path)
        mock_args.force = True

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_result = MagicMock()
        mock_result.path = str(test_file)
        mock_result.score = 80

        with patch("openlabels.cli.commands.restrict.find_matching", return_value=[mock_result]):
            with patch("openlabels.cli.commands.restrict.echo"):
                # Confirm should NOT be called
                with patch("openlabels.cli.commands.restrict.confirm") as mock_confirm:
                    with patch("openlabels.cli.commands.restrict.divider"):
                        with patch("openlabels.cli.commands.restrict.success"):
                            with patch("openlabels.cli.commands.restrict.progress") as mock_progress:
                                mock_progress.return_value.__enter__ = MagicMock(return_value=MagicMock())
                                mock_progress.return_value.__exit__ = MagicMock(return_value=False)
                                with patch("openlabels.cli.commands.restrict.audit"):
                                    result = cmd_restrict(mock_args)

        mock_confirm.assert_not_called()
        assert result == 0


class TestCmdRestrictExtensions:
    """Tests for extension filtering."""

    @pytest.fixture
    def mock_args(self, tmp_path):
        args = MagicMock()
        args.source = str(tmp_path)
        args.where = "score > 50"
        args.acl = "private"
        args.recursive = True
        args.exposure = "PRIVATE"
        args.extensions = "txt,pdf"
        args.dry_run = True
        args.force = True
        args.quiet = True
        return args

    def test_extensions_parsed_correctly(self, mock_args, tmp_path):
        """Extensions should be parsed from comma-separated string."""
        with patch("openlabels.cli.commands.restrict.find_matching") as mock_find:
            mock_find.return_value = []
            with patch("openlabels.cli.commands.restrict.echo"):
                cmd_restrict(mock_args)

        # Check that extensions were passed correctly
        call_args = mock_find.call_args
        assert call_args[1]["extensions"] == ["txt", "pdf"]


class TestAddRestrictParser:
    """Tests for add_restrict_parser function."""

    def test_adds_parser(self):
        """Should add restrict parser to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        result = add_restrict_parser(subparsers)

        assert result is not None

    def test_source_is_required(self):
        """Source argument should be required."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        # Should fail without source
        with pytest.raises(SystemExit):
            parser.parse_args(["restrict", "--where", "score > 50", "--acl", "private"])

    def test_where_is_required(self):
        """--where argument should be required."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        # Should fail without --where
        with pytest.raises(SystemExit):
            parser.parse_args(["restrict", "/tmp", "--acl", "private"])

    def test_acl_is_required(self):
        """--acl argument should be required."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        # Should fail without --acl
        with pytest.raises(SystemExit):
            parser.parse_args(["restrict", "/tmp", "--where", "score > 50"])

    def test_acl_choices(self):
        """--acl should only accept valid choices."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        # Valid choices should work
        for acl in ["private", "internal", "readonly"]:
            args = parser.parse_args(["restrict", "/tmp", "--where", "score > 50", "--acl", acl])
            assert args.acl == acl

        # Invalid choice should fail
        with pytest.raises(SystemExit):
            parser.parse_args(["restrict", "/tmp", "--where", "score > 50", "--acl", "invalid"])

    def test_recursive_default_true(self):
        """--recursive should default to True."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        args = parser.parse_args(["restrict", "/tmp", "--where", "x", "--acl", "private"])
        assert args.recursive is True

    def test_no_recursive_flag(self):
        """--no-recursive should set recursive to False."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        args = parser.parse_args(["restrict", "/tmp", "--where", "x", "--acl", "private", "--no-recursive"])
        assert args.recursive is False

    def test_dry_run_flag(self):
        """--dry-run should be available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        args = parser.parse_args(["restrict", "/tmp", "--where", "x", "--acl", "private", "--dry-run"])
        assert args.dry_run is True

    def test_force_flag(self):
        """--force should be available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        args = parser.parse_args(["restrict", "/tmp", "--where", "x", "--acl", "private", "--force"])
        assert args.force is True

    def test_quiet_flag(self):
        """--quiet should be available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        args = parser.parse_args(["restrict", "/tmp", "--where", "x", "--acl", "private", "--quiet"])
        assert args.quiet is True

    def test_exposure_choices(self):
        """--exposure should accept valid exposure levels."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_restrict_parser(subparsers)

        for exp in ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]:
            args = parser.parse_args(["restrict", "/tmp", "--where", "x", "--acl", "private", "--exposure", exp])
            assert args.exposure == exp

    def test_hidden_mode(self):
        """hidden=True should suppress help text."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        result = add_restrict_parser(subparsers, hidden=True)
        assert result is not None
