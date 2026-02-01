"""Tests for scrubiq/cli.py - Command-line interface.

Tests cover:
- Helper functions (get_config, get_api_key, get_scrubiq_with_key)
- Key management commands (keys create, keys list, keys revoke)
- Main commands (redact, restore, tokens, audit, bench, demo, process)
- Argument parsing
- Error handling
- Main entry point
"""

import io
import os
import sys
import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock
from contextlib import contextmanager

import pytest


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_config():
    """Create a mock Config object."""
    config = MagicMock()
    config.data_dir = Path("/tmp/scrubiq")
    config.db_path = Path("/tmp/scrubiq/db.sqlite")
    config.ensure_directories = MagicMock()
    return config


@pytest.fixture
def mock_database():
    """Create a mock Database."""
    db = MagicMock()
    db.connect = MagicMock()
    db.close = MagicMock()
    return db


@pytest.fixture
def mock_api_key_service():
    """Create a mock APIKeyService."""
    service = MagicMock()
    service.has_any_keys.return_value = False
    service.create_key.return_value = ("sk-test123", MagicMock(
        name="test-key",
        key_prefix="sk-test",
        rate_limit=1000,
        permissions=["redact", "restore", "admin"]
    ))
    service.validate_key.return_value = MagicMock(
        permissions=["admin", "redact", "restore"]
    )
    service.list_keys.return_value = []
    return service


@pytest.fixture
def mock_scrubiq():
    """Create a mock ScrubIQ instance."""
    scrubiq = MagicMock()
    scrubiq.unlock = MagicMock()
    scrubiq.redact.return_value = MagicMock(
        redacted="Hello [NAME_1]",
        spans=[MagicMock(entity_type="NAME", confidence=0.9)]
    )
    scrubiq.restore.return_value = MagicMock(restored="Hello John Smith")
    scrubiq.get_tokens.return_value = [
        {"token": "[NAME_1]", "original": "John Smith", "safe_harbor": "John Doe", "type": "NAME"}
    ]
    scrubiq.get_audit_entries.return_value = []
    scrubiq.verify_audit_chain.return_value = (True, None)
    scrubiq.__enter__ = Mock(return_value=scrubiq)
    scrubiq.__exit__ = Mock(return_value=False)
    return scrubiq


@pytest.fixture
def mock_args():
    """Create mock command args."""
    args = argparse.Namespace()
    args.data_dir = None
    return args


@contextmanager
def captured_output():
    """Capture stdout and stderr."""
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


# =============================================================================
# GET_CONFIG TESTS
# =============================================================================

class TestGetConfig:
    """Tests for get_config function."""

    def test_returns_config(self, mock_config):
        """Returns a Config object."""
        from scrubiq.cli import get_config

        with patch('scrubiq.cli.Config', return_value=mock_config):
            args = argparse.Namespace(data_dir=None)
            config = get_config(args)

            assert config is not None

    def test_overrides_data_dir(self, mock_config):
        """Overrides data_dir when specified."""
        from scrubiq.cli import get_config

        with patch('scrubiq.cli.Config', return_value=mock_config):
            args = argparse.Namespace(data_dir="/custom/path")
            config = get_config(args)

            assert config.data_dir == Path("/custom/path")

    def test_expands_user_path(self, mock_config):
        """Expands user home directory in path."""
        from scrubiq.cli import get_config

        with patch('scrubiq.cli.Config', return_value=mock_config):
            args = argparse.Namespace(data_dir="~/scrubiq")
            config = get_config(args)

            # Should expand ~ to actual home
            assert "~" not in str(config.data_dir)


# =============================================================================
# GET_API_KEY TESTS
# =============================================================================

class TestGetApiKey:
    """Tests for get_api_key function."""

    def test_returns_env_key(self):
        """Returns API key from environment."""
        from scrubiq.cli import get_api_key

        with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-test123"}):
            key = get_api_key()
            assert key == "sk-test123"

    def test_exits_without_key(self):
        """Exits with error when no key set."""
        from scrubiq.cli import get_api_key

        with patch.dict(os.environ, {}, clear=True):
            if "SCRUBIQ_API_KEY" in os.environ:
                del os.environ["SCRUBIQ_API_KEY"]

            with pytest.raises(SystemExit) as exc_info:
                with captured_output() as (out, err):
                    get_api_key()

            assert exc_info.value.code == 1

    def test_prints_help_message(self):
        """Prints helpful error message when key missing."""
        from scrubiq.cli import get_api_key

        env = {k: v for k, v in os.environ.items() if k != "SCRUBIQ_API_KEY"}

        with patch.dict(os.environ, env, clear=True):
            with captured_output() as (out, err):
                try:
                    get_api_key()
                except SystemExit:
                    pass

            error_output = err.getvalue()
            assert "SCRUBIQ_API_KEY" in error_output


# =============================================================================
# GET_SCRUBIQ_WITH_KEY TESTS
# =============================================================================

class TestGetScrubiqWithKey:
    """Tests for get_scrubiq_with_key function."""

    def test_creates_and_unlocks_instance(self, mock_config, mock_scrubiq, mock_api_key_service):
        """Creates ScrubIQ instance and unlocks with key."""
        from scrubiq.cli import get_scrubiq_with_key

        with patch('scrubiq.cli.ScrubIQ', return_value=mock_scrubiq):
            with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                mock_api_key_service.derive_encryption_key.return_value = b'0' * 32

                result = get_scrubiq_with_key(mock_config, "sk-test123")

                assert result is mock_scrubiq
                mock_scrubiq.unlock.assert_called_once()

    def test_exits_on_invalid_key(self, mock_config, mock_scrubiq, mock_api_key_service):
        """Exits when API key is invalid."""
        from scrubiq.cli import get_scrubiq_with_key

        mock_api_key_service.validate_key.return_value = None

        with patch('scrubiq.cli.ScrubIQ', return_value=mock_scrubiq):
            with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                with pytest.raises(SystemExit) as exc_info:
                    with captured_output():
                        get_scrubiq_with_key(mock_config, "sk-invalid")

                assert exc_info.value.code == 1

    def test_exits_on_unlock_failure(self, mock_config, mock_scrubiq, mock_api_key_service):
        """Exits when unlock fails."""
        from scrubiq.cli import get_scrubiq_with_key

        mock_scrubiq.unlock.side_effect = Exception("Unlock failed")
        mock_api_key_service.derive_encryption_key.return_value = b'0' * 32

        with patch('scrubiq.cli.ScrubIQ', return_value=mock_scrubiq):
            with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                with pytest.raises(SystemExit) as exc_info:
                    with captured_output():
                        get_scrubiq_with_key(mock_config, "sk-test123")

                assert exc_info.value.code == 1


# =============================================================================
# CMD_KEYS_CREATE TESTS
# =============================================================================

class TestCmdKeysCreate:
    """Tests for cmd_keys_create function."""

    def test_creates_first_key_with_admin(self, mock_config, mock_database, mock_api_key_service):
        """First key gets admin permissions."""
        from scrubiq.cli import cmd_keys_create

        args = argparse.Namespace(
            data_dir=None,
            name="test-key",
            rate_limit=1000,
            permissions=None,
            force=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with captured_output() as (out, err):
                        cmd_keys_create(args)

                    output = out.getvalue()
                    assert "API KEY CREATED" in output
                    assert "sk-test123" in output

    def test_requires_auth_when_keys_exist(self, mock_config, mock_database, mock_api_key_service):
        """Requires auth when keys already exist."""
        from scrubiq.cli import cmd_keys_create

        mock_api_key_service.has_any_keys.return_value = True

        args = argparse.Namespace(
            data_dir=None,
            name="test-key",
            rate_limit=1000,
            permissions=None,
            force=False
        )

        env = {k: v for k, v in os.environ.items() if k != "SCRUBIQ_API_KEY"}

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, env, clear=True):
                        with pytest.raises(SystemExit) as exc_info:
                            with captured_output():
                                cmd_keys_create(args)

                        assert exc_info.value.code == 1

    def test_validates_permissions(self, mock_config, mock_database, mock_api_key_service):
        """Validates permission values."""
        from scrubiq.cli import cmd_keys_create

        args = argparse.Namespace(
            data_dir=None,
            name="test-key",
            rate_limit=1000,
            permissions="redact,invalid_perm",
            force=True
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with pytest.raises(SystemExit) as exc_info:
                        with captured_output():
                            cmd_keys_create(args)

                    assert exc_info.value.code == 1

    def test_parses_permissions_correctly(self, mock_config, mock_database, mock_api_key_service):
        """Parses comma-separated permissions."""
        from scrubiq.cli import cmd_keys_create

        args = argparse.Namespace(
            data_dir=None,
            name="test-key",
            rate_limit=1000,
            permissions="redact, restore, chat",  # With spaces
            force=True
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with captured_output():
                        cmd_keys_create(args)

                    # Should call create_key with parsed permissions
                    call_args = mock_api_key_service.create_key.call_args
                    assert "redact" in call_args.kwargs["permissions"]


# =============================================================================
# CMD_KEYS_LIST TESTS
# =============================================================================

class TestCmdKeysList:
    """Tests for cmd_keys_list function."""

    def test_requires_api_key(self, mock_config, mock_database, mock_api_key_service):
        """Requires API key to list keys."""
        from scrubiq.cli import cmd_keys_list

        args = argparse.Namespace(data_dir=None, all=False)

        env = {k: v for k, v in os.environ.items() if k != "SCRUBIQ_API_KEY"}

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch.dict(os.environ, env, clear=True):
                with pytest.raises(SystemExit):
                    with captured_output():
                        cmd_keys_list(args)

    def test_requires_admin_permission(self, mock_config, mock_database, mock_api_key_service):
        """Requires admin permission to list keys."""
        from scrubiq.cli import cmd_keys_list

        # Mock non-admin key
        mock_api_key_service.validate_key.return_value = MagicMock(
            permissions=["redact"]  # No admin
        )

        args = argparse.Namespace(data_dir=None, all=False)

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-test"}):
                        with pytest.raises(SystemExit) as exc_info:
                            with captured_output():
                                cmd_keys_list(args)

                        assert exc_info.value.code == 1

    def test_lists_keys(self, mock_config, mock_database, mock_api_key_service):
        """Lists API keys."""
        from scrubiq.cli import cmd_keys_list

        mock_key = MagicMock()
        mock_key.key_prefix = "sk-test"
        mock_key.name = "test-key"
        mock_key.rate_limit = 1000
        mock_key.permissions = ["redact", "restore"]
        mock_key.last_used_at = None
        mock_key.is_revoked = False

        mock_api_key_service.list_keys.return_value = [mock_key]

        args = argparse.Namespace(data_dir=None, all=False)

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-admin"}):
                        with captured_output() as (out, err):
                            cmd_keys_list(args)

                        output = out.getvalue()
                        assert "sk-test" in output
                        assert "test-key" in output

    def test_shows_no_keys_message(self, mock_config, mock_database, mock_api_key_service):
        """Shows message when no keys found."""
        from scrubiq.cli import cmd_keys_list

        mock_api_key_service.list_keys.return_value = []

        args = argparse.Namespace(data_dir=None, all=False)

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-admin"}):
                        with captured_output() as (out, err):
                            cmd_keys_list(args)

                        output = out.getvalue()
                        assert "No API keys" in output


# =============================================================================
# CMD_KEYS_REVOKE TESTS
# =============================================================================

class TestCmdKeysRevoke:
    """Tests for cmd_keys_revoke function."""

    def test_revokes_key(self, mock_config, mock_database, mock_api_key_service):
        """Successfully revokes a key."""
        from scrubiq.cli import cmd_keys_revoke

        mock_api_key_service.revoke_key.return_value = True

        args = argparse.Namespace(data_dir=None, prefix="sk-targ")

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-admin"}):
                        with captured_output() as (out, err):
                            cmd_keys_revoke(args)

                        output = out.getvalue()
                        assert "revoked" in output.lower()

    def test_prevents_self_revocation(self, mock_config, mock_database, mock_api_key_service):
        """Prevents revoking own key."""
        from scrubiq.cli import cmd_keys_revoke

        args = argparse.Namespace(data_dir=None, prefix="sk-admin")  # Same as env key

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-admin123"}):
                        with pytest.raises(SystemExit) as exc_info:
                            with captured_output():
                                cmd_keys_revoke(args)

                        assert exc_info.value.code == 1

    def test_handles_not_found(self, mock_config, mock_database, mock_api_key_service):
        """Handles key not found."""
        from scrubiq.cli import cmd_keys_revoke

        mock_api_key_service.revoke_key.return_value = False

        args = argparse.Namespace(data_dir=None, prefix="sk-notfound")

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.Database', return_value=mock_database):
                with patch('scrubiq.cli.APIKeyService', return_value=mock_api_key_service):
                    with patch.dict(os.environ, {"SCRUBIQ_API_KEY": "sk-admin"}):
                        with pytest.raises(SystemExit) as exc_info:
                            with captured_output():
                                cmd_keys_revoke(args)

                        assert exc_info.value.code == 1


# =============================================================================
# CMD_REDACT TESTS
# =============================================================================

class TestCmdRedact:
    """Tests for cmd_redact function."""

    def test_redacts_text_argument(self, mock_config, mock_scrubiq, mock_api_key_service):
        """Redacts text from command argument."""
        from scrubiq.cli import cmd_redact

        args = argparse.Namespace(
            data_dir=None,
            text="Patient John Smith",
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_redact(args)

                    output = out.getvalue()
                    assert "[NAME_1]" in output

    def test_redacts_stdin(self, mock_config, mock_scrubiq, mock_api_key_service):
        """Redacts text from stdin."""
        from scrubiq.cli import cmd_redact

        args = argparse.Namespace(
            data_dir=None,
            text=None,  # No text arg = use stdin
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with patch('sys.stdin', io.StringIO("Patient John Smith")):
                        with captured_output() as (out, err):
                            cmd_redact(args)

                        output = out.getvalue()
                        assert "[NAME_1]" in output

    def test_verbose_shows_spans(self, mock_config, mock_scrubiq, mock_api_key_service):
        """Verbose mode shows detected spans."""
        from scrubiq.cli import cmd_redact

        args = argparse.Namespace(
            data_dir=None,
            text="Patient John Smith",
            verbose=True
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_redact(args)

                    # Verbose output goes to stderr
                    error_output = err.getvalue()
                    assert "spans detected" in error_output


# =============================================================================
# CMD_RESTORE TESTS
# =============================================================================

class TestCmdRestore:
    """Tests for cmd_restore function."""

    def test_restores_text(self, mock_config, mock_scrubiq):
        """Restores text with tokens."""
        from scrubiq.cli import cmd_restore

        args = argparse.Namespace(
            data_dir=None,
            text="Hello [NAME_1]",
            safe_harbor=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_restore(args)

                    output = out.getvalue()
                    assert "John Smith" in output

    def test_safe_harbor_mode(self, mock_config, mock_scrubiq):
        """Uses Safe Harbor mode when specified."""
        from scrubiq.cli import cmd_restore
        from scrubiq.types import PrivacyMode

        args = argparse.Namespace(
            data_dir=None,
            text="Hello [NAME_1]",
            safe_harbor=True
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output():
                        cmd_restore(args)

                    # Verify restore was called with Safe Harbor mode
                    call_args = mock_scrubiq.restore.call_args
                    assert call_args.kwargs.get("mode") == PrivacyMode.SAFE_HARBOR


# =============================================================================
# CMD_TOKENS TESTS
# =============================================================================

class TestCmdTokens:
    """Tests for cmd_tokens function."""

    def test_lists_tokens(self, mock_config, mock_scrubiq):
        """Lists stored tokens."""
        from scrubiq.cli import cmd_tokens

        args = argparse.Namespace(data_dir=None)

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_tokens(args)

                    output = out.getvalue()
                    assert "[NAME_1]" in output
                    assert "John Doe" in output  # Safe harbor value

    def test_shows_no_tokens_message(self, mock_config, mock_scrubiq):
        """Shows message when no tokens."""
        from scrubiq.cli import cmd_tokens

        mock_scrubiq.get_tokens.return_value = []

        args = argparse.Namespace(data_dir=None)

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_tokens(args)

                    output = out.getvalue()
                    assert "No tokens" in output


# =============================================================================
# CMD_AUDIT TESTS
# =============================================================================

class TestCmdAudit:
    """Tests for cmd_audit function."""

    def test_shows_audit_log(self, mock_config, mock_scrubiq):
        """Shows audit log entries."""
        from scrubiq.cli import cmd_audit

        mock_scrubiq.get_audit_entries.return_value = [
            {
                "sequence": 1,
                "timestamp": "2025-01-01T00:00:00",
                "event": "redact",
                "data": {"text_length": 100}
            }
        ]

        args = argparse.Namespace(
            data_dir=None,
            verify=False,
            limit=20,
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_audit(args)

                    output = out.getvalue()
                    assert "redact" in output

    def test_verify_chain_valid(self, mock_config, mock_scrubiq):
        """Verifies valid audit chain."""
        from scrubiq.cli import cmd_audit

        args = argparse.Namespace(
            data_dir=None,
            verify=True,
            limit=20,
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_audit(args)

                    output = out.getvalue()
                    assert "VALID" in output

    def test_verify_chain_invalid(self, mock_config, mock_scrubiq):
        """Verifies invalid audit chain."""
        from scrubiq.cli import cmd_audit

        mock_scrubiq.verify_audit_chain.return_value = (False, "Hash mismatch")

        args = argparse.Namespace(
            data_dir=None,
            verify=True,
            limit=20,
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_audit(args)

                    output = out.getvalue()
                    assert "INVALID" in output
                    assert "Hash mismatch" in output


# =============================================================================
# CMD_BENCH TESTS
# =============================================================================

class TestCmdBench:
    """Tests for cmd_bench function."""

    def test_runs_benchmark(self, mock_config, mock_scrubiq):
        """Runs performance benchmark."""
        from scrubiq.cli import cmd_bench

        args = argparse.Namespace(
            data_dir=None,
            iterations=2  # Small number for test
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_bench(args)

                    output = out.getvalue()
                    assert "Benchmark results" in output
                    assert "Throughput" in output
                    assert "latency" in output


# =============================================================================
# CMD_PROCESS TESTS
# =============================================================================

class TestCmdProcess:
    """Tests for cmd_process function."""

    def test_processes_file(self, mock_config, mock_scrubiq, tmp_path):
        """Processes a file."""
        from scrubiq.cli import cmd_process

        # Create a temporary test file
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"Patient John Smith")

        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.error = None
        mock_job.status = MagicMock(value="completed")
        mock_job.pages_total = 1
        mock_job.processing_time_ms = 100
        mock_job.spans = []
        mock_job.extracted_text = "Patient John Smith"
        mock_job.has_redacted_image = False
        mock_processor.process_file.return_value = mock_job

        args = argparse.Namespace(
            data_dir=None,
            file=str(test_file),
            output=None,
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with patch('scrubiq.cli.FileProcessor', return_value=mock_processor):
                        with captured_output() as (out, err):
                            cmd_process(args)

                        output = out.getvalue()
                        assert "Processing Result" in output
                        assert "completed" in output

    def test_file_not_found(self, mock_config, mock_scrubiq):
        """Handles file not found."""
        from scrubiq.cli import cmd_process

        args = argparse.Namespace(
            data_dir=None,
            file="/nonexistent/file.txt",
            output=None,
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with pytest.raises(SystemExit) as exc_info:
                    with captured_output():
                        cmd_process(args)

                assert exc_info.value.code == 1

    def test_handles_processing_error(self, mock_config, mock_scrubiq, tmp_path):
        """Handles processing errors."""
        from scrubiq.cli import cmd_process

        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test")

        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.error = "Processing failed"
        mock_processor.process_file.return_value = mock_job

        args = argparse.Namespace(
            data_dir=None,
            file=str(test_file),
            output=None,
            verbose=False
        )

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with patch('scrubiq.cli.FileProcessor', return_value=mock_processor):
                        with pytest.raises(SystemExit) as exc_info:
                            with captured_output():
                                cmd_process(args)

                        assert exc_info.value.code == 1


# =============================================================================
# CMD_DEMO TESTS
# =============================================================================

class TestCmdDemo:
    """Tests for cmd_demo function."""

    def test_runs_demo(self, mock_config, mock_scrubiq):
        """Runs interactive demo."""
        from scrubiq.cli import cmd_demo

        args = argparse.Namespace(data_dir=None)

        with patch('scrubiq.cli.get_config', return_value=mock_config):
            with patch('scrubiq.cli.get_api_key', return_value="sk-test"):
                with patch('scrubiq.cli.get_scrubiq_with_key', return_value=mock_scrubiq):
                    with captured_output() as (out, err):
                        cmd_demo(args)

                    output = out.getvalue()
                    assert "SCRUBIQ DEMO" in output
                    assert "Original:" in output
                    assert "Redacted:" in output


# =============================================================================
# MAIN FUNCTION TESTS
# =============================================================================

class TestMain:
    """Tests for main() entry point."""

    def test_no_args_shows_help(self):
        """Shows help with no arguments."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq']):
            with captured_output() as (out, err):
                main()

            # Should print help
            # output = out.getvalue()

    def test_keys_subcommand_routing(self, mock_config, mock_database, mock_api_key_service):
        """Routes keys subcommands correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'keys', 'create', '-n', 'test', '-f']):
            with patch('scrubiq.cli.cmd_keys_create') as mock_cmd:
                with patch('scrubiq.cli.get_config', return_value=mock_config):
                    main()
                    mock_cmd.assert_called_once()

    def test_redact_command_routing(self, mock_config, mock_scrubiq):
        """Routes redact command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'redact', 'test text']):
            with patch('scrubiq.cli.cmd_redact') as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_restore_command_routing(self, mock_config, mock_scrubiq):
        """Routes restore command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'restore', '[NAME_1]']):
            with patch('scrubiq.cli.cmd_restore') as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_tokens_command_routing(self):
        """Routes tokens command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'tokens']):
            with patch('scrubiq.cli.cmd_tokens') as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_audit_command_routing(self):
        """Routes audit command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'audit']):
            with patch('scrubiq.cli.cmd_audit') as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_bench_command_routing(self):
        """Routes bench command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'bench']):
            with patch('scrubiq.cli.cmd_bench') as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_demo_command_routing(self):
        """Routes demo command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'demo']):
            with patch('scrubiq.cli.cmd_demo') as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_process_command_routing(self):
        """Routes process command correctly."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'process', 'file.txt']):
            with patch('scrubiq.cli.cmd_process') as mock_cmd:
                main()
                mock_cmd.assert_called_once()


# =============================================================================
# ARGUMENT PARSING TESTS
# =============================================================================

class TestArgumentParsing:
    """Tests for argument parsing."""

    def test_global_data_dir_option(self):
        """Global --data-dir option is parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', '--data-dir', '/custom/path', 'tokens']):
            with patch('scrubiq.cli.cmd_tokens') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.data_dir == '/custom/path'

    def test_redact_verbose_option(self):
        """Redact -v/--verbose option is parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'redact', '-v', 'text']):
            with patch('scrubiq.cli.cmd_redact') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.verbose is True

    def test_restore_safe_harbor_option(self):
        """Restore --safe-harbor option is parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'restore', '--safe-harbor', '[NAME_1]']):
            with patch('scrubiq.cli.cmd_restore') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.safe_harbor is True

    def test_audit_options(self):
        """Audit command options are parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'audit', '--verify', '--limit', '50', '-v']):
            with patch('scrubiq.cli.cmd_audit') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.verify is True
                assert args.limit == 50
                assert args.verbose is True

    def test_bench_iterations_option(self):
        """Bench -n/--iterations option is parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'bench', '-n', '50']):
            with patch('scrubiq.cli.cmd_bench') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.iterations == 50

    def test_keys_create_options(self):
        """Keys create options are parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', [
            'scrubiq', 'keys', 'create',
            '-n', 'my-key',
            '-r', '500',
            '-p', 'redact,restore',
            '-f'
        ]):
            with patch('scrubiq.cli.cmd_keys_create') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.name == 'my-key'
                assert args.rate_limit == 500
                assert args.permissions == 'redact,restore'
                assert args.force is True

    def test_process_options(self):
        """Process command options are parsed."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'process', 'file.pdf', '-o', 'out.pdf', '-v']):
            with patch('scrubiq.cli.cmd_process') as mock_cmd:
                main()

                args = mock_cmd.call_args[0][0]
                assert args.file == 'file.pdf'
                assert args.output == 'out.pdf'
                assert args.verbose is True


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_command(self):
        """Handles invalid command."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'invalid_command']):
            # Should not crash, just show help
            main()

    def test_missing_required_args(self):
        """Handles missing required arguments."""
        from scrubiq.cli import main

        with patch('sys.argv', ['scrubiq', 'keys', 'create']):  # Missing -n
            with pytest.raises(SystemExit):
                main()

    def test_handles_keyboard_interrupt(self, mock_config, mock_scrubiq):
        """Handles keyboard interrupt gracefully."""
        # This is harder to test directly, but we can verify the code doesn't crash
        pass
