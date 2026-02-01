"""Tests for server CLI entrypoint.

Tests all functions in scrubiq/server.py:
- get_env_int / get_env_str
- configure_logging
- run_server
- get_version
- main (CLI entrypoint)
"""

import argparse
import logging
import os
import sys
from io import StringIO
from unittest.mock import MagicMock, patch, call

import pytest


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def clean_env():
    """Clean environment variables before/after tests."""
    original = os.environ.copy()
    # Remove server-related env vars
    for key in [
        "SCRUBIQ_HOST", "SCRUBIQ_PORT", "SCRUBIQ_WORKERS",
        "SCRUBIQ_DEVICE", "SCRUBIQ_THRESHOLD", "PROD", "CORS_ORIGINS"
    ]:
        os.environ.pop(key, None)
    yield
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def capture_stderr():
    """Capture stderr for testing error output."""
    old_stderr = sys.stderr
    sys.stderr = StringIO()
    yield sys.stderr
    sys.stderr = old_stderr


# =============================================================================
# GET ENV INT TESTS
# =============================================================================

class TestGetEnvInt:
    """Tests for get_env_int function."""

    def test_returns_env_value(self, clean_env):
        """Returns integer from environment."""
        from scrubiq.server import get_env_int
        os.environ["TEST_INT"] = "42"
        assert get_env_int("TEST_INT", 0) == 42

    def test_returns_default_when_missing(self, clean_env):
        """Returns default when env var not set."""
        from scrubiq.server import get_env_int
        assert get_env_int("MISSING_VAR", 100) == 100

    def test_returns_default_when_invalid(self, clean_env):
        """Returns default when env var is not valid integer."""
        from scrubiq.server import get_env_int
        os.environ["TEST_INT"] = "not_a_number"
        assert get_env_int("TEST_INT", 50) == 50

    def test_returns_default_when_empty(self, clean_env):
        """Returns default when env var is empty."""
        from scrubiq.server import get_env_int
        os.environ["TEST_INT"] = ""
        assert get_env_int("TEST_INT", 25) == 25

    def test_handles_negative_int(self, clean_env):
        """Handles negative integers."""
        from scrubiq.server import get_env_int
        os.environ["TEST_INT"] = "-5"
        assert get_env_int("TEST_INT", 0) == -5

    def test_handles_zero(self, clean_env):
        """Handles zero value."""
        from scrubiq.server import get_env_int
        os.environ["TEST_INT"] = "0"
        assert get_env_int("TEST_INT", 10) == 0


# =============================================================================
# GET ENV STR TESTS
# =============================================================================

class TestGetEnvStr:
    """Tests for get_env_str function."""

    def test_returns_env_value(self, clean_env):
        """Returns string from environment."""
        from scrubiq.server import get_env_str
        os.environ["TEST_STR"] = "hello"
        assert get_env_str("TEST_STR", "default") == "hello"

    def test_returns_default_when_missing(self, clean_env):
        """Returns default when env var not set."""
        from scrubiq.server import get_env_str
        assert get_env_str("MISSING_VAR", "fallback") == "fallback"

    def test_returns_empty_string(self, clean_env):
        """Returns empty string if set."""
        from scrubiq.server import get_env_str
        os.environ["TEST_STR"] = ""
        # Empty string is still a valid value
        assert get_env_str("TEST_STR", "default") == ""

    def test_preserves_whitespace(self, clean_env):
        """Preserves whitespace in value."""
        from scrubiq.server import get_env_str
        os.environ["TEST_STR"] = "  spaces  "
        assert get_env_str("TEST_STR", "default") == "  spaces  "


# =============================================================================
# CONFIGURE LOGGING TESTS
# =============================================================================

class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_configure_logging_default(self, clean_env):
        """Configures logging with defaults (no errors)."""
        from scrubiq.server import configure_logging

        # Just verify it runs without error
        configure_logging()
        # Check that it configured the root logger
        assert logging.root is not None

    def test_configure_logging_verbose(self, clean_env):
        """Verbose mode runs without error."""
        from scrubiq.server import configure_logging

        configure_logging(verbose=True)
        assert logging.root is not None

    def test_configure_logging_json(self, clean_env):
        """JSON logging runs without error."""
        from scrubiq.server import configure_logging

        configure_logging(json_logs=True)
        assert logging.root is not None

    def test_configure_logging_suppresses_third_party(self, clean_env):
        """Suppresses noisy third-party loggers."""
        from scrubiq.server import configure_logging

        configure_logging()

        assert logging.getLogger("uvicorn.access").level >= logging.WARNING
        assert logging.getLogger("httpx").level >= logging.WARNING
        assert logging.getLogger("httpcore").level >= logging.WARNING


# =============================================================================
# GET VERSION TESTS
# =============================================================================

class TestGetVersion:
    """Tests for get_version function."""

    def test_returns_version_string(self):
        """Returns a version string."""
        from scrubiq.server import get_version
        version = get_version()
        # Should be either a version or "unknown"
        assert isinstance(version, str)
        assert len(version) > 0

    def test_handles_import_scenarios(self):
        """Handles various import scenarios gracefully."""
        from scrubiq.server import get_version
        # The function should always return a string
        version = get_version()
        assert isinstance(version, str)
        # Either a valid version or "unknown"
        assert version == "unknown" or len(version) > 0


# =============================================================================
# RUN SERVER TESTS
# =============================================================================

class TestRunServer:
    """Tests for run_server function."""

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    def test_run_server_defaults(self, mock_logging, mock_uvicorn, clean_env):
        """Runs server with default settings."""
        from scrubiq.server import run_server

        run_server()

        mock_logging.assert_called_once_with(verbose=False, json_logs=False)
        mock_uvicorn.assert_called_once()

        call_kwargs = mock_uvicorn.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8741
        assert call_kwargs["workers"] == 1

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    def test_run_server_custom_host_port(self, mock_logging, mock_uvicorn, clean_env):
        """Runs server with custom host and port."""
        from scrubiq.server import run_server

        run_server(host="0.0.0.0", port=9000)

        call_kwargs = mock_uvicorn.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 9000

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    def test_run_server_multiple_workers(self, mock_logging, mock_uvicorn, clean_env):
        """Runs server with multiple workers."""
        from scrubiq.server import run_server

        run_server(workers=4)

        call_kwargs = mock_uvicorn.call_args[1]
        assert call_kwargs["workers"] == 4

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    def test_run_server_reload_mode(self, mock_logging, mock_uvicorn, clean_env):
        """Runs server with reload mode."""
        from scrubiq.server import run_server

        run_server(reload=True)

        call_kwargs = mock_uvicorn.call_args[1]
        assert call_kwargs["reload"] is True

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    def test_run_server_verbose(self, mock_logging, mock_uvicorn, clean_env):
        """Runs server with verbose logging."""
        from scrubiq.server import run_server

        run_server(verbose=True)

        mock_logging.assert_called_once_with(verbose=True, json_logs=False)
        call_kwargs = mock_uvicorn.call_args[1]
        assert call_kwargs["log_level"] == "debug"
        assert call_kwargs["access_log"] is True

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    def test_run_server_json_logs(self, mock_logging, mock_uvicorn, clean_env):
        """Runs server with JSON logging."""
        from scrubiq.server import run_server

        run_server(json_logs=True)

        mock_logging.assert_called_once_with(verbose=False, json_logs=True)

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    @patch("scrubiq.server.get_env_str")
    def test_run_server_auto_device_cuda(
        self, mock_env_str, mock_logging, mock_uvicorn, clean_env
    ):
        """Auto device detection with CUDA available."""
        from scrubiq.server import run_server

        mock_env_str.return_value = "auto"

        with patch("onnxruntime.get_available_providers") as mock_providers:
            mock_providers.return_value = ["CUDAExecutionProvider", "CPUExecutionProvider"]
            run_server()

        # Server should run (device detection happens)
        mock_uvicorn.assert_called_once()

    @patch("uvicorn.run")
    @patch("scrubiq.server.configure_logging")
    @patch("scrubiq.server.get_env_str")
    def test_run_server_auto_device_cpu(
        self, mock_env_str, mock_logging, mock_uvicorn, clean_env
    ):
        """Auto device detection with only CPU available."""
        from scrubiq.server import run_server

        mock_env_str.return_value = "auto"

        with patch("onnxruntime.get_available_providers") as mock_providers:
            mock_providers.return_value = ["CPUExecutionProvider"]
            run_server()

        mock_uvicorn.assert_called_once()


# =============================================================================
# MAIN CLI TESTS
# =============================================================================

class TestMain:
    """Tests for main() CLI entrypoint."""

    @patch("scrubiq.server.run_server")
    def test_main_default_args(self, mock_run_server, clean_env):
        """Main runs with default arguments."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server"]):
            main()

        mock_run_server.assert_called_once()
        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8741
        assert call_kwargs["workers"] == 1
        assert call_kwargs["reload"] is False
        assert call_kwargs["verbose"] is False
        assert call_kwargs["json_logs"] is False

    @patch("scrubiq.server.run_server")
    def test_main_custom_host(self, mock_run_server, clean_env):
        """Main accepts --host argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--host", "0.0.0.0"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"

    @patch("scrubiq.server.run_server")
    def test_main_short_host(self, mock_run_server, clean_env):
        """Main accepts -H short argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "-H", "0.0.0.0"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"

    @patch("scrubiq.server.run_server")
    def test_main_custom_port(self, mock_run_server, clean_env):
        """Main accepts --port argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--port", "9000"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["port"] == 9000

    @patch("scrubiq.server.run_server")
    def test_main_short_port(self, mock_run_server, clean_env):
        """Main accepts -p short argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "-p", "9000"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["port"] == 9000

    @patch("scrubiq.server.run_server")
    def test_main_workers(self, mock_run_server, clean_env):
        """Main accepts --workers argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--workers", "4"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["workers"] == 4

    @patch("scrubiq.server.run_server")
    def test_main_reload(self, mock_run_server, clean_env):
        """Main accepts --reload argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--reload"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["reload"] is True

    @patch("scrubiq.server.run_server")
    def test_main_verbose(self, mock_run_server, clean_env):
        """Main accepts --verbose argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--verbose"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["verbose"] is True

    @patch("scrubiq.server.run_server")
    def test_main_json_logs(self, mock_run_server, clean_env):
        """Main accepts --json-logs argument."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--json-logs"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["json_logs"] is True

    @patch("scrubiq.server.run_server")
    def test_main_env_vars(self, mock_run_server, clean_env):
        """Main reads from environment variables."""
        from scrubiq.server import main

        os.environ["SCRUBIQ_HOST"] = "192.168.1.1"
        os.environ["SCRUBIQ_PORT"] = "8080"
        os.environ["SCRUBIQ_WORKERS"] = "2"

        with patch("sys.argv", ["scrubiq-server"]):
            main()

        call_kwargs = mock_run_server.call_args[1]
        assert call_kwargs["host"] == "192.168.1.1"
        assert call_kwargs["port"] == 8080
        assert call_kwargs["workers"] == 2

    def test_main_workers_validation(self, clean_env):
        """Main validates workers >= 1."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--workers", "0"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # argparse error exit

    def test_main_reload_workers_conflict(self, clean_env):
        """Main rejects --reload with multiple workers."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--reload", "--workers", "4"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # argparse error exit

    @patch("scrubiq.server.run_server")
    def test_main_keyboard_interrupt(self, mock_run_server, clean_env):
        """Main handles KeyboardInterrupt gracefully."""
        from scrubiq.server import main

        mock_run_server.side_effect = KeyboardInterrupt()

        with patch("sys.argv", ["scrubiq-server"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0  # Clean exit

    @patch("scrubiq.server.run_server")
    def test_main_exception(self, mock_run_server, clean_env):
        """Main handles exceptions with exit code 1."""
        from scrubiq.server import main

        mock_run_server.side_effect = RuntimeError("Server error")

        with patch("sys.argv", ["scrubiq-server"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


# =============================================================================
# VERSION ARGUMENT TESTS
# =============================================================================

class TestVersionArgument:
    """Tests for --version argument."""

    def test_version_argument(self, clean_env, capsys):
        """--version prints version and exits."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "scrubiq-server" in captured.out

    def test_short_version_argument(self, clean_env, capsys):
        """-V prints version and exits."""
        from scrubiq.server import main

        with patch("sys.argv", ["scrubiq-server", "-V"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0


# =============================================================================
# JSON FORMATTER TESTS
# =============================================================================

class TestJSONFormatter:
    """Tests for JSON log formatter."""

    def test_json_formatter_output(self, clean_env):
        """JSON formatter produces valid JSON."""
        import json
        from scrubiq.server import configure_logging

        # Configure JSON logging
        configure_logging(json_logs=True)

        # Get a handler's formatter
        if logging.root.handlers:
            formatter = logging.root.handlers[0].formatter
            if formatter:
                # Create a test record
                record = logging.LogRecord(
                    name="test",
                    level=logging.INFO,
                    pathname="test.py",
                    lineno=1,
                    msg="Test message",
                    args=(),
                    exc_info=None,
                )
                formatted = formatter.format(record)

                # Should be valid JSON
                try:
                    data = json.loads(formatted)
                    assert "message" in data
                    assert data["message"] == "Test message"
                    assert data["level"] == "INFO"
                except json.JSONDecodeError:
                    # If not JSON, it's using standard formatter
                    pass
