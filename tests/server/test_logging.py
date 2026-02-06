"""
Comprehensive tests for structured logging module.

Tests focus on:
- Request ID context management
- JSON formatter output
- Development formatter output
- Setup logging configuration
- ContextLogger wrapper
"""

import pytest
import json
import logging
from io import StringIO
from unittest.mock import patch, MagicMock


class TestRequestIdContext:
    """Tests for request ID context variable management."""

    def test_get_request_id_returns_none_by_default(self):
        """Request ID should be None by default."""
        from openlabels.server.logging import get_request_id, request_id_var

        # Reset context
        request_id_var.set(None)

        assert get_request_id() is None

    def test_set_request_id_stores_value(self):
        """Set request ID should store the value."""
        from openlabels.server.logging import get_request_id, set_request_id, request_id_var

        # Reset context
        request_id_var.set(None)

        set_request_id("test-123")
        assert get_request_id() == "test-123"

        # Cleanup
        request_id_var.set(None)

    def test_request_id_can_be_overwritten(self):
        """Request ID can be overwritten with new value."""
        from openlabels.server.logging import get_request_id, set_request_id, request_id_var

        # Reset context
        request_id_var.set(None)

        set_request_id("first")
        assert get_request_id() == "first"

        set_request_id("second")
        assert get_request_id() == "second"

        # Cleanup
        request_id_var.set(None)


class TestJSONFormatter:
    """Tests for JSON log formatter."""

    def test_formats_as_valid_json(self):
        """Output should be valid JSON."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        # Reset context
        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should parse without error
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_includes_timestamp(self):
        """Output should include timestamp."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert "timestamp" in data
        assert "T" in data["timestamp"]  # ISO format

    def test_includes_level(self):
        """Output should include log level."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="/test/file.py",
            lineno=42,
            msg="Warning message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["level"] == "WARNING"

    def test_includes_logger_name(self):
        """Output should include logger name."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="openlabels.server.routes.scans",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["logger"] == "openlabels.server.routes.scans"

    def test_includes_message(self):
        """Output should include log message."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Scan started for file %s",
            args=("/path/to/file.txt",),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["message"] == "Scan started for file /path/to/file.txt"

    def test_includes_request_id_when_set(self):
        """Output should include request ID when set."""
        from openlabels.server.logging import JSONFormatter, set_request_id, request_id_var

        # Reset and set request ID
        request_id_var.set(None)
        set_request_id("req-456")

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["request_id"] == "req-456"

        # Cleanup
        request_id_var.set(None)

    def test_includes_source_for_warning_and_above(self):
        """Output should include source location for WARNING+."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="/path/to/module.py",
            lineno=100,
            msg="Warning message",
            args=(),
            exc_info=None,
        )
        record.funcName = "my_function"

        output = formatter.format(record)
        data = json.loads(output)

        assert "source" in data
        assert data["source"]["file"] == "/path/to/module.py"
        assert data["source"]["line"] == 100
        assert data["source"]["function"] == "my_function"

    def test_excludes_source_for_info(self):
        """Output should not include source for INFO level."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/path/to/module.py",
            lineno=100,
            msg="Info message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert "source" not in data

    def test_includes_extra_fields(self):
        """Output should include extra fields from record."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.scan_id = "scan-123"
        record.file_count = 50

        output = formatter.format(record)
        data = json.loads(output)

        assert data["scan_id"] == "scan-123"
        assert data["file_count"] == 50

    def test_handles_non_serializable_extras(self):
        """Should stringify non-JSON-serializable extra fields."""
        from openlabels.server.logging import JSONFormatter, request_id_var

        request_id_var.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.complex_object = object()

        output = formatter.format(record)
        data = json.loads(output)

        # Should be stringified
        assert "complex_object" in data
        assert "object" in data["complex_object"]


class TestDevelopmentFormatter:
    """Tests for human-readable development formatter."""

    def test_formats_readable_output(self):
        """Output should be human-readable."""
        from openlabels.server.logging import DevelopmentFormatter, request_id_var

        request_id_var.set(None)

        formatter = DevelopmentFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        assert "INFO" in output
        assert "[test.logger]" in output
        assert "Test message" in output

    def test_includes_timestamp(self):
        """Output should include timestamp."""
        from openlabels.server.logging import DevelopmentFormatter, request_id_var

        request_id_var.set(None)

        formatter = DevelopmentFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should have date-like format
        assert "-" in output[:20]  # YYYY-MM-DD format

    def test_includes_extra_fields(self):
        """Output should include extra fields."""
        from openlabels.server.logging import DevelopmentFormatter, request_id_var

        request_id_var.set(None)

        formatter = DevelopmentFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.scan_id = "scan-123"

        output = formatter.format(record)

        assert "scan_id=scan-123" in output

    def test_includes_request_id_when_set(self):
        """Output should include request ID when set."""
        from openlabels.server.logging import DevelopmentFormatter, set_request_id, request_id_var

        request_id_var.set(None)
        set_request_id("req-abc123")

        formatter = DevelopmentFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        assert "[req-abc1" in output  # First 8 chars

        # Cleanup
        request_id_var.set(None)

    def test_color_codes_when_enabled(self):
        """Should include ANSI color codes when colors enabled."""
        from openlabels.server.logging import DevelopmentFormatter, request_id_var

        request_id_var.set(None)

        formatter = DevelopmentFormatter(use_colors=True)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="/test/file.py",
            lineno=42,
            msg="Error message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should contain ANSI escape sequences
        assert "\033[" in output

    def test_no_colors_when_disabled(self):
        """Should not include ANSI codes when colors disabled."""
        from openlabels.server.logging import DevelopmentFormatter, request_id_var

        request_id_var.set(None)

        formatter = DevelopmentFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="/test/file.py",
            lineno=42,
            msg="Error message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should not contain ANSI escape sequences
        assert "\033[" not in output


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_sets_log_level(self):
        """Should set the specified log level."""
        from openlabels.server.logging import setup_logging

        # Save original handlers
        root_logger = logging.getLogger()
        original_handlers = root_logger.handlers[:]
        original_level = root_logger.level

        try:
            setup_logging(level="DEBUG")
            assert root_logger.level == logging.DEBUG

            setup_logging(level="ERROR")
            assert root_logger.level == logging.ERROR
        finally:
            # Restore
            root_logger.setLevel(original_level)
            root_logger.handlers = original_handlers

    def test_case_insensitive_level(self):
        """Should accept case-insensitive log level."""
        from openlabels.server.logging import setup_logging

        root_logger = logging.getLogger()
        original_handlers = root_logger.handlers[:]
        original_level = root_logger.level

        try:
            setup_logging(level="info")
            assert root_logger.level == logging.INFO

            setup_logging(level="WARNING")
            assert root_logger.level == logging.WARNING
        finally:
            root_logger.setLevel(original_level)
            root_logger.handlers = original_handlers

    def test_removes_existing_handlers(self):
        """Should remove existing handlers before adding new ones."""
        from openlabels.server.logging import setup_logging

        root_logger = logging.getLogger()
        original_handlers = root_logger.handlers[:]

        try:
            # Add a dummy handler
            dummy_handler = logging.StreamHandler()
            root_logger.addHandler(dummy_handler)
            handler_count_before = len(root_logger.handlers)

            setup_logging()

            # Should have only the handlers we added
            assert len(root_logger.handlers) == 1  # Just console handler
        finally:
            root_logger.handlers = original_handlers


class TestGetLogger:
    """Tests for get_logger helper function."""

    def test_returns_logger_with_name(self):
        """Should return a logger with the specified name."""
        from openlabels.server.logging import get_logger

        logger = get_logger("test.module.name")

        assert logger.name == "test.module.name"
        assert isinstance(logger, logging.Logger)

    def test_returns_same_logger_for_same_name(self):
        """Should return the same logger instance for same name."""
        from openlabels.server.logging import get_logger

        logger1 = get_logger("test.same.name")
        logger2 = get_logger("test.same.name")

        assert logger1 is logger2


class TestContextLogger:
    """Tests for ContextLogger wrapper."""

    def test_info_logs_with_context(self):
        """Info method should log with context."""
        from openlabels.server.logging import ContextLogger

        with patch.object(logging.Logger, "log") as mock_log:
            logger = ContextLogger("test.context", tenant_id="abc")
            logger.info("Test message", file_path="/path")

            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert args[1] == "Test message"
            assert kwargs["extra"]["tenant_id"] == "abc"
            assert kwargs["extra"]["file_path"] == "/path"

    def test_debug_logs_with_context(self):
        """Debug method should log with context."""
        from openlabels.server.logging import ContextLogger

        with patch.object(logging.Logger, "log") as mock_log:
            logger = ContextLogger("test.context", tenant_id="xyz")
            logger.debug("Debug message")

            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert args[0] == logging.DEBUG
            assert kwargs["extra"]["tenant_id"] == "xyz"

    def test_warning_logs_with_context(self):
        """Warning method should log with context."""
        from openlabels.server.logging import ContextLogger

        with patch.object(logging.Logger, "log") as mock_log:
            logger = ContextLogger("test.context", job_id="456")
            logger.warning("Warning message")

            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert args[0] == logging.WARNING
            assert kwargs["extra"]["job_id"] == "456"

    def test_error_logs_with_context(self):
        """Error method should log with context."""
        from openlabels.server.logging import ContextLogger

        with patch.object(logging.Logger, "log") as mock_log:
            logger = ContextLogger("test.context", scan_id="789")
            logger.error("Error message")

            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert args[0] == logging.ERROR
            assert kwargs["extra"]["scan_id"] == "789"

    def test_extra_kwargs_merged_with_context(self):
        """Extra kwargs should be merged with stored context."""
        from openlabels.server.logging import ContextLogger

        with patch.object(logging.Logger, "log") as mock_log:
            logger = ContextLogger("test.context", tenant_id="abc")
            logger.info("Test", file_path="/path", extra_field="value")

            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert kwargs["extra"]["tenant_id"] == "abc"
            assert kwargs["extra"]["file_path"] == "/path"
            assert kwargs["extra"]["extra_field"] == "value"

    def test_kwargs_override_context(self):
        """Extra kwargs should override context if same key."""
        from openlabels.server.logging import ContextLogger

        with patch.object(logging.Logger, "log") as mock_log:
            logger = ContextLogger("test.context", tenant_id="original")
            logger.info("Test", tenant_id="overridden")

            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert kwargs["extra"]["tenant_id"] == "overridden"
