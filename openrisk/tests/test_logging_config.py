"""
Tests for openlabels.logging_config module.

Tests JSON logging, correlation IDs, and audit logging.
"""

import pytest
import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestCorrelationId:
    """Tests for correlation ID management."""

    def test_get_correlation_id_default_none(self):
        """Should return None when no correlation ID set."""
        from openlabels.logging_config import get_correlation_id, _correlation_id

        # Reset to default
        _correlation_id.set(None)

        result = get_correlation_id()

        assert result is None

    def test_set_correlation_id(self):
        """Should set and retrieve correlation ID."""
        from openlabels.logging_config import (
            get_correlation_id,
            set_correlation_id,
            _correlation_id,
        )

        # Reset first
        _correlation_id.set(None)

        set_correlation_id("test-123")
        result = get_correlation_id()

        assert result == "test-123"

        # Cleanup
        _correlation_id.set(None)

    def test_generate_correlation_id_format(self):
        """Generated correlation ID should be 12 characters."""
        from openlabels.logging_config import generate_correlation_id

        cid = generate_correlation_id()

        assert len(cid) == 12
        # Should be hex characters (from UUID)
        assert all(c in '0123456789abcdef-' for c in cid)

    def test_generate_correlation_id_unique(self):
        """Generated correlation IDs should be unique."""
        from openlabels.logging_config import generate_correlation_id

        ids = [generate_correlation_id() for _ in range(100)]

        assert len(set(ids)) == 100


class TestCorrelationIdContextManager:
    """Tests for correlation_id context manager."""

    def test_context_manager_sets_id(self):
        """Should set correlation ID within context."""
        from openlabels.logging_config import (
            correlation_id,
            get_correlation_id,
            _correlation_id,
        )

        _correlation_id.set(None)

        with correlation_id("ctx-456"):
            assert get_correlation_id() == "ctx-456"

    def test_context_manager_restores_previous(self):
        """Should restore previous ID after context."""
        from openlabels.logging_config import (
            correlation_id,
            get_correlation_id,
            set_correlation_id,
            _correlation_id,
        )

        _correlation_id.set(None)
        set_correlation_id("outer-id")

        with correlation_id("inner-id"):
            assert get_correlation_id() == "inner-id"

        # Should restore outer ID
        assert get_correlation_id() == "outer-id"

        # Cleanup
        _correlation_id.set(None)

    def test_context_manager_yields_id(self):
        """Should yield the correlation ID."""
        from openlabels.logging_config import correlation_id, _correlation_id

        _correlation_id.set(None)

        with correlation_id("yield-test") as cid:
            assert cid == "yield-test"

    def test_context_manager_generates_id_when_none(self):
        """Should generate ID when None passed."""
        from openlabels.logging_config import correlation_id, _correlation_id

        _correlation_id.set(None)

        with correlation_id() as cid:
            assert cid is not None
            assert len(cid) == 12

    def test_context_manager_restores_on_exception(self):
        """Should restore ID even on exception."""
        from openlabels.logging_config import (
            correlation_id,
            get_correlation_id,
            set_correlation_id,
            _correlation_id,
        )

        _correlation_id.set(None)
        set_correlation_id("before")

        with pytest.raises(ValueError):
            with correlation_id("during"):
                raise ValueError("test error")

        assert get_correlation_id() == "before"

        # Cleanup
        _correlation_id.set(None)

    def test_nested_context_managers(self):
        """Should handle nested context managers."""
        from openlabels.logging_config import (
            correlation_id,
            get_correlation_id,
            _correlation_id,
        )

        _correlation_id.set(None)

        with correlation_id("outer"):
            assert get_correlation_id() == "outer"
            with correlation_id("inner"):
                assert get_correlation_id() == "inner"
            assert get_correlation_id() == "outer"

        assert get_correlation_id() is None


class TestJSONFormatter:
    """Tests for JSONFormatter class."""

    def test_format_returns_json(self):
        """Should return valid JSON."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        # Should be valid JSON
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_format_includes_required_fields(self):
        """Should include timestamp, level, logger, message."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "timestamp" in data
        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["message"] == "Test message"

    def test_format_includes_correlation_id_when_set(self):
        """Should include correlation_id when set."""
        from openlabels.logging_config import (
            JSONFormatter,
            set_correlation_id,
            _correlation_id,
        )

        _correlation_id.set(None)
        set_correlation_id("test-cid")

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["correlation_id"] == "test-cid"

        # Cleanup
        _correlation_id.set(None)

    def test_format_excludes_correlation_id_when_not_set(self):
        """Should not include correlation_id when not set."""
        from openlabels.logging_config import JSONFormatter, _correlation_id

        _correlation_id.set(None)

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "correlation_id" not in data

    def test_format_includes_source_for_warning(self):
        """Should include source location for WARNING level."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="/path/test.py",
            lineno=42,
            msg="Warning message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "source" in data
        assert data["source"]["line"] == 42
        assert "test.py" in data["source"]["file"]

    def test_format_includes_source_for_error(self):
        """Should include source location for ERROR level."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="/path/test.py",
            lineno=100,
            msg="Error message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "source" in data

    def test_format_includes_source_for_debug(self):
        """Should include source location for DEBUG level."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="/path/test.py",
            lineno=5,
            msg="Debug message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "source" in data

    def test_format_excludes_source_for_info(self):
        """Should not include source for INFO level."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="/path/test.py",
            lineno=5,
            msg="Info message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "source" not in data

    def test_format_includes_exception_info(self):
        """Should include exception info when present."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()

        try:
            raise ValueError("Test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "exception" in data
        assert "ValueError" in data["exception"]
        assert "Test error" in data["exception"]

    def test_format_includes_extra_fields(self):
        """Should include extra fields passed to logger."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.custom_field = "custom_value"
        record.another_field = 42

        result = formatter.format(record)
        data = json.loads(result)

        assert data["custom_field"] == "custom_value"
        assert data["another_field"] == 42

    def test_format_timestamp_is_iso(self):
        """Timestamp should be ISO 8601 format."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        # Should be parseable as ISO timestamp
        timestamp = data["timestamp"]
        assert "T" in timestamp  # ISO format has T separator
        assert timestamp.endswith("+00:00") or timestamp.endswith("Z")


class TestAuditLogger:
    """Tests for AuditLogger class."""

    def test_log_basic_event(self):
        """Should log basic audit event."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.log("test_event", key="value")

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "AUDIT: test_event" in call_args[0][0]

    def test_log_includes_extra_fields(self):
        """Should include audit data in extra."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.log("test_event", file="/path", count=5)

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "test_event"
        assert extra["audit_data"]["file"] == "/path"
        assert extra["audit_data"]["count"] == 5
        assert "audit_timestamp" in extra

    def test_scan_start_method(self):
        """scan_start should log with path."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.scan_start(path="/data/dir", recursive=True)

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "scan_start"
        assert extra["audit_data"]["path"] == "/data/dir"
        assert extra["audit_data"]["recursive"] is True

    def test_scan_complete_method(self):
        """scan_complete should log with metrics."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.scan_complete(path="/data", files_scanned=100, pii_found=5)

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "scan_complete"
        assert extra["audit_data"]["files_scanned"] == 100
        assert extra["audit_data"]["pii_found"] == 5

    def test_file_quarantine_method(self):
        """file_quarantine should log source, destination, score."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.file_quarantine(source="/data/file.txt", destination="/quarantine", score=85)

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "file_quarantine"
        assert extra["audit_data"]["source"] == "/data/file.txt"
        assert extra["audit_data"]["destination"] == "/quarantine"
        assert extra["audit_data"]["score"] == 85

    def test_file_encrypt_method(self):
        """file_encrypt should log path and tool."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.file_encrypt(path="/data/sensitive.csv", tool="gpg")

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "file_encrypt"
        assert extra["audit_data"]["path"] == "/data/sensitive.csv"
        assert extra["audit_data"]["tool"] == "gpg"

    def test_access_restrict_method(self):
        """access_restrict should log path and mode."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.access_restrict(path="/data/secret.txt", mode="0600")

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "access_restrict"
        assert extra["audit_data"]["path"] == "/data/secret.txt"
        assert extra["audit_data"]["mode"] == "0600"

    def test_file_tag_method(self):
        """file_tag should log path and label_id."""
        from openlabels.logging_config import AuditLogger

        mock_logger = MagicMock()
        audit = AuditLogger(mock_logger)

        audit.file_tag(path="/data/file.txt", label_id="pii:ssn:high")

        call_kwargs = mock_logger.info.call_args[1]
        extra = call_kwargs["extra"]
        assert extra["audit_event"] == "file_tag"
        assert extra["audit_data"]["path"] == "/data/file.txt"
        assert extra["audit_data"]["label_id"] == "pii:ssn:high"


class TestGetAuditLogger:
    """Tests for get_audit_logger function."""

    def test_returns_audit_logger(self):
        """Should return AuditLogger instance."""
        from openlabels.logging_config import get_audit_logger, AuditLogger

        audit = get_audit_logger()

        assert isinstance(audit, AuditLogger)

    def test_returns_same_instance(self):
        """Should return same singleton instance."""
        from openlabels.logging_config import get_audit_logger, _audit_logger
        import openlabels.logging_config as config_module

        # Reset singleton
        config_module._audit_logger = None

        audit1 = get_audit_logger()
        audit2 = get_audit_logger()

        assert audit1 is audit2


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_returns_correlation_id(self, tmp_path):
        """Should return generated correlation ID."""
        from openlabels.logging_config import setup_logging

        cid = setup_logging(no_audit=True)

        assert cid is not None
        assert len(cid) == 12

    def test_sets_correlation_id(self, tmp_path):
        """Should set correlation ID for context."""
        from openlabels.logging_config import setup_logging, get_correlation_id

        cid = setup_logging(no_audit=True)

        assert get_correlation_id() == cid

    def test_verbose_sets_debug_level(self, tmp_path):
        """verbose=True should set DEBUG level."""
        from openlabels.logging_config import setup_logging

        setup_logging(verbose=True, no_audit=True)

        # Check console handler level
        logger = logging.getLogger("openlabels")
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert any(h.level == logging.DEBUG for h in console_handlers)

    def test_quiet_sets_error_level(self, tmp_path):
        """quiet=True should set ERROR level."""
        from openlabels.logging_config import setup_logging

        setup_logging(quiet=True, no_audit=True)

        logger = logging.getLogger("openlabels")
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert any(h.level == logging.ERROR for h in console_handlers)

    def test_default_sets_warning_level(self, tmp_path):
        """Default should set WARNING level (quiet mode for users)."""
        from openlabels.logging_config import setup_logging

        setup_logging(no_audit=True)

        logger = logging.getLogger("openlabels")
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert any(h.level == logging.WARNING for h in console_handlers)

    def test_log_file_creates_handler(self, tmp_path):
        """log_file should create file handler."""
        from openlabels.logging_config import setup_logging

        log_file = tmp_path / "app.log"
        setup_logging(log_file=str(log_file), no_audit=True)

        logger = logging.getLogger("openlabels")
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1

    def test_log_file_creates_parent_dirs(self, tmp_path):
        """Should create parent directories for log file."""
        from openlabels.logging_config import setup_logging

        log_file = tmp_path / "subdir" / "nested" / "app.log"
        setup_logging(log_file=str(log_file), no_audit=True)

        assert log_file.parent.exists()

    def test_audit_log_creates_handler(self, tmp_path):
        """audit_log should create audit handler."""
        from openlabels.logging_config import setup_logging

        audit_file = tmp_path / "audit.log"
        setup_logging(audit_log=str(audit_file))

        audit_logger = logging.getLogger("audit.openlabels")
        file_handlers = [h for h in audit_logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1

    def test_no_audit_disables_audit_handlers(self, tmp_path):
        """no_audit=True should not create audit handlers."""
        from openlabels.logging_config import setup_logging

        setup_logging(no_audit=True)

        audit_logger = logging.getLogger("audit.openlabels")
        # Should have no file handlers (may have been cleared)
        file_handlers = [h for h in audit_logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 0

    def test_clears_existing_handlers(self, tmp_path):
        """Should clear existing handlers."""
        from openlabels.logging_config import setup_logging

        # Add a dummy handler
        logger = logging.getLogger("openlabels")
        dummy = logging.NullHandler()
        logger.addHandler(dummy)

        setup_logging(no_audit=True)

        # Dummy handler should be gone
        assert dummy not in logger.handlers

    def test_suppresses_noisy_loggers(self, tmp_path):
        """Should suppress urllib3, boto loggers."""
        from openlabels.logging_config import setup_logging

        setup_logging(no_audit=True)

        assert logging.getLogger("urllib3").level >= logging.WARNING
        assert logging.getLogger("botocore").level >= logging.WARNING
        assert logging.getLogger("boto3").level >= logging.WARNING


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_logger(self):
        """Should return Logger instance."""
        from openlabels.logging_config import get_logger

        logger = get_logger("test_module")

        assert isinstance(logger, logging.Logger)

    def test_adds_openlabels_prefix(self):
        """Should add openlabels prefix to name."""
        from openlabels.logging_config import get_logger

        logger = get_logger("mymodule")

        assert logger.name == "openlabels.mymodule"

    def test_preserves_openlabels_prefix(self):
        """Should not double-prefix openlabels names."""
        from openlabels.logging_config import get_logger

        logger = get_logger("openlabels.scanner")

        assert logger.name == "openlabels.scanner"

    def test_handles_dunder_name(self):
        """Should handle __name__ style input."""
        from openlabels.logging_config import get_logger

        logger = get_logger("openlabels.adapters.scanner")

        assert logger.name == "openlabels.adapters.scanner"


class TestDefaultAuditLog:
    """Tests for DEFAULT_AUDIT_LOG constant."""

    def test_is_path_in_home(self):
        """Should be path in user's home directory."""
        from openlabels.logging_config import DEFAULT_AUDIT_LOG

        assert isinstance(DEFAULT_AUDIT_LOG, Path)
        assert ".openlabels" in str(DEFAULT_AUDIT_LOG)
        assert "audit.log" in str(DEFAULT_AUDIT_LOG)

    def test_uses_home_directory(self):
        """Should use user's home directory."""
        from openlabels.logging_config import DEFAULT_AUDIT_LOG

        assert str(Path.home()) in str(DEFAULT_AUDIT_LOG)


class TestJSONFormatterStandardAttrs:
    """Tests for STANDARD_ATTRS filtering."""

    def test_standard_attrs_is_frozenset(self):
        """STANDARD_ATTRS should be immutable."""
        from openlabels.logging_config import JSONFormatter

        assert isinstance(JSONFormatter.STANDARD_ATTRS, frozenset)

    def test_standard_attrs_contains_common_fields(self):
        """Should contain common LogRecord attributes."""
        from openlabels.logging_config import JSONFormatter

        expected = {"name", "msg", "levelname", "levelno", "pathname", "filename"}
        assert expected.issubset(JSONFormatter.STANDARD_ATTRS)

    def test_standard_attrs_filtered_from_output(self):
        """Standard attrs should not appear in extra fields."""
        from openlabels.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        # These should not be duplicated as extra fields
        # (they're in specific named fields like "logger" for "name")
        assert "args" not in data
        assert "created" not in data
        assert "msecs" not in data
