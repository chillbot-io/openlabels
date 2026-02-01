"""Tests for PHI-safe logging utilities.

Tests all functions in scrubiq/logging_utils.py:
- _is_production_mode / is_production_mode
- sanitize_for_logging
- safe_repr
- PHISafeLogger class
- get_phi_safe_logger
"""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def clean_env():
    """Clean up environment variables before/after tests."""
    original_env = os.environ.copy()
    # Remove all production-related env vars
    for key in ["SCRUBIQ_ENV", "PROD", "NODE_ENV"]:
        os.environ.pop(key, None)
    yield
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def capture_logs():
    """Capture log messages for testing."""
    class LogCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []
            self.messages = []

        def emit(self, record):
            self.records.append(record)
            self.messages.append(self.format(record))

    return LogCapture


# =============================================================================
# PRODUCTION MODE DETECTION TESTS
# =============================================================================

class TestProductionModeDetection:
    """Tests for _is_production_mode and is_production_mode."""

    def test_not_production_by_default(self, clean_env):
        """Not production when no env vars set."""
        # Need to reimport to re-evaluate _PRODUCTION_MODE
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is False

    def test_production_via_scrubiq_env(self, clean_env):
        """Detects production via SCRUBIQ_ENV=production."""
        os.environ["SCRUBIQ_ENV"] = "production"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_production_via_scrubiq_env_uppercase(self, clean_env):
        """SCRUBIQ_ENV is case-insensitive."""
        os.environ["SCRUBIQ_ENV"] = "PRODUCTION"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_production_via_prod_flag_1(self, clean_env):
        """Detects production via PROD=1."""
        os.environ["PROD"] = "1"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_production_via_prod_flag_true(self, clean_env):
        """Detects production via PROD=true."""
        os.environ["PROD"] = "true"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_production_via_prod_flag_yes(self, clean_env):
        """Detects production via PROD=yes."""
        os.environ["PROD"] = "yes"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_production_via_prod_flag_uppercase(self, clean_env):
        """PROD is case-insensitive."""
        os.environ["PROD"] = "TRUE"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_production_via_node_env(self, clean_env):
        """Detects production via NODE_ENV=production."""
        os.environ["NODE_ENV"] = "production"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is True

    def test_not_production_with_dev_values(self, clean_env):
        """Not production with development values."""
        os.environ["SCRUBIQ_ENV"] = "development"
        os.environ["PROD"] = "0"
        os.environ["NODE_ENV"] = "development"
        from scrubiq import logging_utils
        result = logging_utils._is_production_mode()
        assert result is False

    def test_is_production_mode_public_function(self, clean_env):
        """is_production_mode() returns cached value."""
        from scrubiq.logging_utils import is_production_mode
        # Note: This tests the cached value from module load
        result = is_production_mode()
        assert isinstance(result, bool)


# =============================================================================
# SANITIZE FOR LOGGING TESTS
# =============================================================================

class TestSanitizeForLogging:
    """Tests for sanitize_for_logging function."""

    def test_sanitize_empty_string(self):
        """Empty string returns empty."""
        from scrubiq.logging_utils import sanitize_for_logging
        assert sanitize_for_logging("") == ""

    def test_sanitize_none(self):
        """None returns empty string."""
        from scrubiq.logging_utils import sanitize_for_logging
        assert sanitize_for_logging(None) == ""

    def test_sanitize_plain_text(self):
        """Plain text passes through unchanged."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "This is plain text without any PHI"
        assert sanitize_for_logging(text, max_length=0) == text

    # --- SSN Patterns ---
    def test_sanitize_ssn_dashes(self):
        """Redacts SSN with dashes."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "SSN: 123-45-6789"
        result = sanitize_for_logging(text, max_length=0)
        assert "123-45-6789" not in result
        assert "[SSN-REDACTED]" in result

    def test_sanitize_ssn_spaces(self):
        """Redacts SSN with spaces."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "SSN: 123 45 6789"
        result = sanitize_for_logging(text, max_length=0)
        assert "123 45 6789" not in result
        assert "[SSN-REDACTED]" in result

    def test_sanitize_ssn_nine_digits(self):
        """Redacts 9-digit number (potential SSN)."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Number: 123456789"
        result = sanitize_for_logging(text, max_length=0)
        assert "123456789" not in result
        assert "[9DIGIT-REDACTED]" in result

    # --- Phone Patterns ---
    def test_sanitize_phone_with_parens(self):
        """Redacts phone number with parentheses."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Call me at (555) 123-4567"
        result = sanitize_for_logging(text, max_length=0)
        assert "(555) 123-4567" not in result
        assert "[PHONE-REDACTED]" in result

    def test_sanitize_phone_with_dashes(self):
        """Redacts phone number with dashes."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Phone: 555-123-4567"
        result = sanitize_for_logging(text, max_length=0)
        assert "555-123-4567" not in result
        assert "[PHONE-REDACTED]" in result

    def test_sanitize_phone_with_dots(self):
        """Redacts phone number with dots."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Phone: 555.123.4567"
        result = sanitize_for_logging(text, max_length=0)
        assert "555.123.4567" not in result
        assert "[PHONE-REDACTED]" in result

    # --- Email Patterns ---
    def test_sanitize_email(self):
        """Redacts email addresses."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Email me at john.doe@example.com"
        result = sanitize_for_logging(text, max_length=0)
        assert "john.doe@example.com" not in result
        assert "[EMAIL-REDACTED]" in result

    def test_sanitize_email_complex(self):
        """Redacts email with complex local part."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Contact: user-name_123@sub.domain.org"
        result = sanitize_for_logging(text, max_length=0)
        assert "user-name_123@sub.domain.org" not in result
        assert "[EMAIL-REDACTED]" in result

    # --- Date Patterns ---
    def test_sanitize_date_slash(self):
        """Redacts date with slashes."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "DOB: 12/25/1990"
        result = sanitize_for_logging(text, max_length=0)
        assert "12/25/1990" not in result
        assert "[DATE-REDACTED]" in result

    def test_sanitize_date_iso(self):
        """Redacts ISO date format."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Date: 1990-12-25"
        result = sanitize_for_logging(text, max_length=0)
        assert "1990-12-25" not in result
        assert "[DATE-REDACTED]" in result

    # --- Credit Card Patterns ---
    def test_sanitize_credit_card_spaces(self):
        """Redacts credit card with spaces."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Card: 1234 5678 9012 3456"
        result = sanitize_for_logging(text, max_length=0)
        assert "1234 5678 9012 3456" not in result
        assert "[CC-REDACTED]" in result

    def test_sanitize_credit_card_dashes(self):
        """Redacts credit card with dashes."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Card: 1234-5678-9012-3456"
        result = sanitize_for_logging(text, max_length=0)
        assert "1234-5678-9012-3456" not in result
        assert "[CC-REDACTED]" in result

    def test_sanitize_credit_card_no_separator(self):
        """Redacts credit card without separators."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Card: 1234567890123456"
        result = sanitize_for_logging(text, max_length=0)
        assert "1234567890123456" not in result
        assert "[CC-REDACTED]" in result

    # --- MRN Patterns ---
    def test_sanitize_mrn_digits_only(self):
        """Redacts MRN-like numbers."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "MRN: 12345678"
        result = sanitize_for_logging(text, max_length=0)
        assert "12345678" not in result
        assert "[ID-REDACTED]" in result

    def test_sanitize_mrn_with_prefix(self):
        """Redacts MRN with letter prefix."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Patient ID: MRN1234567"
        result = sanitize_for_logging(text, max_length=0)
        assert "MRN1234567" not in result
        assert "[ID-REDACTED]" in result

    # --- Truncation ---
    def test_sanitize_truncation(self):
        """Truncates long text."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "A" * 300
        result = sanitize_for_logging(text, max_length=100)
        assert len(result) < 200
        assert "...[truncated]" in result

    def test_sanitize_no_truncation_when_zero(self):
        """No truncation when max_length=0."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "A" * 500
        result = sanitize_for_logging(text, max_length=0)
        assert result == text

    def test_sanitize_default_truncation(self):
        """Default truncation at 200 characters."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "A" * 300
        result = sanitize_for_logging(text)  # default max_length=200
        assert "...[truncated]" in result

    # --- Multiple Patterns ---
    def test_sanitize_multiple_patterns(self):
        """Redacts multiple PHI types in same text."""
        from scrubiq.logging_utils import sanitize_for_logging
        text = "Patient John (SSN: 123-45-6789) DOB: 01/15/1985, email: john@test.com"
        result = sanitize_for_logging(text, max_length=0)
        assert "[SSN-REDACTED]" in result
        assert "[DATE-REDACTED]" in result
        assert "[EMAIL-REDACTED]" in result


# =============================================================================
# SAFE REPR TESTS
# =============================================================================

class TestSafeRepr:
    """Tests for safe_repr function."""

    def test_safe_repr_none(self):
        """None returns 'None'."""
        from scrubiq.logging_utils import safe_repr
        assert safe_repr(None) == "None"

    def test_safe_repr_string(self):
        """String is quoted and sanitized."""
        from scrubiq.logging_utils import safe_repr
        result = safe_repr("test string")
        assert result == '"test string"'

    def test_safe_repr_string_with_phi(self):
        """String with PHI is sanitized."""
        from scrubiq.logging_utils import safe_repr
        result = safe_repr("SSN: 123-45-6789")
        assert "123-45-6789" not in result
        assert "[SSN-REDACTED]" in result

    def test_safe_repr_list(self):
        """List shows type and length."""
        from scrubiq.logging_utils import safe_repr
        result = safe_repr([1, 2, 3, 4, 5])
        assert result == "[list len=5]"

    def test_safe_repr_tuple(self):
        """Tuple shows type and length."""
        from scrubiq.logging_utils import safe_repr
        result = safe_repr((1, 2, 3))
        assert result == "[tuple len=3]"

    def test_safe_repr_dict(self):
        """Dict shows keys."""
        from scrubiq.logging_utils import safe_repr
        result = safe_repr({"name": "John", "age": 30})
        assert "dict keys=" in result
        assert "name" in result
        assert "age" in result
        # Should NOT contain the values
        assert "John" not in result
        assert "30" not in result

    def test_safe_repr_int(self):
        """Int passes through."""
        from scrubiq.logging_utils import safe_repr
        assert safe_repr(42) == "42"

    def test_safe_repr_float(self):
        """Float passes through."""
        from scrubiq.logging_utils import safe_repr
        assert safe_repr(3.14) == "3.14"

    def test_safe_repr_bool(self):
        """Bool passes through."""
        from scrubiq.logging_utils import safe_repr
        assert safe_repr(True) == "True"
        assert safe_repr(False) == "False"

    def test_safe_repr_custom_object(self):
        """Custom object shows type name."""
        from scrubiq.logging_utils import safe_repr

        class MyClass:
            pass

        result = safe_repr(MyClass())
        assert result == "<MyClass>"

    def test_safe_repr_max_length(self):
        """Respects max_length for strings."""
        from scrubiq.logging_utils import safe_repr
        long_string = "A" * 200
        result = safe_repr(long_string, max_length=50)
        assert "...[truncated]" in result


# =============================================================================
# PHI SAFE LOGGER TESTS
# =============================================================================

class TestPHISafeLogger:
    """Tests for PHISafeLogger class."""

    def test_logger_creation(self):
        """Creates logger with given name."""
        from scrubiq.logging_utils import PHISafeLogger
        logger = PHISafeLogger("test.module")
        assert logger._logger.name == "test.module"

    def test_format_safe_message_no_kwargs(self):
        """Formats message without kwargs."""
        from scrubiq.logging_utils import PHISafeLogger
        logger = PHISafeLogger("test")
        result = logger._format_safe_message("Test message")
        assert result == "Test message"

    def test_format_safe_message_with_kwargs(self):
        """Formats message with sanitized kwargs."""
        from scrubiq.logging_utils import PHISafeLogger
        logger = PHISafeLogger("test")
        result = logger._format_safe_message("Test", count=5, name="John")
        assert "Test" in result
        assert "count=5" in result
        assert "name=" in result
        assert "|" in result  # separator

    def test_format_safe_message_sanitizes_phi(self):
        """Sanitizes PHI in message and kwargs."""
        from scrubiq.logging_utils import PHISafeLogger
        logger = PHISafeLogger("test")
        result = logger._format_safe_message(
            "Processing SSN: 123-45-6789", patient="john@test.com"
        )
        assert "123-45-6789" not in result
        assert "john@test.com" not in result

    def test_debug_method(self, capture_logs):
        """debug() logs with sanitization."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.DEBUG)

        logger = PHISafeLogger("test.debug")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.DEBUG)

        logger.debug("Debug message", ssn="123-45-6789")

        assert len(handler.records) == 1
        assert handler.records[0].levelno == logging.DEBUG
        assert "123-45-6789" not in handler.messages[0]

    def test_info_method(self, capture_logs):
        """info() logs with sanitization."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.INFO)

        logger = PHISafeLogger("test.info")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.INFO)

        logger.info("Info message", email="user@test.com")

        assert len(handler.records) == 1
        assert handler.records[0].levelno == logging.INFO
        assert "user@test.com" not in handler.messages[0]

    def test_warning_method(self, capture_logs):
        """warning() logs with sanitization."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.WARNING)

        logger = PHISafeLogger("test.warning")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.WARNING)

        logger.warning("Warning message", phone="555-123-4567")

        assert len(handler.records) == 1
        assert handler.records[0].levelno == logging.WARNING
        assert "555-123-4567" not in handler.messages[0]

    def test_error_method(self, capture_logs):
        """error() logs with sanitization."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.ERROR)

        logger = PHISafeLogger("test.error")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.ERROR)

        logger.error("Error message", dob="01/15/1990")

        assert len(handler.records) == 1
        assert handler.records[0].levelno == logging.ERROR
        assert "01/15/1990" not in handler.messages[0]

    def test_error_with_exc_info(self, capture_logs):
        """error() can include exception info."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.ERROR)

        logger = PHISafeLogger("test.error_exc")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.ERROR)

        try:
            raise ValueError("Test error")
        except ValueError:
            logger.error("Error occurred", exc_info=True)

        assert len(handler.records) == 1
        assert handler.records[0].exc_info is not None

    def test_exception_method(self, capture_logs):
        """exception() logs with traceback."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.ERROR)

        logger = PHISafeLogger("test.exception")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.ERROR)

        try:
            raise RuntimeError("Test exception")
        except RuntimeError:
            logger.exception("Exception caught")

        assert len(handler.records) == 1
        assert handler.records[0].exc_info is not None

    def test_debug_safe_no_sanitization(self, capture_logs):
        """debug_safe() does NOT sanitize (for known-safe data)."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.DEBUG)

        logger = PHISafeLogger("test.debug_safe")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.DEBUG)

        # These are safe tokens, not PHI
        logger.debug_safe("Processing", tokens=["[NAME_1]", "[DATE_1]"], count=5)

        assert len(handler.records) == 1
        # Should contain the actual values (not sanitized)
        assert "[NAME_1]" in handler.messages[0]
        assert "[DATE_1]" in handler.messages[0]
        assert "5" in handler.messages[0]

    def test_info_safe_no_sanitization(self, capture_logs):
        """info_safe() does NOT sanitize (for known-safe data)."""
        from scrubiq.logging_utils import PHISafeLogger

        handler = capture_logs()
        handler.setLevel(logging.INFO)

        logger = PHISafeLogger("test.info_safe")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.INFO)

        logger.info_safe("Stats", time_ms=150, entities=10)

        assert len(handler.records) == 1
        assert "150" in handler.messages[0]
        assert "10" in handler.messages[0]


# =============================================================================
# GET PHI SAFE LOGGER TESTS
# =============================================================================

class TestGetPhiSafeLogger:
    """Tests for get_phi_safe_logger factory function."""

    def test_returns_phi_safe_logger(self):
        """Returns PHISafeLogger instance."""
        from scrubiq.logging_utils import get_phi_safe_logger, PHISafeLogger
        logger = get_phi_safe_logger("test.module")
        assert isinstance(logger, PHISafeLogger)

    def test_uses_provided_name(self):
        """Uses the provided module name."""
        from scrubiq.logging_utils import get_phi_safe_logger
        logger = get_phi_safe_logger("my.custom.module")
        assert logger._logger.name == "my.custom.module"

    def test_typical_usage_pattern(self):
        """Works with typical __name__ usage."""
        from scrubiq.logging_utils import get_phi_safe_logger
        logger = get_phi_safe_logger(__name__)
        assert logger._logger.name == __name__


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestLoggingIntegration:
    """Integration tests for the logging utilities."""

    def test_full_workflow(self, capture_logs):
        """Full workflow: create logger, log with PHI, verify sanitization."""
        from scrubiq.logging_utils import get_phi_safe_logger

        handler = capture_logs()
        handler.setLevel(logging.INFO)

        logger = get_phi_safe_logger("integration.test")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.INFO)

        # Log potentially sensitive data
        logger.info(
            "Processing patient data",
            ssn="123-45-6789",
            email="patient@hospital.com",
            dob="1985-05-15",
        )

        # Verify nothing sensitive leaked
        message = handler.messages[0]
        assert "123-45-6789" not in message
        assert "patient@hospital.com" not in message
        assert "1985-05-15" not in message

        # But the message structure is preserved
        assert "Processing patient data" in message
        assert "ssn=" in message
        assert "email=" in message
        assert "dob=" in message

    def test_safe_data_workflow(self, capture_logs):
        """Safe data workflow: tokens and counts are not sanitized."""
        from scrubiq.logging_utils import get_phi_safe_logger

        handler = capture_logs()
        handler.setLevel(logging.DEBUG)

        logger = get_phi_safe_logger("integration.safe")
        logger._logger.addHandler(handler)
        logger._logger.setLevel(logging.DEBUG)

        # Log safe token data
        logger.debug_safe(
            "Redaction complete",
            tokens=["[NAME_1]", "[SSN_1]", "[DATE_1]"],
            count=3,
            time_ms=45.5,
        )

        # Verify tokens are visible (they're safe - not PHI)
        message = handler.messages[0]
        assert "[NAME_1]" in message
        assert "[SSN_1]" in message
        assert "[DATE_1]" in message
