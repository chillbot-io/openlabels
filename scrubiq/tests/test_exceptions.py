"""Tests for ScrubIQ exceptions.

Tests for exception hierarchy and error handling.
"""

import pytest

from scrubiq.exceptions import (
    ScrubIQError,
    ConfigurationError,
    DetectionError,
    StorageError,
    ProcessingError,
    AuthenticationError,
    FileValidationError,
)


# =============================================================================
# SCRUBIQERROR BASE CLASS TESTS
# =============================================================================

class TestScrubIQError:
    """Tests for ScrubIQError base class."""

    def test_can_raise(self):
        """Can raise ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise ScrubIQError("Base error")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = ScrubIQError("Test message")

        assert str(error) == "Test message"

    def test_is_exception_subclass(self):
        """ScrubIQError is Exception subclass."""
        assert issubclass(ScrubIQError, Exception)

    def test_catchable_as_exception(self):
        """Can catch ScrubIQError as Exception."""
        with pytest.raises(Exception):
            raise ScrubIQError("Catchable")


# =============================================================================
# CONFIGURATIONERROR TESTS
# =============================================================================

class TestConfigurationError:
    """Tests for ConfigurationError class."""

    def test_can_raise(self):
        """Can raise ConfigurationError."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("Config error")

    def test_is_scrubiq_error_subclass(self):
        """ConfigurationError is ScrubIQError subclass."""
        assert issubclass(ConfigurationError, ScrubIQError)

    def test_catchable_as_base(self):
        """Can catch ConfigurationError as ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise ConfigurationError("Catchable as base")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = ConfigurationError("Invalid config key")

        assert str(error) == "Invalid config key"

    def test_error_args(self):
        """Error args are accessible."""
        error = ConfigurationError("arg1", "arg2")

        assert error.args == ("arg1", "arg2")


# =============================================================================
# DETECTIONERROR TESTS
# =============================================================================

class TestDetectionError:
    """Tests for DetectionError class."""

    def test_can_raise(self):
        """Can raise DetectionError."""
        with pytest.raises(DetectionError):
            raise DetectionError("Detection failed")

    def test_is_scrubiq_error_subclass(self):
        """DetectionError is ScrubIQError subclass."""
        assert issubclass(DetectionError, ScrubIQError)

    def test_catchable_as_base(self):
        """Can catch DetectionError as ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise DetectionError("Catchable")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = DetectionError("Model not loaded")

        assert str(error) == "Model not loaded"


# =============================================================================
# STORAGEERROR TESTS
# =============================================================================

class TestStorageError:
    """Tests for StorageError class."""

    def test_can_raise(self):
        """Can raise StorageError."""
        with pytest.raises(StorageError):
            raise StorageError("Storage failed")

    def test_is_scrubiq_error_subclass(self):
        """StorageError is ScrubIQError subclass."""
        assert issubclass(StorageError, ScrubIQError)

    def test_catchable_as_base(self):
        """Can catch StorageError as ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise StorageError("Catchable")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = StorageError("Database connection lost")

        assert str(error) == "Database connection lost"


# =============================================================================
# PROCESSINGERROR TESTS
# =============================================================================

class TestProcessingError:
    """Tests for ProcessingError class."""

    def test_can_raise(self):
        """Can raise ProcessingError."""
        with pytest.raises(ProcessingError):
            raise ProcessingError("Processing failed")

    def test_is_scrubiq_error_subclass(self):
        """ProcessingError is ScrubIQError subclass."""
        assert issubclass(ProcessingError, ScrubIQError)

    def test_catchable_as_base(self):
        """Can catch ProcessingError as ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise ProcessingError("Catchable")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = ProcessingError("Invalid input format")

        assert str(error) == "Invalid input format"


# =============================================================================
# AUTHENTICATIONERROR TESTS
# =============================================================================

class TestAuthenticationError:
    """Tests for AuthenticationError class."""

    def test_can_raise(self):
        """Can raise AuthenticationError."""
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Auth failed")

    def test_is_scrubiq_error_subclass(self):
        """AuthenticationError is ScrubIQError subclass."""
        assert issubclass(AuthenticationError, ScrubIQError)

    def test_catchable_as_base(self):
        """Can catch AuthenticationError as ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise AuthenticationError("Catchable")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = AuthenticationError("Invalid token")

        assert str(error) == "Invalid token"


# =============================================================================
# FILEVALIDATIONERROR TESTS
# =============================================================================

class TestFileValidationError:
    """Tests for FileValidationError class."""

    def test_can_raise(self):
        """Can raise FileValidationError."""
        with pytest.raises(FileValidationError):
            raise FileValidationError("File too large")

    def test_is_processing_error_subclass(self):
        """FileValidationError is ProcessingError subclass."""
        assert issubclass(FileValidationError, ProcessingError)

    def test_is_scrubiq_error_subclass(self):
        """FileValidationError is ScrubIQError subclass (transitively)."""
        assert issubclass(FileValidationError, ScrubIQError)

    def test_catchable_as_processing_error(self):
        """Can catch FileValidationError as ProcessingError."""
        with pytest.raises(ProcessingError):
            raise FileValidationError("Catchable")

    def test_catchable_as_scrubiq_error(self):
        """Can catch FileValidationError as ScrubIQError."""
        with pytest.raises(ScrubIQError):
            raise FileValidationError("Catchable")

    def test_preserves_message(self):
        """Error message is preserved."""
        error = FileValidationError("Invalid file type")

        assert str(error) == "Invalid file type"

    def test_stores_filename(self):
        """FileValidationError stores filename attribute."""
        error = FileValidationError("Too large", filename="test.pdf")

        assert error.filename == "test.pdf"

    def test_filename_default_none(self):
        """Filename defaults to None."""
        error = FileValidationError("Error without filename")

        assert error.filename is None

    def test_message_with_filename(self):
        """Message is preserved when filename provided."""
        error = FileValidationError("Unsupported format", filename="image.bmp")

        assert str(error) == "Unsupported format"
        assert error.filename == "image.bmp"


# =============================================================================
# EXCEPTION HIERARCHY TESTS
# =============================================================================

class TestExceptionHierarchy:
    """Tests for exception hierarchy behavior."""

    def test_all_errors_derive_from_base(self):
        """All ScrubIQ exceptions derive from ScrubIQError."""
        exceptions = [
            ConfigurationError,
            DetectionError,
            StorageError,
            ProcessingError,
            AuthenticationError,
            FileValidationError,
        ]

        for exc_class in exceptions:
            assert issubclass(exc_class, ScrubIQError)

    def test_file_validation_derives_from_processing(self):
        """FileValidationError derives from ProcessingError."""
        assert issubclass(FileValidationError, ProcessingError)
        assert not issubclass(FileValidationError, ConfigurationError)
        assert not issubclass(FileValidationError, DetectionError)

    def test_catch_multiple_types(self):
        """Can catch multiple error types with base class."""
        caught = []

        errors = [
            ConfigurationError("config"),
            DetectionError("detection"),
            StorageError("storage"),
            ProcessingError("processing"),
            AuthenticationError("auth"),
        ]

        for error in errors:
            try:
                raise error
            except ScrubIQError as e:
                caught.append(type(e).__name__)

        assert len(caught) == 5
        assert "ConfigurationError" in caught
        assert "DetectionError" in caught
        assert "StorageError" in caught
        assert "ProcessingError" in caught
        assert "AuthenticationError" in caught

    def test_specific_catch_before_general(self):
        """Specific exception type caught before general."""
        caught_type = None

        try:
            raise FileValidationError("specific")
        except FileValidationError:
            caught_type = "FileValidationError"
        except ProcessingError:
            caught_type = "ProcessingError"
        except ScrubIQError:
            caught_type = "ScrubIQError"

        assert caught_type == "FileValidationError"

    def test_chained_exceptions(self):
        """Can chain exceptions with __cause__."""
        original = ValueError("Original error")

        try:
            try:
                raise original
            except ValueError as e:
                raise ConfigurationError("Config failed") from e
        except ConfigurationError as error:
            assert error.__cause__ is original


# =============================================================================
# MODULE EXPORTS TESTS
# =============================================================================

class TestModuleExports:
    """Tests for module __all__ exports."""

    def test_all_exports_importable(self):
        """All __all__ exports are importable."""
        from scrubiq import exceptions

        for name in exceptions.__all__:
            assert hasattr(exceptions, name)

    def test_expected_exports(self):
        """Expected exceptions are exported."""
        from scrubiq import exceptions

        expected = [
            "ScrubIQError",
            "ConfigurationError",
            "DetectionError",
            "StorageError",
            "ProcessingError",
            "AuthenticationError",
            "FileValidationError",
        ]

        for name in expected:
            assert name in exceptions.__all__
