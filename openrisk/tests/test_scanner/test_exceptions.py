"""Comprehensive tests for scanner exceptions.py.

Tests the exception hierarchy used throughout the scanner module.
"""

import pytest

from openlabels.adapters.scanner.exceptions import (
    ScannerError,
    ConfigurationError,
    DetectionError,
    ProcessingError,
    FileValidationError,
)


class TestScannerError:
    """Tests for base ScannerError exception."""

    def test_is_exception(self):
        """ScannerError should inherit from Exception."""
        assert issubclass(ScannerError, Exception)

    def test_can_raise(self):
        """ScannerError can be raised and caught."""
        with pytest.raises(ScannerError):
            raise ScannerError("test error")

    def test_message_preserved(self):
        """Error message should be preserved."""
        err = ScannerError("test message")
        assert str(err) == "test message"

    def test_empty_message(self):
        """Empty message should work."""
        err = ScannerError()
        assert str(err) == ""

    def test_can_catch_as_exception(self):
        """ScannerError can be caught as generic Exception."""
        with pytest.raises(Exception):
            raise ScannerError("test")

    def test_args_preserved(self):
        """Exception args should be preserved."""
        err = ScannerError("message", "extra1", "extra2")
        assert err.args == ("message", "extra1", "extra2")


class TestConfigurationError:
    """Tests for ConfigurationError exception."""

    def test_inherits_from_scanner_error(self):
        """ConfigurationError should inherit from ScannerError."""
        assert issubclass(ConfigurationError, ScannerError)

    def test_can_raise(self):
        """ConfigurationError can be raised and caught."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("invalid config")

    def test_can_catch_as_scanner_error(self):
        """ConfigurationError can be caught as ScannerError."""
        with pytest.raises(ScannerError):
            raise ConfigurationError("invalid config")

    def test_message_preserved(self):
        """Error message should be preserved."""
        err = ConfigurationError("missing API key")
        assert str(err) == "missing API key"

    def test_use_case_invalid_settings(self):
        """Test real-world use case: invalid settings."""
        def configure(timeout):
            if timeout < 0:
                raise ConfigurationError(f"Timeout must be positive, got {timeout}")
            return timeout

        with pytest.raises(ConfigurationError) as exc:
            configure(-1)
        assert "positive" in str(exc.value)

    def test_use_case_missing_required(self):
        """Test real-world use case: missing required config."""
        def initialize(api_key):
            if not api_key:
                raise ConfigurationError("API key is required")
            return True

        with pytest.raises(ConfigurationError) as exc:
            initialize(None)
        assert "required" in str(exc.value)


class TestDetectionError:
    """Tests for DetectionError exception."""

    def test_inherits_from_scanner_error(self):
        """DetectionError should inherit from ScannerError."""
        assert issubclass(DetectionError, ScannerError)

    def test_can_raise(self):
        """DetectionError can be raised and caught."""
        with pytest.raises(DetectionError):
            raise DetectionError("detection failed")

    def test_can_catch_as_scanner_error(self):
        """DetectionError can be caught as ScannerError."""
        with pytest.raises(ScannerError):
            raise DetectionError("detection failed")

    def test_message_preserved(self):
        """Error message should be preserved."""
        err = DetectionError("pattern matching timeout")
        assert str(err) == "pattern matching timeout"

    def test_use_case_detector_failure(self):
        """Test real-world use case: detector failure."""
        def detect(text):
            if not text:
                raise DetectionError("Cannot detect on empty text")
            return []

        with pytest.raises(DetectionError) as exc:
            detect("")
        assert "empty" in str(exc.value)

    def test_use_case_timeout(self):
        """Test real-world use case: detection timeout."""
        def detect_with_timeout(text, timeout=5):
            elapsed = 10  # Simulate timeout
            if elapsed > timeout:
                raise DetectionError(f"Detection timed out after {timeout}s")
            return []

        with pytest.raises(DetectionError) as exc:
            detect_with_timeout("text", timeout=5)
        assert "timed out" in str(exc.value)


class TestProcessingError:
    """Tests for ProcessingError exception."""

    def test_inherits_from_scanner_error(self):
        """ProcessingError should inherit from ScannerError."""
        assert issubclass(ProcessingError, ScannerError)

    def test_can_raise(self):
        """ProcessingError can be raised and caught."""
        with pytest.raises(ProcessingError):
            raise ProcessingError("processing failed")

    def test_can_catch_as_scanner_error(self):
        """ProcessingError can be caught as ScannerError."""
        with pytest.raises(ScannerError):
            raise ProcessingError("processing failed")

    def test_message_preserved(self):
        """Error message should be preserved."""
        err = ProcessingError("failed to extract text")
        assert str(err) == "failed to extract text"

    def test_use_case_extraction_failure(self):
        """Test real-world use case: extraction failure."""
        def extract_text(content):
            if len(content) == 0:
                raise ProcessingError("Empty content cannot be processed")
            return content.decode()

        with pytest.raises(ProcessingError) as exc:
            extract_text(b"")
        assert "Empty" in str(exc.value)

    def test_use_case_corrupt_file(self):
        """Test real-world use case: corrupt file."""
        def process_pdf(content):
            if content[:4] != b'%PDF':
                raise ProcessingError("Invalid PDF header")
            return "processed"

        with pytest.raises(ProcessingError) as exc:
            process_pdf(b"not a pdf")
        assert "Invalid PDF" in str(exc.value)


class TestFileValidationError:
    """Tests for FileValidationError exception."""

    def test_inherits_from_processing_error(self):
        """FileValidationError should inherit from ProcessingError."""
        assert issubclass(FileValidationError, ProcessingError)

    def test_inherits_from_scanner_error(self):
        """FileValidationError should also be a ScannerError."""
        assert issubclass(FileValidationError, ScannerError)

    def test_can_raise(self):
        """FileValidationError can be raised and caught."""
        with pytest.raises(FileValidationError):
            raise FileValidationError("validation failed")

    def test_can_catch_as_processing_error(self):
        """FileValidationError can be caught as ProcessingError."""
        with pytest.raises(ProcessingError):
            raise FileValidationError("validation failed")

    def test_can_catch_as_scanner_error(self):
        """FileValidationError can be caught as ScannerError."""
        with pytest.raises(ScannerError):
            raise FileValidationError("validation failed")

    def test_message_preserved(self):
        """Error message should be preserved."""
        err = FileValidationError("file too large")
        assert str(err) == "file too large"

    def test_filename_attribute(self):
        """FileValidationError should have filename attribute."""
        err = FileValidationError("file too large", filename="test.pdf")
        assert err.filename == "test.pdf"
        assert str(err) == "file too large"

    def test_filename_none_by_default(self):
        """Filename should be None by default."""
        err = FileValidationError("validation failed")
        assert err.filename is None

    def test_use_case_file_too_large(self):
        """Test real-world use case: file too large."""
        MAX_SIZE = 100 * 1024 * 1024  # 100MB

        def validate_file(content, filename):
            if len(content) > MAX_SIZE:
                raise FileValidationError(
                    f"File exceeds {MAX_SIZE // (1024*1024)}MB limit",
                    filename=filename
                )
            return True

        large_content = b"x" * (MAX_SIZE + 1)
        with pytest.raises(FileValidationError) as exc:
            validate_file(large_content, "huge.bin")
        assert exc.value.filename == "huge.bin"
        assert "100MB" in str(exc.value)

    def test_use_case_invalid_type(self):
        """Test real-world use case: invalid file type."""
        ALLOWED_TYPES = {".pdf", ".docx", ".txt"}

        def validate_type(filename):
            import os
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_TYPES:
                raise FileValidationError(
                    f"Unsupported file type: {ext}",
                    filename=filename
                )
            return True

        with pytest.raises(FileValidationError) as exc:
            validate_type("malware.exe")
        assert exc.value.filename == "malware.exe"
        assert ".exe" in str(exc.value)

    def test_use_case_missing_file(self):
        """Test real-world use case: missing file."""
        def validate_exists(filepath):
            import os
            if not os.path.exists(filepath):
                raise FileValidationError(
                    f"File not found: {filepath}",
                    filename=filepath
                )
            return True

        with pytest.raises(FileValidationError) as exc:
            validate_exists("/nonexistent/path/file.txt")
        assert "not found" in str(exc.value)


class TestExceptionHierarchy:
    """Tests for the complete exception hierarchy."""

    def test_hierarchy_depth(self):
        """Test the exception hierarchy depth."""
        # ScannerError -> Exception
        assert ScannerError.__bases__ == (Exception,)
        # ConfigurationError -> ScannerError
        assert ConfigurationError.__bases__ == (ScannerError,)
        # DetectionError -> ScannerError
        assert DetectionError.__bases__ == (ScannerError,)
        # ProcessingError -> ScannerError
        assert ProcessingError.__bases__ == (ScannerError,)
        # FileValidationError -> ProcessingError
        assert FileValidationError.__bases__ == (ProcessingError,)

    def test_catch_all_scanner_errors(self):
        """ScannerError should catch all custom exceptions."""
        exceptions = [
            ScannerError("base"),
            ConfigurationError("config"),
            DetectionError("detection"),
            ProcessingError("processing"),
            FileValidationError("validation"),
        ]

        for exc in exceptions:
            try:
                raise exc
            except ScannerError as caught:
                assert caught is exc
            else:
                pytest.fail(f"{type(exc).__name__} not caught by ScannerError")

    def test_processing_catches_file_validation(self):
        """ProcessingError should catch FileValidationError."""
        try:
            raise FileValidationError("test", filename="test.txt")
        except ProcessingError as exc:
            assert isinstance(exc, FileValidationError)
            assert exc.filename == "test.txt"

    def test_specific_catches_dont_cross_branches(self):
        """ConfigurationError should not catch DetectionError."""
        with pytest.raises(DetectionError):
            try:
                raise DetectionError("detection issue")
            except ConfigurationError:
                pytest.fail("ConfigurationError should not catch DetectionError")

    def test_exception_chaining(self):
        """Test exception chaining with __cause__."""
        try:
            try:
                raise ValueError("original error")
            except ValueError as e:
                raise ProcessingError("wrapped error") from e
        except ProcessingError as exc:
            assert exc.__cause__ is not None
            assert isinstance(exc.__cause__, ValueError)
            assert str(exc.__cause__) == "original error"


class TestExceptionModuleExports:
    """Tests for module __all__ exports."""

    def test_all_exports_defined(self):
        """All expected exceptions should be in __all__."""
        from openlabels.adapters.scanner import exceptions
        expected = [
            "ScannerError",
            "ConfigurationError",
            "DetectionError",
            "ProcessingError",
            "FileValidationError",
        ]
        for name in expected:
            assert name in exceptions.__all__, f"{name} not in __all__"

    def test_all_exports_importable(self):
        """All items in __all__ should be importable."""
        from openlabels.adapters.scanner import exceptions
        for name in exceptions.__all__:
            assert hasattr(exceptions, name), f"{name} not found in module"
            obj = getattr(exceptions, name)
            assert issubclass(obj, Exception), f"{name} is not an exception"
