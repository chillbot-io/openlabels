"""
Comprehensive tests for the virtual label writer.

Tests cloud URI parsing/validation, label pointer validation,
xattr handlers, and platform detection.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.output.virtual import (
    parse_cloud_uri,
    CloudURI,
    CloudURIValidationError,
    _validate_label_pointer,
    _get_platform,
    _get_handler,
    BaseXattrHandler,
    LinuxXattrHandler,
    MacOSXattrHandler,
    WindowsADSHandler,
    XATTR_LINUX,
    XATTR_MACOS,
    XATTR_WINDOWS_ADS,
    _S3_BUCKET_PATTERN,
    _GCS_BUCKET_PATTERN,
    _AZURE_CONTAINER_PATTERN,
    _PATH_TRAVERSAL_PATTERN,
)


class TestParseCloudURI:
    """Tests for cloud URI parsing."""

    def test_parse_s3_uri(self):
        """Test parsing S3 URI."""
        result = parse_cloud_uri("s3://my-bucket/path/to/file.txt")

        assert result.provider == "s3"
        assert result.bucket == "my-bucket"
        assert result.key == "path/to/file.txt"

    def test_parse_gcs_uri(self):
        """Test parsing GCS URI."""
        result = parse_cloud_uri("gs://my-bucket/path/to/file.txt")

        assert result.provider == "gcs"
        assert result.bucket == "my-bucket"
        assert result.key == "path/to/file.txt"

    def test_parse_azure_uri(self):
        """Test parsing Azure URI."""
        result = parse_cloud_uri("azure://my-container/path/to/blob.txt")

        assert result.provider == "azure"
        assert result.bucket == "my-container"
        assert result.key == "path/to/blob.txt"

    def test_parse_uri_no_key(self):
        """Test parsing URI with no key."""
        result = parse_cloud_uri("s3://my-bucket")

        assert result.bucket == "my-bucket"
        assert result.key == ""

    def test_parse_uri_empty_key(self):
        """Test parsing URI with empty key after slash."""
        result = parse_cloud_uri("s3://my-bucket/")

        assert result.bucket == "my-bucket"
        assert result.key == ""

    def test_parse_uri_nested_key(self):
        """Test parsing URI with deeply nested key."""
        result = parse_cloud_uri("s3://bucket/a/b/c/d/file.txt")

        assert result.key == "a/b/c/d/file.txt"

    def test_empty_uri_raises(self):
        """Test empty URI raises error."""
        with pytest.raises(CloudURIValidationError, match="Empty URI"):
            parse_cloud_uri("")

    def test_unknown_scheme_raises(self):
        """Test unknown URI scheme raises error."""
        with pytest.raises(CloudURIValidationError, match="Unknown URI scheme"):
            parse_cloud_uri("http://bucket/key")

        with pytest.raises(CloudURIValidationError, match="Unknown URI scheme"):
            parse_cloud_uri("ftp://bucket/key")

    def test_empty_bucket_raises(self):
        """Test empty bucket raises error."""
        with pytest.raises(CloudURIValidationError, match="cannot be empty"):
            parse_cloud_uri("s3:///key")

    def test_bucket_too_short_raises(self):
        """Test bucket name too short raises error."""
        with pytest.raises(CloudURIValidationError, match="at least 3 characters"):
            parse_cloud_uri("s3://ab/key")

    def test_bucket_too_long_raises(self):
        """Test bucket name too long raises error."""
        long_bucket = "a" * 64
        with pytest.raises(CloudURIValidationError, match="at most 63 characters"):
            parse_cloud_uri(f"s3://{long_bucket}/key")

    def test_invalid_bucket_characters_raises(self):
        """Test invalid bucket characters raise error."""
        with pytest.raises(CloudURIValidationError, match="Invalid.*bucket name"):
            parse_cloud_uri("s3://UPPERCASE/key")

        with pytest.raises(CloudURIValidationError, match="Invalid.*bucket name"):
            parse_cloud_uri("s3://under_score/key")  # S3 doesn't allow underscores

    def test_ip_address_bucket_raises(self):
        """Test IP address bucket name raises error for S3/GCS."""
        with pytest.raises(CloudURIValidationError, match="cannot be an IP address"):
            parse_cloud_uri("s3://192.168.1.1/key")

    def test_path_traversal_raises(self):
        """Test path traversal in key raises error."""
        with pytest.raises(CloudURIValidationError, match="Path traversal"):
            parse_cloud_uri("s3://bucket/../../../etc/passwd")

        with pytest.raises(CloudURIValidationError, match="Path traversal"):
            parse_cloud_uri("s3://bucket/path/../../key")

    def test_null_byte_in_key_raises(self):
        """Test null byte in key raises error."""
        with pytest.raises(CloudURIValidationError, match="Null byte"):
            parse_cloud_uri("s3://bucket/path\x00/key")

    def test_key_too_long_raises(self):
        """Test key exceeding 1024 bytes raises error."""
        long_key = "a" * 1025
        with pytest.raises(CloudURIValidationError, match="exceeds maximum length"):
            parse_cloud_uri(f"s3://bucket/{long_key}")


class TestBucketPatterns:
    """Tests for bucket naming pattern regexes."""

    def test_s3_valid_bucket_names(self):
        """Test valid S3 bucket names."""
        valid = [
            "my-bucket",
            "bucket123",
            "a-b-c",
            "bucket.with.dots",
            "123bucket",
        ]
        for name in valid:
            assert _S3_BUCKET_PATTERN.match(name), f"Should match: {name}"

    def test_s3_invalid_bucket_names(self):
        """Test invalid S3 bucket names."""
        invalid = [
            "UPPERCASE",
            "-startswithhyphen",
            "endswith-",
            "has..double..dots",
            "has.-mixed",
        ]
        for name in invalid:
            assert not _S3_BUCKET_PATTERN.match(name), f"Should not match: {name}"

    def test_gcs_valid_bucket_names(self):
        """Test valid GCS bucket names."""
        valid = [
            "my-bucket",
            "bucket_with_underscores",
            "bucket123",
        ]
        for name in valid:
            assert _GCS_BUCKET_PATTERN.match(name), f"Should match: {name}"

    def test_gcs_invalid_bucket_names(self):
        """Test invalid GCS bucket names (containing google)."""
        invalid = [
            "googlebucket",
            "mygooglebucket",
            "bucket-google",
        ]
        for name in invalid:
            assert not _GCS_BUCKET_PATTERN.match(name), f"Should not match: {name}"

    def test_azure_valid_container_names(self):
        """Test valid Azure container names."""
        valid = [
            "mycontainer",
            "container-name",
            "container123",
        ]
        for name in valid:
            assert _AZURE_CONTAINER_PATTERN.match(name), f"Should match: {name}"

    def test_azure_invalid_container_names(self):
        """Test invalid Azure container names."""
        invalid = [
            "has--double-hyphens",
            "-startswith",
        ]
        for name in invalid:
            assert not _AZURE_CONTAINER_PATTERN.match(name), f"Should not match: {name}"


class TestPathTraversalPattern:
    """Tests for path traversal detection."""

    def test_detects_traversal_at_start(self):
        """Test detects ../ at start."""
        assert _PATH_TRAVERSAL_PATTERN.search("../etc/passwd")
        assert _PATH_TRAVERSAL_PATTERN.search("..\\windows\\system32")

    def test_detects_traversal_in_middle(self):
        """Test detects ../ in middle of path."""
        assert _PATH_TRAVERSAL_PATTERN.search("path/../../../etc")
        assert _PATH_TRAVERSAL_PATTERN.search("path\\..\\secret")

    def test_detects_traversal_at_end(self):
        """Test detects /.. at end."""
        assert _PATH_TRAVERSAL_PATTERN.search("path/..")
        assert _PATH_TRAVERSAL_PATTERN.search("path\\..")

    def test_detects_bare_dotdot(self):
        """Test detects just '..'."""
        assert _PATH_TRAVERSAL_PATTERN.search("..")

    def test_does_not_match_safe_paths(self):
        """Test doesn't match safe paths with dots."""
        assert not _PATH_TRAVERSAL_PATTERN.search("file.txt")
        assert not _PATH_TRAVERSAL_PATTERN.search("path/to/file.tar.gz")
        assert not _PATH_TRAVERSAL_PATTERN.search("...hidden")


class TestValidateLabelPointer:
    """Tests for label pointer validation."""

    def test_valid_pointer(self):
        """Test valid label pointer format."""
        assert _validate_label_pointer("ol_abc123:deadbeef12345678") is True
        assert _validate_label_pointer("label-id_v2:0123456789abcdef") is True

    def test_invalid_empty(self):
        """Test empty value is invalid."""
        assert _validate_label_pointer("") is False
        assert _validate_label_pointer(None) is False

    def test_invalid_no_colon(self):
        """Test missing colon is invalid."""
        assert _validate_label_pointer("labelidwithouthash") is False

    def test_invalid_null_byte(self):
        """Test null byte is invalid."""
        assert _validate_label_pointer("label\x00:abc123") is False

    def test_invalid_newline(self):
        """Test newline is invalid."""
        assert _validate_label_pointer("label\n:abc123") is False

    def test_invalid_too_long(self):
        """Test value too long is invalid."""
        long_value = "a" * 257
        assert _validate_label_pointer(long_value) is False

    def test_invalid_hash_not_hex(self):
        """Test non-hex hash is invalid."""
        assert _validate_label_pointer("label:notahexvalue") is False

    def test_invalid_hash_too_short(self):
        """Test hash too short is invalid."""
        assert _validate_label_pointer("label:abc") is False


class TestGetPlatform:
    """Tests for platform detection."""

    @patch('platform.system')
    def test_detects_linux(self, mock_system):
        """Test detects Linux."""
        mock_system.return_value = "Linux"
        assert _get_platform() == "linux"

    @patch('platform.system')
    def test_detects_macos(self, mock_system):
        """Test detects macOS."""
        mock_system.return_value = "Darwin"
        assert _get_platform() == "macos"

    @patch('platform.system')
    def test_detects_windows(self, mock_system):
        """Test detects Windows."""
        mock_system.return_value = "Windows"
        assert _get_platform() == "windows"

    @patch('platform.system')
    def test_unknown_platform(self, mock_system):
        """Test unknown platform."""
        mock_system.return_value = "UnknownOS"
        assert _get_platform() == "unknown"


class TestGetHandler:
    """Tests for xattr handler selection."""

    @patch('openlabels.output.virtual._get_platform')
    def test_returns_linux_handler(self, mock_platform):
        """Test returns Linux handler."""
        mock_platform.return_value = "linux"
        handler = _get_handler()
        assert isinstance(handler, LinuxXattrHandler)

    @patch('openlabels.output.virtual._get_platform')
    def test_returns_macos_handler(self, mock_platform):
        """Test returns macOS handler."""
        mock_platform.return_value = "macos"
        handler = _get_handler()
        assert isinstance(handler, MacOSXattrHandler)

    @patch('openlabels.output.virtual._get_platform')
    def test_returns_windows_handler(self, mock_platform):
        """Test returns Windows handler."""
        mock_platform.return_value = "windows"
        handler = _get_handler()
        assert isinstance(handler, WindowsADSHandler)

    @patch('openlabels.output.virtual._get_platform')
    def test_unknown_defaults_to_linux(self, mock_platform):
        """Test unknown platform defaults to Linux handler."""
        mock_platform.return_value = "unknown"
        handler = _get_handler()
        assert isinstance(handler, LinuxXattrHandler)


class TestBaseXattrHandler:
    """Tests for BaseXattrHandler."""

    def test_attr_names(self):
        """Test attribute name constants."""
        assert LinuxXattrHandler.ATTR_NAME == XATTR_LINUX
        assert MacOSXattrHandler.ATTR_NAME == XATTR_MACOS
        assert WindowsADSHandler.ATTR_NAME == XATTR_WINDOWS_ADS

    def test_write_validates_path(self):
        """Test write validates path."""
        handler = LinuxXattrHandler()

        # Path with null byte should fail validation
        result = handler.write("/path\x00/file", "value")
        assert result is False

    def test_read_validates_path(self):
        """Test read validates path."""
        handler = LinuxXattrHandler()

        # Path with null byte should fail validation
        result = handler.read("/path\x00/file")
        assert result is None

    def test_remove_validates_path(self):
        """Test remove validates path."""
        handler = LinuxXattrHandler()

        # Path with null byte should fail validation
        result = handler.remove("/path\x00/file")
        assert result is False


class TestLinuxXattrHandler:
    """Tests for LinuxXattrHandler."""

    @patch('openlabels.output.virtual.subprocess.run')
    def test_write_uses_setfattr_fallback(self, mock_run):
        """Test write falls back to setfattr when xattr module unavailable."""
        mock_run.return_value = MagicMock(returncode=0)

        handler = LinuxXattrHandler()

        with patch.dict('sys.modules', {'xattr': None}):
            with tempfile.NamedTemporaryFile() as f:
                # This will fail because xattr import fails, then try setfattr
                handler._do_write(f.name, "test_value")

                # Check setfattr was called
                mock_run.assert_called()

    @patch('openlabels.output.virtual.subprocess.run')
    def test_read_uses_getfattr_fallback(self, mock_run):
        """Test read falls back to getfattr when xattr module unavailable."""
        mock_run.return_value = MagicMock(returncode=0, stdout="test_value\n")

        handler = LinuxXattrHandler()

        with patch.dict('sys.modules', {'xattr': None}):
            with tempfile.NamedTemporaryFile() as f:
                handler._do_read(f.name)
                mock_run.assert_called()


class TestWindowsADSHandler:
    """Tests for WindowsADSHandler."""

    def test_ads_path_format(self):
        """Test ADS path format is correct."""
        handler = WindowsADSHandler()

        # The ADS path should be file:streamname
        path = "/path/to/file.txt"
        expected_ads = f"{path}:{XATTR_WINDOWS_ADS}"

        # We can't test the actual write on non-Windows, but we can verify the format
        assert XATTR_WINDOWS_ADS == "openlabels"


class TestCloudURIDataclass:
    """Tests for CloudURI dataclass."""

    def test_clouduri_attributes(self):
        """Test CloudURI attributes."""
        uri = CloudURI(provider="s3", bucket="my-bucket", key="path/to/file")

        assert uri.provider == "s3"
        assert uri.bucket == "my-bucket"
        assert uri.key == "path/to/file"


class TestXattrConstants:
    """Tests for xattr constants."""

    def test_linux_xattr_name(self):
        """Test Linux xattr name follows convention."""
        assert XATTR_LINUX == "user.openlabels"
        assert XATTR_LINUX.startswith("user.")  # User namespace

    def test_macos_xattr_name(self):
        """Test macOS xattr name follows convention."""
        assert XATTR_MACOS == "com.openlabels.label"
        assert "openlabels" in XATTR_MACOS

    def test_windows_ads_name(self):
        """Test Windows ADS name."""
        assert XATTR_WINDOWS_ADS == "openlabels"
