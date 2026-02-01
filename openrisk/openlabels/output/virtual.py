"""
OpenLabels Virtual Label Writer.

Writes label pointers to extended attributes (xattr) for files that
don't support native metadata embedding.

Virtual labels store a pointer (labelID:content_hash) in xattr,
with the full LabelSet stored in the index.

Platform support:
- Linux: user.openlabels
- macOS: com.openlabels.label
- Windows: NTFS ADS (Alternate Data Stream)
- Cloud: S3 x-amz-meta-openlabels, GCS/Azure metadata
"""

import os
import logging
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from ..core.labels import LabelSet, VirtualLabelPointer
from ..utils.retry import with_retry, CircuitBreaker
from ..adapters.scanner.constants import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BASE_DELAY,
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
)
from ..utils.validation import (
    validate_path_for_subprocess,
    validate_xattr_value,
)

logger = logging.getLogger(__name__)

# Platform-specific attribute names
XATTR_LINUX = "user.openlabels"
XATTR_MACOS = "com.openlabels.label"
XATTR_WINDOWS_ADS = "openlabels"  # Stored as file.txt:openlabels


# S3 bucket naming rules:
# - 3-63 characters
# - Lowercase letters, numbers, hyphens, periods
# - Must start and end with letter or number
# - Cannot be formatted as IP address
_S3_BUCKET_PATTERN = re.compile(
    r'^(?!.*\.\.)(?!.*-\.)(?!.*\.-)'  # No consecutive dots or dot-hyphen
    r'[a-z0-9]'                        # Start with lowercase letter or digit
    r'[a-z0-9.-]{1,61}'               # Middle: letters, digits, dots, hyphens
    r'[a-z0-9]$'                       # End with lowercase letter or digit
)

# GCS bucket naming rules (similar to S3 with some differences)
_GCS_BUCKET_PATTERN = re.compile(
    r'^(?!goog)(?!.*google.*)'        # Cannot contain "google" or start with "goog"
    r'[a-z0-9]'                        # Start with lowercase letter or digit
    r'[a-z0-9_.-]{1,61}'              # Middle: letters, digits, underscores, dots, hyphens
    r'[a-z0-9]$'                       # End with lowercase letter or digit
)

# Azure container naming rules:
# - 3-63 characters
# - Lowercase letters, numbers, hyphens
# - Must start with letter or number
# - No consecutive hyphens
_AZURE_CONTAINER_PATTERN = re.compile(
    r'^(?!.*--)'
    r'[a-z0-9]'
    r'[a-z0-9-]{1,61}'
    r'[a-z0-9]$'
)

# Path traversal detection pattern
_PATH_TRAVERSAL_PATTERN = re.compile(
    r'(^|[/\\])\.\.[/\\]|'  # ../ or ..\ at start or after separator
    r'[/\\]\.\.$|'           # /.. or \.. at end
    r'^\.\.$'                # Just ".."
)

# Label pointer validation pattern
# Expected format: labelID:content_hash
# labelID: alphanumeric with underscores, typically like "ol_7f3a9b2c4d5e"
# content_hash: hexadecimal string, typically 32-64 chars
_LABEL_POINTER_PATTERN = re.compile(
    r'^[a-zA-Z0-9_-]{1,128}:[a-fA-F0-9]{8,128}$'
)


def _validate_label_pointer(value: str) -> bool:
    """
    Validate a virtual label pointer value from xattr.

    Expected format: labelID:content_hash
    - labelID: alphanumeric with underscores/hyphens, max 128 chars
    - content_hash: hex string, 8-128 chars

    Args:
        value: The xattr value to validate

    Returns:
        True if valid, False otherwise
    """
    if not value or not isinstance(value, str):
        return False

    # Check for suspicious characters (potential injection)
    if '\x00' in value or '\n' in value or '\r' in value:
        return False

    # Length sanity check
    if len(value) > 256:
        return False

    return bool(_LABEL_POINTER_PATTERN.match(value))


@dataclass
class CloudURI:
    """Parsed and validated cloud storage URI."""
    provider: str  # 's3', 'gcs', or 'azure'
    bucket: str    # bucket name (or container for Azure)
    key: str       # object key/blob name


class CloudURIValidationError(ValueError):
    """Raised when a cloud URI fails validation."""


def parse_cloud_uri(uri: str) -> CloudURI:
    """
    Parse and validate a cloud storage URI.

    Supports:
    - s3://bucket/key
    - gs://bucket/blob
    - azure://container/blob

    Args:
        uri: Cloud storage URI

    Returns:
        CloudURI with validated components

    Raises:
        CloudURIValidationError: If URI is malformed or contains invalid characters

    Examples:
        >>> parse_cloud_uri("s3://my-bucket/path/to/file.txt")
        CloudURI(provider='s3', bucket='my-bucket', key='path/to/file.txt')

        >>> parse_cloud_uri("s3://bucket/../../../etc/passwd")
        CloudURIValidationError: Path traversal detected in key
    """
    if not uri:
        raise CloudURIValidationError("Empty URI")

    # Determine provider and extract bucket/key
    if uri.startswith('s3://'):
        provider = 's3'
        remainder = uri[5:]
        bucket_pattern = _S3_BUCKET_PATTERN
        provider_name = "S3"
    elif uri.startswith('gs://'):
        provider = 'gcs'
        remainder = uri[5:]
        bucket_pattern = _GCS_BUCKET_PATTERN
        provider_name = "GCS"
    elif uri.startswith('azure://'):
        provider = 'azure'
        remainder = uri[8:]
        bucket_pattern = _AZURE_CONTAINER_PATTERN
        provider_name = "Azure"
    else:
        raise CloudURIValidationError(
            f"Unknown URI scheme. Supported: s3://, gs://, azure://. Got: {uri[:20]}"
        )

    # Split into bucket and key
    parts = remainder.split('/', 1)
    bucket = parts[0]
    key = parts[1] if len(parts) > 1 else ''

    # Validate bucket name
    if not bucket:
        raise CloudURIValidationError(f"{provider_name} bucket name cannot be empty")

    if len(bucket) < 3:
        raise CloudURIValidationError(
            f"{provider_name} bucket name must be at least 3 characters: {bucket}"
        )

    if len(bucket) > 63:
        raise CloudURIValidationError(
            f"{provider_name} bucket name must be at most 63 characters: {bucket[:20]}..."
        )

    if not bucket_pattern.match(bucket):
        raise CloudURIValidationError(
            f"Invalid {provider_name} bucket name: {bucket}. "
            f"Must contain only lowercase letters, numbers, and hyphens, "
            f"and start/end with a letter or number."
        )

    # Check for IP address format (not allowed for S3/GCS)
    if provider in ('s3', 'gcs'):
        ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
        if ip_pattern.match(bucket):
            raise CloudURIValidationError(
                f"{provider_name} bucket name cannot be an IP address: {bucket}"
            )

    # Validate key (path traversal check)
    if key:
        if _PATH_TRAVERSAL_PATTERN.search(key):
            raise CloudURIValidationError(
                f"Path traversal detected in {provider_name} key: {key[:50]}"
            )

        # Check for null bytes (could be used for injection)
        if '\x00' in key:
            raise CloudURIValidationError(
                f"Null byte not allowed in {provider_name} key"
            )

        # S3 key length limit is 1024 bytes
        if len(key.encode('utf-8')) > 1024:
            raise CloudURIValidationError(
                f"{provider_name} key exceeds maximum length of 1024 bytes"
            )

    return CloudURI(provider=provider, bucket=bucket, key=key)


def _get_platform() -> str:
    """Detect current platform."""
    system = platform.system()
    if system == "Linux":
        return "linux"
    elif system == "Darwin":
        return "macos"
    elif system == "Windows":
        return "windows"
    return "unknown"


class BaseXattrHandler:
    """Base class for platform-specific extended attribute handlers."""

    ATTR_NAME: str = ""

    def write(self, path: str, value: str) -> bool:
        """Write xattr value with validation."""
        if not validate_path_for_subprocess(path):
            logger.error(f"Invalid path for xattr write: {path[:100]}")
            return False
        if not validate_xattr_value(value):
            logger.error("Invalid value for xattr write")
            return False
        return self._do_write(path, value)

    def read(self, path: str) -> Optional[str]:
        """Read xattr value with validation."""
        if not validate_path_for_subprocess(path):
            logger.debug(f"Invalid path for xattr read: {path[:100]}")
            return None
        return self._do_read(path)

    def remove(self, path: str) -> bool:
        """Remove xattr with validation."""
        if not validate_path_for_subprocess(path):
            logger.debug(f"Invalid path for xattr remove: {path[:100]}")
            return False
        return self._do_remove(path)

    def _do_write(self, path: str, value: str) -> bool:
        raise NotImplementedError

    def _do_read(self, path: str) -> Optional[str]:
        raise NotImplementedError

    def _do_remove(self, path: str) -> bool:
        raise NotImplementedError


class LinuxXattrHandler(BaseXattrHandler):
    """Handle extended attributes on Linux using xattr module or setfattr."""

    ATTR_NAME = XATTR_LINUX

    def _do_write(self, path: str, value: str) -> bool:
        try:
            import xattr
            xattr.setxattr(path, self.ATTR_NAME, value.encode('utf-8'))
            return True
        except ImportError:
            logger.debug("xattr module not available, falling back to setfattr")
        except OSError as e:
            logger.debug(f"xattr module failed: {e}")

        try:
            result = subprocess.run(
                ["setfattr", "-n", self.ATTR_NAME, "-v", value, path],
                capture_output=True, text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("setfattr not found. Install attr package.")
        except OSError as e:
            logger.error(f"setfattr failed: {e}")
        return False

    def _do_read(self, path: str) -> Optional[str]:
        try:
            import xattr
            return xattr.getxattr(path, self.ATTR_NAME).decode('utf-8')
        except ImportError:
            logger.debug("xattr module not available, falling back to getfattr")
        except OSError as e:
            logger.debug(f"xattr read failed for {path}: {e}")

        try:
            result = subprocess.run(
                ["getfattr", "-n", self.ATTR_NAME, "--only-values", path],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except FileNotFoundError:
            logger.debug("getfattr not found")
        except OSError as e:
            logger.debug(f"getfattr failed for {path}: {e}")
        return None

    def _do_remove(self, path: str) -> bool:
        try:
            import xattr
            xattr.removexattr(path, self.ATTR_NAME)
            return True
        except ImportError:
            logger.debug("xattr module not available, falling back to setfattr")
        except OSError as e:
            logger.debug(f"xattr remove failed for {path}: {e}")

        try:
            result = subprocess.run(
                ["setfattr", "-x", self.ATTR_NAME, path],
                capture_output=True,
            )
            return result.returncode == 0
        except OSError as e:
            logger.debug(f"setfattr remove failed for {path}: {e}")
        return False


class MacOSXattrHandler(BaseXattrHandler):
    """Handle extended attributes on macOS using xattr command."""

    ATTR_NAME = XATTR_MACOS

    def _do_write(self, path: str, value: str) -> bool:
        try:
            result = subprocess.run(
                ["xattr", "-w", self.ATTR_NAME, value, path],
                capture_output=True, text=True,
            )
            return result.returncode == 0
        except OSError as e:
            logger.error(f"macOS xattr write failed: {e}")
            return False

    def _do_read(self, path: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["xattr", "-p", self.ATTR_NAME, path],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except OSError as e:
            logger.debug(f"macOS xattr read failed for {path}: {e}")
        return None

    def _do_remove(self, path: str) -> bool:
        try:
            result = subprocess.run(
                ["xattr", "-d", self.ATTR_NAME, path],
                capture_output=True,
            )
            return result.returncode == 0
        except OSError as e:
            logger.debug(f"macOS xattr remove failed for {path}: {e}")
            return False


class WindowsADSHandler(BaseXattrHandler):
    """Handle NTFS Alternate Data Streams on Windows."""

    ATTR_NAME = XATTR_WINDOWS_ADS

    def _do_write(self, path: str, value: str) -> bool:
        ads_path = f"{path}:{self.ATTR_NAME}"
        try:
            with open(ads_path, 'w', encoding='utf-8') as f:
                f.write(value)
            return True
        except OSError as e:
            logger.error(f"Windows ADS write failed: {e}")
            return False

    def _do_read(self, path: str) -> Optional[str]:
        ads_path = f"{path}:{self.ATTR_NAME}"
        try:
            with open(ads_path, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except FileNotFoundError:
            return None
        except OSError as e:
            logger.debug(f"Windows ADS read failed for {path}: {e}")
            return None

    def _do_remove(self, path: str) -> bool:
        ads_path = f"{path}:{self.ATTR_NAME}"
        try:
            os.remove(ads_path)
            return True
        except OSError as e:
            logger.debug(f"Windows ADS remove failed for {path}: {e}")
            return False


def _get_handler():
    """Get the appropriate xattr handler for the current platform."""
    plat = _get_platform()
    if plat == "linux":
        return LinuxXattrHandler()
    elif plat == "macos":
        return MacOSXattrHandler()
    elif plat == "windows":
        return WindowsADSHandler()
    else:
        logger.warning(f"Unknown platform: {plat}, using Linux handler")
        return LinuxXattrHandler()


_handler = None


def get_handler():
    """Get cached xattr handler."""
    global _handler
    if _handler is None:
        _handler = _get_handler()
    return _handler


def write_virtual_label(
    path: Union[str, Path],
    label_set: LabelSet,
) -> bool:
    """
    Write a virtual label pointer to a file's extended attributes.

    The pointer format is: labelID:content_hash
    The full LabelSet should be stored in the index separately.

    Args:
        path: Path to the file
        label_set: The LabelSet (used to extract pointer info)

    Returns:
        True if successful, False otherwise

    Example:
        >>> label_set = LabelSet.create(labels, content)
        >>> write_virtual_label("data.csv", label_set)
        True
        >>> # Store full LabelSet in index
        >>> index.store(label_set)
    """
    path = str(path)
    pointer = VirtualLabelPointer(
        label_id=label_set.label_id,
        content_hash=label_set.content_hash,
    )
    return get_handler().write(path, pointer.to_string())


def read_virtual_label(path: Union[str, Path]) -> Optional[VirtualLabelPointer]:
    """
    Read a virtual label pointer from a file's extended attributes.

    Validates the xattr value format before parsing to prevent injection
    of malicious data through manually crafted xattr values.

    Args:
        path: Path to the file

    Returns:
        VirtualLabelPointer if found and valid, None otherwise

    Example:
        >>> pointer = read_virtual_label("data.csv")
        >>> if pointer:
        ...     label_set = index.get(pointer.label_id, pointer.content_hash)
    """
    path_str = str(path)
    value = get_handler().read(path_str)
    if value:
        # Validate format before parsing to prevent injection attacks
        if not _validate_label_pointer(value):
            logger.warning(
                f"Invalid xattr format on {path_str}: "
                f"{value[:50] if len(value) > 50 else value!r}"
            )
            return None

        try:
            return VirtualLabelPointer.from_string(value)
        except ValueError as e:
            logger.warning(f"Invalid virtual label format: {e}")
    return None


def remove_virtual_label(path: Union[str, Path]) -> bool:
    """
    Remove a virtual label from a file's extended attributes.

    Args:
        path: Path to the file

    Returns:
        True if successful, False otherwise
    """
    return get_handler().remove(str(path))


def has_virtual_label(path: Union[str, Path]) -> bool:
    """Check if a file has a virtual label."""
    return read_virtual_label(path) is not None


# Module-level circuit breakers for each cloud provider
# These prevent overwhelming failing services with retries
_s3_circuit_breaker = CircuitBreaker(
    failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    recovery_timeout=CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
    name="s3_metadata",
)
_gcs_circuit_breaker = CircuitBreaker(
    failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    recovery_timeout=CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
    name="gcs_metadata",
)
_azure_circuit_breaker = CircuitBreaker(
    failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    recovery_timeout=CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
    name="azure_metadata",
)


class S3MetadataHandler:
    """Handle OpenLabels metadata on S3 objects."""

    METADATA_KEY = "openlabels"  # Becomes x-amz-meta-openlabels

    def write(self, bucket: str, key: str, value: str, s3_client=None) -> bool:
        """Write OpenLabels metadata to S3 object (copies object to update)."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 not installed")
            return False

        client = s3_client or boto3.client('s3')

        try:
            with _s3_circuit_breaker:
                return self._write_with_retry(client, bucket, key, value)
        except Exception as e:
            logger.error(f"S3 metadata write failed: {e}")
            return False

    @with_retry(max_retries=DEFAULT_MAX_RETRIES, base_delay=DEFAULT_RETRY_BASE_DELAY)
    def _write_with_retry(self, client, bucket: str, key: str, value: str) -> bool:
        """Internal write with retry decorator."""
        # Get current metadata
        response = client.head_object(Bucket=bucket, Key=key)
        current_metadata = response.get('Metadata', {})

        # Update with our label
        current_metadata[self.METADATA_KEY] = value

        # Copy object to itself with new metadata
        client.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={'Bucket': bucket, 'Key': key},
            Metadata=current_metadata,
            MetadataDirective='REPLACE',
        )
        return True

    def read(self, bucket: str, key: str, s3_client=None) -> Optional[str]:
        """Read OpenLabels metadata from S3 object."""
        try:
            import boto3
        except ImportError:
            return None

        client = s3_client or boto3.client('s3')

        try:
            with _s3_circuit_breaker:
                return self._read_with_retry(client, bucket, key)
        except Exception as e:
            logger.debug(f"S3 metadata read failed for {bucket}/{key}: {e}")
            return None

    @with_retry(max_retries=DEFAULT_MAX_RETRIES, base_delay=DEFAULT_RETRY_BASE_DELAY)
    def _read_with_retry(self, client, bucket: str, key: str) -> Optional[str]:
        """Internal read with retry decorator."""
        response = client.head_object(Bucket=bucket, Key=key)
        metadata = response.get('Metadata', {})
        return metadata.get(self.METADATA_KEY)


class GCSMetadataHandler:
    """Handle OpenLabels metadata on GCS objects."""

    METADATA_KEY = "openlabels"

    def write(self, bucket: str, blob_name: str, value: str, client=None) -> bool:
        """Write OpenLabels metadata to GCS object."""
        try:
            from google.cloud import storage
        except ImportError:
            logger.error("google-cloud-storage not installed")
            return False

        gcs_client = client or storage.Client()

        try:
            with _gcs_circuit_breaker:
                return self._write_with_retry(gcs_client, bucket, blob_name, value)
        except Exception as e:
            logger.error(f"GCS metadata write failed: {e}")
            return False

    @with_retry(max_retries=DEFAULT_MAX_RETRIES, base_delay=DEFAULT_RETRY_BASE_DELAY)
    def _write_with_retry(self, gcs_client, bucket: str, blob_name: str, value: str) -> bool:
        """Internal write with retry decorator."""
        bucket_obj = gcs_client.bucket(bucket)
        blob = bucket_obj.blob(blob_name)

        # Get current metadata
        blob.reload()
        metadata = blob.metadata or {}
        metadata[self.METADATA_KEY] = value
        blob.metadata = metadata
        blob.patch()
        return True

    def read(self, bucket: str, blob_name: str, client=None) -> Optional[str]:
        """Read OpenLabels metadata from GCS object."""
        try:
            from google.cloud import storage
        except ImportError:
            return None

        gcs_client = client or storage.Client()

        try:
            with _gcs_circuit_breaker:
                return self._read_with_retry(gcs_client, bucket, blob_name)
        except Exception as e:
            logger.debug(f"GCS metadata read failed for {bucket}/{blob_name}: {e}")
            return None

    @with_retry(max_retries=DEFAULT_MAX_RETRIES, base_delay=DEFAULT_RETRY_BASE_DELAY)
    def _read_with_retry(self, gcs_client, bucket: str, blob_name: str) -> Optional[str]:
        """Internal read with retry decorator."""
        bucket_obj = gcs_client.bucket(bucket)
        blob = bucket_obj.blob(blob_name)
        blob.reload()
        metadata = blob.metadata or {}
        return metadata.get(self.METADATA_KEY)


def _redact_connection_string(error_msg: str) -> str:
    """Redact connection strings from error messages to prevent credential leakage."""
    import re
    # Redact Azure connection strings (AccountKey=..., SharedAccessSignature=...)
    redacted = re.sub(
        r'(AccountKey=)[^;]+',
        r'\1[REDACTED]',
        str(error_msg),
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r'(SharedAccessSignature=)[^;]+',
        r'\1[REDACTED]',
        redacted,
        flags=re.IGNORECASE
    )
    # Redact full connection strings that might appear
    redacted = re.sub(
        r'DefaultEndpointsProtocol=[^"\'>\s]+',
        'DefaultEndpointsProtocol=[REDACTED]',
        redacted,
        flags=re.IGNORECASE
    )
    return redacted


class AzureBlobMetadataHandler:
    """Handle OpenLabels metadata on Azure Blob Storage."""

    METADATA_KEY = "openlabels"

    def write(
        self,
        container: str,
        blob_name: str,
        value: str,
        connection_string: Optional[str] = None,
    ) -> bool:
        """Write OpenLabels metadata to Azure Blob."""
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError:
            logger.error("azure-storage-blob not installed")
            return False

        conn_str = connection_string or os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
        if not conn_str:
            logger.error("Azure connection string not provided")
            return False

        try:
            with _azure_circuit_breaker:
                return self._write_with_retry(conn_str, container, blob_name, value)
        except Exception as e:
            # Redact connection string from error message to prevent credential leakage
            logger.error(f"Azure Blob metadata write failed: {_redact_connection_string(str(e))}")
            return False

    @with_retry(max_retries=DEFAULT_MAX_RETRIES, base_delay=DEFAULT_RETRY_BASE_DELAY)
    def _write_with_retry(
        self, conn_str: str, container: str, blob_name: str, value: str
    ) -> bool:
        """Internal write with retry decorator."""
        from azure.storage.blob import BlobServiceClient

        service = BlobServiceClient.from_connection_string(conn_str)
        blob_client = service.get_blob_client(container=container, blob=blob_name)

        # Get current metadata
        props = blob_client.get_blob_properties()
        metadata = props.metadata or {}
        metadata[self.METADATA_KEY] = value
        blob_client.set_blob_metadata(metadata)
        return True

    def read(
        self,
        container: str,
        blob_name: str,
        connection_string: Optional[str] = None,
    ) -> Optional[str]:
        """Read OpenLabels metadata from Azure Blob."""
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError:
            return None

        conn_str = connection_string or os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
        if not conn_str:
            return None

        try:
            with _azure_circuit_breaker:
                return self._read_with_retry(conn_str, container, blob_name)
        except Exception as e:
            # Redact connection string from error message to prevent credential leakage
            logger.debug(f"Azure blob metadata read failed for {container}/{blob_name}: {_redact_connection_string(str(e))}")
            return None

    @with_retry(max_retries=DEFAULT_MAX_RETRIES, base_delay=DEFAULT_RETRY_BASE_DELAY)
    def _read_with_retry(
        self, conn_str: str, container: str, blob_name: str
    ) -> Optional[str]:
        """Internal read with retry decorator."""
        from azure.storage.blob import BlobServiceClient

        service = BlobServiceClient.from_connection_string(conn_str)
        blob_client = service.get_blob_client(container=container, blob=blob_name)
        props = blob_client.get_blob_properties()
        metadata = props.metadata or {}
        return metadata.get(self.METADATA_KEY)


def _get_cloud_handler_for_provider(provider: str, context=None):
    """
    Get cloud handler for a provider.

    Args:
        provider: Cloud provider ('s3', 'gcs', 'azure')
        context: Optional Context instance for isolation

    Returns:
        Cloud metadata handler instance
    """
    if context is not None:
        return context.get_cloud_handler(provider)

    # Create handler directly
    if provider == 's3':
        return S3MetadataHandler()
    elif provider == 'gcs':
        return GCSMetadataHandler()
    elif provider == 'azure':
        return AzureBlobMetadataHandler()
    return None


def write_cloud_label(
    uri: str,
    label_set: LabelSet,
    context=None,
    **kwargs,
) -> bool:
    """
    Write a virtual label to a cloud storage object.

    Supports:
    - s3://bucket/key
    - gs://bucket/blob
    - azure://container/blob (requires AZURE_STORAGE_CONNECTION_STRING)

    Args:
        uri: Cloud storage URI
        label_set: The LabelSet to write
        context: Optional Context for handler isolation
        **kwargs: Additional arguments for the cloud client

    Returns:
        True if successful, False otherwise

    Raises:
        CloudURIValidationError: If URI is malformed or contains path traversal
    """
    # Validate URI before processing
    parsed = parse_cloud_uri(uri)

    pointer = VirtualLabelPointer(
        label_id=label_set.label_id,
        content_hash=label_set.content_hash,
    )
    value = pointer.to_string()

    # Use context-aware handler if provided
    handler = _get_cloud_handler_for_provider(parsed.provider, context)
    if handler is None:
        logger.error(f"Unknown cloud provider: {parsed.provider}")
        return False

    if parsed.provider == 's3':
        return handler.write(
            parsed.bucket, parsed.key, value, kwargs.get('s3_client')
        )
    elif parsed.provider == 'gcs':
        return handler.write(
            parsed.bucket, parsed.key, value, kwargs.get('gcs_client')
        )
    elif parsed.provider == 'azure':
        return handler.write(
            parsed.bucket, parsed.key, value, kwargs.get('connection_string')
        )
    else:
        logger.error(f"Unknown cloud provider: {parsed.provider}")
        return False


def read_cloud_label(uri: str, context=None, **kwargs) -> Optional[VirtualLabelPointer]:
    """
    Read a virtual label from a cloud storage object.

    Args:
        uri: Cloud storage URI
        context: Optional Context for handler isolation
        **kwargs: Additional arguments for the cloud client

    Returns:
        VirtualLabelPointer if found, None otherwise

    Raises:
        CloudURIValidationError: If URI is malformed or contains path traversal
    """
    # Validate URI before processing
    parsed = parse_cloud_uri(uri)

    # Use context-aware handler if provided
    handler = _get_cloud_handler_for_provider(parsed.provider, context)
    if handler is None:
        return None

    value = None

    if parsed.provider == 's3':
        value = handler.read(
            parsed.bucket, parsed.key, kwargs.get('s3_client')
        )
    elif parsed.provider == 'gcs':
        value = handler.read(
            parsed.bucket, parsed.key, kwargs.get('gcs_client')
        )
    elif parsed.provider == 'azure':
        value = handler.read(
            parsed.bucket, parsed.key, kwargs.get('connection_string')
        )

    if value:
        # Validate format before parsing
        if not _validate_label_pointer(value):
            logger.warning(
                f"Invalid cloud label format for {uri}: "
                f"{value[:50] if len(value) > 50 else value!r}"
            )
            return None

        try:
            return VirtualLabelPointer.from_string(value)
        except ValueError as e:
            logger.warning(f"Invalid cloud label format: {e}")

    return None
