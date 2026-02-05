"""
Domain-specific exceptions for OpenLabels.

This module defines a hierarchy of exceptions that provide:
- Clear categorization of error types
- Actionable error messages with context
- Exception chaining to preserve stack traces
- Type-safe error handling in calling code

Usage:
    from openlabels.core.exceptions import DetectionError, ExtractionError

    try:
        result = detector.detect(text)
    except DetectionError as e:
        logger.error(f"Detection failed: {e}")
        # Handle detection-specific recovery

Exception Hierarchy:
    OpenLabelsError (base)
    ├── DetectionError - detection pipeline failures
    ├── ExtractionError - text extraction failures
    ├── ScoringError - risk scoring failures
    ├── AdapterError - storage adapter failures
    │   ├── GraphAPIError - Microsoft Graph API errors
    │   └── FilesystemError - local filesystem errors
    ├── ConfigurationError - configuration/settings issues
    ├── ModelLoadError - ML model loading failures
    └── JobError - background job processing failures
"""

from typing import Any, Optional


class OpenLabelsError(Exception):
    """
    Base exception for all OpenLabels errors.

    Provides consistent error formatting with optional context.

    Attributes:
        message: Human-readable error description
        context: Additional context about what was being done
        details: Technical details (file paths, entity types, etc.)
    """

    def __init__(
        self,
        message: str,
        context: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        self.message = message
        self.context = context
        self.details = details or {}
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with context and details."""
        parts = [self.message]
        if self.context:
            parts.append(f"Context: {self.context}")
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            parts.append(f"Details: {detail_str}")
        return ". ".join(parts)


class DetectionError(OpenLabelsError):
    """
    Raised when the detection pipeline fails to process content.

    Examples:
        - Pattern matching engine failure
        - ML model inference error
        - Invalid input format
        - Timeout during detection

    Usage:
        try:
            spans = detector.detect(text)
        except DetectionError as e:
            logger.error(f"Detection failed for {file_path}: {e}")
    """

    def __init__(
        self,
        message: str,
        detector_name: Optional[str] = None,
        input_length: Optional[int] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if detector_name:
            details["detector"] = detector_name
        if input_length is not None:
            details["input_length"] = input_length
        super().__init__(message, details=details, **kwargs)
        self.detector_name = detector_name
        self.input_length = input_length


class ExtractionError(OpenLabelsError):
    """
    Raised when text extraction from a file fails.

    Examples:
        - Corrupted document format
        - Unsupported file type
        - Decompression bomb detected
        - OCR failure on scanned document
        - Missing extraction library

    Usage:
        try:
            text = extract_text(content, filename)
        except ExtractionError as e:
            logger.error(f"Failed to extract text from {filename}: {e}")
    """

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        file_type: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if file_path:
            details["file_path"] = file_path
        if file_type:
            details["file_type"] = file_type
        super().__init__(message, details=details, **kwargs)
        self.file_path = file_path
        self.file_type = file_type


class ScoringError(OpenLabelsError):
    """
    Raised when risk scoring calculation fails.

    Examples:
        - Invalid entity counts format
        - Unknown exposure level
        - Scoring engine misconfiguration

    Usage:
        try:
            result = score(entities, exposure)
        except ScoringError as e:
            logger.error(f"Scoring failed: {e}")
    """

    def __init__(
        self,
        message: str,
        entity_counts: Optional[dict[str, int]] = None,
        exposure_level: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if entity_counts is not None:
            details["entity_count"] = len(entity_counts)
        if exposure_level:
            details["exposure"] = exposure_level
        super().__init__(message, details=details, **kwargs)
        self.entity_counts = entity_counts
        self.exposure_level = exposure_level


class AdapterError(OpenLabelsError):
    """
    Base class for storage adapter failures.

    Raised when communication with storage backends fails.

    Examples:
        - Network connectivity issues
        - Authentication failures
        - Permission denied
        - Resource not found

    Usage:
        try:
            files = await adapter.list_files(path)
        except AdapterError as e:
            logger.error(f"Adapter failed: {e}")
    """

    def __init__(
        self,
        message: str,
        adapter_type: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if adapter_type:
            details["adapter"] = adapter_type
        if operation:
            details["operation"] = operation
        super().__init__(message, details=details, **kwargs)
        self.adapter_type = adapter_type
        self.operation = operation


class GraphAPIError(AdapterError):
    """
    Raised when Microsoft Graph API requests fail.

    Examples:
        - Authentication token expired
        - Rate limiting (429)
        - Resource not found (404)
        - Server error (5xx)

    Usage:
        try:
            data = await client.get("/me/drive/root")
        except GraphAPIError as e:
            if e.status_code == 429:
                await asyncio.sleep(e.retry_after or 60)
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        retry_after: Optional[int] = None,
        endpoint: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if status_code:
            details["status_code"] = status_code
        if retry_after:
            details["retry_after"] = retry_after
        if endpoint:
            details["endpoint"] = endpoint
        super().__init__(message, adapter_type="graph_api", details=details, **kwargs)
        self.status_code = status_code
        self.retry_after = retry_after
        self.endpoint = endpoint


class FilesystemError(AdapterError):
    """
    Raised when local filesystem operations fail.

    Examples:
        - Permission denied
        - File not found
        - Disk full
        - Path traversal blocked

    Usage:
        try:
            content = await adapter.read_file(file_info)
        except FilesystemError as e:
            logger.error(f"Cannot read {e.path}: {e}")
    """

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if path:
            details["path"] = path
        super().__init__(message, adapter_type="filesystem", details=details, **kwargs)
        self.path = path


class ConfigurationError(OpenLabelsError):
    """
    Raised when configuration or settings are invalid.

    Examples:
        - Missing required setting
        - Invalid value format
        - Conflicting options
        - Environment variable not set

    Usage:
        try:
            settings = get_settings()
        except ConfigurationError as e:
            logger.error(f"Invalid configuration: {e}")
            sys.exit(1)
    """

    def __init__(
        self,
        message: str,
        setting_name: Optional[str] = None,
        setting_value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if setting_name:
            details["setting"] = setting_name
        if setting_value is not None:
            details["value"] = repr(setting_value)
        super().__init__(message, details=details, **kwargs)
        self.setting_name = setting_name
        self.setting_value = setting_value


class ModelLoadError(OpenLabelsError):
    """
    Raised when ML model loading fails.

    Examples:
        - Model file not found
        - Corrupted model weights
        - Incompatible model version
        - Insufficient memory
        - Missing CUDA/GPU drivers

    Usage:
        try:
            detector = PHIBertDetector(model_path)
        except ModelLoadError as e:
            logger.warning(f"ML detector disabled: {e}")
    """

    def __init__(
        self,
        message: str,
        model_name: Optional[str] = None,
        model_path: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if model_name:
            details["model"] = model_name
        if model_path:
            details["path"] = model_path
        super().__init__(message, details=details, **kwargs)
        self.model_name = model_name
        self.model_path = model_path


class JobError(OpenLabelsError):
    """
    Raised when background job processing fails.

    Examples:
        - Job not found
        - Job already completed
        - Worker timeout
        - Database connection lost

    Usage:
        try:
            result = await queue.dequeue(worker_id)
        except JobError as e:
            logger.error(f"Job processing failed: {e}")
    """

    def __init__(
        self,
        message: str,
        job_id: Optional[str] = None,
        job_type: Optional[str] = None,
        worker_id: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if job_id:
            details["job_id"] = job_id
        if job_type:
            details["job_type"] = job_type
        if worker_id:
            details["worker_id"] = worker_id
        super().__init__(message, details=details, **kwargs)
        self.job_id = job_id
        self.job_type = job_type
        self.worker_id = worker_id


class ValidationError(OpenLabelsError):
    """
    Raised when input validation fails.

    Examples:
        - Invalid file path format
        - Malformed entity data
        - Out-of-range values
        - Required field missing

    Usage:
        try:
            validate_scan_request(request)
        except ValidationError as e:
            return {"error": str(e)}, 400
    """

    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        field_value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if field_name:
            details["field"] = field_name
        if field_value is not None:
            details["value"] = repr(field_value)
        super().__init__(message, details=details, **kwargs)
        self.field_name = field_name
        self.field_value = field_value


class SecurityError(OpenLabelsError):
    """
    Raised when security checks fail.

    Examples:
        - Path traversal attempt
        - Decompression bomb detected
        - Suspicious file content
        - Rate limit exceeded

    Usage:
        try:
            safe_path = validate_path(user_input)
        except SecurityError as e:
            logger.warning(f"Security violation: {e}")
            audit_log.record(e)
    """

    def __init__(
        self,
        message: str,
        violation_type: Optional[str] = None,
        source: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if violation_type:
            details["violation"] = violation_type
        if source:
            details["source"] = source
        super().__init__(message, details=details, **kwargs)
        self.violation_type = violation_type
        self.source = source
