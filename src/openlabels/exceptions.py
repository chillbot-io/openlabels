"""
Unified exception hierarchy for OpenLabels.

All exception classes live here. No per-module exception files.

Hierarchy:
    OpenLabelsError (base)
    ├── DetectionError
    ├── ExtractionError
    ├── AdapterError
    │   ├── AdapterUnavailableError
    │   ├── GraphAPIError
    │   └── FilesystemError
    ├── AuthError
    │   ├── TokenExpiredError
    │   ├── TokenInvalidError
    │   └── ForbiddenError
    ├── LabelingError
    ├── RemediationError
    │   ├── QuarantineError
    │   └── RemediationPermissionError
    ├── MonitoringError
    │   ├── SACLError
    │   └── AuditRuleError
    ├── ModelLoadError
    ├── JobError
    ├── SecurityError
    ├── NotFoundError
    ├── ConflictError
    ├── ValidationError
    └── APIError
        ├── BadRequestError
        ├── RateLimitError
        └── InternalError

Usage:
    from openlabels.exceptions import DetectionError, NotFoundError
"""

from __future__ import annotations

from typing import Any

# =============================================================================
# ROOT
# =============================================================================


class OpenLabelsError(Exception):
    """
    Base exception for all OpenLabels errors.

    Attributes:
        message: Human-readable error description
        context: Additional context about what was being done
        details: Technical details (file paths, entity types, etc.)
    """

    def __init__(
        self,
        message: str,
        context: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        self.message = message
        self.context = context
        self.details = details or {}
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [self.message]
        if self.context:
            parts.append(f"Context: {self.context}")
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            parts.append(f"Details: {detail_str}")
        return ". ".join(parts)


# =============================================================================
# DETECTION & EXTRACTION
# =============================================================================


class DetectionError(OpenLabelsError):
    """Raised when the detection pipeline fails to process content."""

    def __init__(
        self,
        message: str,
        detector_name: str | None = None,
        input_length: int | None = None,
        **kwargs: Any,
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
    """Raised when text extraction from a file fails."""

    def __init__(
        self,
        message: str,
        file_path: str | None = None,
        file_type: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if file_path:
            details["file_path"] = file_path
        if file_type:
            details["file_type"] = file_type
        super().__init__(message, details=details, **kwargs)
        self.file_path = file_path
        self.file_type = file_type


# =============================================================================
# ADAPTERS
# =============================================================================


class AdapterError(OpenLabelsError):
    """Raised when communication with a storage adapter fails."""

    def __init__(
        self,
        message: str,
        adapter_type: str | None = None,
        operation: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if adapter_type:
            details["adapter"] = adapter_type
        if operation:
            details["operation"] = operation
        super().__init__(message, details=details, **kwargs)
        self.adapter_type = adapter_type
        self.operation = operation


class AdapterUnavailableError(AdapterError):
    """Adapter is temporarily unavailable (circuit breaker open)."""

    pass


class GraphAPIError(AdapterError):
    """Microsoft Graph API error with response details."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        retry_after: int | None = None,
        endpoint: str | None = None,
        **kwargs: Any,
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
    """Local filesystem adapter error."""

    def __init__(
        self,
        message: str,
        path: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if path:
            details["path"] = path
        super().__init__(message, adapter_type="filesystem", details=details, **kwargs)
        self.path = path


# =============================================================================
# AUTH
# =============================================================================


class AuthError(OpenLabelsError):
    """Authentication or authorization error."""

    pass


class TokenExpiredError(AuthError):
    """JWT token has expired."""

    pass


class TokenInvalidError(AuthError):
    """JWT token is malformed or has invalid signature."""

    pass


class ForbiddenError(AuthError):
    """403 Forbidden — authenticated but insufficient permissions."""

    pass


# =============================================================================
# LABELING
# =============================================================================


class LabelingError(OpenLabelsError):
    """Error during label application."""

    pass


# =============================================================================
# REMEDIATION
# =============================================================================


class RemediationError(OpenLabelsError):
    """Base exception for remediation failures."""

    def __init__(
        self,
        message: str,
        path: Any | None = None,
        code: int | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if path is not None:
            details["path"] = str(path)
        if code is not None:
            details["code"] = code
        super().__init__(message, details=details, **kwargs)
        self.path = path
        self.code = code


class QuarantineError(RemediationError):
    """Exception raised when quarantine operation fails."""

    pass


class RemediationPermissionError(RemediationError):
    """Exception raised when permission modification fails.

    Named RemediationPermissionError to avoid shadowing the built-in PermissionError.
    """

    pass


# =============================================================================
# MONITORING
# =============================================================================


class MonitoringError(OpenLabelsError):
    """Base exception for monitoring operations."""

    def __init__(
        self,
        message: str,
        path: Any | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if path is not None:
            details["path"] = str(path)
        super().__init__(message, details=details, **kwargs)
        self.path = path


class SACLError(MonitoringError):
    """Error managing Windows SACL."""

    pass


class AuditRuleError(MonitoringError):
    """Error managing Linux audit rules."""

    pass


# =============================================================================
# ML / JOBS / SECURITY
# =============================================================================


class ModelLoadError(OpenLabelsError):
    """ML model loading failure."""

    def __init__(
        self,
        message: str,
        model_name: str | None = None,
        model_path: str | None = None,
        **kwargs: Any,
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
    """Background job processing failure."""

    def __init__(
        self,
        message: str,
        job_id: str | None = None,
        job_type: str | None = None,
        worker_id: str | None = None,
        **kwargs: Any,
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


class SecurityError(OpenLabelsError):
    """Security check failure (path traversal, injection, etc.)."""

    def __init__(
        self,
        message: str,
        violation_type: str | None = None,
        source: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if violation_type:
            details["violation"] = violation_type
        if source:
            details["source"] = source
        super().__init__(message, details=details, **kwargs)
        self.violation_type = violation_type
        self.source = source


# =============================================================================
# DOMAIN ERRORS (not API-specific, but used across server and other modules)
# =============================================================================


class NotFoundError(OpenLabelsError):
    """Requested resource not found."""

    def __init__(
        self,
        message: str = "The requested resource was not found",
        resource_type: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id
        super().__init__(message, details=details, **kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id


class ConflictError(OpenLabelsError):
    """Resource conflict (duplicate, version mismatch)."""

    def __init__(
        self,
        message: str = "The request conflicts with the current state of the resource",
        conflicting_field: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if conflicting_field:
            details["conflicting_field"] = conflicting_field
        super().__init__(message, details=details, **kwargs)


class ValidationError(OpenLabelsError):
    """Input validation error."""

    def __init__(
        self,
        message: str = "Request validation failed",
        field: str | None = None,
        reason: str | None = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if field:
            details["field"] = field
        if reason:
            details["reason"] = reason
        super().__init__(message, details=details, **kwargs)


# =============================================================================
# API-LAYER EXCEPTIONS (used by server error handlers)
# =============================================================================


class APIError(OpenLabelsError):
    """
    Base for API-specific errors with HTTP status code.

    The server error handler catches APIError and uses status_code,
    error_code, and to_dict() to build the HTTP response.
    """

    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str = "An unexpected error occurred",
        details: dict[str, Any] | None = None,
        error_code: str | None = None,
    ):
        if error_code is not None:
            self.error_code = error_code
        super().__init__(message, details=details)

    def to_dict(self, request_id: str | None = None) -> dict[str, Any]:
        """Convert to dictionary suitable for ErrorResponse."""
        result: dict[str, Any] = {
            "error": self.error_code,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        if request_id is not None:
            result["request_id"] = request_id
        return result


class BadRequestError(APIError):
    """400 Bad Request."""

    status_code = 400
    error_code = "BAD_REQUEST"

    def __init__(
        self,
        message: str = "The request could not be processed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message=message, details=details)


class RateLimitError(APIError):
    """429 Too Many Requests."""

    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self,
        message: str = "Rate limit exceeded. Please try again later.",
        details: dict[str, Any] | None = None,
        retry_after: int | None = None,
    ):
        if details is None:
            details = {}
        if retry_after is not None:
            details["retry_after_seconds"] = retry_after
        super().__init__(message=message, details=details if details else None)
        self.retry_after = retry_after


class InternalError(APIError):
    """500 Internal Server Error."""

    status_code = 500
    error_code = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str = "An internal error occurred",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message=message, details=details)
