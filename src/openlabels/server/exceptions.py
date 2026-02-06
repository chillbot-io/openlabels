"""
Custom exception classes for OpenLabels API.

These exceptions provide standardized error handling across the application.
Each exception maps to a specific HTTP status code and error type.

Usage:
    from openlabels.server.exceptions import NotFoundError, ValidationError

    # Raise with just a message
    raise NotFoundError("User not found")

    # Raise with additional details
    raise NotFoundError(
        message="User not found",
        details={"user_id": "123", "searched_in": "active_users"}
    )

    # Raise validation error with field info
    raise ValidationError(
        message="Invalid email format",
        details={"field": "email", "value": "not-an-email"}
    )
"""

from typing import Optional, Any


class APIError(Exception):
    """
    Base class for all API exceptions.

    All custom API exceptions should inherit from this class.
    The exception handler in app.py will catch these and convert
    them to standardized ErrorResponse objects.

    Attributes:
        message: Human-readable error message
        error_code: Error code in SCREAMING_SNAKE_CASE
        status_code: HTTP status code
        details: Optional dictionary with additional context
    """

    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str = "An unexpected error occurred",
        details: Optional[dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        """
        Initialize the API error.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
            error_code: Override the default error code for this exception type
        """
        self.message = message
        self.details = details
        if error_code is not None:
            self.error_code = error_code
        super().__init__(message)

    def to_dict(self, request_id: Optional[str] = None) -> dict[str, Any]:
        """
        Convert exception to a dictionary suitable for ErrorResponse.

        Args:
            request_id: Optional request correlation ID

        Returns:
            Dictionary with error, message, details, and request_id
        """
        result: dict[str, Any] = {
            "error": self.error_code,
            "message": self.message,
        }
        if self.details is not None:
            result["details"] = self.details
        if request_id is not None:
            result["request_id"] = request_id
        return result


class NotFoundError(APIError):
    """
    Raised when a requested resource is not found.

    HTTP Status: 404

    Examples:
        - User not found
        - Scan target doesn't exist
        - File not in inventory
    """

    status_code = 404
    error_code = "NOT_FOUND"

    def __init__(
        self,
        message: str = "The requested resource was not found",
        details: Optional[dict[str, Any]] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ):
        """
        Initialize NotFoundError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
            resource_type: Type of resource that wasn't found (e.g., "User", "ScanJob")
            resource_id: ID of the resource that wasn't found
        """
        if details is None:
            details = {}
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id
        super().__init__(message=message, details=details if details else None)


class ValidationError(APIError):
    """
    Raised when request validation fails.

    HTTP Status: 400

    Examples:
        - Invalid email format
        - Missing required field
        - Value out of range
    """

    status_code = 400
    error_code = "VALIDATION_ERROR"

    def __init__(
        self,
        message: str = "Request validation failed",
        details: Optional[dict[str, Any]] = None,
        field: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        """
        Initialize ValidationError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
            field: Name of the field that failed validation
            reason: Specific reason for validation failure
        """
        if details is None:
            details = {}
        if field:
            details["field"] = field
        if reason:
            details["reason"] = reason
        super().__init__(message=message, details=details if details else None)


class RateLimitError(APIError):
    """
    Raised when rate limits are exceeded.

    HTTP Status: 429

    Examples:
        - Too many API requests
        - Too many login attempts
        - Scan creation rate limit exceeded
    """

    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self,
        message: str = "Rate limit exceeded. Please try again later.",
        details: Optional[dict[str, Any]] = None,
        retry_after: Optional[int] = None,
    ):
        """
        Initialize RateLimitError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
            retry_after: Seconds until the rate limit resets
        """
        if details is None:
            details = {}
        if retry_after is not None:
            details["retry_after_seconds"] = retry_after
        super().__init__(message=message, details=details if details else None)
        self.retry_after = retry_after


class ConflictError(APIError):
    """
    Raised when there's a conflict with the current state of a resource.

    HTTP Status: 409

    Examples:
        - User with email already exists
        - Resource already monitored
        - Concurrent modification conflict
    """

    status_code = 409
    error_code = "CONFLICT"

    def __init__(
        self,
        message: str = "The request conflicts with the current state of the resource",
        details: Optional[dict[str, Any]] = None,
        conflicting_field: Optional[str] = None,
    ):
        """
        Initialize ConflictError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
            conflicting_field: The field that caused the conflict
        """
        if details is None:
            details = {}
        if conflicting_field:
            details["conflicting_field"] = conflicting_field
        super().__init__(message=message, details=details if details else None)


class BadRequestError(APIError):
    """
    Raised for general bad request errors that don't fit other categories.

    HTTP Status: 400

    Examples:
        - Invalid operation on resource state
        - Unsupported action
        - Missing required configuration
    """

    status_code = 400
    error_code = "BAD_REQUEST"

    def __init__(
        self,
        message: str = "The request could not be processed",
        details: Optional[dict[str, Any]] = None,
    ):
        """
        Initialize BadRequestError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
        """
        super().__init__(message=message, details=details)


class InternalError(APIError):
    """
    Raised for internal server errors.

    HTTP Status: 500

    Note: Use sparingly - most errors should have a more specific type.

    Examples:
        - Database connection failed
        - External service unavailable
        - Unexpected state
    """

    status_code = 500
    error_code = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str = "An internal error occurred",
        details: Optional[dict[str, Any]] = None,
    ):
        """
        Initialize InternalError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional context
        """
        super().__init__(message=message, details=details)
