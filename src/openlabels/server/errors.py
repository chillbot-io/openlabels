"""
Standardized error handling for OpenLabels API.

This module provides:
- Standard error response model (ErrorResponse)
- Error code constants
- Helper functions to create standardized error responses
- Custom exception classes that map to error codes
"""

from enum import Enum
from typing import Any, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from openlabels.server.logging import get_request_id


# =============================================================================
# ERROR CODES
# =============================================================================


class ErrorCode(str, Enum):
    """Standardized error codes for the API."""

    # General errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"

    # Resource-specific errors
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    RESULT_NOT_FOUND = "RESULT_NOT_FOUND"
    LABEL_NOT_FOUND = "LABEL_NOT_FOUND"
    RULE_NOT_FOUND = "RULE_NOT_FOUND"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    USER_NOT_FOUND = "USER_NOT_FOUND"

    # Operation errors
    SCAN_CANNOT_CANCEL = "SCAN_CANNOT_CANCEL"
    SCAN_CANNOT_RETRY = "SCAN_CANNOT_RETRY"
    NO_RECOMMENDED_LABEL = "NO_RECOMMENDED_LABEL"
    TARGET_NOT_AVAILABLE = "TARGET_NOT_AVAILABLE"
    INVALID_RULE_TYPE = "INVALID_RULE_TYPE"

    # Integration errors
    DATABASE_ERROR = "DATABASE_ERROR"
    AZURE_AD_NOT_CONFIGURED = "AZURE_AD_NOT_CONFIGURED"
    HTTPX_NOT_AVAILABLE = "HTTPX_NOT_AVAILABLE"
    LABEL_SYNC_FAILED = "LABEL_SYNC_FAILED"
    CACHE_INVALIDATION_FAILED = "CACHE_INVALIDATION_FAILED"


# =============================================================================
# RESPONSE MODELS
# =============================================================================


class ErrorDetail(BaseModel):
    """Inner error detail structure."""

    code: str
    message: str
    request_id: Optional[str] = None
    details: Optional[dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """
    Standard error response format.

    Example:
        {
            "error": {
                "code": "SCAN_NOT_FOUND",
                "message": "The specified scan does not exist",
                "request_id": "abc123",
                "details": {"scan_id": "..."}
            }
        }
    """

    error: ErrorDetail


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================


class APIError(HTTPException):
    """
    Base exception for API errors with standardized error codes.

    Usage:
        raise APIError(
            status_code=404,
            code=ErrorCode.SCAN_NOT_FOUND,
            message="The specified scan does not exist"
        )
    """

    def __init__(
        self,
        status_code: int,
        code: ErrorCode | str,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        self.error_code = code if isinstance(code, str) else code.value
        self.error_message = message
        self.error_details = details
        # Store as detail dict for compatibility with FastAPI's exception handling
        super().__init__(status_code=status_code, detail={
            "code": self.error_code,
            "message": message,
            "details": details,
        })


class NotFoundError(APIError):
    """Resource not found error (404)."""

    def __init__(
        self,
        code: ErrorCode | str = ErrorCode.NOT_FOUND,
        message: str = "Resource not found",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=404, code=code, message=message, details=details)


class BadRequestError(APIError):
    """Bad request error (400)."""

    def __init__(
        self,
        code: ErrorCode | str = ErrorCode.BAD_REQUEST,
        message: str = "Invalid request",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=400, code=code, message=message, details=details)


class UnauthorizedError(APIError):
    """Unauthorized error (401)."""

    def __init__(
        self,
        code: ErrorCode | str = ErrorCode.UNAUTHORIZED,
        message: str = "Authentication required",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=401, code=code, message=message, details=details)


class ForbiddenError(APIError):
    """Forbidden error (403)."""

    def __init__(
        self,
        code: ErrorCode | str = ErrorCode.FORBIDDEN,
        message: str = "Access denied",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=403, code=code, message=message, details=details)


class ServiceUnavailableError(APIError):
    """Service unavailable error (503)."""

    def __init__(
        self,
        code: ErrorCode | str = ErrorCode.SERVICE_UNAVAILABLE,
        message: str = "Service temporarily unavailable",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=503, code=code, message=message, details=details)


class InternalServerError(APIError):
    """Internal server error (500)."""

    def __init__(
        self,
        code: ErrorCode | str = ErrorCode.INTERNAL_ERROR,
        message: str = "An unexpected error occurred",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=500, code=code, message=message, details=details)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def create_error_response(
    status_code: int,
    code: ErrorCode | str,
    message: str,
    details: Optional[dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> JSONResponse:
    """
    Create a standardized error JSONResponse.

    Args:
        status_code: HTTP status code
        code: Error code from ErrorCode enum or string
        message: Human-readable error message
        details: Optional additional details dict
        request_id: Optional request ID (auto-retrieved if not provided)

    Returns:
        JSONResponse with standardized error format
    """
    if request_id is None:
        request_id = get_request_id()

    error_code = code if isinstance(code, str) else code.value

    error_detail = {
        "code": error_code,
        "message": message,
    }

    if request_id:
        error_detail["request_id"] = request_id

    if details:
        error_detail["details"] = details

    return JSONResponse(
        status_code=status_code,
        content={"error": error_detail},
    )


def format_api_error(exc: APIError, request_id: Optional[str] = None) -> JSONResponse:
    """
    Format an APIError exception into a standardized JSONResponse.

    Args:
        exc: The APIError exception
        request_id: Optional request ID (auto-retrieved if not provided)

    Returns:
        JSONResponse with standardized error format
    """
    return create_error_response(
        status_code=exc.status_code,
        code=exc.error_code,
        message=exc.error_message,
        details=exc.error_details,
        request_id=request_id,
    )


def format_http_exception(
    exc: HTTPException,
    request_id: Optional[str] = None,
) -> JSONResponse:
    """
    Format a standard HTTPException into standardized error format.

    Maps common HTTP status codes to appropriate error codes.

    Args:
        exc: The HTTPException
        request_id: Optional request ID (auto-retrieved if not provided)

    Returns:
        JSONResponse with standardized error format
    """
    # Map status codes to default error codes
    status_code_map = {
        400: ErrorCode.BAD_REQUEST,
        401: ErrorCode.UNAUTHORIZED,
        403: ErrorCode.FORBIDDEN,
        404: ErrorCode.NOT_FOUND,
        429: ErrorCode.RATE_LIMITED,
        500: ErrorCode.INTERNAL_ERROR,
        503: ErrorCode.SERVICE_UNAVAILABLE,
    }

    code = status_code_map.get(exc.status_code, ErrorCode.INTERNAL_ERROR)

    # Extract message from detail
    if isinstance(exc.detail, dict):
        # If detail is already structured (from APIError), use it
        message = exc.detail.get("message", str(exc.detail))
        code_from_detail = exc.detail.get("code")
        if code_from_detail:
            code = code_from_detail
        details = exc.detail.get("details")
    else:
        message = str(exc.detail) if exc.detail else "An error occurred"
        details = None

    return create_error_response(
        status_code=exc.status_code,
        code=code,
        message=message,
        details=details,
        request_id=request_id,
    )


def format_validation_error(
    errors: list[dict[str, Any]],
    request_id: Optional[str] = None,
) -> JSONResponse:
    """
    Format Pydantic validation errors into standardized error format.

    Args:
        errors: List of validation error dicts from Pydantic
        request_id: Optional request ID (auto-retrieved if not provided)

    Returns:
        JSONResponse with standardized error format
    """
    # Format validation errors as details
    formatted_errors = []
    for error in errors:
        loc = ".".join(str(x) for x in error.get("loc", []))
        formatted_errors.append({
            "field": loc,
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "validation_error"),
        })

    return create_error_response(
        status_code=422,
        code=ErrorCode.VALIDATION_ERROR,
        message="Request validation failed",
        details={"errors": formatted_errors},
        request_id=request_id,
    )
