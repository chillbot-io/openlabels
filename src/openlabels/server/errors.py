"""
Standardized error response handling for OpenLabels API.

This module provides a unified error response format across all API endpoints.

Standard Error Response Format:
{
    "error": {
        "code": "error_code",       # Machine-readable error code
        "message": "Human-readable message",
        "details": {...}            # Optional additional context
    },
    "request_id": "abc123"          # Optional request correlation ID
}

Error Codes:
- validation_error: Request validation failed
- not_found: Resource not found
- unauthorized: Authentication required
- forbidden: Access denied
- conflict: Resource conflict (e.g., duplicate)
- bad_request: Invalid request
- rate_limited: Rate limit exceeded
- internal_error: Internal server error
- service_unavailable: Service temporarily unavailable
"""

from typing import Any, Optional
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from openlabels.server.logging import get_request_id


# =============================================================================
# Error Response Models
# =============================================================================


class ErrorDetail(BaseModel):
    """Inner error detail structure."""

    code: str
    message: str
    details: Optional[dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standardized error response model."""

    error: ErrorDetail
    request_id: Optional[str] = None


# =============================================================================
# API Exception Classes
# =============================================================================


class APIError(Exception):
    """
    Base exception for API errors with standardized format.

    Use this for custom errors that need the standardized format.

    Example:
        raise APIError(
            status_code=404,
            code="resource_not_found",
            message="The requested scan was not found",
            details={"scan_id": str(scan_id)}
        )
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)


class NotFoundError(APIError):
    """Resource not found error."""

    def __init__(
        self,
        message: str = "Resource not found",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code="not_found",
            message=message,
            details=details,
        )


class ValidationError(APIError):
    """Request validation error."""

    def __init__(
        self,
        message: str = "Validation failed",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="validation_error",
            message=message,
            details=details,
        )


class UnauthorizedError(APIError):
    """Authentication required error."""

    def __init__(
        self,
        message: str = "Authentication required",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="unauthorized",
            message=message,
            details=details,
        )


class ForbiddenError(APIError):
    """Access denied error."""

    def __init__(
        self,
        message: str = "Access denied",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            code="forbidden",
            message=message,
            details=details,
        )


class ConflictError(APIError):
    """Resource conflict error."""

    def __init__(
        self,
        message: str = "Resource conflict",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code="conflict",
            message=message,
            details=details,
        )


class BadRequestError(APIError):
    """Bad request error."""

    def __init__(
        self,
        message: str = "Bad request",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="bad_request",
            message=message,
            details=details,
        )


class RateLimitError(APIError):
    """Rate limit exceeded error."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="rate_limited",
            message=message,
            details=details,
        )


class ServiceUnavailableError(APIError):
    """Service unavailable error."""

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="service_unavailable",
            message=message,
            details=details,
        )


# =============================================================================
# Helper Functions
# =============================================================================


def create_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Optional[dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> JSONResponse:
    """
    Create a standardized error JSONResponse.

    Args:
        status_code: HTTP status code
        code: Machine-readable error code
        message: Human-readable error message
        details: Optional additional error details
        request_id: Optional request correlation ID

    Returns:
        JSONResponse with standardized error format
    """
    error_body: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }

    if details:
        error_body["error"]["details"] = details

    # Include request ID if available
    if request_id is None:
        request_id = get_request_id()
    if request_id:
        error_body["request_id"] = request_id

    return JSONResponse(
        status_code=status_code,
        content=error_body,
    )


# =============================================================================
# Status Code to Error Code Mapping
# =============================================================================


HTTP_STATUS_TO_ERROR_CODE = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "request_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}


def get_error_code_for_status(status_code: int) -> str:
    """Get the standard error code for an HTTP status code."""
    return HTTP_STATUS_TO_ERROR_CODE.get(status_code, "error")


# =============================================================================
# Exception Handlers (to be registered with FastAPI app)
# =============================================================================


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle APIError exceptions."""
    return create_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
    )


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """
    Handle FastAPI HTTPException with standardized format.

    Converts the standard HTTPException (which returns {"detail": "..."})
    to our standardized format.
    """
    error_code = get_error_code_for_status(exc.status_code)

    # Handle both string and dict detail
    if isinstance(exc.detail, dict):
        message = exc.detail.get("message", str(exc.detail))
        details = exc.detail if "message" not in exc.detail else None
    else:
        message = str(exc.detail)
        details = None

    return create_error_response(
        status_code=exc.status_code,
        code=error_code,
        message=message,
        details=details,
    )


async def starlette_http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """Handle Starlette HTTPException with standardized format."""
    error_code = get_error_code_for_status(exc.status_code)
    message = str(exc.detail) if exc.detail else "An error occurred"

    return create_error_response(
        status_code=exc.status_code,
        code=error_code,
        message=message,
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """
    Handle Pydantic validation errors with standardized format.

    Converts validation errors to a structured format that's easier
    to understand and process.
    """
    # Extract field-level errors
    errors = []
    for error in exc.errors():
        field_path = ".".join(str(loc) for loc in error["loc"])
        errors.append({
            "field": field_path,
            "message": error["msg"],
            "type": error["type"],
        })

    return create_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="validation_error",
        message="Request validation failed",
        details={"errors": errors},
    )


async def general_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    Handle unexpected exceptions with standardized format.

    In debug mode, includes the exception message.
    In production, returns a generic message.
    """
    import logging
    from openlabels.server.config import get_settings

    logger = logging.getLogger(__name__)
    logger.exception(
        f"Unhandled exception: {exc}",
        extra={
            "path": request.url.path,
            "method": request.method,
        }
    )

    settings = get_settings()
    message = str(exc) if settings.server.debug else "An unexpected error occurred"

    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="internal_error",
        message=message,
    )


def register_exception_handlers(app) -> None:
    """
    Register all standardized exception handlers with a FastAPI app.

    Usage:
        from openlabels.server.errors import register_exception_handlers
        register_exception_handlers(app)
    """
    from slowapi.errors import RateLimitExceeded

    # Custom API errors
    app.add_exception_handler(APIError, api_error_handler)

    # FastAPI/Starlette HTTP exceptions
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)

    # Validation errors
    app.add_exception_handler(RequestValidationError, validation_exception_handler)

    # Rate limit errors (from slowapi)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return create_error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="rate_limited",
            message=f"Rate limit exceeded: {exc.detail}",
            details={"retry_after": getattr(exc, "retry_after", None)},
        )

    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

    # General exception handler (must be last)
    app.add_exception_handler(Exception, general_exception_handler)
