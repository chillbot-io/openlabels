"""Standardized error responses for the API.

Provides consistent error response format across all endpoints:
- All errors return JSON with 'detail' and 'error_code' fields
- Optionally includes 'request_id' for tracing
- Includes 'retry_after' for rate limit errors

Usage:
    from scrubiq.api.errors import (
        bad_request, not_found, rate_limited, server_error
    )

    # In a route:
    raise bad_request("Invalid input format", error_code="INVALID_FORMAT")
    raise not_found("Conversation not found", error_code="CONVERSATION_NOT_FOUND")
    raise rate_limited(retry_after=30)
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


# Standard error codes for client handling
class ErrorCode:
    """Standard error codes for API responses."""
    # 400 Bad Request
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_FORMAT = "INVALID_FORMAT"
    MISSING_FIELD = "MISSING_FIELD"
    VALIDATION_ERROR = "VALIDATION_ERROR"

    # 401 Unauthorized
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"

    # 403 Forbidden
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CSRF_ERROR = "CSRF_ERROR"

    # 404 Not Found
    NOT_FOUND = "NOT_FOUND"
    CONVERSATION_NOT_FOUND = "CONVERSATION_NOT_FOUND"
    MESSAGE_NOT_FOUND = "MESSAGE_NOT_FOUND"
    TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND"
    UPLOAD_NOT_FOUND = "UPLOAD_NOT_FOUND"
    MEMORY_NOT_FOUND = "MEMORY_NOT_FOUND"

    # 409 Conflict
    ALREADY_EXISTS = "ALREADY_EXISTS"
    CONFLICT = "CONFLICT"

    # 413 Payload Too Large
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"

    # 429 Too Many Requests
    RATE_LIMITED = "RATE_LIMITED"

    # 500 Internal Server Error
    INTERNAL_ERROR = "INTERNAL_ERROR"
    DATABASE_ERROR = "DATABASE_ERROR"
    PROCESSING_ERROR = "PROCESSING_ERROR"

    # 503 Service Unavailable
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    MODELS_LOADING = "MODELS_LOADING"
    INITIALIZING = "INITIALIZING"


class APIError(HTTPException):
    """
    Standardized API error with consistent response format.

    Response body:
    {
        "detail": "Human-readable error message",
        "error_code": "MACHINE_READABLE_CODE",
        "request_id": "abc123" (optional),
        "retry_after": 30 (optional, for rate limits)
    }
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str = None,
        headers: Optional[Dict[str, str]] = None,
        retry_after: Optional[int] = None,
    ):
        self.error_code = error_code or self._default_error_code(status_code)
        self.retry_after = retry_after

        # Build headers
        all_headers = headers or {}
        if retry_after:
            all_headers["Retry-After"] = str(retry_after)

        super().__init__(
            status_code=status_code,
            detail=detail,
            headers=all_headers if all_headers else None,
        )

    def _default_error_code(self, status_code: int) -> str:
        """Get default error code for status code."""
        defaults = {
            400: ErrorCode.INVALID_INPUT,
            401: ErrorCode.NOT_AUTHENTICATED,
            403: ErrorCode.PERMISSION_DENIED,
            404: ErrorCode.NOT_FOUND,
            409: ErrorCode.CONFLICT,
            413: ErrorCode.REQUEST_TOO_LARGE,
            429: ErrorCode.RATE_LIMITED,
            500: ErrorCode.INTERNAL_ERROR,
            503: ErrorCode.SERVICE_UNAVAILABLE,
        }
        return defaults.get(status_code, "UNKNOWN_ERROR")


# Convenience functions for common errors

def bad_request(
    detail: str,
    error_code: str = ErrorCode.INVALID_INPUT,
) -> APIError:
    """Create a 400 Bad Request error."""
    return APIError(status_code=400, detail=detail, error_code=error_code)


def unauthorized(
    detail: str = "Authentication required",
    error_code: str = ErrorCode.NOT_AUTHENTICATED,
    headers: Optional[Dict[str, str]] = None,
) -> APIError:
    """Create a 401 Unauthorized error."""
    return APIError(status_code=401, detail=detail, error_code=error_code, headers=headers)


def forbidden(
    detail: str = "Permission denied",
    error_code: str = ErrorCode.PERMISSION_DENIED,
) -> APIError:
    """Create a 403 Forbidden error."""
    return APIError(status_code=403, detail=detail, error_code=error_code)


def not_found(
    detail: str = "Resource not found",
    error_code: str = ErrorCode.NOT_FOUND,
) -> APIError:
    """Create a 404 Not Found error."""
    return APIError(status_code=404, detail=detail, error_code=error_code)


def conflict(
    detail: str,
    error_code: str = ErrorCode.CONFLICT,
) -> APIError:
    """Create a 409 Conflict error."""
    return APIError(status_code=409, detail=detail, error_code=error_code)


def payload_too_large(
    detail: str,
    error_code: str = ErrorCode.REQUEST_TOO_LARGE,
) -> APIError:
    """Create a 413 Payload Too Large error."""
    return APIError(status_code=413, detail=detail, error_code=error_code)


def rate_limited(
    retry_after: int,
    detail: str = None,
    error_code: str = ErrorCode.RATE_LIMITED,
) -> APIError:
    """Create a 429 Too Many Requests error."""
    if detail is None:
        detail = f"Too many requests. Try again in {retry_after} seconds."
    return APIError(
        status_code=429,
        detail=detail,
        error_code=error_code,
        retry_after=retry_after,
    )


def server_error(
    detail: str = "An internal error occurred",
    error_code: str = ErrorCode.INTERNAL_ERROR,
) -> APIError:
    """Create a 500 Internal Server Error."""
    return APIError(status_code=500, detail=detail, error_code=error_code)


def service_unavailable(
    detail: str = "Service temporarily unavailable",
    error_code: str = ErrorCode.SERVICE_UNAVAILABLE,
    retry_after: Optional[int] = None,
) -> APIError:
    """Create a 503 Service Unavailable error."""
    return APIError(
        status_code=503,
        detail=detail,
        error_code=error_code,
        retry_after=retry_after,
    )


def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """
    Custom exception handler for APIError.

    Adds request_id and error_code to response body.
    """
    request_id = getattr(request.state, "request_id", None)

    body: Dict[str, Any] = {
        "detail": exc.detail,
        "error_code": exc.error_code,
    }

    if request_id:
        body["request_id"] = request_id

    if exc.retry_after:
        body["retry_after"] = exc.retry_after

    return JSONResponse(
        status_code=exc.status_code,
        content=body,
        headers=exc.headers,
    )


def register_error_handlers(app):
    """Register custom error handlers on FastAPI app."""
    app.add_exception_handler(APIError, api_error_handler)
