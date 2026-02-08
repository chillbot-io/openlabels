"""Global exception handlers for the FastAPI application."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError as PydanticValidationError
from slowapi.errors import RateLimitExceeded

from openlabels.exceptions import (
    APIError,
    ConflictError,
    NotFoundError,
    OpenLabelsError,
    RateLimitError,
    ValidationError,
)
from openlabels.server.config import get_settings
from openlabels.server.logging import get_request_id

logger = logging.getLogger(__name__)

# Domain exceptions mapped to HTTP status codes.
_DOMAIN_ERROR_STATUS: dict[type[OpenLabelsError], tuple[int, str]] = {
    NotFoundError: (404, "NOT_FOUND"),
    ConflictError: (409, "CONFLICT"),
    ValidationError: (400, "VALIDATION_ERROR"),
}

# HTTP status code → error code label.
_HTTP_ERROR_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "REQUEST_TOO_LARGE",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMIT_EXCEEDED",
    500: "INTERNAL_ERROR",
    502: "BAD_GATEWAY",
    503: "SERVICE_UNAVAILABLE",
    504: "GATEWAY_TIMEOUT",
}


def register_error_handlers(app: FastAPI) -> None:
    """Register all exception handlers on *app*."""

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_exceeded_handler(
        request: Request, exc: RateLimitExceeded,
    ) -> JSONResponse:
        request_id = get_request_id()
        body: dict[str, Any] = {
            "error": "RATE_LIMIT_EXCEEDED",
            "message": "Rate limit exceeded. Please try again later.",
            "details": {"limit": str(exc.detail) if hasattr(exc, "detail") else None},
        }
        if request_id:
            body["request_id"] = request_id

        response = JSONResponse(status_code=429, content=body)
        if hasattr(exc, "headers") and exc.headers:
            for key, value in exc.headers.items():
                response.headers[key] = value
        return response

    @app.exception_handler(APIError)
    async def api_error_handler(
        request: Request, exc: APIError,
    ) -> JSONResponse:
        request_id = get_request_id()
        error_response = exc.to_dict(request_id=request_id)

        log = logger.warning if exc.status_code >= 500 else logger.debug
        log(
            f"API error: {exc.error_code} - {exc.message}",
            extra={
                "path": request.url.path,
                "method": request.method,
                "status_code": exc.status_code,
                "error_code": exc.error_code,
            },
        )

        response = JSONResponse(status_code=exc.status_code, content=error_response)
        if isinstance(exc, RateLimitError) and exc.retry_after:
            response.headers["Retry-After"] = str(exc.retry_after)
        return response

    @app.exception_handler(OpenLabelsError)
    async def domain_error_handler(
        request: Request, exc: OpenLabelsError,
    ) -> JSONResponse:
        request_id = get_request_id()
        status_code, error_code = _DOMAIN_ERROR_STATUS.get(
            type(exc), (500, "INTERNAL_ERROR"),
        )

        body: dict[str, Any] = {"error": error_code, "message": exc.message}
        if exc.details:
            body["details"] = exc.details
        if request_id:
            body["request_id"] = request_id

        log = logger.warning if status_code >= 500 else logger.debug
        log(f"Domain error: {error_code} - {exc.message}")
        return JSONResponse(status_code=status_code, content=body)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException,
    ) -> JSONResponse:
        request_id = get_request_id()
        error_code = _HTTP_ERROR_CODES.get(exc.status_code, "ERROR")

        body: dict[str, Any] = {
            "error": error_code,
            "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
        }
        if request_id:
            body["request_id"] = request_id

        if exc.status_code >= 500:
            logger.warning(
                f"HTTP exception: {exc.status_code} - {exc.detail}",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "status_code": exc.status_code,
                },
            )
        return JSONResponse(status_code=exc.status_code, content=body)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error_handler(
        request: Request, exc: RequestValidationError,
    ) -> JSONResponse:
        request_id = get_request_id()

        validation_errors: list[dict[str, Any]] = []
        for error in exc.errors():
            detail: dict[str, Any] = {
                "field": ".".join(str(loc) for loc in error.get("loc", [])),
                "message": error.get("msg", "Validation error"),
                "type": error.get("type", "value_error"),
            }
            if "input" in error and error["input"] is not None:
                input_val = error["input"]
                if isinstance(input_val, (str, int, float, bool)):
                    if isinstance(input_val, str) and len(input_val) > 100:
                        input_val = input_val[:100] + "..."
                    detail["input"] = input_val
            validation_errors.append(detail)

        body: dict[str, Any] = {
            "error": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "details": {"validation_errors": validation_errors},
        }
        if request_id:
            body["request_id"] = request_id

        logger.debug(
            f"Validation error: {len(validation_errors)} field(s) failed validation",
            extra={
                "path": request.url.path,
                "method": request.method,
                "error_count": len(validation_errors),
            },
        )
        return JSONResponse(status_code=422, content=body)

    @app.exception_handler(PydanticValidationError)
    async def pydantic_validation_error_handler(
        request: Request, exc: PydanticValidationError,
    ) -> JSONResponse:
        request_id = get_request_id()

        validation_errors = [
            {
                "field": ".".join(str(loc) for loc in err.get("loc", [])),
                "message": err.get("msg", "Validation error"),
                "type": err.get("type", "value_error"),
            }
            for err in exc.errors()
        ]

        body: dict[str, Any] = {
            "error": "VALIDATION_ERROR",
            "message": "Data validation failed",
            "details": {"validation_errors": validation_errors},
        }
        if request_id:
            body["request_id"] = request_id
        return JSONResponse(status_code=422, content=body)

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request, exc: Exception,
    ) -> JSONResponse:
        request_id = get_request_id()
        settings = get_settings()

        logger.exception(
            f"Unhandled exception: {exc}",
            extra={
                "path": request.url.path,
                "method": request.method,
                "exception_type": type(exc).__name__,
            },
        )

        if settings.server.debug:
            body: dict[str, Any] = {
                "error": "INTERNAL_ERROR",
                "message": str(exc),
                "details": {"exception_type": type(exc).__name__},
            }
        else:
            body = {
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
            }

        if request_id:
            body["request_id"] = request_id
        return JSONResponse(status_code=500, content=body)
