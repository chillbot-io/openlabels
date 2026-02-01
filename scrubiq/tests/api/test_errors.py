"""Tests for API error handling.

Tests for standardized error responses and error factory functions.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.responses import JSONResponse

# Direct import of the errors module bypassing scrubiq.api.__init__.py
# This avoids the SQLCipher import chain
_errors_path = Path(__file__).parent.parent.parent / "scrubiq" / "api" / "errors.py"
_spec = importlib.util.spec_from_file_location("scrubiq_api_errors", _errors_path)
_errors_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_errors_module)

ErrorCode = _errors_module.ErrorCode
APIError = _errors_module.APIError
bad_request = _errors_module.bad_request
unauthorized = _errors_module.unauthorized
forbidden = _errors_module.forbidden
not_found = _errors_module.not_found
conflict = _errors_module.conflict
payload_too_large = _errors_module.payload_too_large
rate_limited = _errors_module.rate_limited
server_error = _errors_module.server_error
service_unavailable = _errors_module.service_unavailable
api_error_handler = _errors_module.api_error_handler
register_error_handlers = _errors_module.register_error_handlers


# =============================================================================
# ERRORCODE CONSTANTS TESTS
# =============================================================================

class TestErrorCode:
    """Tests for ErrorCode constants."""

    def test_400_error_codes(self):
        """400-level error codes exist."""
        assert ErrorCode.INVALID_INPUT == "INVALID_INPUT"
        assert ErrorCode.INVALID_FORMAT == "INVALID_FORMAT"
        assert ErrorCode.MISSING_FIELD == "MISSING_FIELD"
        assert ErrorCode.VALIDATION_ERROR == "VALIDATION_ERROR"

    def test_401_error_codes(self):
        """401-level error codes exist."""
        assert ErrorCode.NOT_AUTHENTICATED == "NOT_AUTHENTICATED"
        assert ErrorCode.SESSION_EXPIRED == "SESSION_EXPIRED"
        assert ErrorCode.INVALID_CREDENTIALS == "INVALID_CREDENTIALS"

    def test_403_error_codes(self):
        """403-level error codes exist."""
        assert ErrorCode.PERMISSION_DENIED == "PERMISSION_DENIED"
        assert ErrorCode.CSRF_ERROR == "CSRF_ERROR"

    def test_404_error_codes(self):
        """404-level error codes exist."""
        assert ErrorCode.NOT_FOUND == "NOT_FOUND"
        assert ErrorCode.CONVERSATION_NOT_FOUND == "CONVERSATION_NOT_FOUND"
        assert ErrorCode.MESSAGE_NOT_FOUND == "MESSAGE_NOT_FOUND"
        assert ErrorCode.TOKEN_NOT_FOUND == "TOKEN_NOT_FOUND"
        assert ErrorCode.UPLOAD_NOT_FOUND == "UPLOAD_NOT_FOUND"
        assert ErrorCode.MEMORY_NOT_FOUND == "MEMORY_NOT_FOUND"

    def test_409_error_codes(self):
        """409-level error codes exist."""
        assert ErrorCode.ALREADY_EXISTS == "ALREADY_EXISTS"
        assert ErrorCode.CONFLICT == "CONFLICT"

    def test_413_error_codes(self):
        """413-level error codes exist."""
        assert ErrorCode.FILE_TOO_LARGE == "FILE_TOO_LARGE"
        assert ErrorCode.REQUEST_TOO_LARGE == "REQUEST_TOO_LARGE"

    def test_429_error_codes(self):
        """429-level error codes exist."""
        assert ErrorCode.RATE_LIMITED == "RATE_LIMITED"

    def test_500_error_codes(self):
        """500-level error codes exist."""
        assert ErrorCode.INTERNAL_ERROR == "INTERNAL_ERROR"
        assert ErrorCode.DATABASE_ERROR == "DATABASE_ERROR"
        assert ErrorCode.PROCESSING_ERROR == "PROCESSING_ERROR"

    def test_503_error_codes(self):
        """503-level error codes exist."""
        assert ErrorCode.SERVICE_UNAVAILABLE == "SERVICE_UNAVAILABLE"
        assert ErrorCode.MODELS_LOADING == "MODELS_LOADING"
        assert ErrorCode.INITIALIZING == "INITIALIZING"


# =============================================================================
# APIERROR TESTS
# =============================================================================

class TestAPIError:
    """Tests for APIError class."""

    def test_create_basic_error(self):
        """APIError stores basic properties."""
        error = APIError(status_code=400, detail="Bad request")

        assert error.status_code == 400
        assert error.detail == "Bad request"

    def test_create_with_error_code(self):
        """APIError stores custom error code."""
        error = APIError(
            status_code=400,
            detail="Invalid",
            error_code="CUSTOM_CODE",
        )

        assert error.error_code == "CUSTOM_CODE"

    def test_default_error_code_for_400(self):
        """APIError uses default code for 400."""
        error = APIError(status_code=400, detail="Bad")

        assert error.error_code == ErrorCode.INVALID_INPUT

    def test_default_error_code_for_401(self):
        """APIError uses default code for 401."""
        error = APIError(status_code=401, detail="Unauthorized")

        assert error.error_code == ErrorCode.NOT_AUTHENTICATED

    def test_default_error_code_for_403(self):
        """APIError uses default code for 403."""
        error = APIError(status_code=403, detail="Forbidden")

        assert error.error_code == ErrorCode.PERMISSION_DENIED

    def test_default_error_code_for_404(self):
        """APIError uses default code for 404."""
        error = APIError(status_code=404, detail="Not found")

        assert error.error_code == ErrorCode.NOT_FOUND

    def test_default_error_code_for_429(self):
        """APIError uses default code for 429."""
        error = APIError(status_code=429, detail="Rate limited")

        assert error.error_code == ErrorCode.RATE_LIMITED

    def test_default_error_code_for_500(self):
        """APIError uses default code for 500."""
        error = APIError(status_code=500, detail="Error")

        assert error.error_code == ErrorCode.INTERNAL_ERROR

    def test_default_error_code_for_503(self):
        """APIError uses default code for 503."""
        error = APIError(status_code=503, detail="Unavailable")

        assert error.error_code == ErrorCode.SERVICE_UNAVAILABLE

    def test_default_error_code_for_unknown(self):
        """APIError uses UNKNOWN_ERROR for unknown status."""
        error = APIError(status_code=418, detail="Teapot")

        assert error.error_code == "UNKNOWN_ERROR"

    def test_retry_after_header(self):
        """APIError adds Retry-After header when specified."""
        error = APIError(
            status_code=429,
            detail="Rate limited",
            retry_after=30,
        )

        assert error.headers["Retry-After"] == "30"

    def test_retry_after_stored(self):
        """APIError stores retry_after value."""
        error = APIError(
            status_code=429,
            detail="Rate limited",
            retry_after=60,
        )

        assert error.retry_after == 60

    def test_custom_headers(self):
        """APIError supports custom headers."""
        error = APIError(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )

        assert error.headers["WWW-Authenticate"] == "Bearer"

    def test_combined_headers(self):
        """APIError combines custom headers with retry_after."""
        error = APIError(
            status_code=429,
            detail="Rate limited",
            headers={"X-Custom": "value"},
            retry_after=30,
        )

        assert error.headers["X-Custom"] == "value"
        assert error.headers["Retry-After"] == "30"


# =============================================================================
# ERROR FACTORY FUNCTION TESTS
# =============================================================================

class TestBadRequest:
    """Tests for bad_request factory."""

    def test_creates_400_error(self):
        """bad_request creates 400 error."""
        error = bad_request("Invalid input")

        assert error.status_code == 400
        assert error.detail == "Invalid input"

    def test_default_error_code(self):
        """bad_request uses INVALID_INPUT by default."""
        error = bad_request("Invalid")

        assert error.error_code == ErrorCode.INVALID_INPUT

    def test_custom_error_code(self):
        """bad_request accepts custom error code."""
        error = bad_request("Bad format", error_code=ErrorCode.INVALID_FORMAT)

        assert error.error_code == ErrorCode.INVALID_FORMAT


class TestUnauthorized:
    """Tests for unauthorized factory."""

    def test_creates_401_error(self):
        """unauthorized creates 401 error."""
        error = unauthorized("Token expired")

        assert error.status_code == 401
        assert error.detail == "Token expired"

    def test_default_message(self):
        """unauthorized has default message."""
        error = unauthorized()

        assert error.detail == "Authentication required"

    def test_supports_headers(self):
        """unauthorized supports custom headers."""
        error = unauthorized(headers={"WWW-Authenticate": "Bearer"})

        assert error.headers["WWW-Authenticate"] == "Bearer"


class TestForbidden:
    """Tests for forbidden factory."""

    def test_creates_403_error(self):
        """forbidden creates 403 error."""
        error = forbidden("Access denied")

        assert error.status_code == 403
        assert error.detail == "Access denied"

    def test_default_message(self):
        """forbidden has default message."""
        error = forbidden()

        assert error.detail == "Permission denied"


class TestNotFound:
    """Tests for not_found factory."""

    def test_creates_404_error(self):
        """not_found creates 404 error."""
        error = not_found("User not found")

        assert error.status_code == 404
        assert error.detail == "User not found"

    def test_default_message(self):
        """not_found has default message."""
        error = not_found()

        assert error.detail == "Resource not found"


class TestConflict:
    """Tests for conflict factory."""

    def test_creates_409_error(self):
        """conflict creates 409 error."""
        error = conflict("Already exists")

        assert error.status_code == 409
        assert error.detail == "Already exists"


class TestPayloadTooLarge:
    """Tests for payload_too_large factory."""

    def test_creates_413_error(self):
        """payload_too_large creates 413 error."""
        error = payload_too_large("File exceeds 10MB limit")

        assert error.status_code == 413
        assert error.detail == "File exceeds 10MB limit"


class TestRateLimited:
    """Tests for rate_limited factory."""

    def test_creates_429_error(self):
        """rate_limited creates 429 error."""
        error = rate_limited(retry_after=30)

        assert error.status_code == 429

    def test_default_message(self):
        """rate_limited generates message with retry_after."""
        error = rate_limited(retry_after=30)

        assert "30 seconds" in error.detail

    def test_custom_message(self):
        """rate_limited accepts custom message."""
        error = rate_limited(retry_after=30, detail="Too fast!")

        assert error.detail == "Too fast!"

    def test_sets_retry_after(self):
        """rate_limited sets retry_after."""
        error = rate_limited(retry_after=60)

        assert error.retry_after == 60


class TestServerError:
    """Tests for server_error factory."""

    def test_creates_500_error(self):
        """server_error creates 500 error."""
        error = server_error("Database connection failed")

        assert error.status_code == 500
        assert error.detail == "Database connection failed"

    def test_default_message(self):
        """server_error has default message."""
        error = server_error()

        assert error.detail == "An internal error occurred"


class TestServiceUnavailable:
    """Tests for service_unavailable factory."""

    def test_creates_503_error(self):
        """service_unavailable creates 503 error."""
        error = service_unavailable("System maintenance")

        assert error.status_code == 503
        assert error.detail == "System maintenance"

    def test_default_message(self):
        """service_unavailable has default message."""
        error = service_unavailable()

        assert error.detail == "Service temporarily unavailable"

    def test_supports_retry_after(self):
        """service_unavailable supports retry_after."""
        error = service_unavailable(retry_after=300)

        assert error.retry_after == 300


# =============================================================================
# ERROR HANDLER TESTS
# =============================================================================

class TestApiErrorHandler:
    """Tests for api_error_handler function."""

    def test_returns_json_response(self):
        """api_error_handler returns JSONResponse."""
        request = MagicMock()
        request.state = MagicMock(spec=[])
        error = APIError(status_code=400, detail="Bad request")

        response = api_error_handler(request, error)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 400

    def test_includes_detail_and_error_code(self):
        """Response includes detail and error_code."""
        request = MagicMock()
        request.state = MagicMock(spec=[])
        error = APIError(
            status_code=404,
            detail="Not found",
            error_code="CUSTOM_NOT_FOUND",
        )

        response = api_error_handler(request, error)

        # Get response body
        body = response.body
        assert b"Not found" in body
        assert b"CUSTOM_NOT_FOUND" in body

    def test_includes_request_id_when_available(self):
        """Response includes request_id when set."""
        request = MagicMock()
        request.state.request_id = "abc-123"
        error = APIError(status_code=500, detail="Error")

        response = api_error_handler(request, error)

        body = response.body
        assert b"abc-123" in body

    def test_no_request_id_when_not_set(self):
        """Response omits request_id when not set."""
        request = MagicMock()
        request.state = MagicMock(spec=[])  # No request_id attribute
        error = APIError(status_code=500, detail="Error")

        response = api_error_handler(request, error)

        body = response.body
        assert b"request_id" not in body

    def test_includes_retry_after_when_set(self):
        """Response includes retry_after when set."""
        request = MagicMock()
        request.state = MagicMock(spec=[])
        error = rate_limited(retry_after=45)

        response = api_error_handler(request, error)

        body = response.body
        assert b"45" in body


# =============================================================================
# REGISTER ERROR HANDLERS TESTS
# =============================================================================

class TestRegisterErrorHandlers:
    """Tests for register_error_handlers function."""

    def test_registers_handler(self):
        """register_error_handlers adds exception handler to app."""
        mock_app = MagicMock()

        register_error_handlers(mock_app)

        mock_app.add_exception_handler.assert_called_once()
        args = mock_app.add_exception_handler.call_args[0]
        assert args[0] == APIError
        assert args[1] == api_error_handler
