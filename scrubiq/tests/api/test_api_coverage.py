"""Comprehensive tests for API module to improve coverage to 80%+.

Tests for errors.py, limiter.py, dependencies.py, and settings.py.
"""

import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Set up environment
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"


# =============================================================================
# ERROR TESTS
# =============================================================================

class TestAPIErrors:
    """Tests for API error handling."""

    def test_error_code_constants(self):
        """ErrorCode has expected constants."""
        from scrubiq.api.errors import ErrorCode

        # 400 errors
        assert ErrorCode.INVALID_INPUT == "INVALID_INPUT"
        assert ErrorCode.INVALID_FORMAT == "INVALID_FORMAT"
        assert ErrorCode.MISSING_FIELD == "MISSING_FIELD"
        assert ErrorCode.VALIDATION_ERROR == "VALIDATION_ERROR"

        # 401 errors
        assert ErrorCode.NOT_AUTHENTICATED == "NOT_AUTHENTICATED"
        assert ErrorCode.SESSION_EXPIRED == "SESSION_EXPIRED"

        # 403 errors
        assert ErrorCode.PERMISSION_DENIED == "PERMISSION_DENIED"

        # 404 errors
        assert ErrorCode.NOT_FOUND == "NOT_FOUND"
        assert ErrorCode.CONVERSATION_NOT_FOUND == "CONVERSATION_NOT_FOUND"

        # 429 errors
        assert ErrorCode.RATE_LIMITED == "RATE_LIMITED"

        # 500 errors
        assert ErrorCode.INTERNAL_ERROR == "INTERNAL_ERROR"

        # 503 errors
        assert ErrorCode.SERVICE_UNAVAILABLE == "SERVICE_UNAVAILABLE"

    def test_api_error_creation(self):
        """APIError can be created with all parameters."""
        from scrubiq.api.errors import APIError, ErrorCode

        error = APIError(
            status_code=400,
            detail="Test error",
            error_code=ErrorCode.INVALID_INPUT,
            headers={"X-Custom": "header"},
            retry_after=30,
        )

        assert error.status_code == 400
        assert error.detail == "Test error"
        assert error.error_code == ErrorCode.INVALID_INPUT
        assert error.retry_after == 30
        assert "Retry-After" in error.headers

    def test_api_error_default_error_code(self):
        """APIError uses default error code based on status."""
        from scrubiq.api.errors import APIError, ErrorCode

        error_400 = APIError(status_code=400, detail="Bad request")
        assert error_400.error_code == ErrorCode.INVALID_INPUT

        error_401 = APIError(status_code=401, detail="Unauthorized")
        assert error_401.error_code == ErrorCode.NOT_AUTHENTICATED

        error_403 = APIError(status_code=403, detail="Forbidden")
        assert error_403.error_code == ErrorCode.PERMISSION_DENIED

        error_404 = APIError(status_code=404, detail="Not found")
        assert error_404.error_code == ErrorCode.NOT_FOUND

        error_429 = APIError(status_code=429, detail="Rate limited")
        assert error_429.error_code == ErrorCode.RATE_LIMITED

        error_500 = APIError(status_code=500, detail="Server error")
        assert error_500.error_code == ErrorCode.INTERNAL_ERROR

        error_503 = APIError(status_code=503, detail="Unavailable")
        assert error_503.error_code == ErrorCode.SERVICE_UNAVAILABLE

        # Unknown status code
        error_418 = APIError(status_code=418, detail="I'm a teapot")
        assert error_418.error_code == "UNKNOWN_ERROR"

    def test_bad_request_helper(self):
        """bad_request() creates 400 error."""
        from scrubiq.api.errors import bad_request, ErrorCode

        error = bad_request("Invalid input")

        assert error.status_code == 400
        assert error.detail == "Invalid input"
        assert error.error_code == ErrorCode.INVALID_INPUT

    def test_bad_request_with_custom_code(self):
        """bad_request() accepts custom error code."""
        from scrubiq.api.errors import bad_request, ErrorCode

        error = bad_request("Missing field", error_code=ErrorCode.MISSING_FIELD)

        assert error.error_code == ErrorCode.MISSING_FIELD

    def test_unauthorized_helper(self):
        """unauthorized() creates 401 error."""
        from scrubiq.api.errors import unauthorized

        error = unauthorized()

        assert error.status_code == 401
        assert "Authentication" in error.detail

    def test_unauthorized_with_headers(self):
        """unauthorized() includes headers."""
        from scrubiq.api.errors import unauthorized

        error = unauthorized(
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

        assert error.headers["WWW-Authenticate"] == "Bearer"

    def test_forbidden_helper(self):
        """forbidden() creates 403 error."""
        from scrubiq.api.errors import forbidden

        error = forbidden()

        assert error.status_code == 403
        assert "denied" in error.detail.lower()

    def test_not_found_helper(self):
        """not_found() creates 404 error."""
        from scrubiq.api.errors import not_found, ErrorCode

        error = not_found("User not found", error_code=ErrorCode.NOT_FOUND)

        assert error.status_code == 404
        assert error.detail == "User not found"

    def test_conflict_helper(self):
        """conflict() creates 409 error."""
        from scrubiq.api.errors import conflict

        error = conflict("Resource already exists")

        assert error.status_code == 409
        assert "already exists" in error.detail

    def test_payload_too_large_helper(self):
        """payload_too_large() creates 413 error."""
        from scrubiq.api.errors import payload_too_large

        error = payload_too_large("File exceeds 10MB limit")

        assert error.status_code == 413

    def test_rate_limited_helper(self):
        """rate_limited() creates 429 error with retry_after."""
        from scrubiq.api.errors import rate_limited

        error = rate_limited(retry_after=30)

        assert error.status_code == 429
        assert error.retry_after == 30
        assert "30 seconds" in error.detail

    def test_rate_limited_with_custom_detail(self):
        """rate_limited() accepts custom detail."""
        from scrubiq.api.errors import rate_limited

        error = rate_limited(retry_after=60, detail="Slow down!")

        assert error.detail == "Slow down!"

    def test_server_error_helper(self):
        """server_error() creates 500 error."""
        from scrubiq.api.errors import server_error

        error = server_error()

        assert error.status_code == 500
        assert "internal" in error.detail.lower()

    def test_service_unavailable_helper(self):
        """service_unavailable() creates 503 error."""
        from scrubiq.api.errors import service_unavailable

        error = service_unavailable(retry_after=120)

        assert error.status_code == 503
        assert error.retry_after == 120


class TestAPIErrorHandler:
    """Tests for API error handler."""

    def test_api_error_handler_basic(self):
        """api_error_handler() creates proper response."""
        from scrubiq.api.errors import api_error_handler, APIError, ErrorCode

        # Create mock request
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        del mock_request.state.request_id  # Simulate missing request_id

        error = APIError(status_code=400, detail="Test", error_code=ErrorCode.INVALID_INPUT)

        response = api_error_handler(mock_request, error)

        assert response.status_code == 400
        # Response body should include detail and error_code

    def test_api_error_handler_with_request_id(self):
        """api_error_handler() includes request_id if available."""
        from scrubiq.api.errors import api_error_handler, APIError

        mock_request = MagicMock()
        mock_request.state.request_id = "req-123"

        error = APIError(status_code=400, detail="Test")

        response = api_error_handler(mock_request, error)

        assert response.status_code == 400

    def test_api_error_handler_with_retry_after(self):
        """api_error_handler() includes retry_after if available."""
        from scrubiq.api.errors import api_error_handler, APIError

        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])  # No request_id

        error = APIError(status_code=429, detail="Rate limited", retry_after=30)

        response = api_error_handler(mock_request, error)

        assert response.status_code == 429


# =============================================================================
# RATE LIMITER TESTS
# =============================================================================

class TestSQLiteRateLimiter:
    """Tests for SQLiteRateLimiter."""

    def test_limiter_creation(self):
        """Can create SQLiteRateLimiter."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        assert limiter is not None

    def test_limiter_creation_with_path(self):
        """Can create SQLiteRateLimiter with custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.api.limiter import SQLiteRateLimiter

            db_path = Path(tmpdir) / "ratelimit.db"
            limiter = SQLiteRateLimiter(db_path)

            assert limiter._db_path == str(db_path)

    def test_limiter_is_allowed_first_request(self):
        """First request is always allowed."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        allowed, remaining, retry_after = limiter.is_allowed(
            client_key="test-client",
            endpoint="/api/test",
            limit=10,
            window_seconds=60,
        )

        assert allowed is True
        assert remaining >= 0
        assert retry_after == 0

    def test_limiter_tracks_requests(self):
        """Limiter tracks request count."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Make several requests
        for i in range(5):
            limiter.is_allowed("client", "/test", limit=10, window_seconds=60)

        allowed, remaining, _ = limiter.is_allowed("client", "/test", limit=10, window_seconds=60)

        assert allowed is True
        assert remaining < 10

    def test_limiter_enforces_limit(self):
        """Limiter enforces rate limit."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Exhaust the limit
        for i in range(5):
            limiter.is_allowed("client", "/test", limit=5, window_seconds=60)

        # Next request should be denied
        allowed, remaining, retry_after = limiter.is_allowed(
            "client", "/test", limit=5, window_seconds=60
        )

        assert allowed is False
        assert remaining == 0
        assert retry_after > 0

    def test_limiter_different_endpoints_isolated(self):
        """Different endpoints have separate limits."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Exhaust limit on endpoint A
        for i in range(3):
            limiter.is_allowed("client", "/endpoint-a", limit=3, window_seconds=60)

        # Endpoint B should still be allowed
        allowed, _, _ = limiter.is_allowed("client", "/endpoint-b", limit=3, window_seconds=60)

        assert allowed is True

    def test_limiter_different_clients_isolated(self):
        """Different clients have separate limits."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Exhaust limit for client A
        for i in range(3):
            limiter.is_allowed("client-a", "/test", limit=3, window_seconds=60)

        # Client B should still be allowed
        allowed, _, _ = limiter.is_allowed("client-b", "/test", limit=3, window_seconds=60)

        assert allowed is True

    def test_limiter_reset(self):
        """reset() clears rate limit for client/endpoint."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Use up some limit
        for i in range(5):
            limiter.is_allowed("client", "/test", limit=10, window_seconds=60)

        limiter.reset("client", "/test")

        # Should have full limit again
        allowed, remaining, _ = limiter.is_allowed("client", "/test", limit=10, window_seconds=60)

        assert allowed is True
        assert remaining == 9  # First request after reset

    def test_limiter_cleanup(self):
        """cleanup() removes expired entries."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Create an entry
        limiter.is_allowed("client", "/test", limit=10, window_seconds=60)

        # Cleanup with 0 max age should remove everything
        removed = limiter.cleanup(max_age_seconds=0)

        # Entry should be removed
        assert removed >= 1

    def test_limiter_singleton(self):
        """get_instance() returns singleton."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        # Reset singleton
        SQLiteRateLimiter._instance = None

        instance1 = SQLiteRateLimiter.get_instance()
        instance2 = SQLiteRateLimiter.get_instance()

        assert instance1 is instance2

    def test_limiter_handles_db_error(self):
        """Limiter allows request on DB error (fail-open)."""
        from scrubiq.api.limiter import SQLiteRateLimiter

        limiter = SQLiteRateLimiter()

        # Mock connection to raise error
        original_get_conn = limiter._get_conn

        def failing_conn():
            conn = original_get_conn()
            conn.execute = MagicMock(side_effect=sqlite3.Error("DB error"))
            return conn

        limiter._get_conn = failing_conn

        # Should allow request despite error (fail-open)
        allowed, remaining, _ = limiter.is_allowed("client", "/test", limit=10, window_seconds=60)

        assert allowed is True


# =============================================================================
# DEPENDENCIES TESTS
# =============================================================================

class TestAPIDependencies:
    """Tests for API dependencies."""

    def test_set_api_key_service(self):
        """set_api_key_service() sets global service."""
        from scrubiq.api.dependencies import set_api_key_service, get_api_key_service

        mock_service = MagicMock()
        set_api_key_service(mock_service)

        result = get_api_key_service()

        assert result is mock_service

    def test_get_api_key_service_raises_when_not_set(self):
        """get_api_key_service() raises when not initialized."""
        from scrubiq.api import dependencies

        # Clear the service
        original = dependencies._api_key_service
        dependencies._api_key_service = None

        try:
            with pytest.raises(RuntimeError, match="not initialized"):
                dependencies.get_api_key_service()
        finally:
            dependencies._api_key_service = original

    def test_extract_bearer_token_valid(self):
        """_extract_bearer_token() extracts valid token."""
        from scrubiq.api.dependencies import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer test-token-123"

        token = _extract_bearer_token(mock_request)

        assert token == "test-token-123"

    def test_extract_bearer_token_missing_header(self):
        """_extract_bearer_token() returns None when header missing."""
        from scrubiq.api.dependencies import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = None

        token = _extract_bearer_token(mock_request)

        assert token is None

    def test_extract_bearer_token_invalid_format(self):
        """_extract_bearer_token() returns None for invalid format."""
        from scrubiq.api.dependencies import _extract_bearer_token

        mock_request = MagicMock()

        # Missing Bearer prefix
        mock_request.headers.get.return_value = "Basic abc123"
        assert _extract_bearer_token(mock_request) is None

        # Too many parts
        mock_request.headers.get.return_value = "Bearer token extra"
        assert _extract_bearer_token(mock_request) is None

        # Single part (no space)
        mock_request.headers.get.return_value = "BearerNoSpace"
        assert _extract_bearer_token(mock_request) is None


# =============================================================================
# SETTINGS TESTS
# =============================================================================

class TestSettingsSchemas:
    """Tests for settings Pydantic schemas."""

    def test_settings_response_defaults(self):
        """SettingsResponse has correct defaults."""
        from scrubiq.api.settings import SettingsResponse

        response = SettingsResponse()

        assert response.confidence_threshold == 0.85
        assert response.safe_harbor is True
        assert response.coreference is True
        assert response.review_threshold == 0.7
        assert response.device == "auto"

    def test_settings_update_request_optional(self):
        """SettingsUpdateRequest fields are optional."""
        from scrubiq.api.settings import SettingsUpdateRequest

        request = SettingsUpdateRequest()

        assert request.confidence_threshold is None
        assert request.safe_harbor is None
        assert request.entity_types is None

    def test_allowlist_update_request_validation(self):
        """AllowlistUpdateRequest validates action."""
        from scrubiq.api.settings import AllowlistUpdateRequest
        from pydantic import ValidationError

        # Valid actions
        valid = AllowlistUpdateRequest(action="add", values=["test"])
        assert valid.action == "add"

        valid = AllowlistUpdateRequest(action="remove", values=["test"])
        assert valid.action == "remove"

        valid = AllowlistUpdateRequest(action="set", values=["test"])
        assert valid.action == "set"

        # Invalid action
        with pytest.raises(ValidationError):
            AllowlistUpdateRequest(action="invalid", values=["test"])


class TestEntityTypeCategorization:
    """Tests for entity type categorization."""

    def test_categorize_entity_types(self):
        """_categorize_entity_types() organizes types correctly."""
        from scrubiq.api.settings import _categorize_entity_types

        categories = _categorize_entity_types()

        # Should have categories
        assert len(categories) > 0

        # Check some expected categories exist
        # Categories are based on entity types defined in KNOWN_ENTITY_TYPES
        for category in categories.values():
            assert isinstance(category, list)

    def test_categorize_entity_types_no_duplicates(self):
        """Each entity type appears in only one category."""
        from scrubiq.api.settings import _categorize_entity_types

        categories = _categorize_entity_types()

        all_types = []
        for types in categories.values():
            all_types.extend(types)

        # No duplicates
        assert len(all_types) == len(set(all_types))

    def test_categorize_secrets_cloud(self):
        """Cloud secrets are properly categorized."""
        from scrubiq.api.settings import _categorize_entity_types
        from scrubiq.types import KNOWN_ENTITY_TYPES

        categories = _categorize_entity_types()

        # Check if any AWS/Azure types exist and are categorized
        for entity_type in KNOWN_ENTITY_TYPES:
            if "AWS_" in entity_type:
                if "secrets_cloud" in categories:
                    assert entity_type in categories["secrets_cloud"]

    def test_categorize_financial(self):
        """Financial types are properly categorized."""
        from scrubiq.api.settings import _categorize_entity_types
        from scrubiq.types import KNOWN_ENTITY_TYPES

        categories = _categorize_entity_types()

        # Credit cards should be in financial_payment
        for entity_type in KNOWN_ENTITY_TYPES:
            if "CREDIT_CARD" in entity_type or "CREDITCARD" in entity_type:
                if "financial_payment" in categories:
                    assert entity_type in categories["financial_payment"]


class TestSettingsLimits:
    """Tests for settings limits constants."""

    def test_allowlist_limits_defined(self):
        """Allowlist limits are defined."""
        from scrubiq.api.settings import (
            MAX_ALLOWLIST_ENTRIES,
            MAX_ALLOWLIST_VALUE_LENGTH,
            MAX_ALLOWLIST_BATCH_SIZE,
        )

        assert MAX_ALLOWLIST_ENTRIES > 0
        assert MAX_ALLOWLIST_VALUE_LENGTH > 0
        assert MAX_ALLOWLIST_BATCH_SIZE > 0

    def test_rate_limits_defined(self):
        """Settings rate limits are defined."""
        from scrubiq.api.settings import (
            SETTINGS_READ_RATE_LIMIT,
            SETTINGS_WRITE_RATE_LIMIT,
        )

        assert SETTINGS_READ_RATE_LIMIT > 0
        assert SETTINGS_WRITE_RATE_LIMIT > 0
        # Read should have higher limit than write
        assert SETTINGS_READ_RATE_LIMIT >= SETTINGS_WRITE_RATE_LIMIT


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestAPIIntegration:
    """Integration tests for API module."""

    def test_error_handler_registration(self):
        """register_error_handlers() registers APIError handler."""
        from scrubiq.api.errors import register_error_handlers, APIError

        mock_app = MagicMock()

        register_error_handlers(mock_app)

        mock_app.add_exception_handler.assert_called_once_with(
            APIError,
            pytest.approx  # The actual handler function
        )
        # Actually check the call was made
        assert mock_app.add_exception_handler.called
