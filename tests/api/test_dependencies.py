"""Tests for API dependencies (authentication layer).

Tests all functions in scrubiq/api/dependencies.py:
- set_api_key_service / get_api_key_service
- _extract_bearer_token
- _validate_api_key
- require_api_key
- require_permission
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.api.dependencies import (
    set_api_key_service,
    get_api_key_service,
    _extract_bearer_token,
    _validate_api_key,
    require_api_key,
    require_permission,
    _api_key_service,
)
from scrubiq.api.errors import APIError, ErrorCode
from scrubiq.services.api_keys import APIKeyService, APIKeyMetadata
from scrubiq.storage.database import Database


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db_and_service():
    """Create a database and API key service."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.connect()
        service = APIKeyService(db)
        yield db, service
        db.close()


@pytest.fixture
def mock_request():
    """Create a mock FastAPI Request object."""
    request = MagicMock(spec=Request)
    request.headers = {}
    request.state = MagicMock()
    return request


@pytest.fixture
def mock_request_with_token():
    """Create a mock request with a Bearer token."""
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Bearer sk-test123"}
    request.state = MagicMock()
    return request


@pytest.fixture(autouse=True)
def reset_api_key_service():
    """Reset the global API key service before and after each test."""
    import scrubiq.api.dependencies as deps
    original = deps._api_key_service
    deps._api_key_service = None
    yield
    deps._api_key_service = original


# =============================================================================
# SET/GET API KEY SERVICE TESTS
# =============================================================================

class TestSetGetApiKeyService:
    """Tests for set_api_key_service and get_api_key_service."""

    def test_set_api_key_service(self, db_and_service):
        """set_api_key_service sets the global service."""
        db, service = db_and_service
        set_api_key_service(service)
        assert get_api_key_service() is service

    def test_get_api_key_service_not_initialized(self):
        """get_api_key_service raises RuntimeError if not initialized."""
        with pytest.raises(RuntimeError, match="API key service not initialized"):
            get_api_key_service()

    def test_set_api_key_service_replaces_existing(self, db_and_service):
        """set_api_key_service can replace an existing service."""
        db, service1 = db_and_service
        service2 = MagicMock(spec=APIKeyService)

        set_api_key_service(service1)
        assert get_api_key_service() is service1

        set_api_key_service(service2)
        assert get_api_key_service() is service2


# =============================================================================
# EXTRACT BEARER TOKEN TESTS
# =============================================================================

class TestExtractBearerToken:
    """Tests for _extract_bearer_token function."""

    def test_extract_bearer_token_valid(self, mock_request):
        """Extracts token from valid Bearer header."""
        mock_request.headers = {"Authorization": "Bearer sk-validtoken123"}
        token = _extract_bearer_token(mock_request)
        assert token == "sk-validtoken123"

    def test_extract_bearer_token_no_header(self, mock_request):
        """Returns None when no Authorization header."""
        mock_request.headers = {}
        token = _extract_bearer_token(mock_request)
        assert token is None

    def test_extract_bearer_token_empty_header(self, mock_request):
        """Returns None when Authorization header is empty."""
        mock_request.headers = {"Authorization": ""}
        token = _extract_bearer_token(mock_request)
        assert token is None

    def test_extract_bearer_token_not_bearer(self, mock_request):
        """Returns None when not Bearer auth scheme."""
        mock_request.headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        token = _extract_bearer_token(mock_request)
        assert token is None

    def test_extract_bearer_token_bearer_only(self, mock_request):
        """Returns None when just 'Bearer' without token."""
        mock_request.headers = {"Authorization": "Bearer"}
        token = _extract_bearer_token(mock_request)
        assert token is None

    def test_extract_bearer_token_extra_parts(self, mock_request):
        """Returns None when header has extra parts."""
        mock_request.headers = {"Authorization": "Bearer token extra stuff"}
        token = _extract_bearer_token(mock_request)
        assert token is None

    def test_extract_bearer_token_case_insensitive(self, mock_request):
        """Bearer scheme is case-insensitive."""
        mock_request.headers = {"Authorization": "BEARER sk-token"}
        token = _extract_bearer_token(mock_request)
        assert token == "sk-token"

    def test_extract_bearer_token_lowercase(self, mock_request):
        """Bearer scheme works in lowercase."""
        mock_request.headers = {"Authorization": "bearer sk-token"}
        token = _extract_bearer_token(mock_request)
        assert token == "sk-token"


# =============================================================================
# VALIDATE API KEY TESTS
# =============================================================================

class TestValidateApiKey:
    """Tests for _validate_api_key function."""

    def test_validate_api_key_with_credentials(self, db_and_service, mock_request):
        """Validates key from HTTPAuthorizationCredentials."""
        db, service = db_and_service
        set_api_key_service(service)

        # Create a valid key
        api_key, metadata = service.create_key(name="test-key")

        # Mock credentials
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        result_key, result_metadata = _validate_api_key(mock_request, credentials)
        assert result_key == api_key
        assert result_metadata.key_prefix == metadata.key_prefix

    def test_validate_api_key_fallback_to_header(self, db_and_service, mock_request):
        """Falls back to manual header extraction when credentials is None."""
        db, service = db_and_service
        set_api_key_service(service)

        # Create a valid key
        api_key, metadata = service.create_key(name="test-key")

        mock_request.headers = {"Authorization": f"Bearer {api_key}"}

        result_key, result_metadata = _validate_api_key(mock_request, None)
        assert result_key == api_key
        assert result_metadata.key_prefix == metadata.key_prefix

    def test_validate_api_key_no_token(self, db_and_service, mock_request):
        """Raises 401 when no token provided."""
        db, service = db_and_service
        set_api_key_service(service)

        mock_request.headers = {}

        with pytest.raises(APIError) as exc_info:
            _validate_api_key(mock_request, None)

        assert exc_info.value.status_code == 401
        assert exc_info.value.error_code == ErrorCode.NOT_AUTHENTICATED
        assert "API key required" in exc_info.value.detail

    def test_validate_api_key_invalid_token(self, db_and_service, mock_request):
        """Raises 401 when token is invalid."""
        db, service = db_and_service
        set_api_key_service(service)

        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = "sk-invalidkey123"

        with pytest.raises(APIError) as exc_info:
            _validate_api_key(mock_request, credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.error_code == ErrorCode.NOT_AUTHENTICATED
        assert "Invalid API key" in exc_info.value.detail

    def test_validate_api_key_stores_metadata_in_request_state(
        self, db_and_service, mock_request
    ):
        """Stores API key metadata in request.state."""
        db, service = db_and_service
        set_api_key_service(service)

        api_key, metadata = service.create_key(name="test-key")
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        _validate_api_key(mock_request, credentials)

        assert hasattr(mock_request.state, "api_key")
        assert mock_request.state.api_key.key_prefix == metadata.key_prefix


# =============================================================================
# REQUIRE API KEY TESTS
# =============================================================================

class TestRequireApiKey:
    """Tests for require_api_key dependency."""

    def test_require_api_key_success(self, db_and_service, mock_request):
        """Successfully returns ScrubIQ instance for valid key."""
        db, service = db_and_service
        set_api_key_service(service)

        # Create a valid key
        api_key, metadata = service.create_key(name="test-key")
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        # Mock instance pool
        mock_instance = MagicMock()
        mock_pool = MagicMock()
        mock_pool.get_or_create.return_value = mock_instance

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit"):
                result = require_api_key(mock_request, credentials)

        assert result is mock_instance
        mock_pool.get_or_create.assert_called_once()

    def test_require_api_key_checks_rate_limit(self, db_and_service, mock_request):
        """Checks rate limit before getting instance."""
        db, service = db_and_service
        set_api_key_service(service)

        api_key, _ = service.create_key(name="test-key")
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        mock_pool = MagicMock()
        mock_pool.get_or_create.return_value = MagicMock()

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit") as mock_rate_limit:
                require_api_key(mock_request, credentials)
                mock_rate_limit.assert_called_once_with(mock_request, action="api")

    def test_require_api_key_derives_encryption_key(self, db_and_service, mock_request):
        """Derives encryption key from API key."""
        db, service = db_and_service
        set_api_key_service(service)

        api_key, metadata = service.create_key(name="test-key")
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        mock_pool = MagicMock()
        mock_pool.get_or_create.return_value = MagicMock()

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit"):
                require_api_key(mock_request, credentials)

        # Verify encryption key was passed to pool
        call_kwargs = mock_pool.get_or_create.call_args[1]
        assert "encryption_key" in call_kwargs
        assert call_kwargs["encryption_key"] is not None
        assert len(call_kwargs["encryption_key"]) == 32  # 256 bits

    def test_require_api_key_pool_failure(self, db_and_service, mock_request):
        """Raises 401 when pool fails to create instance."""
        db, service = db_and_service
        set_api_key_service(service)

        api_key, _ = service.create_key(name="test-key")
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        mock_pool = MagicMock()
        mock_pool.get_or_create.side_effect = Exception("Pool error")

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit"):
                with pytest.raises(APIError) as exc_info:
                    require_api_key(mock_request, credentials)

        assert exc_info.value.status_code == 401
        assert "Failed to initialize session" in exc_info.value.detail

    def test_require_api_key_no_token(self, db_and_service, mock_request):
        """Raises 401 when no token provided."""
        db, service = db_and_service
        set_api_key_service(service)

        mock_request.headers = {}

        with pytest.raises(APIError) as exc_info:
            require_api_key(mock_request, None)

        assert exc_info.value.status_code == 401


# =============================================================================
# REQUIRE PERMISSION TESTS
# =============================================================================

class TestRequirePermission:
    """Tests for require_permission dependency factory."""

    def test_require_permission_granted(self, db_and_service, mock_request):
        """Allows access when permission is granted."""
        db, service = db_and_service
        set_api_key_service(service)

        # Create key with admin permission
        api_key, metadata = service.create_key(name="admin-key", permissions=["admin"])
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        mock_instance = MagicMock()
        mock_pool = MagicMock()
        mock_pool.get_or_create.return_value = mock_instance

        # Create the permission dependency
        require_admin = require_permission("admin")

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit"):
                # First get the base instance (simulating Depends chain)
                base_instance = require_api_key(mock_request, credentials)

                # Now call the permission check
                result = require_admin(mock_request, base_instance)
                assert result is base_instance

    def test_require_permission_denied(self, db_and_service, mock_request):
        """Raises 403 when permission is not granted."""
        db, service = db_and_service
        set_api_key_service(service)

        # Create key WITHOUT admin permission
        api_key, metadata = service.create_key(name="user-key", permissions=["read"])
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        mock_instance = MagicMock()
        mock_pool = MagicMock()
        mock_pool.get_or_create.return_value = mock_instance

        # Create the permission dependency
        require_admin = require_permission("admin")

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit"):
                # First get the base instance (simulating Depends chain)
                base_instance = require_api_key(mock_request, credentials)

                # Now call the permission check - should fail
                with pytest.raises(APIError) as exc_info:
                    require_admin(mock_request, base_instance)

                assert exc_info.value.status_code == 403
                assert exc_info.value.error_code == ErrorCode.PERMISSION_DENIED
                assert "admin" in exc_info.value.detail

    def test_require_permission_multiple_permissions(self, db_and_service, mock_request):
        """Works with multiple permissions on key."""
        db, service = db_and_service
        set_api_key_service(service)

        # Create key with multiple permissions
        api_key, metadata = service.create_key(
            name="multi-key", permissions=["read", "write", "admin"]
        )
        credentials = MagicMock(spec=HTTPAuthorizationCredentials)
        credentials.credentials = api_key

        mock_instance = MagicMock()
        mock_pool = MagicMock()
        mock_pool.get_or_create.return_value = mock_instance

        with patch("scrubiq.api.dependencies.get_pool", return_value=mock_pool):
            with patch("scrubiq.rate_limiter.check_api_key_rate_limit"):
                # Check each permission works
                for perm in ["read", "write", "admin"]:
                    require_perm = require_permission(perm)
                    base_instance = require_api_key(mock_request, credentials)
                    result = require_perm(mock_request, base_instance)
                    assert result is base_instance

    def test_require_permission_returns_callable(self):
        """require_permission returns a callable dependency."""
        dep = require_permission("admin")
        assert callable(dep)


# =============================================================================
# BACKWARD COMPATIBILITY TESTS
# =============================================================================

class TestBackwardCompatibility:
    """Tests for backward compatibility aliases."""

    def test_require_unlocked_alias(self):
        """require_unlocked is alias for require_api_key."""
        from scrubiq.api.dependencies import require_unlocked
        assert require_unlocked is require_api_key
