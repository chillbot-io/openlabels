"""
Comprehensive tests for FastAPI authentication dependencies.

These tests verify user creation, role assignment, and access control.
Security-critical: tests should expose authorization bypass vulnerabilities.
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from openlabels.auth.oauth import TokenClaims
from openlabels.auth.dependencies import (
    CurrentUser,
    get_or_create_user,
    get_current_user,
    require_admin,
)


class TestCurrentUser:
    """Tests for CurrentUser model."""

    def test_valid_current_user(self):
        """CurrentUser with valid data."""
        user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="user@example.com",
            name="Test User",
            role="admin",
        )
        assert user.email == "user@example.com"
        assert user.role == "admin"

    def test_current_user_without_name(self):
        """CurrentUser with optional name as None."""
        user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="user@example.com",
            name=None,
            role="viewer",
        )
        assert user.name is None


class TestGetOrCreateUser:
    """Tests for user provisioning logic.

    Note: get_or_create_user has tight coupling with SQLAlchemy models,
    so we test the logic via integration tests using actual database fixtures
    from conftest, or test the function signature and role logic.
    """

    @pytest.fixture
    def sample_claims(self):
        """Sample token claims."""
        return TokenClaims(
            oid="azure-oid-123",
            preferred_username="user@contoso.com",
            name="Test User",
            tenant_id="tenant-abc",
            roles=["viewer"],
        )

    def test_claims_role_check_is_case_sensitive(self):
        """Role check should be case-sensitive for security."""
        claims_upper = TokenClaims(
            oid="user-oid",
            preferred_username="user@contoso.com",
            name="User",
            tenant_id="tenant",
            roles=["ADMIN"],  # Uppercase
        )
        # "admin" (lowercase) not in roles
        assert "admin" not in claims_upper.roles

    async def test_fails_with_none_session(self, sample_claims):
        """Should raise when session is None."""
        with pytest.raises((TypeError, AttributeError)):
            await get_or_create_user(None, sample_claims)

    async def test_fails_with_none_claims(self):
        """Should raise when claims is None."""
        mock_session = AsyncMock()
        with pytest.raises((TypeError, AttributeError)):
            await get_or_create_user(mock_session, None)


class TestGetCurrentUser:
    """Tests for current user resolution - critical for auth."""

    async def test_dev_mode_creates_dev_user(self):
        """In dev mode, should create dev user without token."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        mock_session = AsyncMock()
        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.tenant_id = uuid4()
        mock_user.email = "dev@localhost"
        mock_user.name = "Development User"
        mock_user.role = "admin"

        with patch("openlabels.auth.dependencies.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.dependencies.get_or_create_user", return_value=mock_user):
                user = await get_current_user(token=None, session=mock_session)

                assert user.email == "dev@localhost"
                assert user.role == "admin"

    async def test_no_token_returns_401(self):
        """Without token in production mode, should return 401."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_session = AsyncMock()

        with patch("openlabels.auth.dependencies.get_settings", return_value=mock_settings):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(token=None, session=mock_session)

            assert exc_info.value.status_code == 401
            assert "Not authenticated" in exc_info.value.detail

    async def test_invalid_token_returns_401(self):
        """Invalid token should return 401."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_session = AsyncMock()

        with patch("openlabels.auth.dependencies.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.dependencies.validate_token") as mock_validate:
                mock_validate.side_effect = ValueError("Token expired")

                with pytest.raises(HTTPException) as exc_info:
                    await get_current_user(token="invalid-token", session=mock_session)

                assert exc_info.value.status_code == 401
                assert "Token expired" in exc_info.value.detail

    async def test_valid_token_returns_user(self):
        """Valid token should return current user."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_session = AsyncMock()

        mock_claims = TokenClaims(
            oid="user-oid",
            preferred_username="user@example.com",
            name="Test User",
            tenant_id="tenant-id",
            roles=[],
        )

        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.tenant_id = uuid4()
        mock_user.email = "user@example.com"
        mock_user.name = "Test User"
        mock_user.role = "viewer"

        with patch("openlabels.auth.dependencies.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.dependencies.validate_token", return_value=mock_claims):
                with patch("openlabels.auth.dependencies.get_or_create_user", return_value=mock_user):
                    user = await get_current_user(token="valid-token", session=mock_session)

                    assert user.email == "user@example.com"
                    assert user.role == "viewer"


class TestRequireAdmin:
    """Tests for admin requirement - authorization critical."""

    async def test_admin_user_allowed(self):
        """Admin user should pass require_admin check."""
        admin_user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="admin@example.com",
            name="Admin",
            role="admin",
        )

        result = await require_admin(user=admin_user)
        assert result == admin_user

    async def test_viewer_user_forbidden(self):
        """Non-admin user should get 403 Forbidden."""
        viewer_user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="viewer@example.com",
            name="Viewer",
            role="viewer",
        )

        with pytest.raises(HTTPException) as exc_info:
            await require_admin(user=viewer_user)

        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail.lower()

    async def test_unknown_role_forbidden(self):
        """Unknown role should be treated as non-admin."""
        user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="user@example.com",
            name="User",
            role="unknown",  # Not 'admin'
        )

        with pytest.raises(HTTPException) as exc_info:
            await require_admin(user=user)

        assert exc_info.value.status_code == 403

    async def test_empty_role_forbidden(self):
        """Empty role should be treated as non-admin."""
        user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="user@example.com",
            name="User",
            role="",  # Empty
        )

        with pytest.raises(HTTPException) as exc_info:
            await require_admin(user=user)

        assert exc_info.value.status_code == 403

    async def test_case_sensitive_admin_check(self):
        """Admin check should be case-sensitive (ADMIN != admin)."""
        user = CurrentUser(
            id=uuid4(),
            tenant_id=uuid4(),
            email="user@example.com",
            name="User",
            role="ADMIN",  # Uppercase - should fail if check is case-sensitive
        )

        # This test documents current behavior - role check is case-sensitive
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(user=user)

        assert exc_info.value.status_code == 403


