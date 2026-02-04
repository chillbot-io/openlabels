"""
Comprehensive tests for authentication API endpoints.

Tests focus on:
- Login flow initiation and dev mode behavior
- OAuth callback handling and state validation
- Session creation and management
- Logout and session termination
- Current user info retrieval
- Token endpoint and refresh logic
- Auth status checking
- Session revocation
- Logout-all functionality
- Open redirect prevention
- CSRF/state parameter validation
- Security edge cases
"""

import pytest
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.fixture
async def setup_auth_test_data(test_db):
    """Set up test data for auth endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    return {
        "tenant": tenant,
        "user": user,
        "session": test_db,
    }


@pytest.fixture
async def create_test_session(test_db):
    """Factory fixture to create test sessions."""
    from openlabels.server.models import Session

    created_sessions = []

    async def _create_session(
        session_id: str = None,
        data: dict = None,
        expires_at: datetime = None,
        tenant_id: str = None,
        user_id: str = None,
    ):
        if session_id is None:
            session_id = secrets.token_urlsafe(32)
        if data is None:
            data = {
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": user_id or "test-oid",
                    "preferred_username": "test@localhost",
                    "name": "Test User",
                    "tid": tenant_id or "test-tenant",
                    "roles": ["admin"],
                },
            }
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        session = Session(
            id=session_id,
            data=data,
            expires_at=expires_at,
            tenant_id=tenant_id,
            user_id=user_id,
        )
        test_db.add(session)
        await test_db.flush()
        created_sessions.append(session)
        return session

    yield _create_session

    # Cleanup is handled by test_db fixture rollback


@pytest.fixture
async def create_pending_auth(test_db):
    """Factory fixture to create pending auth entries."""
    from openlabels.server.models import PendingAuth

    async def _create_pending(
        state: str = None,
        redirect_uri: str = "/",
        callback_url: str = "http://test/auth/callback",
    ):
        if state is None:
            state = secrets.token_urlsafe(32)

        pending = PendingAuth(
            state=state,
            redirect_uri=redirect_uri,
            callback_url=callback_url,
        )
        test_db.add(pending)
        await test_db.flush()
        return pending

    return _create_pending


# =============================================================================
# LOGIN ENDPOINT TESTS
# =============================================================================


class TestLoginEndpoint:
    """Tests for GET /auth/login endpoint."""

    @pytest.mark.asyncio
    async def test_dev_mode_creates_session_and_redirects(self, test_db, setup_auth_test_data):
        """Dev mode login should create session and redirect."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        # Disable rate limiting for this test
        auth_limiter.enabled = False

        # Mock settings for dev mode
        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login")

                    # Should redirect
                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"

                    # Should set session cookie
                    assert "openlabels_session" in response.cookies
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_dev_mode_respects_redirect_uri(self, test_db, setup_auth_test_data):
        """Dev mode login should redirect to specified redirect_uri."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login?redirect_uri=/dashboard")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/dashboard"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_dev_mode_blocked_in_production(self, test_db, setup_auth_test_data):
        """Dev mode auth should be blocked in production environment."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "production"
        mock_settings.server.debug = False
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get("/auth/login")

                    assert response.status_code == 503
                    assert "not configured" in response.json()["detail"].lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_dev_mode_requires_debug_flag(self, test_db, setup_auth_test_data):
        """Dev mode auth should require DEBUG=true."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = False  # Debug off but not production
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get("/auth/login")

                    assert response.status_code == 503
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_dev_mode_invalidates_existing_session(self, test_db, setup_auth_test_data, create_test_session):
        """Dev mode login should invalidate existing session (session fixation prevention)."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Create an existing session
        old_session = await create_test_session(session_id="old-session-id")
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    # Send request with existing session cookie
                    response = await client.get(
                        "/auth/login",
                        cookies={"openlabels_session": "old-session-id"}
                    )

                    assert response.status_code == 302

                    # Old session should be deleted
                    await test_db.commit()
                    result = await test_db.execute(
                        select(Session).where(Session.id == "old-session-id")
                    )
                    assert result.scalar_one_or_none() is None

                    # New session should be created
                    new_session_id = response.cookies.get("openlabels_session")
                    assert new_session_id is not None
                    assert new_session_id != "old-session-id"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


class TestLoginRedirectValidation:
    """Tests for redirect URI validation in login endpoint."""

    @pytest.mark.asyncio
    async def test_blocks_external_redirect(self, test_db, setup_auth_test_data):
        """Login should block external redirect URIs."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    # Attempt external redirect
                    response = await client.get("/auth/login?redirect_uri=https://evil.com/steal")

                    assert response.status_code == 302
                    # Should redirect to / instead of external URL
                    assert response.headers.get("location") == "/"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_blocks_protocol_relative_redirect(self, test_db, setup_auth_test_data):
        """Login should block protocol-relative URLs (//evil.com)."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login?redirect_uri=//evil.com/path")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_allows_relative_paths(self, test_db, setup_auth_test_data):
        """Login should allow relative path redirects."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login?redirect_uri=/dashboard/settings")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/dashboard/settings"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_allows_cors_origin_redirect(self, test_db, setup_auth_test_data):
        """Login should allow redirects to CORS allowed origins."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000", "https://app.example.com"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login?redirect_uri=https://app.example.com/dashboard")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "https://app.example.com/dashboard"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_blocks_javascript_scheme(self, test_db, setup_auth_test_data):
        """Login should block javascript: scheme redirects."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login?redirect_uri=javascript:alert(1)")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# CALLBACK ENDPOINT TESTS
# =============================================================================


class TestCallbackEndpoint:
    """Tests for GET /auth/callback endpoint."""

    @pytest.mark.asyncio
    async def test_callback_missing_code_returns_400(self, test_db, setup_auth_test_data):
        """Callback without code should return 400."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get("/auth/callback?state=some-state")

                    assert response.status_code == 400
                    assert "Missing" in response.json()["detail"] or "code" in response.json()["detail"].lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_missing_state_returns_400(self, test_db, setup_auth_test_data):
        """Callback without state should return 400."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get("/auth/callback?code=some-code")

                    assert response.status_code == 400
                    assert "Missing" in response.json()["detail"] or "state" in response.json()["detail"].lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_invalid_state_returns_400(self, test_db, setup_auth_test_data):
        """Callback with invalid/unknown state should return 400."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get("/auth/callback?code=test-code&state=invalid-state")

                    assert response.status_code == 400
                    assert "Invalid" in response.json()["detail"] or "state" in response.json()["detail"].lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_oauth_error_returns_400(self, test_db, setup_auth_test_data):
        """Callback with OAuth error should return 400."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get(
                        "/auth/callback?error=access_denied&error_description=User%20denied%20access"
                    )

                    assert response.status_code == 400
                    assert "Authentication failed" in response.json()["detail"]
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_success_creates_session(self, test_db, setup_auth_test_data, create_pending_auth):
        """Successful callback should create session and redirect."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Create pending auth state
        state = secrets.token_urlsafe(32)
        await create_pending_auth(state=state, redirect_uri="/dashboard")
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        # Mock MSAL token response
        mock_msal_result = {
            "access_token": "mock-access-token",
            "refresh_token": "mock-refresh-token",
            "id_token": "mock-id-token",
            "expires_in": 3600,
            "id_token_claims": {
                "oid": "user-oid-123",
                "preferred_username": "user@example.com",
                "name": "Test User",
                "tid": "tenant-id-123",
                "roles": ["user"],
            },
        }

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_authorization_code.return_value = mock_msal_result

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                        response = await client.get(f"/auth/callback?code=test-code&state={state}")

                        assert response.status_code == 302
                        assert response.headers.get("location") == "/dashboard"
                        assert "openlabels_session" in response.cookies

                        # Verify session was created in database
                        await test_db.commit()
                        result = await test_db.execute(select(Session))
                        sessions = result.scalars().all()
                        assert len(sessions) >= 1
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_token_error_returns_400(self, test_db, setup_auth_test_data, create_pending_auth):
        """Callback with token acquisition error should return 400."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Create pending auth state
        state = secrets.token_urlsafe(32)
        await create_pending_auth(state=state)
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        # Mock MSAL error response
        mock_msal_result = {
            "error": "invalid_grant",
            "error_description": "Code expired",
        }

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_authorization_code.return_value = mock_msal_result

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.get(f"/auth/callback?code=expired-code&state={state}")

                        assert response.status_code == 400
                        assert "Failed to complete authentication" in response.json()["detail"]
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_token_exception_returns_400(self, test_db, setup_auth_test_data, create_pending_auth):
        """Callback with token acquisition exception should return 400."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        state = secrets.token_urlsafe(32)
        await create_pending_auth(state=state)
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_authorization_code.side_effect = Exception("Network error")

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.get(f"/auth/callback?code=test-code&state={state}")

                        assert response.status_code == 400
                        assert "Failed to acquire token" in response.json()["detail"]
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_dev_mode_redirects_to_root(self, test_db, setup_auth_test_data):
        """Callback in dev mode should redirect to /."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/callback")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# LOGOUT ENDPOINT TESTS
# =============================================================================


class TestLogoutEndpoint:
    """Tests for GET /auth/logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_clears_session(self, test_db, setup_auth_test_data, create_test_session):
        """Logout should delete session from database."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session

        session = await create_test_session(session_id="logout-test-session")
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.auth.tenant_id = None

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get(
                        "/auth/logout",
                        cookies={"openlabels_session": "logout-test-session"}
                    )

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"

                    # Session should be deleted
                    await test_db.commit()
                    result = await test_db.execute(
                        select(Session).where(Session.id == "logout-test-session")
                    )
                    assert result.scalar_one_or_none() is None
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logout_clears_cookie(self, test_db, setup_auth_test_data, create_test_session):
        """Logout should clear the session cookie."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        await create_test_session(session_id="cookie-test-session")
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.auth.tenant_id = None

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get(
                        "/auth/logout",
                        cookies={"openlabels_session": "cookie-test-session"}
                    )

                    # Cookie should be deleted (max-age=0 or expires in past)
                    set_cookie = response.headers.get("set-cookie", "")
                    assert "openlabels_session" in set_cookie
                    # Cookie deletion is indicated by max-age=0 or empty value
                    assert 'max-age=0' in set_cookie.lower() or 'openlabels_session=""' in set_cookie or 'openlabels_session=;' in set_cookie
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logout_redirects_to_azure_when_configured(self, test_db, setup_auth_test_data):
        """Logout with Azure AD should redirect to Microsoft logout."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant-123"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/logout")

                    assert response.status_code == 302
                    location = response.headers.get("location")
                    assert "login.microsoftonline.com" in location
                    assert "test-tenant-123" in location
                    assert "logout" in location
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logout_without_session_still_redirects(self, test_db, setup_auth_test_data):
        """Logout without session cookie should still redirect."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.auth.tenant_id = None

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/logout")

                    assert response.status_code == 302
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# CURRENT USER INFO TESTS
# =============================================================================


class TestMeEndpoint:
    """Tests for GET /auth/me endpoint."""

    @pytest.mark.asyncio
    async def test_me_returns_user_info(self, test_db, setup_auth_test_data, create_test_session):
        """GET /auth/me should return current user info."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        session = await create_test_session(
            session_id="me-test-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": "user-123",
                    "preferred_username": "user@example.com",
                    "name": "Test User",
                    "tid": "tenant-456",
                    "roles": ["admin", "user"],
                },
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    "/auth/me",
                    cookies={"openlabels_session": "me-test-session"}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["id"] == "user-123"
                assert data["email"] == "user@example.com"
                assert data["name"] == "Test User"
                assert data["tenant_id"] == "tenant-456"
                assert "admin" in data["roles"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_me_without_session_returns_401(self, test_db, setup_auth_test_data):
        """GET /auth/me without session should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/auth/me")

                assert response.status_code == 401
                assert "Not authenticated" in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_me_with_invalid_session_returns_401(self, test_db, setup_auth_test_data):
        """GET /auth/me with invalid session should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    "/auth/me",
                    cookies={"openlabels_session": "nonexistent-session"}
                )

                assert response.status_code == 401
                assert "expired or invalid" in response.json()["detail"].lower()
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_me_with_expired_session_returns_401(self, test_db, setup_auth_test_data, create_test_session):
        """GET /auth/me with expired session should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create session with expired token (session row exists but token expired)
        session = await create_test_session(
            session_id="expired-token-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),  # Expired
                "claims": {
                    "oid": "user-123",
                    "preferred_username": "user@example.com",
                    "name": "Test User",
                    "tid": "tenant-456",
                    "roles": [],
                },
            },
            # Session row itself is still valid
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    "/auth/me",
                    cookies={"openlabels_session": "expired-token-session"}
                )

                assert response.status_code == 401
                assert "expired" in response.json()["detail"].lower()
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# TOKEN ENDPOINT TESTS
# =============================================================================


class TestTokenEndpoint:
    """Tests for POST /auth/token endpoint."""

    @pytest.mark.asyncio
    async def test_token_returns_access_token(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/token should return access token."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        session = await create_test_session(
            session_id="token-test-session",
            data={
                "access_token": "my-access-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {},
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/auth/token",
                    cookies={"openlabels_session": "token-test-session"}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["access_token"] == "my-access-token"
                assert data["token_type"] == "Bearer"
                assert data["expires_in"] > 0
                assert "scope" in data
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_token_without_session_returns_401(self, test_db, setup_auth_test_data):
        """POST /auth/token without session should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post("/auth/token")

                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_token_with_expired_session_attempts_refresh(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/token with expired token should attempt refresh."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        session = await create_test_session(
            session_id="refresh-test-session",
            data={
                "access_token": "old-token",
                "refresh_token": "my-refresh-token",
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),  # Expired
                "claims": {},
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"

        # Mock successful refresh
        mock_refresh_result = {
            "access_token": "new-access-token",
            "expires_in": 3600,
        }

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_refresh_token.return_value = mock_refresh_result

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.post(
                            "/auth/token",
                            cookies={"openlabels_session": "refresh-test-session"}
                        )

                        assert response.status_code == 200
                        data = response.json()
                        assert data["access_token"] == "new-access-token"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_token_refresh_failure_returns_401(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/token with failed refresh should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        session = await create_test_session(
            session_id="failed-refresh-session",
            data={
                "access_token": "old-token",
                "refresh_token": "bad-refresh-token",
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                "claims": {},
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"

        # Mock failed refresh
        mock_refresh_result = {
            "error": "invalid_grant",
        }

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_refresh_token.return_value = mock_refresh_result

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.post(
                            "/auth/token",
                            cookies={"openlabels_session": "failed-refresh-session"}
                        )

                        assert response.status_code == 401
                        assert "expired" in response.json()["detail"].lower()
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# AUTH STATUS TESTS
# =============================================================================


class TestAuthStatusEndpoint:
    """Tests for GET /auth/status endpoint."""

    @pytest.mark.asyncio
    async def test_status_authenticated(self, test_db, setup_auth_test_data, create_test_session):
        """GET /auth/status should return authenticated=True with valid session."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        session = await create_test_session(
            session_id="status-test-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": "user-123",
                    "preferred_username": "user@example.com",
                    "name": "Test User",
                },
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get(
                        "/auth/status",
                        cookies={"openlabels_session": "status-test-session"}
                    )

                    assert response.status_code == 200
                    data = response.json()
                    assert data["authenticated"] is True
                    assert data["provider"] == "azure_ad"
                    assert data["user"]["id"] == "user-123"
                    assert data["login_url"] is None
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_status_not_authenticated(self, test_db, setup_auth_test_data):
        """GET /auth/status should return authenticated=False without session."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get("/auth/status")

                    assert response.status_code == 200
                    data = response.json()
                    assert data["authenticated"] is False
                    assert data["user"] is None
                    assert data["login_url"] == "/auth/login"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_status_with_expired_token(self, test_db, setup_auth_test_data, create_test_session):
        """GET /auth/status should return authenticated=False with expired token."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        session = await create_test_session(
            session_id="expired-status-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),  # Expired
                "claims": {
                    "oid": "user-123",
                    "preferred_username": "user@example.com",
                    "name": "Test User",
                },
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get(
                        "/auth/status",
                        cookies={"openlabels_session": "expired-status-session"}
                    )

                    assert response.status_code == 200
                    data = response.json()
                    assert data["authenticated"] is False
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# REVOKE ENDPOINT TESTS
# =============================================================================


class TestRevokeEndpoint:
    """Tests for POST /auth/revoke endpoint."""

    @pytest.mark.asyncio
    async def test_revoke_deletes_session(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/revoke should delete the session."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session

        session = await create_test_session(session_id="revoke-test-session")
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/auth/revoke",
                    cookies={"openlabels_session": "revoke-test-session"}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "revoked"

                # Session should be deleted
                await test_db.commit()
                result = await test_db.execute(
                    select(Session).where(Session.id == "revoke-test-session")
                )
                assert result.scalar_one_or_none() is None
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_revoke_without_session_returns_401(self, test_db, setup_auth_test_data):
        """POST /auth/revoke without session should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post("/auth/revoke")

                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_revoke_invalid_session_returns_404(self, test_db, setup_auth_test_data):
        """POST /auth/revoke with invalid session should return 404."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/auth/revoke",
                    cookies={"openlabels_session": "nonexistent-session"}
                )

                assert response.status_code == 404
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# LOGOUT ALL SESSIONS TESTS
# =============================================================================


class TestLogoutAllEndpoint:
    """Tests for POST /auth/logout-all endpoint."""

    @pytest.mark.asyncio
    async def test_logout_all_deletes_user_sessions(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/logout-all should delete all sessions for the user."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select, func
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session

        user_id = "multi-session-user"

        # Create multiple sessions for the same user
        for i in range(5):
            await create_test_session(
                session_id=f"user-session-{i}",
                data={
                    "access_token": f"token-{i}",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "claims": {"oid": user_id, "tid": "test-tenant"},
                },
                user_id=user_id,
            )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/auth/logout-all",
                    cookies={"openlabels_session": "user-session-0"}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "success"
                assert data["sessions_revoked"] == 5

                # All sessions for this user should be deleted
                await test_db.commit()
                result = await test_db.execute(
                    select(func.count(Session.id)).where(Session.user_id == user_id)
                )
                assert result.scalar() == 0
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logout_all_without_session_returns_401(self, test_db, setup_auth_test_data):
        """POST /auth/logout-all without session should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post("/auth/logout-all")

                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_logout_all_without_user_id_deletes_current_only(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/logout-all without user_id in claims should only delete current session."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create session without user_id in claims
        await create_test_session(
            session_id="no-user-id-session",
            data={
                "access_token": "token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {},  # No oid
            },
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/auth/logout-all",
                    cookies={"openlabels_session": "no-user-id-session"}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["sessions_revoked"] == 1
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# REDIRECT URI VALIDATION UNIT TESTS
# =============================================================================


class TestValidateRedirectUri:
    """Unit tests for validate_redirect_uri function."""

    def test_empty_redirect_returns_root(self):
        """Empty redirect_uri should return /."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        assert validate_redirect_uri(None, mock_request) == "/"
        assert validate_redirect_uri("", mock_request) == "/"

    def test_relative_path_allowed(self):
        """Relative paths should be allowed."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        assert validate_redirect_uri("/dashboard", mock_request) == "/dashboard"
        assert validate_redirect_uri("/api/v1/resource", mock_request) == "/api/v1/resource"

    def test_protocol_relative_blocked(self):
        """Protocol-relative URLs should be blocked."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        assert validate_redirect_uri("//evil.com", mock_request) == "/"
        assert validate_redirect_uri("//evil.com/path", mock_request) == "/"

    def test_same_host_allowed(self):
        """Same-host redirects should be allowed."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        assert validate_redirect_uri("http://test.example.com/path", mock_request) == "http://test.example.com/path"
        assert validate_redirect_uri("https://test.example.com/path", mock_request) == "https://test.example.com/path"

    def test_different_host_blocked(self):
        """Different host redirects should be blocked unless in CORS."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        mock_settings = MagicMock()
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]

        with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
            assert validate_redirect_uri("https://evil.com/steal", mock_request) == "/"

    def test_cors_origin_allowed(self):
        """Redirects to CORS origins should be allowed."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        mock_settings = MagicMock()
        mock_settings.cors.allowed_origins = ["http://localhost:3000", "https://app.example.com"]

        with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
            assert validate_redirect_uri("http://localhost:3000/callback", mock_request) == "http://localhost:3000/callback"
            assert validate_redirect_uri("https://app.example.com/path", mock_request) == "https://app.example.com/path"

    def test_invalid_scheme_blocked(self):
        """Invalid schemes like javascript: should be blocked."""
        from openlabels.server.routes.auth import validate_redirect_uri

        mock_request = MagicMock()
        mock_request.url.netloc = "test.example.com"

        assert validate_redirect_uri("javascript:alert(1)", mock_request) == "/"
        assert validate_redirect_uri("data:text/html,<script>", mock_request) == "/"
        assert validate_redirect_uri("file:///etc/passwd", mock_request) == "/"


# =============================================================================
# SESSION COOKIE SECURITY TESTS
# =============================================================================


class TestSessionCookieSecurity:
    """Tests for secure session cookie settings."""

    @pytest.mark.asyncio
    async def test_session_cookie_is_httponly(self, test_db, setup_auth_test_data):
        """Session cookie should have HttpOnly flag."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login")

                    set_cookie = response.headers.get("set-cookie", "")
                    assert "httponly" in set_cookie.lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_session_cookie_has_samesite(self, test_db, setup_auth_test_data):
        """Session cookie should have SameSite attribute."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    response = await client.get("/auth/login")

                    set_cookie = response.headers.get("set-cookie", "")
                    assert "samesite" in set_cookie.lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# MSAL APP CONFIGURATION TESTS
# =============================================================================


class TestMsalAppConfiguration:
    """Tests for MSAL app configuration."""

    def test_get_msal_app_raises_when_auth_none(self):
        """_get_msal_app should raise when auth provider is none."""
        from fastapi import HTTPException
        from openlabels.server.routes.auth import _get_msal_app

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
            with pytest.raises(HTTPException) as exc_info:
                _get_msal_app()

            assert exc_info.value.status_code == 501
            assert "not configured" in exc_info.value.detail.lower()

    def test_get_msal_app_creates_client_when_configured(self):
        """_get_msal_app should create MSAL client when configured."""
        from openlabels.server.routes.auth import _get_msal_app

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.client_id = "test-client-id"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.auth.tenant_id = "test-tenant-id"

        with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.auth.ConfidentialClientApplication') as mock_msal:
                mock_msal.return_value = MagicMock()
                result = _get_msal_app()

                mock_msal.assert_called_once()
                call_kwargs = mock_msal.call_args
                assert call_kwargs[1]["client_id"] == "test-client-id"
                assert call_kwargs[1]["client_credential"] == "test-secret"
                assert "test-tenant-id" in call_kwargs[1]["authority"]


# =============================================================================
# SESSION GENERATION TESTS
# =============================================================================


class TestSessionGeneration:
    """Tests for session ID generation."""

    def test_session_id_is_secure(self):
        """Session IDs should be cryptographically secure."""
        from openlabels.server.routes.auth import _generate_session_id

        session_ids = [_generate_session_id() for _ in range(100)]

        # All should be unique
        assert len(set(session_ids)) == 100

        # Should be URL-safe base64
        for session_id in session_ids:
            assert isinstance(session_id, str)
            assert len(session_id) >= 32  # At least 32 chars for security

    def test_session_id_uses_secrets_module(self):
        """Session ID generation should use secrets module."""
        with patch('openlabels.server.routes.auth.secrets.token_urlsafe') as mock_secrets:
            mock_secrets.return_value = "mocked-session-id"

            from openlabels.server.routes.auth import _generate_session_id
            result = _generate_session_id()

            mock_secrets.assert_called_once_with(32)
            assert result == "mocked-session-id"
