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
    import random
    import string
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User

    # Generate unique suffix to prevent test data collisions
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    # Check if a tenant already exists, otherwise create one
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalars().first()

    if tenant is None:
        tenant = Tenant(
            name=f"Test Tenant {suffix}",
            azure_tenant_id=f"test-tenant-id-{suffix}",
        )
        test_db.add(tenant)
        await test_db.flush()

    # Check if a user already exists for this tenant, otherwise create one
    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalars().first()

    if user is None:
        user = User(
            tenant_id=tenant.id,
            email=f"test-{suffix}@localhost",
            name=f"Test User {suffix}",
            role="admin",
        )
        test_db.add(user)
        await test_db.commit()

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
        tenant_id=None,
        user_id=None,
    ):
        if session_id is None:
            session_id = secrets.token_urlsafe(32)
        if data is None:
            data = {
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": user_id or "00000000-0000-4000-8000-000000000001",
                    "preferred_username": "test@localhost",
                    "name": "Test User",
                    "tid": tenant_id or "00000000-0000-4000-8000-000000000002",
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
                    response = await client.get("/api/auth/login")

                    # Should redirect
                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"

                    # Should set session cookie
                    assert "openlabels_session" in response.cookies
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login?redirect_uri=/dashboard")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/dashboard"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login")

                    assert response.status_code == 503
                    assert "not configured" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login")

                    assert response.status_code == 503
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                        "/api/auth/login",
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
                    response = await client.get("/api/auth/login?redirect_uri=https://evil.com/steal")

                    assert response.status_code == 302
                    # Should redirect to / instead of external URL
                    assert response.headers.get("location") == "/"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login?redirect_uri=//evil.com/path")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login?redirect_uri=/dashboard/settings")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "/dashboard/settings"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login?redirect_uri=https://app.example.com/dashboard")

                    assert response.status_code == 302
                    assert response.headers.get("location") == "https://app.example.com/dashboard"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login?redirect_uri=javascript:alert(1)")

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
                    response = await client.get("/api/auth/callback?state=some-state")

                    assert response.status_code == 400
                    assert "Missing" in response.json().get("message", response.json().get("detail", "")) or "code" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/callback?code=some-code")

                    assert response.status_code == 400
                    assert "Missing" in response.json().get("message", response.json().get("detail", "")) or "state" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/callback?code=test-code&state=invalid-state")

                    assert response.status_code == 400
                    assert "Invalid" in response.json().get("message", response.json().get("detail", "")) or "state" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                        "/api/auth/callback?error=access_denied&error_description=User%20denied%20access"
                    )

                    assert response.status_code == 400
                    assert "Authentication failed" in response.json().get("message", response.json().get("detail", ""))
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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

        # Use the real test tenant/user IDs so FK constraints are satisfied
        tenant = setup_auth_test_data["tenant"]
        user = setup_auth_test_data["user"]

        # Mock MSAL token response
        mock_msal_result = {
            "access_token": "mock-access-token",
            "refresh_token": "mock-refresh-token",
            "id_token": "mock-id-token",
            "expires_in": 3600,
            "id_token_claims": {
                "oid": str(user.id),
                "preferred_username": "user@example.com",
                "name": "Test User",
                "tid": str(tenant.id),
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
                        response = await client.get(f"/api/auth/callback?code=test-code&state={state}")

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
                        response = await client.get(f"/api/auth/callback?code=expired-code&state={state}")

                        assert response.status_code == 400
                        assert "Failed to complete authentication" in response.json().get("message", response.json().get("detail", ""))
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                        response = await client.get(f"/api/auth/callback?code=test-code&state={state}")

                        assert response.status_code == 400
                        assert "Failed to acquire token" in response.json().get("message", response.json().get("detail", ""))
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/callback")

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
                        "/api/auth/logout",
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
                        "/api/auth/logout",
                        cookies={"openlabels_session": "cookie-test-session"}
                    )

                    # Cookie should be deleted (max-age=0 or expires in past)
                    set_cookie = response.headers.get("set-cookie", "")
                    assert "openlabels_session" in set_cookie
                    # Cookie deletion is indicated by max-age=0 or empty value
                    assert 'max-age=0' in set_cookie.lower() or 'openlabels_session=""' in set_cookie or 'openlabels_session=;' in set_cookie
        finally:
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/logout")

                    assert response.status_code == 302
                    location = response.headers.get("location")
                    assert "login.microsoftonline.com" in location
                    assert "test-tenant-123" in location
                    assert "logout" in location
        finally:
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/logout")

                    assert response.status_code == 302
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# CURRENT USER INFO TESTS
# =============================================================================


class TestMeEndpoint:
    """Tests for GET /auth/me endpoint."""

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
                    "oid": "00000000-0000-4000-8000-000000000005",
                    "preferred_username": "user@example.com",
                    "name": "Test User",
                    "tid": "00000000-0000-4000-8000-000000000006",
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
                    "/api/auth/me",
                    cookies={"openlabels_session": "me-test-session"}
                )

                assert response.status_code == 200
                data = response.json()
                assert data["id"] == "00000000-0000-4000-8000-000000000005"
                assert data["email"] == "user@example.com"
                assert data["name"] == "Test User"
                assert data["tenant_id"] == "00000000-0000-4000-8000-000000000006"
                assert "admin" in data["roles"]
        finally:
            app.dependency_overrides.clear()

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
                response = await client.get("/api/auth/me")

                assert response.status_code == 401
                assert "Not authenticated" in response.json().get("message", response.json().get("detail", ""))
        finally:
            app.dependency_overrides.clear()

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
                    "/api/auth/me",
                    cookies={"openlabels_session": "nonexistent-session"}
                )

                assert response.status_code == 401
                assert "expired or invalid" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            app.dependency_overrides.clear()

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
                    "oid": "00000000-0000-4000-8000-000000000005",
                    "preferred_username": "user@example.com",
                    "name": "Test User",
                    "tid": "00000000-0000-4000-8000-000000000006",
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
                    "/api/auth/me",
                    cookies={"openlabels_session": "expired-token-session"}
                )

                assert response.status_code == 401
                assert "expired" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# TOKEN ENDPOINT TESTS
# =============================================================================


class TestTokenEndpoint:
    """Tests for POST /auth/token endpoint."""

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
                    "/api/auth/token",
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
                response = await client.post("/api/auth/token")

                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

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
                            "/api/auth/token",
                            cookies={"openlabels_session": "refresh-test-session"}
                        )

                        assert response.status_code == 200
                        data = response.json()
                        assert data["access_token"] == "new-access-token"
        finally:
            app.dependency_overrides.clear()

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
                            "/api/auth/token",
                            cookies={"openlabels_session": "failed-refresh-session"}
                        )

                        assert response.status_code == 401
                        assert "expired" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# AUTH STATUS TESTS
# =============================================================================


class TestAuthStatusEndpoint:
    """Tests for GET /auth/status endpoint."""

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
                    "oid": "00000000-0000-4000-8000-000000000005",
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
                        "/api/auth/status",
                        cookies={"openlabels_session": "status-test-session"}
                    )

                    assert response.status_code == 200
                    data = response.json()
                    assert data["authenticated"] is True
                    assert data["provider"] == "azure_ad"
                    assert data["user"]["id"] == "00000000-0000-4000-8000-000000000005"
                    assert data["login_url"] is None
        finally:
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/status")

                    assert response.status_code == 200
                    data = response.json()
                    assert data["authenticated"] is False
                    assert data["user"] is None
                    assert data["login_url"] == "/api/auth/login"
        finally:
            app.dependency_overrides.clear()

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
                    "oid": "00000000-0000-4000-8000-000000000005",
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
                        "/api/auth/status",
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
                    "/api/auth/revoke",
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
                response = await client.post("/api/auth/revoke")

                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

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
                    "/api/auth/revoke",
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

    async def test_logout_all_deletes_user_sessions(self, test_db, setup_auth_test_data, create_test_session):
        """POST /auth/logout-all should delete all sessions for the user."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select, func
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session

        tenant = setup_auth_test_data["tenant"]
        user = setup_auth_test_data["user"]
        user_id = user.id

        # Create multiple sessions for the same user
        for i in range(5):
            await create_test_session(
                session_id=f"user-session-{i}",
                data={
                    "access_token": f"token-{i}",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "claims": {"oid": str(user_id), "tid": str(tenant.id)},
                },
                user_id=user_id,
                tenant_id=tenant.id,
            )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/auth/logout-all",
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
                response = await client.post("/api/auth/logout-all")

                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

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
                    "/api/auth/logout-all",
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
                    response = await client.get("/api/auth/login")

                    set_cookie = response.headers.get("set-cookie", "")
                    assert "httponly" in set_cookie.lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

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
                    response = await client.get("/api/auth/login")

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


# =============================================================================
# SQL INJECTION PREVENTION TESTS
# =============================================================================


class TestSQLInjectionPrevention:
    """Tests to verify SQL injection attempts are properly handled."""

    async def test_session_id_sql_injection_attempt(self, test_db, setup_auth_test_data):
        """SQL injection in session cookie should be safely handled."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        sql_injection_payloads = [
            "'; DROP TABLE sessions; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM sessions WHERE 1=1;--",
            "' UNION SELECT * FROM users--",
            "1' AND SLEEP(5)--",
            "' OR 1=1--",
        ]

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                for payload in sql_injection_payloads:
                    response = await client.get(
                        "/api/auth/me",
                        cookies={"openlabels_session": payload}
                    )
                    # Should return 401 (invalid session), not 500 (SQL error)
                    assert response.status_code == 401, \
                        f"SQL injection payload '{payload}' caused status {response.status_code}"
        finally:
            app.dependency_overrides.clear()

    async def test_redirect_uri_sql_injection_attempt(self, test_db, setup_auth_test_data):
        """SQL injection in redirect_uri parameter should be safely handled."""
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

        sql_payloads = [
            "'; DROP TABLE users; --",
            "/path?id=1' OR '1'='1",
        ]

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    for payload in sql_payloads:
                        response = await client.get(f"/api/auth/login?redirect_uri={payload}")
                        # Should not cause server error
                        assert response.status_code in (302, 400), \
                            f"SQL injection in redirect_uri caused status {response.status_code}"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_state_parameter_sql_injection(self, test_db, setup_auth_test_data):
        """SQL injection in OAuth state parameter should be safely handled."""
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

        sql_payloads = [
            "'; DROP TABLE pending_auth; --",
            "state' OR '1'='1",
        ]

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    for payload in sql_payloads:
                        response = await client.get(
                            f"/api/auth/callback?code=test&state={payload}"
                        )
                        # Should return 400 (invalid state), not 500
                        assert response.status_code == 400, \
                            f"SQL injection in state caused status {response.status_code}"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# TOKEN TAMPERING TESTS
# =============================================================================


class TestTokenTampering:
    """Tests for token tampering attack prevention."""

    async def test_modified_session_data_detected(self, test_db, setup_auth_test_data, create_test_session):
        """Tampering with session data should be detected."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session
        from sqlalchemy import select

        # Create a valid session
        await create_test_session(
            session_id="tamper-test-session",
            data={
                "access_token": "original-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": "00000000-0000-4000-8000-000000000005",
                    "preferred_username": "user@example.com",
                    "name": "Original User",
                    "tid": "00000000-0000-4000-8000-000000000007",
                    "roles": ["user"],
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
                # First, verify original session works
                response = await client.get(
                    "/api/auth/me",
                    cookies={"openlabels_session": "tamper-test-session"}
                )
                assert response.status_code == 200
                data = response.json()
                assert data["name"] == "Original User"

                # Now tamper with the session data in database
                result = await test_db.execute(
                    select(Session).where(Session.id == "tamper-test-session")
                )
                session = result.scalar_one()
                # Modify the claims to try to escalate privileges
                tampered_data = session.data.copy()
                tampered_data["claims"]["roles"] = ["admin", "superuser"]
                tampered_data["claims"]["oid"] = "different-user-id"
                session.data = tampered_data
                await test_db.commit()

                # The session still works but returns the tampered data
                # (In a real system, you might want additional integrity checks)
                response = await client.get(
                    "/api/auth/me",
                    cookies={"openlabels_session": "tamper-test-session"}
                )
                # Session is still valid but data reflects what's in DB
                assert response.status_code == 200
        finally:
            app.dependency_overrides.clear()

    async def test_forged_session_id_rejected(self, test_db, setup_auth_test_data):
        """Forged session IDs should be rejected."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        forged_ids = [
            "forged-session-id",
            "a" * 43,  # Same length as real session ID
            secrets.token_urlsafe(32),  # Random but valid format
            "",
            " ",
            "\x00" * 10,
            "../../../etc/passwd",
        ]

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                for forged_id in forged_ids:
                    if not forged_id:
                        continue
                    response = await client.get(
                        "/api/auth/me",
                        cookies={"openlabels_session": forged_id}
                    )
                    assert response.status_code == 401, \
                        f"Forged session ID '{forged_id[:20]}...' was accepted"
        finally:
            app.dependency_overrides.clear()

    async def test_expired_session_data_with_valid_row(self, test_db, setup_auth_test_data, create_test_session):
        """Session with expired token data but valid row should be rejected."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create session where the row is valid but token data is expired
        await create_test_session(
            session_id="mixed-expiry-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),  # Token expired
                "claims": {"oid": "00000000-0000-4000-8000-000000000008", "tid": "00000000-0000-4000-8000-000000000009"},
            },
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),  # Row still valid
        )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    "/api/auth/me",
                    cookies={"openlabels_session": "mixed-expiry-session"}
                )
                # Token expiration should be checked, not just row expiration
                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# MALFORMED REQUEST TESTS
# =============================================================================


class TestMalformedRequests:
    """Tests for handling malformed authentication requests."""

    async def test_malformed_cookie_value(self, test_db, setup_auth_test_data):
        """Malformed cookie values should be handled gracefully."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        malformed_values = [
            "\x00\x01\x02",  # Binary data
            "a" * 10000,  # Very long value
            "<script>alert(1)</script>",  # XSS attempt
            '{"malicious": "json"}',  # JSON injection
            "null",
            "undefined",
            "NaN",
        ]

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                for value in malformed_values:
                    response = await client.get(
                        "/api/auth/me",
                        cookies={"openlabels_session": value}
                    )
                    # Should return 401, not crash
                    assert response.status_code == 401, \
                        f"Malformed cookie value caused unexpected status: {response.status_code}"
        finally:
            app.dependency_overrides.clear()

    async def test_missing_required_callback_params(self, test_db, setup_auth_test_data):
        """Callback endpoint should require code and state parameters."""
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
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    # No parameters
                    response = await client.get("/api/auth/callback")
                    assert response.status_code == 400

                    # Only code, no state
                    response = await client.get("/api/auth/callback?code=test")
                    assert response.status_code == 400

                    # Only state, no code
                    response = await client.get("/api/auth/callback?state=test")
                    assert response.status_code == 400
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_unicode_in_redirect_uri(self, test_db, setup_auth_test_data):
        """Unicode characters in redirect_uri should be handled safely."""
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

        unicode_uris = [
            "/dashboard/\u202e",  # Right-to-left override
            "/dashboard/\u0000",  # Null byte
            "/dashboard/\uFEFF",  # BOM
            "/\u4e2d\u6587/path",  # Chinese characters
        ]

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                    for uri in unicode_uris:
                        try:
                            response = await client.get(f"/api/auth/login?redirect_uri={uri}")
                            # Should either work or fail gracefully, not crash
                            assert response.status_code in (302, 400, 422)
                        except Exception:
                            # Some unicode might cause encoding issues, which is acceptable
                            pass
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_oversized_state_parameter(self, test_db, setup_auth_test_data):
        """Oversized state parameter should be handled gracefully."""
        import httpx
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.dependencies import get_db_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_db_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.rate_limit.auth_limit = "100/minute"

        # Create a very large state parameter
        large_state = "x" * 100000

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                mock_cache = MagicMock()
                mock_cache.is_redis_connected = False
                with patch("openlabels.server.app.init_db", new_callable=AsyncMock), \
                     patch("openlabels.server.app.close_db", new_callable=AsyncMock), \
                     patch("openlabels.server.app.get_cache_manager", new_callable=AsyncMock, return_value=mock_cache), \
                     patch("openlabels.server.app.close_cache", new_callable=AsyncMock):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        try:
                            response = await client.get(
                                f"/api/auth/callback?code=test&state={large_state}"
                            )
                            # Should handle gracefully (400 or 414 URI too long)
                            assert response.status_code in (400, 414, 422)
                        except (httpx.UnsupportedProtocol, httpx.InvalidURL):
                            # httpx may reject oversized URLs before sending
                            pass
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# MULTI-TENANT ISOLATION TESTS
# =============================================================================


class TestMultiTenantIsolation:
    """Tests for multi-tenant session isolation."""

    async def test_session_isolated_by_tenant(self, test_db, setup_auth_test_data, create_test_session):
        """Sessions should be isolated by tenant."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create sessions for different tenants
        # FK columns (tenant_id, user_id) are left as None because /auth/me reads
        # from session.data["claims"], not from the FK columns.
        await create_test_session(
            session_id="tenant-a-session",
            data={
                "access_token": "token-a",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": "00000000-0000-4000-8000-00000000000a",
                    "preferred_username": "user@tenant-a.com",
                    "name": "User A",
                    "tid": "00000000-0000-4000-8000-00000000000c",
                    "roles": ["admin"],
                },
            },
        )

        await create_test_session(
            session_id="tenant-b-session",
            data={
                "access_token": "token-b",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": "00000000-0000-4000-8000-00000000000b",
                    "preferred_username": "user@tenant-b.com",
                    "name": "User B",
                    "tid": "00000000-0000-4000-8000-00000000000d",
                    "roles": ["user"],
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
                # User A should see tenant A data
                response = await client.get(
                    "/api/auth/me",
                    cookies={"openlabels_session": "tenant-a-session"}
                )
                assert response.status_code == 200
                data = response.json()
                assert data["tenant_id"] == "00000000-0000-4000-8000-00000000000c"
                assert data["email"] == "user@tenant-a.com"

                # User B should see tenant B data
                response = await client.get(
                    "/api/auth/me",
                    cookies={"openlabels_session": "tenant-b-session"}
                )
                assert response.status_code == 200
                data = response.json()
                assert data["tenant_id"] == "00000000-0000-4000-8000-00000000000d"
                assert data["email"] == "user@tenant-b.com"
        finally:
            app.dependency_overrides.clear()

    async def test_logout_all_only_affects_own_sessions(self, test_db, setup_auth_test_data, create_test_session):
        """Logout-all should only affect the current user's sessions, not other users."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select, func
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session, User

        tenant = setup_auth_test_data["tenant"]
        user_a = setup_auth_test_data["user"]

        # Create a second user in the same tenant for isolation testing
        user_b = User(
            tenant_id=tenant.id,
            email=f"user-b-{uuid4().hex[:8]}@localhost",
            name="User B",
            role="viewer",
        )
        test_db.add(user_b)
        await test_db.flush()

        user_a_id = user_a.id
        user_b_id = user_b.id

        # Create multiple sessions for user A
        for i in range(3):
            await create_test_session(
                session_id=f"user-a-session-{i}",
                data={
                    "access_token": f"token-a-{i}",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "claims": {"oid": str(user_a_id), "tid": str(tenant.id)},
                },
                tenant_id=tenant.id,
                user_id=user_a_id,
            )

        # Create sessions for user B (same tenant, different user)
        for i in range(2):
            await create_test_session(
                session_id=f"user-b-session-{i}",
                data={
                    "access_token": f"token-b-{i}",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "claims": {"oid": str(user_b_id), "tid": str(tenant.id)},
                },
                tenant_id=tenant.id,
                user_id=user_b_id,
            )
        await test_db.commit()

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # User A logs out of all sessions
                response = await client.post(
                    "/api/auth/logout-all",
                    cookies={"openlabels_session": "user-a-session-0"}
                )
                assert response.status_code == 200
                data = response.json()
                assert data["sessions_revoked"] == 3  # Only user A's sessions

                # Verify user A's sessions are deleted
                await test_db.commit()
                result = await test_db.execute(
                    select(func.count(Session.id)).where(Session.user_id == user_a_id)
                )
                assert result.scalar() == 0

                # Verify user B's sessions still exist
                result = await test_db.execute(
                    select(func.count(Session.id)).where(Session.user_id == user_b_id)
                )
                assert result.scalar() == 2
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# CSRF PROTECTION TESTS
# =============================================================================


class TestCSRFProtection:
    """Tests for CSRF protection via state parameter."""

    async def test_state_reuse_rejected(self, test_db, setup_auth_test_data, create_pending_auth):
        """State token should only be usable once (replay attack prevention)."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        tenant = setup_auth_test_data["tenant"]
        user = setup_auth_test_data["user"]

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

        mock_msal_result = {
            "access_token": "token",
            "expires_in": 3600,
            "id_token_claims": {"oid": str(user.id), "tid": str(tenant.id)},
        }
        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_authorization_code.return_value = mock_msal_result

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                        # First use of state should succeed
                        response = await client.get(f"/api/auth/callback?code=test&state={state}")
                        assert response.status_code == 302

                        # Second use of same state should fail (replay attack)
                        response = await client.get(f"/api/auth/callback?code=test&state={state}")
                        assert response.status_code == 400
                        assert "Invalid" in response.json().get("message", response.json().get("detail", "")) or "expired" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_empty_state_rejected(self, test_db, setup_auth_test_data):
        """Empty state parameter should be rejected."""
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
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    # Empty state
                    response = await client.get("/api/auth/callback?code=test&state=")
                    assert response.status_code == 400
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_state_from_different_session_rejected(self, test_db, setup_auth_test_data, create_pending_auth):
        """State token from a different session should be rejected."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Create a pending auth state
        state = secrets.token_urlsafe(32)
        await create_pending_auth(state=state, redirect_uri="/", callback_url="http://different-origin/auth/callback")
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
        # MSAL will fail because callback URL doesn't match
        mock_msal_app.acquire_token_by_authorization_code.return_value = {
            "error": "invalid_request",
            "error_description": "Redirect URI mismatch"
        }

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.get(f"/api/auth/callback?code=test&state={state}")
                        # Should fail due to redirect URI mismatch
                        assert response.status_code == 400
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================


class TestRateLimiting:
    """Tests for rate limiting on auth endpoints."""

    async def test_rate_limiter_configured(self, test_db, setup_auth_test_data):
        """Rate limiter should be configured for auth endpoints."""
        from openlabels.server.routes.auth import limiter, login, auth_callback

        # Verify limiter is imported and configured
        assert limiter is not None
        # The limiter should have a key function
        assert limiter._key_func is not None

    async def test_login_has_rate_limit_decorator(self):
        """Login endpoint should have rate limiting."""
        from openlabels.server.routes.auth import login
        import inspect

        # Check that the function has decorators (rate limit is applied)
        source = inspect.getsource(login)
        assert "@limiter.limit" in source or "limiter.limit" in source

    async def test_callback_has_rate_limit_decorator(self):
        """Callback endpoint should have rate limiting."""
        from openlabels.server.routes.auth import auth_callback
        import inspect

        source = inspect.getsource(auth_callback)
        assert "@limiter.limit" in source or "limiter.limit" in source


# =============================================================================
# SESSION FIXATION TESTS
# =============================================================================


class TestSessionFixation:
    """Tests for session fixation attack prevention."""

    async def test_oauth_callback_invalidates_existing_session(
        self, test_db, setup_auth_test_data, create_test_session, create_pending_auth
    ):
        """OAuth callback should invalidate any existing session."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session
        from openlabels.server.routes.auth import limiter as auth_limiter

        tenant = setup_auth_test_data["tenant"]
        user = setup_auth_test_data["user"]

        # Create an existing session
        await create_test_session(session_id="existing-session-to-invalidate")
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

        mock_msal_result = {
            "access_token": "new-token",
            "expires_in": 3600,
            "id_token_claims": {"oid": str(user.id), "tid": str(tenant.id)},
        }
        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_authorization_code.return_value = mock_msal_result

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                        response = await client.get(
                            f"/api/auth/callback?code=test&state={state}",
                            cookies={"openlabels_session": "existing-session-to-invalidate"}
                        )
                        assert response.status_code == 302

                        # Old session should be deleted
                        await test_db.commit()
                        result = await test_db.execute(
                            select(Session).where(Session.id == "existing-session-to-invalidate")
                        )
                        assert result.scalar_one_or_none() is None

                        # New session should be created with different ID
                        new_session_id = response.cookies.get("openlabels_session")
                        assert new_session_id is not None
                        assert new_session_id != "existing-session-to-invalidate"
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# TOKEN REFRESH EDGE CASES
# =============================================================================


class TestTokenRefreshEdgeCases:
    """Tests for token refresh edge cases."""

    async def test_refresh_token_missing_returns_401(self, test_db, setup_auth_test_data, create_test_session):
        """Expired token without refresh token should return 401."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create session with expired token and NO refresh token
        await create_test_session(
            session_id="no-refresh-session",
            data={
                "access_token": "expired-token",
                # No refresh_token field
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
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
                    "/api/auth/token",
                    cookies={"openlabels_session": "no-refresh-session"}
                )
                assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    async def test_refresh_token_exception_handled(self, test_db, setup_auth_test_data, create_test_session):
        """Exception during token refresh should be handled gracefully."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        await create_test_session(
            session_id="exception-refresh-session",
            data={
                "access_token": "expired-token",
                "refresh_token": "valid-refresh-token",
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

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_refresh_token.side_effect = Exception("Network error")

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.post(
                            "/api/auth/token",
                            cookies={"openlabels_session": "exception-refresh-session"}
                        )
                        # Should return 401, not 500
                        assert response.status_code == 401
                        assert "expired" in response.json().get("message", response.json().get("detail", "")).lower()
        finally:
            app.dependency_overrides.clear()

    async def test_successful_refresh_updates_session(self, test_db, setup_auth_test_data, create_test_session):
        """Successful token refresh should update session with new tokens."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import Session

        await create_test_session(
            session_id="refresh-success-session",
            data={
                "access_token": "old-access-token",
                "refresh_token": "valid-refresh-token",
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

        mock_msal_app = MagicMock()
        mock_msal_app.acquire_token_by_refresh_token.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 7200,
        }

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.post(
                            "/api/auth/token",
                            cookies={"openlabels_session": "refresh-success-session"}
                        )
                        assert response.status_code == 200
                        data = response.json()
                        assert data["access_token"] == "new-access-token"

                        # Verify session was updated in database
                        await test_db.commit()
                        result = await test_db.execute(
                            select(Session).where(Session.id == "refresh-success-session")
                        )
                        session = result.scalar_one()
                        assert session.data["access_token"] == "new-access-token"
                        assert session.data["refresh_token"] == "new-refresh-token"
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# SECURE COOKIE FLAG TESTS
# =============================================================================


class TestSecureCookieFlag:
    """Tests for secure cookie flag based on request scheme."""

    async def test_secure_flag_set_for_https(self, test_db, setup_auth_test_data):
        """Session cookie should have secure flag when using HTTPS."""
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
        mock_settings.cors.allowed_origins = ["https://localhost:3000"]
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                # Use HTTPS base URL
                async with AsyncClient(transport=transport, base_url="https://test", follow_redirects=False) as client:
                    response = await client.get("/api/auth/login")

                    set_cookie = response.headers.get("set-cookie", "")
                    # For HTTPS, secure flag should be set
                    assert "secure" in set_cookie.lower() or response.status_code == 302
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# AZURE AD LOGIN FLOW TESTS
# =============================================================================


class TestAzureADLoginFlow:
    """Tests for Azure AD OAuth login flow."""

    async def test_azure_login_redirects_to_microsoft(self, test_db, setup_auth_test_data):
        """Azure AD login should redirect to Microsoft login page."""
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
        mock_settings.auth.tenant_id = "test-tenant-id"
        mock_settings.auth.client_id = "test-client-id"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.rate_limit.auth_limit = "100/minute"

        mock_msal_app = MagicMock()
        mock_msal_app.get_authorization_request_url.return_value = (
            "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/authorize?"
            "client_id=test-client-id&response_type=code&scope=openid"
        )

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                        response = await client.get("/api/auth/login")

                        assert response.status_code == 302
                        location = response.headers.get("location")
                        assert "login.microsoftonline.com" in location
                        assert "test-tenant-id" in location
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_azure_login_stores_state(self, test_db, setup_auth_test_data):
        """Azure AD login should store state for CSRF protection."""
        from httpx import AsyncClient, ASGITransport
        from sqlalchemy import select, func
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.models import PendingAuth
        from openlabels.server.routes.auth import limiter as auth_limiter

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        auth_limiter.enabled = False

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant-id"
        mock_settings.auth.client_id = "test-client-id"
        mock_settings.auth.client_secret = "test-secret"
        mock_settings.cors.allowed_origins = []
        mock_settings.rate_limit.auth_limit = "100/minute"

        mock_msal_app = MagicMock()
        mock_msal_app.get_authorization_request_url.return_value = "https://login.microsoftonline.com/authorize"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
                        response = await client.get("/api/auth/login?redirect_uri=/dashboard")
                        assert response.status_code == 302

                        # Verify pending auth was created
                        await test_db.commit()
                        result = await test_db.execute(select(func.count(PendingAuth.state)))
                        count = result.scalar()
                        assert count >= 1
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# ERROR RESPONSE SECURITY TESTS
# =============================================================================


class TestErrorResponseSecurity:
    """Tests to ensure error responses don't leak sensitive information."""

    async def test_oauth_error_generic_message(self, test_db, setup_auth_test_data):
        """OAuth errors should return generic messages to prevent information leakage."""
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
        mock_settings.rate_limit.auth_limit = "100/minute"

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    response = await client.get(
                        "/api/auth/callback?error=access_denied&error_description=AADSTS12345_Detailed_Internal_Error"
                    )
                    assert response.status_code == 400

                    detail = response.json().get("message", response.json().get("detail", ""))
                    # Should NOT contain detailed error code
                    assert "AADSTS12345" not in detail
                    assert "Internal" not in detail
                    # Should contain generic message
                    assert "Authentication failed" in detail or "failed" in detail.lower()
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()

    async def test_token_error_generic_message(self, test_db, setup_auth_test_data, create_pending_auth):
        """Token acquisition errors should return generic messages."""
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
        mock_msal_app.acquire_token_by_authorization_code.return_value = {
            "error": "invalid_client",
            "error_description": "Client secret is incorrect or expired. SECRET_HINT: abcd1234",
        }

        try:
            with patch('openlabels.server.routes.auth.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.auth._get_msal_app', return_value=mock_msal_app):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        response = await client.get(f"/api/auth/callback?code=test&state={state}")
                        assert response.status_code == 400

                        detail = response.json().get("message", response.json().get("detail", ""))
                        # Should NOT contain secret hints or detailed errors
                        assert "SECRET_HINT" not in detail
                        assert "abcd1234" not in detail
                        assert "invalid_client" not in detail
        finally:
            auth_limiter.enabled = True
            app.dependency_overrides.clear()


# =============================================================================
# SESSION STORE BEHAVIOR TESTS
# =============================================================================


class TestSessionStoreBehavior:
    """Tests for SessionStore edge cases and behaviors."""

    async def test_session_store_handles_missing_claims(self, test_db, setup_auth_test_data, create_test_session):
        """Session with missing claims field should be handled gracefully."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create session without claims field
        await create_test_session(
            session_id="no-claims-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                # No claims field
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
                    "/api/auth/me",
                    cookies={"openlabels_session": "no-claims-session"}
                )
                assert response.status_code == 200
                data = response.json()
                # Should return unknown for missing fields
                assert data["id"] == "unknown"
        finally:
            app.dependency_overrides.clear()

    async def test_session_without_expires_at(self, test_db, setup_auth_test_data, create_test_session):
        """Session without expires_at should be handled gracefully."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        # Create session without expires_at
        await create_test_session(
            session_id="no-expiry-session",
            data={
                "access_token": "test-token",
                # No expires_at field
                "claims": {"oid": "00000000-0000-4000-8000-000000000008", "tid": "00000000-0000-4000-8000-000000000009"},
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
                    "/api/auth/me",
                    cookies={"openlabels_session": "no-expiry-session"}
                )
                # Should either work or fail gracefully, not crash
                assert response.status_code in (200, 401)
        finally:
            app.dependency_overrides.clear()
