"""
Tests for security header configuration.

Security headers provide defense-in-depth protection against
various web attacks like XSS, clickjacking, and MIME sniffing.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import Request
from fastapi.responses import Response


class TestSecurityHeadersMiddleware:
    """Tests for the security headers middleware."""

    @pytest.fixture
    def mock_settings_production(self):
        """Mock settings for production environment."""
        settings = Mock()
        settings.server.environment = "production"
        return settings

    @pytest.fixture
    def mock_settings_development(self):
        """Mock settings for development environment."""
        settings = Mock()
        settings.server.environment = "development"
        return settings

    async def test_content_type_options_header(self, mock_settings_production):
        """X-Content-Type-Options should be set to nosniff."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("X-Content-Type-Options") == "nosniff"

    async def test_frame_options_header(self, mock_settings_production):
        """X-Frame-Options should be SAMEORIGIN."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("X-Frame-Options") == "SAMEORIGIN"

    async def test_xss_protection_header(self, mock_settings_production):
        """X-XSS-Protection should be set for legacy browsers."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("X-XSS-Protection") == "1; mode=block"

    async def test_referrer_policy_header(self, mock_settings_production):
        """Referrer-Policy should limit referrer information."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    async def test_csp_header_present(self, mock_settings_production):
        """Content-Security-Policy should be configured."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            csp = result.headers.get("Content-Security-Policy")
            assert csp is not None
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "frame-ancestors 'self'" in csp

    async def test_permissions_policy_header(self, mock_settings_production):
        """Permissions-Policy should restrict browser features."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            permissions = result.headers.get("Permissions-Policy")
            assert permissions is not None
            assert "camera=()" in permissions
            assert "microphone=()" in permissions
            assert "geolocation=()" in permissions

    async def test_hsts_in_production(self, mock_settings_production):
        """HSTS should be set in production."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            hsts = result.headers.get("Strict-Transport-Security")
            assert hsts is not None
            assert "max-age=31536000" in hsts
            assert "includeSubDomains" in hsts

    async def test_hsts_not_in_development(self, mock_settings_development):
        """HSTS should not be set in development."""
        from openlabels.server.middleware.stack import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=mock_settings_development):
            result = await add_security_headers(request, call_next)
            hsts = result.headers.get("Strict-Transport-Security")
            assert hsts is None


class TestCookieSecurityFlags:
    """Tests for cookie security configuration."""

    async def test_session_cookie_has_security_flags(self):
        """Session cookie should have HttpOnly and SameSite flags when set."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.app import limiter as app_limiter
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Verify the cookie settings are correct in the source code by
        # testing the dev mode login flow which sets a session cookie.
        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"
        mock_settings.auth.tenant_id = None
        mock_settings.auth.client_id = None
        mock_settings.auth.client_secret = None
        mock_settings.server.environment = "development"
        mock_settings.server.debug = True
        mock_settings.server.host = "localhost"
        mock_settings.rate_limit.enabled = False
        mock_settings.rate_limit.auth_limit = "100/minute"
        mock_settings.rate_limit.api_limit = "100/minute"
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]
        mock_settings.cors.allow_credentials = True
        mock_settings.cors.allow_methods = ["*"]
        mock_settings.cors.allow_headers = ["*"]
        mock_settings.security.max_request_size_mb = 10

        # Create a mock DB session
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_result.scalar = MagicMock(return_value=0)
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.flush = AsyncMock()
        # Mock SessionStore and PendingAuthStore methods
        mock_session.get = AsyncMock(return_value=None)

        async def override_get_session():
            yield mock_session

        app.dependency_overrides[get_session] = override_get_session
        original_app = app_limiter.enabled
        original_auth = auth_limiter.enabled
        app_limiter.enabled = False
        auth_limiter.enabled = False

        try:
            with patch("openlabels.server.routes.auth.get_settings", return_value=mock_settings), \
                 patch("openlabels.server.lifespan.init_db", new_callable=AsyncMock), \
                 patch("openlabels.server.lifespan.close_db", new_callable=AsyncMock), \
                 patch("openlabels.server.lifespan.get_cache_manager", new_callable=AsyncMock, return_value=MagicMock(is_redis_connected=False)), \
                 patch("openlabels.server.lifespan.close_cache", new_callable=AsyncMock):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                    # Use the dev mode login which sets a session cookie
                    response = await client.get(
                        "/api/auth/login",
                        follow_redirects=False,
                    )

                    # Check set-cookie headers
                    set_cookie = response.headers.get("set-cookie", "")
                    if set_cookie and "openlabels_session" in set_cookie:
                        assert "httponly" in set_cookie.lower(), \
                            f"Session cookie missing HttpOnly flag: {set_cookie}"
                        assert "samesite" in set_cookie.lower(), \
                            f"Session cookie missing SameSite flag: {set_cookie}"
        finally:
            app.dependency_overrides.pop(get_session, None)
            app_limiter.enabled = original_app
            auth_limiter.enabled = original_auth

    async def test_api_responses_dont_set_tracking_cookies(self, test_client):
        """API responses should not set unnecessary tracking or advertising cookies."""
        # Test multiple endpoints to ensure no tracking cookies are set anywhere
        endpoints = ["/api/health/status", "/api/targets", "/api/dashboard/stats"]

        for endpoint in endpoints:
            response = await test_client.get(endpoint)
            set_cookie = response.headers.get("set-cookie", "")
            # Should not set advertising/tracking cookies
            tracking_patterns = ["tracking", "_ga", "_fb", "_gid", "analytics", "fbp"]
            for pattern in tracking_patterns:
                assert pattern not in set_cookie.lower(), \
                    f"Endpoint {endpoint} set tracking cookie matching '{pattern}': {set_cookie}"

    async def test_regular_api_calls_dont_set_session_cookies(self, test_client):
        """Regular API calls (using token auth) should not set session cookies."""
        # test_client uses dependency overrides for auth, so no session cookies needed
        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200

        set_cookie = response.headers.get("set-cookie", "")
        # Regular API calls using token/dependency auth should not set session cookies
        assert "openlabels_session" not in set_cookie, \
            f"Regular API call should not set session cookie: {set_cookie}"


class TestCookieSecurityAttributes:
    """Detailed tests for cookie security attributes."""

    async def test_no_sensitive_data_in_cookie_values(self, test_client):
        """Cookie values should not contain sensitive data."""
        response = await test_client.get("/api/health/status")

        set_cookie = response.headers.get("set-cookie", "")

        # Cookies should not contain:
        # - Passwords
        # - API keys
        # - User PII
        # - Unencoded tokens
        sensitive_patterns = [
            "password=",
            "apikey=",
            "api_key=",
            "secret=",
            "ssn=",
            "credit_card=",
        ]

        for pattern in sensitive_patterns:
            assert pattern not in set_cookie.lower(), \
                f"Cookie contains sensitive pattern: {pattern}"


class TestCSPDirectives:
    """Tests for Content-Security-Policy directives."""

    async def test_csp_blocks_inline_scripts(self):
        """CSP should block inline scripts by not including 'unsafe-inline' for scripts."""
        from openlabels.server.middleware.stack import add_security_headers

        settings = Mock()
        settings.server.environment = "production"

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=settings):
            result = await add_security_headers(request, call_next)
            csp = result.headers.get("Content-Security-Policy")
            # script-src should be 'self' only, not 'unsafe-inline'
            assert "script-src 'self'" in csp
            assert "script-src 'self' 'unsafe-inline'" not in csp

    async def test_csp_allows_websockets(self):
        """CSP should allow WebSocket connections for real-time updates."""
        from openlabels.server.middleware.stack import add_security_headers

        settings = Mock()
        settings.server.environment = "production"

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.middleware.stack.get_settings", return_value=settings):
            result = await add_security_headers(request, call_next)
            csp = result.headers.get("Content-Security-Policy")
            assert "connect-src" in csp
            assert "wss:" in csp or "ws:" in csp
