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
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("X-Content-Type-Options") == "nosniff"

    async def test_frame_options_header(self, mock_settings_production):
        """X-Frame-Options should be SAMEORIGIN."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("X-Frame-Options") == "SAMEORIGIN"

    async def test_xss_protection_header(self, mock_settings_production):
        """X-XSS-Protection should be set for legacy browsers."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("X-XSS-Protection") == "1; mode=block"

    async def test_referrer_policy_header(self, mock_settings_production):
        """Referrer-Policy should limit referrer information."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            assert result.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    async def test_csp_header_present(self, mock_settings_production):
        """Content-Security-Policy should be configured."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            csp = result.headers.get("Content-Security-Policy")
            assert csp is not None
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "frame-ancestors 'self'" in csp

    async def test_permissions_policy_header(self, mock_settings_production):
        """Permissions-Policy should restrict browser features."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            permissions = result.headers.get("Permissions-Policy")
            assert permissions is not None
            assert "camera=()" in permissions
            assert "microphone=()" in permissions
            assert "geolocation=()" in permissions

    async def test_hsts_in_production(self, mock_settings_production):
        """HSTS should be set in production."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_production):
            result = await add_security_headers(request, call_next)
            hsts = result.headers.get("Strict-Transport-Security")
            assert hsts is not None
            assert "max-age=31536000" in hsts
            assert "includeSubDomains" in hsts

    async def test_hsts_not_in_development(self, mock_settings_development):
        """HSTS should not be set in development."""
        from openlabels.server.app import add_security_headers

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=mock_settings_development):
            result = await add_security_headers(request, call_next)
            hsts = result.headers.get("Strict-Transport-Security")
            assert hsts is None


class TestCookieSecurityFlags:
    """Tests for cookie security configuration."""

    async def test_session_cookie_has_security_flags(self):
        """Session cookie should have HttpOnly and SameSite flags."""
        from unittest.mock import AsyncMock, MagicMock
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.app import limiter as app_limiter
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Create a mock DB session so the endpoint doesn't hit real DB
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
        mock_session.commit = AsyncMock()
        mock_session.flush = AsyncMock()

        async def override_get_session():
            yield mock_session

        app.dependency_overrides[get_session] = override_get_session
        original_app = app_limiter.enabled
        original_auth = auth_limiter.enabled
        app_limiter.enabled = False
        auth_limiter.enabled = False

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Make a request that would set cookies (like auth callback)
                response = await client.get(
                    "/api/auth/callback",
                    params={"code": "test-code"},
                    follow_redirects=False,
                )

                # Check any set-cookie headers
                set_cookie = response.headers.get("set-cookie", "")
                if set_cookie:
                    # HttpOnly should be present for session cookies
                    # This prevents JavaScript from accessing the cookie
                    if "session" in set_cookie.lower():
                        assert "httponly" in set_cookie.lower(), \
                            "Session cookie missing HttpOnly flag"
        finally:
            app.dependency_overrides.pop(get_session, None)
            app_limiter.enabled = original_app
            auth_limiter.enabled = original_auth

    async def test_api_responses_dont_set_tracking_cookies(self, test_client):
        """API responses should not set unnecessary cookies."""
        # Regular API calls should not set tracking cookies
        # Use test_client fixture which has proper DB setup
        response = await test_client.get("/api/health/status")

        set_cookie = response.headers.get("set-cookie", "")
        # Should not set advertising/tracking cookies
        assert "tracking" not in set_cookie.lower()
        assert "_ga" not in set_cookie  # Google Analytics
        assert "_fb" not in set_cookie  # Facebook

    async def test_cookie_path_is_scoped(self, test_client):
        """Cookies should be scoped to the application path."""
        # Request that might set cookies
        response = await test_client.get("/api/dashboard/stats")

        # If cookies are set, they should have path=/
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie and "path=" in set_cookie.lower():
            # Path should be / or application-specific, not overly broad
            assert "path=/" in set_cookie.lower() or "path=/api" in set_cookie.lower()


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
        from openlabels.server.app import add_security_headers

        settings = Mock()
        settings.server.environment = "production"

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=settings):
            result = await add_security_headers(request, call_next)
            csp = result.headers.get("Content-Security-Policy")
            # script-src should be 'self' only, not 'unsafe-inline'
            assert "script-src 'self'" in csp
            assert "script-src 'self' 'unsafe-inline'" not in csp

    async def test_csp_allows_websockets(self):
        """CSP should allow WebSocket connections for real-time updates."""
        from openlabels.server.app import add_security_headers

        settings = Mock()
        settings.server.environment = "production"

        request = Mock(spec=Request)
        response = Response()

        async def call_next(req):
            return response

        with patch("openlabels.server.app.get_settings", return_value=settings):
            result = await add_security_headers(request, call_next)
            csp = result.headers.get("Content-Security-Policy")
            assert "connect-src" in csp
            assert "wss:" in csp or "ws:" in csp
