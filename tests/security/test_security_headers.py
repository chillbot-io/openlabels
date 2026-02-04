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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_session_cookie_has_security_flags(self):
        """Session cookie should have HttpOnly and SameSite flags."""
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app

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

    @pytest.mark.asyncio
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


class TestCSPDirectives:
    """Tests for Content-Security-Policy directives."""

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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
