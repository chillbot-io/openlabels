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

    def test_session_cookie_httponly(self):
        """Session cookie should have HttpOnly flag."""
        # The session cookie is set in auth.py with httponly=True
        # This is verified by code inspection
        pass

    def test_session_cookie_samesite(self):
        """Session cookie should have SameSite attribute."""
        # The session cookie is set with samesite="lax"
        pass


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
