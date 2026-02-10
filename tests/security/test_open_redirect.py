"""
Tests for open redirect vulnerabilities.

Open redirect attacks occur when an application accepts user-controlled
URLs for redirection without validation, allowing attackers to redirect
users to malicious sites after authentication.
"""

import pytest
from unittest.mock import Mock, MagicMock

from openlabels.server.routes.auth import validate_redirect_uri


class TestValidateRedirectUri:
    """Tests for the validate_redirect_uri function."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock request with standard settings."""
        request = Mock()
        request.url.netloc = "localhost:8000"
        return request

    @pytest.fixture
    def mock_settings(self):
        """Mock settings with allowed origins."""
        settings = Mock()
        settings.cors.allowed_origins = [
            "http://localhost:3000",
            "http://localhost:8000",
            "https://app.example.com",
        ]
        return settings

    def test_none_redirect_returns_root(self, mock_request, mock_settings):
        """None redirect_uri should return root path."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)
            result = validate_redirect_uri(None, mock_request)
            assert result == "/"

    def test_empty_redirect_returns_root(self, mock_request, mock_settings):
        """Empty redirect_uri should return root path."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)
            result = validate_redirect_uri("", mock_request)
            assert result == "/"

    def test_relative_path_allowed(self, mock_request, mock_settings):
        """Relative paths starting with / should be allowed."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            safe_paths = ["/", "/dashboard", "/ui/scans", "/ui/results?page=1"]
            for path in safe_paths:
                result = validate_redirect_uri(path, mock_request)
                assert result == path, f"Path {path} should be allowed"

    def test_protocol_relative_url_blocked(self, mock_request, mock_settings):
        """Protocol-relative URLs (//evil.com) should be blocked."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            result = validate_redirect_uri("//evil.com/phishing", mock_request)
            assert result == "/", "Protocol-relative URL should be blocked"

    def test_external_url_blocked(self, mock_request, mock_settings):
        """External URLs not in whitelist should be blocked."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            malicious_urls = [
                "https://evil.com/phishing",
                "http://attacker.com/steal",
                "https://malware.net/payload",
            ]
            for url in malicious_urls:
                result = validate_redirect_uri(url, mock_request)
                assert result == "/", f"External URL {url} should be blocked"

    def test_same_origin_url_allowed(self, mock_request, mock_settings):
        """URLs to the same origin should be allowed."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            result = validate_redirect_uri("http://localhost:8000/dashboard", mock_request)
            assert result == "http://localhost:8000/dashboard"

    def test_whitelisted_origin_allowed(self, mock_request, mock_settings):
        """URLs in CORS whitelist should be allowed."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            result = validate_redirect_uri("https://app.example.com/callback", mock_request)
            assert result == "https://app.example.com/callback"

    def test_javascript_url_blocked(self, mock_request, mock_settings):
        """JavaScript URLs should be blocked."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            malicious_urls = [
                "javascript:alert('xss')",
                "JAVASCRIPT:alert(1)",
            ]
            for url in malicious_urls:
                result = validate_redirect_uri(url, mock_request)
                assert result == "/", f"JavaScript URL {url} should be blocked"

    def test_data_url_blocked(self, mock_request, mock_settings):
        """Data URLs should be blocked."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            result = validate_redirect_uri("data:text/html,<script>alert(1)</script>", mock_request)
            assert result == "/", "Data URL should be blocked"

    def test_ftp_url_blocked(self, mock_request, mock_settings):
        """Non-HTTP schemes should be blocked."""
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("openlabels.server.routes.auth.get_settings", lambda: mock_settings)

            result = validate_redirect_uri("ftp://evil.com/malware", mock_request)
            assert result == "/", "FTP URL should be blocked"


class TestOpenRedirectIntegration:
    """Integration tests for open redirect prevention."""

    async def test_login_endpoint_validates_redirect(self):
        """Login endpoint should use validated redirect_uri."""
        from unittest.mock import AsyncMock, MagicMock
        from httpx import AsyncClient, ASGITransport
        from openlabels.server.app import app
        from openlabels.server.db import get_session
        from openlabels.server.app import limiter as app_limiter
        from openlabels.server.routes.auth import limiter as auth_limiter

        # Create a mock DB session so the endpoint doesn't hit real DB
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
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
            async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                # Test with malicious redirect
                response = await client.get(
                    "/api/auth/login",
                    params={"redirect": "https://evil.com/phishing"},
                    follow_redirects=False,
                )
                # Should either redirect to safe URL or reject
                if response.status_code in (302, 307):
                    location = response.headers.get("location", "")
                    assert "evil.com" not in location, \
                        "Login endpoint allowed redirect to external site"
        finally:
            app.dependency_overrides.pop(get_session, None)
            app_limiter.enabled = original_app
            auth_limiter.enabled = original_auth

    async def test_callback_rejects_malicious_redirect_override(self):
        """OAuth callback should not use untrusted redirect from query."""
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
            async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                # Attacker tries to inject redirect in callback
                response = await client.get(
                    "/api/auth/callback",
                    params={
                        "code": "fake-code",
                        "redirect": "https://evil.com/steal-tokens",
                    },
                    follow_redirects=False,
                )
                # Should not redirect to evil.com
                if response.status_code in (302, 307):
                    location = response.headers.get("location", "")
                    assert "evil.com" not in location, \
                        "Callback allowed attacker to override redirect"
        finally:
            app.dependency_overrides.pop(get_session, None)
            app_limiter.enabled = original_app
            auth_limiter.enabled = original_auth
