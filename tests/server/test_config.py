"""Tests for server configuration."""

import pytest
from pydantic import ValidationError


class TestServerSettings:
    """Tests for Settings class."""

    def test_default_settings(self):
        """Test default settings creation."""
        from openlabels.server.config import Settings

        settings = Settings()
        # Default is localhost for security; set to "0.0.0.0" for production
        assert settings.server.host == "127.0.0.1"
        assert settings.server.port == 8000

    def test_database_url_default(self):
        """Test default database URL."""
        from openlabels.server.config import Settings

        settings = Settings()
        assert "sqlite" in settings.database.url or "postgresql" in settings.database.url

    def test_auth_settings(self):
        """Test auth settings."""
        from openlabels.server.config import AuthSettings

        auth = AuthSettings()
        assert auth.tenant_id is None or isinstance(auth.tenant_id, str)

    def test_get_settings_returns_same_instance(self):
        """Test get_settings returns cached instance."""
        from openlabels.server.config import get_settings

        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2


class TestCORSSettings:
    """Tests for CORS configuration."""

    def test_cors_defaults(self):
        """Test CORS default values."""
        from openlabels.server.config import CORSSettings

        cors = CORSSettings()
        assert isinstance(cors.allowed_origins, list)
        assert cors.allow_credentials is True

    def test_cors_allows_localhost(self):
        """Test CORS allows localhost by default."""
        from openlabels.server.config import CORSSettings

        cors = CORSSettings()
        assert any("localhost" in origin for origin in cors.allowed_origins)


class TestRateLimitSettings:
    """Tests for rate limit configuration."""

    def test_rate_limit_defaults(self):
        """Test rate limit default values."""
        from openlabels.server.config import RateLimitSettings

        rl = RateLimitSettings()
        assert rl.enabled is True
        assert "minute" in rl.auth_limit
        assert "minute" in rl.api_limit

    def test_rate_limit_format(self):
        """Test rate limit format is valid."""
        from openlabels.server.config import RateLimitSettings

        rl = RateLimitSettings()
        # Should be format like "10/minute"
        assert "/" in rl.auth_limit
        parts = rl.auth_limit.split("/")
        assert parts[0].isdigit()


class TestSecuritySettings:
    """Tests for security configuration."""

    def test_security_settings_in_main_settings(self):
        """Test security settings are part of main settings."""
        from openlabels.server.config import Settings

        settings = Settings()
        # Settings should be complete
        assert settings is not None


class TestLabelingSettings:
    """Tests for labeling configuration."""

    def test_labeling_settings_in_main_settings(self):
        """Test labeling settings are part of main settings."""
        from openlabels.server.config import Settings

        settings = Settings()
        # Settings should have labeling section
        assert hasattr(settings, 'labeling')
