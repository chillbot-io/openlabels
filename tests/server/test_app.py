"""
Tests for FastAPI application configuration components.

Tests actual behavior of settings loading, validation, and defaults.
"""

import os
import pytest
from unittest.mock import patch


class TestServerSettings:
    """Tests for ServerSettings behavior."""

    def test_defaults_to_localhost_for_security(self):
        """Server should default to 127.0.0.1, not 0.0.0.0 for security."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()

        assert settings.host == "127.0.0.1", "Should default to localhost, not expose to network"
        assert settings.port == 8000

    def test_debug_defaults_to_false(self):
        """Debug should be off by default for security."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()

        assert settings.debug is False

    def test_environment_must_be_valid(self):
        """Environment must be one of the allowed values."""
        from openlabels.server.config import ServerSettings
        from pydantic import ValidationError

        # Valid values should work
        for env in ["development", "staging", "production"]:
            settings = ServerSettings(environment=env)
            assert settings.environment == env

        # Invalid should raise
        with pytest.raises(ValidationError):
            ServerSettings(environment="invalid")


class TestDatabaseSettings:
    """Tests for DatabaseSettings."""

    def test_has_sensible_pool_defaults(self):
        """Pool settings should be reasonable defaults."""
        from openlabels.server.config import DatabaseSettings

        settings = DatabaseSettings()

        assert settings.pool_size >= 1
        assert settings.max_overflow >= 0
        assert settings.pool_size <= 20, "Pool size too large for default"


class TestAuthSettings:
    """Tests for AuthSettings - security critical."""

    def test_defaults_to_disabled_for_safety(self):
        """Auth should default to 'none' so app doesn't fail without config."""
        from openlabels.server.config import AuthSettings

        settings = AuthSettings()

        assert settings.provider == "none"

    def test_authority_requires_tenant_id(self):
        """Authority URL should only be generated when tenant_id exists."""
        from openlabels.server.config import AuthSettings

        # Without tenant_id
        settings = AuthSettings(tenant_id=None)
        assert settings.authority is None

        # With tenant_id
        settings = AuthSettings(tenant_id="test-tenant-123")
        assert settings.authority == "https://login.microsoftonline.com/test-tenant-123"

    def test_provider_must_be_valid(self):
        """Provider must be azure_ad or none."""
        from openlabels.server.config import AuthSettings
        from pydantic import ValidationError

        # Valid
        AuthSettings(provider="azure_ad")
        AuthSettings(provider="none")

        # Invalid
        with pytest.raises(ValidationError):
            AuthSettings(provider="oauth2")


class TestSecuritySettings:
    """Tests for SecuritySettings."""

    def test_max_request_size_has_limit(self):
        """Should have a default max request size to prevent DoS."""
        from openlabels.server.config import SecuritySettings

        settings = SecuritySettings()

        assert settings.max_request_size_mb > 0
        assert settings.max_request_size_mb <= 500, "Default max size too permissive"


class TestRateLimitSettings:
    """Tests for RateLimitSettings."""

    def test_rate_limiting_enabled_by_default(self):
        """Rate limiting should be on by default for security."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()

        assert settings.enabled is True

    def test_auth_endpoint_has_stricter_limits(self):
        """Auth endpoints should have stricter rate limits."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()

        # Parse rate limit strings (format: "N/period")
        def parse_rate(rate_str):
            num, _ = rate_str.split("/")
            return int(num)

        auth_limit = parse_rate(settings.auth_limit)
        api_limit = parse_rate(settings.api_limit)

        assert auth_limit < api_limit, "Auth endpoints should have stricter limits"


class TestCORSSettings:
    """Tests for CORS configuration."""

    def test_default_origins_are_localhost_only(self):
        """Default CORS should only allow localhost origins."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()

        for origin in settings.allowed_origins:
            assert "localhost" in origin or "127.0.0.1" in origin, \
                f"Default origin {origin} should be localhost only"

    def test_credentials_enabled(self):
        """Credentials should be allowed for cookie-based auth."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()

        assert settings.allow_credentials is True


class TestLabelingSettings:
    """Tests for labeling configuration."""

    def test_risk_tier_mapping_covers_all_tiers(self):
        """Risk tier mapping should have entries for all risk tiers."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()

        required_tiers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
        for tier in required_tiers:
            assert tier in settings.risk_tier_mapping, f"Missing mapping for {tier}"

    def test_critical_tier_maps_to_label(self):
        """CRITICAL risk tier should map to a label, not None."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()

        assert settings.risk_tier_mapping["CRITICAL"] is not None


class TestMainSettings:
    """Tests for the main Settings class."""

    def test_creates_with_all_subsections(self):
        """Main Settings should have all configuration subsections."""
        from openlabels.server.config import Settings

        settings = Settings()

        assert settings.server is not None
        assert settings.database is not None
        assert settings.auth is not None
        assert settings.adapters is not None
        assert settings.labeling is not None
        assert settings.detection is not None
        assert settings.logging is not None
        assert settings.cors is not None
        assert settings.rate_limit is not None
        assert settings.security is not None

    def test_env_prefix_is_openlabels(self):
        """Environment variables should use OPENLABELS_ prefix."""
        from openlabels.server.config import Settings

        # Check model_config
        assert Settings.model_config.get("env_prefix") == "OPENLABELS_"


class TestGetSettings:
    """Tests for get_settings function."""

    def test_returns_settings_instance(self):
        """get_settings should return a Settings instance."""
        from openlabels.server.config import get_settings, Settings

        settings = get_settings()

        assert isinstance(settings, Settings)

    def test_is_cached(self):
        """get_settings should return the same cached instance."""
        from openlabels.server.config import get_settings, reload_settings

        # Clear cache first
        reload_settings()

        settings1 = get_settings()
        settings2 = get_settings()

        assert settings1 is settings2

    def test_reload_clears_cache(self):
        """reload_settings should return a new instance."""
        from openlabels.server.config import get_settings, reload_settings

        settings1 = get_settings()
        settings2 = reload_settings()

        # After reload, should be a different object
        # (though with same values if env unchanged)
        assert settings1 is not settings2
