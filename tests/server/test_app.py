"""
Tests for FastAPI application configuration components.

Tests actual behavior of settings loading, validation, and defaults.
"""

import pytest


class TestServerSettings:
    """Tests for ServerSettings behavior."""

    def test_environment_must_be_valid(self):
        """Environment must be one of the allowed values."""
        from pydantic import ValidationError

        from openlabels.server.config import ServerSettings

        # Valid values should work
        for env in ["development", "staging", "production"]:
            settings = ServerSettings(environment=env)
            assert settings.environment == env

        # Invalid should raise
        with pytest.raises(ValidationError):
            ServerSettings(environment="invalid")


class TestAuthSettings:
    """Tests for AuthSettings - security critical."""

    def test_provider_must_be_valid(self):
        """Provider must be azure_ad or none."""
        from pydantic import ValidationError

        from openlabels.server.config import AuthSettings

        # Valid
        AuthSettings(provider="azure_ad")
        AuthSettings(provider="none")

        # Invalid
        with pytest.raises(ValidationError):
            AuthSettings(provider="oauth2")


class TestGetSettings:
    """Tests for get_settings function."""

    def test_reload_clears_cache(self):
        """reload_settings should return a new instance."""
        from openlabels.server.config import get_settings, reload_settings

        settings1 = get_settings()
        settings2 = reload_settings()

        # After reload, should be a different object
        # (though with same values if env unchanged)
        assert settings1 is not settings2
