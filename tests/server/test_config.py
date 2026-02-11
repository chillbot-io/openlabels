"""
Tests for server configuration.

Tests actual configuration behavior, defaults, validation, and security.
"""

import pytest


class TestServerSettings:
    """Tests for ServerSettings defaults and validation."""

    def test_default_host_is_localhost(self):
        """Host should default to localhost (127.0.0.1) for security."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()
        assert settings.host == "127.0.0.1", \
            "Default host must be 127.0.0.1 (localhost) for security - not 0.0.0.0"

    def test_default_port_is_8000(self):
        """Default port should be 8000."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()
        assert settings.port == 8000

    def test_default_workers_is_4(self):
        """Default workers should be 4."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()
        assert settings.workers == 4

    def test_debug_defaults_to_false(self):
        """Debug should default to False for security."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()
        assert settings.debug is False

    def test_default_environment_is_development(self):
        """Default environment should be development."""
        from openlabels.server.config import ServerSettings

        settings = ServerSettings()
        assert settings.environment == "development"


class TestDatabaseSettings:
    """Tests for DatabaseSettings defaults and validation."""

    def test_default_url_uses_postgresql(self):
        """Database URL should default to PostgreSQL (not SQLite)."""
        from openlabels.server.config import DatabaseSettings

        settings = DatabaseSettings()
        assert "postgresql" in settings.url, \
            "Default database must be PostgreSQL - SQLite doesn't support JSONB"
        assert "asyncpg" in settings.url, \
            "Must use asyncpg driver for async support"

    def test_default_pool_size_is_reasonable(self):
        """Pool size should be a reasonable default (5)."""
        from openlabels.server.config import DatabaseSettings

        settings = DatabaseSettings()
        assert settings.pool_size == 20

    def test_max_overflow_is_reasonable(self):
        """Max overflow should be reasonable (10)."""
        from openlabels.server.config import DatabaseSettings

        settings = DatabaseSettings()
        assert settings.max_overflow == 10


class TestAuthSettings:
    """Tests for AuthSettings defaults and behavior."""

    def test_default_provider_is_none(self):
        """Default auth provider should be 'none' for local development."""
        from openlabels.server.config import AuthSettings

        settings = AuthSettings()
        assert settings.provider == "none"

    def test_tenant_id_defaults_to_none(self):
        """Tenant ID should default to None when not configured."""
        from openlabels.server.config import AuthSettings

        settings = AuthSettings()
        assert settings.tenant_id is None

    def test_authority_is_none_without_tenant_id(self):
        """Authority property should be None without tenant_id."""
        from openlabels.server.config import AuthSettings

        settings = AuthSettings()
        assert settings.authority is None

    def test_authority_includes_tenant_id(self):
        """Authority should include tenant_id when set."""
        from openlabels.server.config import AuthSettings

        settings = AuthSettings(tenant_id="test-tenant-123")
        assert settings.authority == "https://login.microsoftonline.com/test-tenant-123"

class TestCORSSettings:
    """Tests for CORS configuration."""

    def test_default_allows_localhost_3000(self):
        """CORS should allow localhost:3000 (frontend dev server)."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()
        assert "http://localhost:3000" in settings.allowed_origins

    def test_default_allows_localhost_8000(self):
        """CORS should allow localhost:8000 (backend server)."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()
        assert "http://localhost:8000" in settings.allowed_origins

    def test_credentials_allowed_by_default(self):
        """Credentials should be allowed for session cookies."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()
        assert settings.allow_credentials is True

    def test_common_http_methods_allowed(self):
        """Common HTTP methods should be allowed."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()
        required_methods = ["GET", "POST", "PUT", "DELETE"]
        for method in required_methods:
            assert method in settings.allow_methods, \
                f"Method {method} should be allowed by default"

    def test_authorization_header_allowed(self):
        """Authorization header must be allowed for token auth."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()
        assert "Authorization" in settings.allow_headers

    def test_content_type_header_allowed(self):
        """Content-Type header must be allowed for JSON requests."""
        from openlabels.server.config import CORSSettings

        settings = CORSSettings()
        assert "Content-Type" in settings.allow_headers


class TestRateLimitSettings:
    """Tests for rate limiting configuration."""

    def test_rate_limiting_enabled_by_default(self):
        """Rate limiting should be enabled by default for security."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()
        assert settings.enabled is True

    def test_auth_limit_format_is_valid(self):
        """Auth limit should be in 'number/period' format."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()
        # Format should be like "10/minute"
        parts = settings.auth_limit.split("/")
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert parts[1] in ("second", "minute", "hour", "day")

    def test_api_limit_format_is_valid(self):
        """API limit should be in 'number/period' format."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()
        parts = settings.api_limit.split("/")
        assert len(parts) == 2
        assert parts[0].isdigit()

    def test_auth_limit_is_restrictive(self):
        """Auth endpoints should have restrictive limits (prevent brute force)."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()
        parts = settings.auth_limit.split("/")
        limit = int(parts[0])
        # Should be <= 20 per minute to prevent brute force
        assert limit <= 20, \
            f"Auth rate limit {limit} is too permissive - should be <= 20/minute"

    def test_api_limit_is_reasonable(self):
        """API endpoints should have reasonable limits."""
        from openlabels.server.config import RateLimitSettings

        settings = RateLimitSettings()
        parts = settings.api_limit.split("/")
        limit = int(parts[0])
        # Should be >= 50 per minute for normal usage
        assert limit >= 50, \
            f"API rate limit {limit} is too restrictive - should be >= 50/minute"


class TestSecuritySettings:
    """Tests for security configuration."""

    def test_max_request_size_is_reasonable(self):
        """Max request size should be reasonable (not too large)."""
        from openlabels.server.config import SecuritySettings

        settings = SecuritySettings()
        # Should be <= 100MB to prevent DoS
        assert settings.max_request_size_mb <= 100


class TestLabelingSettings:
    """Tests for labeling configuration."""

    def test_labeling_enabled_by_default(self):
        """Labeling should be enabled by default."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()
        assert settings.enabled is True

    def test_default_mode_is_auto(self):
        """Default labeling mode should be 'auto'."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()
        assert settings.mode == "auto"

    def test_risk_tier_mapping_covers_all_tiers(self):
        """Risk tier mapping should have entries for all tiers."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()
        required_tiers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
        for tier in required_tiers:
            assert tier in settings.risk_tier_mapping, \
                f"Missing mapping for risk tier: {tier}"

    def test_critical_tier_maps_to_label(self):
        """CRITICAL tier should map to 'Highly Confidential'."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()
        assert settings.risk_tier_mapping["CRITICAL"] == "Highly Confidential"
        assert settings.risk_tier_mapping["HIGH"] == "Confidential"
        assert settings.risk_tier_mapping["MEDIUM"] == "Internal"
        assert settings.risk_tier_mapping["LOW"] is None, "LOW tier should not auto-label"
        assert settings.risk_tier_mapping["MINIMAL"] is None, "MINIMAL tier should not auto-label"

    def test_sync_interval_is_reasonable(self):
        """Label sync interval should be reasonable (12-48 hours)."""
        from openlabels.server.config import LabelingSettings

        settings = LabelingSettings()
        assert 12 <= settings.sync_interval_hours <= 48


class TestMipSettings:
    """Tests for MIP SDK configuration."""

    def test_mip_disabled_by_default(self):
        """MIP SDK should be disabled by default (requires Windows)."""
        from openlabels.server.config import MipSettings

        settings = MipSettings()
        assert settings.enabled is False

    def test_is_available_false_when_disabled(self):
        """is_available should be False when MIP is disabled."""
        from openlabels.server.config import MipSettings

        settings = MipSettings(enabled=False)
        assert settings.is_available is False


class TestDetectionSettings:
    """Tests for detection engine configuration."""

    def test_confidence_threshold_is_reasonable(self):
        """Confidence threshold should be in valid range."""
        from openlabels.server.config import DetectionSettings

        settings = DetectionSettings()
        assert 0.5 <= settings.confidence_threshold <= 1.0, \
            "Confidence threshold should be 0.5-1.0"

    def test_ml_enabled_by_default(self):
        """ML detection should be enabled by default."""
        from openlabels.server.config import DetectionSettings

        settings = DetectionSettings()
        assert settings.enable_ml is True

    def test_ocr_enabled_by_default(self):
        """OCR should be enabled by default."""
        from openlabels.server.config import DetectionSettings

        settings = DetectionSettings()
        assert settings.enable_ocr is True

    def test_max_file_size_is_reasonable(self):
        """Max file size should be reasonable (not too large)."""
        from openlabels.server.config import DetectionSettings

        settings = DetectionSettings()
        # Should be <= 500MB to prevent memory issues
        assert settings.max_file_size_mb <= 500


class TestMainSettings:
    """Tests for main Settings class."""

    def test_settings_has_all_sections(self):
        """Main Settings should have all configuration sections."""
        from openlabels.server.config import Settings

        settings = Settings()
        required_sections = [
            "server", "database", "auth", "adapters", "labeling",
            "detection", "logging", "cors", "rate_limit", "security"
        ]
        for section in required_sections:
            assert hasattr(settings, section), \
                f"Settings missing section: {section}"

    def test_settings_uses_environment_prefix(self):
        """Settings should use OPENLABELS_ prefix for env vars."""
        from openlabels.server.config import Settings

        assert Settings.model_config["env_prefix"] == "OPENLABELS_"

    def test_settings_uses_nested_delimiter(self):
        """Settings should use __ as nested delimiter."""
        from openlabels.server.config import Settings

        assert Settings.model_config["env_nested_delimiter"] == "__"


class TestGetSettings:
    """Tests for get_settings function."""

    def test_returns_cached_instance(self):
        """get_settings should return the same cached instance."""
        from openlabels.server.config import get_settings

        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2


class TestAdapterSettings:
    """Tests for adapter configuration."""

    def test_filesystem_enabled_by_default(self):
        """Filesystem adapter should be enabled by default."""
        from openlabels.server.config import AdapterSettings

        settings = AdapterSettings()
        assert settings.filesystem.enabled is True

    def test_sharepoint_enabled_by_default(self):
        """SharePoint adapter should be enabled by default."""
        from openlabels.server.config import AdapterSettings

        settings = AdapterSettings()
        assert settings.sharepoint.enabled is True

    def test_sharepoint_scan_all_sites_disabled_by_default(self):
        """SharePoint scan_all_sites should be disabled by default (security)."""
        from openlabels.server.config import AdapterSettings

        settings = AdapterSettings()
        assert settings.sharepoint.scan_all_sites is False

    def test_onedrive_enabled_by_default(self):
        """OneDrive adapter should be enabled by default."""
        from openlabels.server.config import AdapterSettings

        settings = AdapterSettings()
        assert settings.onedrive.enabled is True

    def test_onedrive_scan_all_users_disabled_by_default(self):
        """OneDrive scan_all_users should be disabled by default (security)."""
        from openlabels.server.config import AdapterSettings

        settings = AdapterSettings()
        assert settings.onedrive.scan_all_users is False
