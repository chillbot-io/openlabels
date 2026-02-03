"""
Configuration management for OpenLabels Server.

Configuration is loaded from:
1. Environment variables (highest priority)
2. config.yaml file
3. Default values (lowest priority)
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


class ServerSettings(BaseSettings):
    """Server configuration."""

    # Default to localhost for security. Set to "0.0.0.0" explicitly for production
    # behind a reverse proxy (nginx, traefik, etc.)
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 4
    debug: bool = False
    environment: Literal["development", "staging", "production"] = "development"


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    url: str = "postgresql+asyncpg://localhost/openlabels"
    pool_size: int = 5
    max_overflow: int = 10


class AuthSettings(BaseSettings):
    """
    Authentication configuration for Azure AD / Microsoft Graph API.

    Required Azure AD App Registration:
    1. Create an App Registration in Azure Portal
    2. Configure the following API Permissions (Application type):

    SCANNING PERMISSIONS (minimum for SharePoint/OneDrive scanning):
    - Sites.Read.All          - Read items in all site collections
    - Files.Read.All          - Read all files that user can access
    - User.Read.All           - Read all users' full profiles (for OneDrive)

    LABELING PERMISSIONS (for applying sensitivity labels):
    - Sites.ReadWrite.All     - Edit or delete items in all site collections
    - Files.ReadWrite.All     - Read and write all files that user can access
    - InformationProtectionPolicy.Read.All  - Read sensitivity labels

    LABEL MANAGEMENT PERMISSIONS (for syncing labels from M365):
    - InformationProtectionPolicy.Read.All  - Read sensitivity labels and policies

    OPTIONAL PERMISSIONS (for full functionality):
    - User.ReadBasic.All      - Read basic profiles of all users
    - Directory.Read.All      - Read directory data

    3. Grant admin consent for the permissions
    4. Create a client secret and note the value

    Environment variables:
    - AUTH_TENANT_ID: Azure AD tenant ID (GUID)
    - AUTH_CLIENT_ID: App registration client/application ID (GUID)
    - AUTH_CLIENT_SECRET: Client secret value
    """

    provider: Literal["azure_ad", "none"] = "none"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None

    @property
    def authority(self) -> str | None:
        if self.tenant_id:
            return f"https://login.microsoftonline.com/{self.tenant_id}"
        return None


class FilesystemAdapterSettings(BaseSettings):
    """Filesystem adapter configuration."""

    enabled: bool = True
    service_account: str | None = None


class SharePointAdapterSettings(BaseSettings):
    """SharePoint adapter configuration."""

    enabled: bool = True
    scan_all_sites: bool = False
    sites: list[str] = Field(default_factory=list)


class OneDriveAdapterSettings(BaseSettings):
    """OneDrive adapter configuration."""

    enabled: bool = True
    scan_all_users: bool = False
    users: list[str] = Field(default_factory=list)


class AdapterSettings(BaseSettings):
    """All adapter configurations."""

    filesystem: FilesystemAdapterSettings = Field(default_factory=FilesystemAdapterSettings)
    sharepoint: SharePointAdapterSettings = Field(default_factory=SharePointAdapterSettings)
    onedrive: OneDriveAdapterSettings = Field(default_factory=OneDriveAdapterSettings)


class MipSettings(BaseSettings):
    """
    Microsoft Information Protection SDK configuration.

    The MIP SDK enables native sensitivity label application with full
    encryption and protection features. Requires:
    - Windows with .NET Framework
    - MIP SDK assemblies
    - pythonnet package

    When MIP SDK is unavailable, OpenLabels falls back to:
    - Office metadata (docx/xlsx/pptx custom properties)
    - PDF metadata
    - Sidecar files (.openlabels JSON)

    Environment variables:
    - MIP_ENABLED: Enable/disable MIP SDK integration
    - MIP_SDK_PATH: Path to MIP SDK assemblies
    - MIP_APP_NAME: Application name registered with MIP
    - MIP_APP_VERSION: Application version for MIP
    """

    enabled: bool = False  # Disabled by default - requires Windows + .NET
    sdk_path: str | None = None  # Path to MIP SDK assemblies
    app_name: str = "OpenLabels"
    app_version: str = "1.0.0"

    @property
    def is_available(self) -> bool:
        """Check if MIP SDK should be attempted."""
        if not self.enabled:
            return False
        # Only available on Windows
        import sys
        return sys.platform == "win32"


class LabelCacheSettings(BaseSettings):
    """Label caching configuration."""

    enabled: bool = True
    ttl_seconds: int = 300  # 5 minutes
    max_labels: int = 1000  # Maximum cached labels


class LabelingSettings(BaseSettings):
    """Labeling configuration."""

    enabled: bool = True
    mode: Literal["auto", "recommend"] = "auto"
    auto_sync_on_startup: bool = True  # Sync labels on server start
    sync_interval_hours: int = 24  # How often to auto-sync labels
    cache: LabelCacheSettings = Field(default_factory=LabelCacheSettings)
    mip: MipSettings = Field(default_factory=MipSettings)
    risk_tier_mapping: dict[str, str | None] = Field(
        default_factory=lambda: {
            "CRITICAL": "Highly Confidential",
            "HIGH": "Confidential",
            "MEDIUM": "Internal",
            "LOW": None,
            "MINIMAL": None,
        }
    )


class DetectionSettings(BaseSettings):
    """Detection engine configuration."""

    confidence_threshold: float = 0.70
    enable_ml: bool = True
    enable_ocr: bool = True
    max_file_size_mb: int = 100


class LoggingSettings(BaseSettings):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    file: str | None = None
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class CORSSettings(BaseSettings):
    """CORS configuration for production security."""

    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8000"]
    )
    allow_credentials: bool = True
    allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    allow_headers: list[str] = Field(
        default_factory=lambda: [
            "Accept",
            "Accept-Language",
            "Authorization",
            "Content-Type",
            "Origin",
            "X-Request-ID",
            "X-Requested-With",
        ]
    )


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""

    enabled: bool = True
    # Requests per minute by endpoint type
    auth_limit: str = "10/minute"  # /auth/* endpoints
    api_limit: str = "100/minute"  # General API
    scan_create_limit: str = "20/minute"  # POST /api/scans


class SecuritySettings(BaseSettings):
    """Security middleware configuration."""

    max_request_size_mb: int = 100  # Max request body size


class Settings(BaseSettings):
    """Main settings class that combines all configuration sections."""

    model_config = SettingsConfigDict(
        env_prefix="OPENLABELS_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    server: ServerSettings = Field(default_factory=ServerSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    adapters: AdapterSettings = Field(default_factory=AdapterSettings)
    labeling: LabelingSettings = Field(default_factory=LabelingSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)


def load_yaml_config(path: Path | None = None) -> dict:
    """Load configuration from YAML file."""
    if path is None:
        # Look for config.yaml in standard locations
        from openlabels.core.constants import DATA_DIR
        candidates = [
            Path("config.yaml"),
            Path("config/config.yaml"),
            DATA_DIR / "config.yaml",
            Path("/etc/openlabels/config.yaml"),
        ]
        for candidate in candidates:
            if candidate.exists():
                path = candidate
                break

    if path and path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}

    return {}


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    yaml_config = load_yaml_config()

    # Merge YAML config with environment variables
    # Environment variables take precedence
    return Settings(**yaml_config)


def reload_settings() -> Settings:
    """Force reload of settings (clears cache)."""
    get_settings.cache_clear()
    return get_settings()
