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

from pydantic import Field, PostgresDsn, field_validator, model_validator
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
    pool_recycle: int = 3600  # Recycle connections after 1 hour to prevent stale connections
    pool_pre_ping: bool = True  # Enable connection health checks before use


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

    @model_validator(mode="after")
    def validate_cors_security(self) -> "CORSSettings":
        """
        Validate CORS configuration for security.

        Security: Wildcard origins (*) with credentials is a security vulnerability
        as it allows any site to make credentialed requests.
        """
        has_wildcard = "*" in self.allowed_origins
        if has_wildcard and self.allow_credentials:
            raise ValueError(
                "SECURITY ERROR: Cannot use wildcard (*) in allowed_origins with "
                "allow_credentials=True. This would allow any site to make "
                "credentialed requests. Specify explicit origins instead."
            )
        return self


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


class TimeoutSettings(BaseSettings):
    """
    Centralized timeout configuration.

    All timeout values in seconds. Configurable via environment variables:
    - OPENLABELS_TIMEOUTS__HTTP_DEFAULT=30.0
    - OPENLABELS_TIMEOUTS__HTTP_CONNECT=10.0
    - etc.
    """

    # HTTP client timeouts
    http_default: float = 30.0  # Default HTTP request timeout
    http_connect: float = 10.0  # HTTP connection establishment
    http_health_check: float = 5.0  # Health check endpoints
    http_long_running: float = 60.0  # Long operations (exports, etc.)

    # Graph API specific
    graph_api: float = 30.0  # Graph API requests
    graph_token: float = 30.0  # Token acquisition
    graph_delta_page: float = 60.0  # Delta query pagination

    # Job processing
    job_default: int = 3600  # Default job timeout (1 hour)
    job_scan: int = 7200  # Scan job timeout (2 hours)
    job_label: int = 1800  # Label job timeout (30 min)

    # Detection/ML
    detector: float = 30.0  # Individual detector timeout
    model_load: float = 60.0  # ML model loading
    ocr_ready: float = 30.0  # OCR engine initialization

    # WebSocket
    websocket_ping: int = 20  # WebSocket ping interval
    websocket_receive: float = 30.0  # WebSocket receive timeout

    # Database
    db_query: float = 30.0  # Database query timeout

    # Retry delays
    retry_base: float = 2.0  # Base retry delay for exponential backoff
    retry_max: int = 3600  # Maximum retry delay (1 hour)

    # Polling intervals
    worker_poll: float = 1.0  # Worker job poll interval
    status_poll: float = 2.0  # Status check poll interval
    concurrency_check: int = 5  # Worker concurrency check interval
    stuck_job_check: int = 300  # Stuck job reclaim interval (5 min)


class CircuitBreakerSettings(BaseSettings):
    """
    Circuit breaker configuration for external service resilience.

    The circuit breaker pattern prevents cascading failures by:
    1. Tracking consecutive failures
    2. Opening the circuit after failure_threshold failures
    3. Allowing test requests after recovery_timeout seconds
    4. Closing the circuit after success_threshold successes

    Configurable via environment variables:
    - OPENLABELS_CIRCUIT_BREAKER__ENABLED=true
    - OPENLABELS_CIRCUIT_BREAKER__FAILURE_THRESHOLD=5
    - etc.
    """

    enabled: bool = True
    failure_threshold: int = 5  # Failures before circuit opens
    success_threshold: int = 2  # Successes needed to close circuit
    recovery_timeout: int = 60  # Seconds to wait before half-open
    exclude_status_codes: list[int] = Field(
        default_factory=lambda: [400, 401, 403, 404]  # Client errors don't count
    )


class SentrySettings(BaseSettings):
    """
    Sentry error tracking and performance monitoring configuration.

    Sentry integration is optional - if dsn is not set, Sentry will not initialize.
    This allows running the application without Sentry in development environments.

    Environment variables:
    - SENTRY_DSN: Sentry Data Source Name (required to enable)
    - OPENLABELS_SENTRY__ENVIRONMENT: Override environment name
    - OPENLABELS_SENTRY__TRACES_SAMPLE_RATE: Performance monitoring sample rate
    - OPENLABELS_SENTRY__PROFILES_SAMPLE_RATE: Profiling sample rate
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTRY_",
        extra="ignore",
    )

    # DSN is loaded directly from SENTRY_DSN environment variable
    dsn: str | None = None
    # Environment defaults to server.environment but can be overridden
    environment: str | None = None
    # Sampling rates (0.0 to 1.0)
    # Default to lower rates in production, higher in development
    traces_sample_rate: float = 0.1  # Sample 10% of transactions for performance monitoring
    profiles_sample_rate: float = 0.1  # Sample 10% of profiled transactions

    # List of sensitive field names to scrub from error reports
    sensitive_fields: list[str] = Field(
        default_factory=lambda: [
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "auth",
            "authorization",
            "cookie",
            "session",
            "jwt",
            "bearer",
            "credential",
            "private_key",
            "client_secret",
        ]
    )


class JobSettings(BaseSettings):
    """Job queue configuration."""

    # Retry configuration
    max_retries: int = 3
    retry_base_delay: int = 2  # Seconds

    # TTL/Expiration
    completed_job_ttl_days: int = 7  # Auto-delete completed jobs after N days
    failed_job_ttl_days: int = 30  # Keep failed jobs longer for debugging
    pending_job_max_age_hours: int = 24  # Alert on jobs pending too long

    # Stuck job recovery
    stuck_job_timeout: int = 3600  # Consider running jobs stuck after 1 hour

    # Concurrency
    default_worker_concurrency: int = 4
    max_worker_concurrency: int = 32


class SentrySettings(BaseSettings):
    """
    Sentry error tracking and performance monitoring configuration.

    Sentry integration is optional - if SENTRY_DSN is not set, the application
    runs normally without Sentry.

    Environment variables:
    - SENTRY_DSN: Your Sentry Data Source Name (required for Sentry to be active)
    - SENTRY_ENVIRONMENT: Environment name (production/staging/development)
    - SENTRY_TRACES_SAMPLE_RATE: Sample rate for performance monitoring (0.0-1.0)
    - SENTRY_PROFILES_SAMPLE_RATE: Sample rate for profiling (0.0-1.0)
    - SENTRY_SEND_DEFAULT_PII: Whether to send PII data (default: False)
    - SENTRY_DEBUG: Enable Sentry debug mode (default: False)

    Note: These use SENTRY_ prefix directly (not OPENLABELS_SENTRY_) for
    compatibility with standard Sentry SDK environment variable conventions.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTRY_",
        extra="ignore",
    )

    dsn: str | None = None  # Required for Sentry to be active
    environment: str | None = None  # Defaults to server.environment if not set
    traces_sample_rate: float = Field(default=0.1, ge=0.0, le=1.0)  # 10% of transactions
    profiles_sample_rate: float = Field(default=0.1, ge=0.0, le=1.0)  # 10% of profiled transactions
    send_default_pii: bool = False  # Don't send PII by default
    debug: bool = False  # Sentry SDK debug mode
    release: str | None = None  # Version/release identifier

    @property
    def is_enabled(self) -> bool:
        """Check if Sentry should be initialized."""
        return self.dsn is not None and self.dsn.strip() != ""


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
    timeouts: TimeoutSettings = Field(default_factory=TimeoutSettings)
    circuit_breaker: CircuitBreakerSettings = Field(default_factory=CircuitBreakerSettings)
    jobs: JobSettings = Field(default_factory=JobSettings)
    sentry: SentrySettings = Field(default_factory=SentrySettings)


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
