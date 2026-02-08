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

from pydantic import Field, model_validator
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
    pool_size: int = 20
    max_overflow: int = 10
    pool_recycle: int = 1800  # Recycle connections every 30 min to prevent stale connections
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
    """
    Rate limiting configuration.

    For distributed deployments with multiple server instances, configure
    Redis storage to ensure rate limits are shared across all instances.

    Environment variables:
    - OPENLABELS_RATE_LIMIT__ENABLED: Enable/disable rate limiting
    - OPENLABELS_RATE_LIMIT__STORAGE_URI: Redis URI for distributed rate limiting
    - OPENLABELS_RATE_LIMIT__AUTH_LIMIT: Rate limit for auth endpoints
    - OPENLABELS_RATE_LIMIT__API_LIMIT: Rate limit for general API
    - OPENLABELS_RATE_LIMIT__SCAN_CREATE_LIMIT: Rate limit for scan creation
    """

    enabled: bool = True
    # Storage backend URI for distributed rate limiting (e.g., "redis://localhost:6379")
    # If not set, defaults to redis.url when Redis is enabled
    # Set to empty string "" to force in-memory storage even when Redis is available
    storage_uri: str | None = None
    # Requests per minute by endpoint type (IP-based, slowapi)
    auth_limit: str = "10/minute"  # /auth/* endpoints
    api_limit: str = "100/minute"  # General API
    scan_create_limit: str = "20/minute"  # POST /api/scans
    # Per-tenant rate limits (authenticated endpoints)
    tenant_rpm: int = 300  # Requests per minute per tenant
    tenant_rph: int = 10_000  # Requests per hour per tenant


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


class SchedulerSettings(BaseSettings):
    """
    Database-driven scheduler configuration.

    The scheduler polls the database for due schedules and triggers scan jobs.
    Multiple server instances can run safely - database locking prevents
    duplicate triggers.

    Environment variables:
    - OPENLABELS_SCHEDULER__ENABLED: Enable/disable the scheduler
    - OPENLABELS_SCHEDULER__POLL_INTERVAL: Polling interval in seconds
    - OPENLABELS_SCHEDULER__MIN_TRIGGER_INTERVAL: Minimum seconds between triggers
    """

    enabled: bool = True  # Enable scheduler on startup
    poll_interval: int = 30  # Seconds between schedule checks
    min_trigger_interval: int = 60  # Minimum seconds between triggering same schedule


class RedisSettings(BaseSettings):
    """
    Redis caching configuration.

    Redis is used for caching frequently accessed data to improve performance.
    If Redis is unavailable, the system falls back to in-memory caching.

    Environment variables:
    - OPENLABELS_REDIS__URL: Redis connection URL
    - OPENLABELS_REDIS__CACHE_TTL_SECONDS: Default cache TTL
    - OPENLABELS_REDIS__ENABLED: Enable/disable caching
    - OPENLABELS_REDIS__MAX_CONNECTIONS: Connection pool size
    - OPENLABELS_REDIS__KEY_PREFIX: Prefix for all cache keys
    """

    url: str = "redis://localhost:6379"
    cache_ttl_seconds: int = 300  # 5 minutes default
    enabled: bool = True
    max_connections: int = 10
    key_prefix: str = "openlabels:"
    # Connection timeouts
    connect_timeout: float = 5.0
    socket_timeout: float = 5.0
    # In-memory fallback settings
    memory_cache_max_size: int = 1000  # Max items in memory cache


class S3CatalogSettings(BaseSettings):
    """S3 storage configuration for the data catalog."""

    bucket: str = ""
    prefix: str = "openlabels/catalog"
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    endpoint_url: str | None = None  # For S3-compatible (MinIO)


class AzureCatalogSettings(BaseSettings):
    """Azure Blob storage configuration for the data catalog."""

    container: str = ""
    prefix: str = "openlabels/catalog"
    connection_string: str | None = None
    account_name: str | None = None
    account_key: str | None = None


class MonitoringSettings(BaseSettings):
    """
    File access monitoring and event harvesting configuration.

    Controls the EventHarvester background tasks that periodically collect
    access events from OS audit subsystems (Windows SACL, Linux auditd)
    and cloud APIs (M365 Management Activity API) and persist them to the
    ``file_access_events`` table.

    Environment variables::

        OPENLABELS_MONITORING__ENABLED=true
        OPENLABELS_MONITORING__HARVEST_INTERVAL_SECONDS=60
        OPENLABELS_MONITORING__PROVIDERS=windows_sacl,auditd,m365_audit
        OPENLABELS_MONITORING__STORE_RAW_EVENTS=false
        OPENLABELS_MONITORING__M365_HARVEST_INTERVAL_SECONDS=300
        OPENLABELS_MONITORING__M365_SITE_URLS=https://contoso.sharepoint.com/sites/finance
        OPENLABELS_MONITORING__WEBHOOK_ENABLED=false
        OPENLABELS_MONITORING__WEBHOOK_URL=https://your-domain.com/api/v1/webhooks/graph
        OPENLABELS_MONITORING__WEBHOOK_CLIENT_STATE=<random-secret>
    """

    enabled: bool = False
    # DB tenant UUID for registry cache sync (populate on startup, sync on shutdown).
    # If not set, cache sync is skipped (the harvester still works via DB queries).
    tenant_id: str | None = None
    # How often the EventHarvester polls OS providers for new events
    harvest_interval_seconds: int = 60
    # Which event providers to activate (comma-separated in env vars)
    providers: list[str] = Field(default_factory=lambda: ["windows_sacl", "auditd"])
    # Store the raw OS event in FileAccessEvent.raw_event (useful for debugging)
    store_raw_events: bool = False
    # Maximum events to process per harvest cycle (back-pressure)
    max_events_per_cycle: int = 10_000
    # Sync registry cache to DB on startup and shutdown
    sync_cache_on_startup: bool = True
    sync_cache_on_shutdown: bool = True

    # --- M365 audit (Management Activity API) ---
    # Separate harvest interval for M365 (API batches events; 5 min is typical)
    m365_harvest_interval_seconds: int = 300
    # SharePoint site URLs to filter events (None = all sites)
    m365_site_urls: list[str] = Field(default_factory=list)

    # --- Real-time event streams (Phase I) ---
    # Enable EventStreamManager for continuous kernel-level monitoring
    stream_enabled: bool = False
    # Stream providers to activate (usn_journal on Windows, fanotify on Linux)
    stream_providers: list[str] = Field(default_factory=lambda: ["usn_journal", "fanotify"])
    # Batch size for stream flush to DB
    stream_batch_size: int = 500
    # Flush interval (seconds) for stream buffer
    stream_flush_interval: float = 5.0
    # USN journal drive letter (Windows only)
    usn_drive_letter: str = "C"
    # Scan trigger settings
    scan_trigger_enabled: bool = False
    scan_trigger_rate_limit: int = 10
    scan_trigger_cooldown_seconds: float = 60.0
    scan_trigger_min_risk_tier: str = "MEDIUM"

    # --- Graph webhooks ---
    webhook_enabled: bool = False
    # Public HTTPS URL for Graph change notification subscriptions.
    # Graph sends POST notifications to this URL when drive items change.
    # Example: https://your-domain.com/api/v1/webhooks/graph
    webhook_url: str = ""
    # Shared secret for validating inbound webhook notifications
    # (matched against ``clientState`` in the subscription).
    webhook_client_state: str = ""


class CatalogSettings(BaseSettings):
    """
    Data lake / Parquet catalog configuration.

    When ``enabled`` is True, analytical queries (dashboard stats, trends,
    heatmaps, exports) are served from DuckDB over Parquet files instead
    of PostgreSQL.  PostgreSQL remains the source of truth — Parquet is a
    derived, append-optimised analytical copy.

    Environment variables::

        OPENLABELS_CATALOG__ENABLED=true
        OPENLABELS_CATALOG__BACKEND=local
        OPENLABELS_CATALOG__LOCAL_PATH=/data/openlabels/catalog
        OPENLABELS_CATALOG__S3__BUCKET=my-bucket
        OPENLABELS_CATALOG__S3__REGION=us-east-1
        OPENLABELS_CATALOG__AZURE__CONTAINER=my-container
    """

    enabled: bool = False
    backend: Literal["local", "s3", "azure"] = "local"
    local_path: str = ""

    # Remote storage sub-configs
    s3: S3CatalogSettings = Field(default_factory=S3CatalogSettings)
    azure: AzureCatalogSettings = Field(default_factory=AzureCatalogSettings)

    # Flush tuning
    event_flush_interval_seconds: int = 300  # 5 minutes
    max_parquet_row_group_size: int = 100_000
    max_parquet_file_size_mb: int = 256
    compression: Literal["zstd", "snappy", "gzip", "none"] = "zstd"

    # DuckDB tuning
    duckdb_memory_limit: str = "2GB"
    duckdb_threads: int = 4


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
    sentry: SentrySettings = Field(default_factory=SentrySettings)
    jobs: JobSettings = Field(default_factory=JobSettings)
    scheduler: SchedulerSettings = Field(default_factory=SchedulerSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    catalog: CatalogSettings = Field(default_factory=CatalogSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)


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
    """Clear settings cache and return a fresh instance."""
    get_settings.cache_clear()
    return get_settings()


