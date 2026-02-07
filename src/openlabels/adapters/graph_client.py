"""
Microsoft Graph API client with rate limiting and connection pooling.

Features:
- Adaptive rate limiting with Retry-After header support
- Token bucket algorithm for request throttling
- Connection pooling for HTTP/2 multiplexing
- Automatic token refresh
- Delta query support for incremental sync
- Circuit breaker for fault tolerance
- Configurable timeouts
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime, timedelta, timezone

import httpx

from openlabels.core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
)
from openlabels.exceptions import GraphAPIError

logger = logging.getLogger(__name__)

# Graph API configuration
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_AUTH_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Default rate limiting (well under Graph's 2000/sec limit)
DEFAULT_REQUESTS_PER_SECOND = 100
DEFAULT_BURST_SIZE = 50
DEFAULT_MAX_RETRIES = 5
DEFAULT_BASE_BACKOFF_SECONDS = 1.0


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiting."""

    requests_per_second: float = DEFAULT_REQUESTS_PER_SECOND
    burst_size: int = DEFAULT_BURST_SIZE
    max_retries: int = DEFAULT_MAX_RETRIES
    base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS


@dataclass
class TokenBucket:
    """
    Token bucket rate limiter with async support.

    Allows bursts up to burst_size, then rate-limits to requests_per_second.
    """

    rate: float  # tokens per second
    capacity: int  # max tokens (burst size)
    tokens: float = field(default=0.0)
    last_update: float = field(default_factory=time.monotonic)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        self.tokens = float(self.capacity)

    async def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens, waiting if necessary.

        Returns the time waited in seconds.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Add tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0

            # Calculate wait time
            deficit = tokens - self.tokens
            wait_time = deficit / self.rate
            self.tokens = 0

            return wait_time


@dataclass
class DeltaToken:
    """Delta token for incremental sync."""

    delta_link: str
    resource_path: str
    acquired_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    item_count: int = 0

    def is_expired(self, max_age_hours: int = 24) -> bool:
        """Check if delta token is too old to use."""
        age = datetime.now(timezone.utc) - self.acquired_at
        return age > timedelta(hours=max_age_hours)


class GraphClient:
    """
    Microsoft Graph API client with rate limiting and connection pooling.

    Usage:
        client = GraphClient(tenant_id, client_id, client_secret)
        async with client:
            data = await client.get("/me/drive/root/children")

    Security Notes:
        - Client secret is stored in memory only while the client is active
        - Call clear_credentials() or use context manager to clear sensitive data
        - Access tokens are also cleared on exit
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        rate_config: Optional[RateLimiterConfig] = None,
        pool_size: int = 100,
        timeout: Optional[float] = None,
        connect_timeout: Optional[float] = None,
    ):
        """
        Initialize Graph client.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: App registration client ID
            client_secret: App registration client secret
            rate_config: Rate limiting configuration
            pool_size: HTTP connection pool size
            timeout: Request timeout in seconds (uses config default if None)
            connect_timeout: Connection timeout in seconds (uses config default if None)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        # Store secret in a private attribute to discourage direct access
        self._client_secret: str = client_secret

        self.rate_config = rate_config or RateLimiterConfig()
        self.pool_size = pool_size

        # Get timeout configuration from settings
        try:
            from openlabels.server.config import get_settings
            settings = get_settings()
            self._timeout = timeout or settings.timeouts.graph_api
            self._connect_timeout = connect_timeout or settings.timeouts.http_connect
            cb_config = CircuitBreakerConfig(
                failure_threshold=settings.circuit_breaker.failure_threshold,
                success_threshold=settings.circuit_breaker.success_threshold,
                recovery_timeout=settings.circuit_breaker.recovery_timeout,
                exclude_status_codes=tuple(settings.circuit_breaker.exclude_status_codes),
            )
        except ImportError as settings_err:
            # Fallback to defaults if settings module not available (e.g., during tests)
            logger.debug(
                f"Using default Graph client config (settings module not available): {settings_err}",
                exc_info=True
            )
            self._timeout = timeout or 30.0
            self._connect_timeout = connect_timeout or 10.0
            cb_config = CircuitBreakerConfig()
        except (AttributeError, KeyError, TypeError) as settings_err:
            # Fallback to defaults if settings are misconfigured
            logger.debug(
                f"Using default Graph client config (settings misconfigured): {settings_err}",
                exc_info=True
            )
            self._timeout = timeout or 30.0
            self._connect_timeout = connect_timeout or 10.0
            cb_config = CircuitBreakerConfig()
        except Exception as settings_err:
            # Catch-all for unexpected errors during settings loading
            logger.warning(
                f"Using default Graph client config (unexpected error loading settings: "
                f"{type(settings_err).__name__}): {settings_err}",
                exc_info=True
            )
            self._timeout = timeout or 30.0
            self._connect_timeout = connect_timeout or 10.0
            cb_config = CircuitBreakerConfig()

        # Token management
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._token_lock = asyncio.Lock()

        # Rate limiting
        self._rate_limiter = TokenBucket(
            rate=self.rate_config.requests_per_second,
            capacity=self.rate_config.burst_size,
        )

        # Circuit breaker for fault tolerance
        self._circuit_breaker = CircuitBreaker(
            name=f"graph_api_{tenant_id[:8]}",
            config=cb_config,
        )

        # Connection pool (created on __aenter__)
        self._client: Optional[httpx.AsyncClient] = None

        # Delta tokens by resource path
        self._delta_tokens: dict[str, DeltaToken] = {}

        # Stats
        self.stats = {
            "requests": 0,
            "retries": 0,
            "throttled": 0,
            "errors": 0,
            "circuit_open_rejections": 0,
        }

    def clear_credentials(self) -> None:
        """
        Clear sensitive credentials from memory.

        Call this when the client is no longer needed to minimize
        the time credentials remain in memory.
        """
        # Overwrite with empty strings before clearing (defense in depth)
        if self._client_secret:
            self._client_secret = ""
        if self._access_token:
            self._access_token = ""
        self._token_expires_at = None

    async def __aenter__(self) -> "GraphClient":
        """Create connection pool on context enter."""
        self._client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=self.pool_size,
                max_keepalive_connections=self.pool_size // 2,
            ),
            timeout=httpx.Timeout(self._timeout, connect=self._connect_timeout),
            http2=True,  # Enable HTTP/2 for multiplexing
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Close connection pool and clear credentials on context exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
        # Clear sensitive data when context exits
        self.clear_credentials()

    async def _ensure_token(self) -> str:
        """Ensure we have a valid access token, refreshing if needed."""
        async with self._token_lock:
            now = datetime.now(timezone.utc)

            # Check if token is still valid (with 60s buffer)
            if (
                self._access_token
                and self._token_expires_at
                and self._token_expires_at > now + timedelta(seconds=60)
            ):
                return self._access_token

            # Acquire new token
            logger.debug("Acquiring new Graph API access token")

            auth_url = GRAPH_AUTH_URL.format(tenant_id=self.tenant_id)
            data = {
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }

            # Use connection pool if available, otherwise create temp client
            try:
                if self._client:
                    response = await self._client.post(auth_url, data=data)
                else:
                    async with httpx.AsyncClient() as temp_client:
                        response = await temp_client.post(auth_url, data=data)

                if response.status_code == 401:
                    raise GraphAPIError(
                        "Authentication failed - invalid client credentials",
                        status_code=401,
                        endpoint=auth_url,
                        context="acquiring access token for Graph API",
                    )
                elif response.status_code == 400:
                    error_detail = response.json().get("error_description", "Bad request")
                    raise GraphAPIError(
                        f"Token request failed: {error_detail}",
                        status_code=400,
                        endpoint=auth_url,
                        context="acquiring access token for Graph API",
                    )

                response.raise_for_status()
                token_data = response.json()

            except httpx.TimeoutException as e:
                raise GraphAPIError(
                    "Timeout while acquiring access token",
                    endpoint=auth_url,
                    context="connection to Azure AD timed out",
                ) from e
            except httpx.ConnectError as e:
                raise GraphAPIError(
                    "Failed to connect to Azure AD for authentication",
                    endpoint=auth_url,
                    context="network connectivity issue to login.microsoftonline.com",
                ) from e

            self._access_token = token_data["access_token"]
            expires_in = token_data.get("expires_in", 3600)
            self._token_expires_at = now + timedelta(seconds=expires_in)

            logger.debug(f"Token acquired, expires in {expires_in}s")
            return self._access_token

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> httpx.Response:
        """
        Make a rate-limited request to Graph API with circuit breaker protection.

        Handles:
        - Circuit breaker for fault tolerance
        - Rate limiting via token bucket
        - 429 throttling with Retry-After
        - Automatic retries with exponential backoff
        """
        if not self._client:
            raise RuntimeError("GraphClient must be used as async context manager")

        # Check circuit breaker first
        if not await self._circuit_breaker.allow_request():
            self.stats["circuit_open_rejections"] += 1
            raise CircuitOpenError(
                self._circuit_breaker.name,
                self._circuit_breaker.time_until_recovery,
            )

        # Wait for rate limiter
        wait_time = await self._rate_limiter.acquire()
        if wait_time > 0:
            await asyncio.sleep(wait_time)

        # Build URL
        if path.startswith("http"):
            url = path  # Full URL (e.g., nextLink)
        else:
            url = f"{GRAPH_API_BASE}{path}"

        # Get auth header
        token = await self._ensure_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"

        # Retry loop
        last_error = None
        for attempt in range(self.rate_config.max_retries):
            try:
                self.stats["requests"] += 1
                response = await self._client.request(
                    method, url, headers=headers, **kwargs
                )

                # Handle throttling
                if response.status_code == 429:
                    self.stats["throttled"] += 1
                    retry_after = int(response.headers.get("Retry-After", "5"))
                    logger.warning(
                        f"Graph API throttled, waiting {retry_after}s "
                        f"(attempt {attempt + 1}/{self.rate_config.max_retries})"
                    )
                    await asyncio.sleep(retry_after)
                    self.stats["retries"] += 1
                    continue

                # Handle server errors with retry
                if response.status_code >= 500:
                    backoff = self.rate_config.base_backoff_seconds * (2 ** attempt)
                    logger.warning(
                        f"Graph API error {response.status_code}, "
                        f"retrying in {backoff}s"
                    )
                    await asyncio.sleep(backoff)
                    self.stats["retries"] += 1
                    # Record failure for circuit breaker
                    await self._circuit_breaker.record_failure()
                    continue

                # Success - record for circuit breaker
                await self._circuit_breaker.record_success()
                return response

            except httpx.TimeoutException as e:
                last_error = GraphAPIError(
                    f"Request timed out after {self._timeout}s",
                    endpoint=url,
                    context=f"{method} request to Graph API",
                )
                last_error.__cause__ = e
                backoff = self.rate_config.base_backoff_seconds * (2 ** attempt)
                logger.warning(f"Timeout error on {url}: {e}, retrying in {backoff}s")
                await asyncio.sleep(backoff)
                self.stats["retries"] += 1
                await self._circuit_breaker.record_failure(e)

            except httpx.ConnectError as e:
                last_error = GraphAPIError(
                    "Failed to connect to Graph API",
                    endpoint=url,
                    context="network connectivity issue to graph.microsoft.com",
                )
                last_error.__cause__ = e
                backoff = self.rate_config.base_backoff_seconds * (2 ** attempt)
                logger.warning(f"Connection error on {url}: {e}, retrying in {backoff}s")
                await asyncio.sleep(backoff)
                self.stats["retries"] += 1
                await self._circuit_breaker.record_failure(e)

            except httpx.TransportError as e:
                last_error = GraphAPIError(
                    f"Transport error during Graph API request: {type(e).__name__}",
                    endpoint=url,
                    context=f"{method} request encountered network issue",
                )
                last_error.__cause__ = e
                backoff = self.rate_config.base_backoff_seconds * (2 ** attempt)
                logger.warning(f"Transport error on {url}: {e}, retrying in {backoff}s")
                await asyncio.sleep(backoff)
                self.stats["retries"] += 1
                # Record failure for circuit breaker
                await self._circuit_breaker.record_failure(e)

        self.stats["errors"] += 1
        if last_error:
            raise last_error
        raise GraphAPIError(
            "Max retries exceeded for Graph API request",
            endpoint=url,
            context=f"failed after {self.rate_config.max_retries} attempts",
        )

    async def get(self, path: str, **kwargs) -> dict[str, Any]:
        """GET request returning JSON."""
        response = await self._request("GET", path, **kwargs)
        response.raise_for_status()
        return response.json()

    async def get_bytes(self, path: str, **kwargs) -> bytes:
        """GET request returning raw bytes (for file downloads)."""
        response = await self._request("GET", path, **kwargs)
        response.raise_for_status()
        return response.content

    async def post(self, path: str, **kwargs) -> dict[str, Any]:
        """POST request returning JSON."""
        response = await self._request("POST", path, **kwargs)
        response.raise_for_status()
        return response.json()

    # =========================================================================
    # Delta Query Support
    # =========================================================================

    def get_delta_token(self, resource_path: str) -> Optional[DeltaToken]:
        """Get stored delta token for a resource path."""
        token = self._delta_tokens.get(resource_path)
        if token and not token.is_expired():
            return token
        return None

    def store_delta_token(
        self,
        resource_path: str,
        delta_link: str,
        item_count: int = 0,
    ) -> None:
        """Store a delta token for future incremental sync."""
        self._delta_tokens[resource_path] = DeltaToken(
            delta_link=delta_link,
            resource_path=resource_path,
            item_count=item_count,
        )
        logger.debug(f"Stored delta token for {resource_path}")

    def clear_delta_token(self, resource_path: str) -> None:
        """Clear delta token for a resource path."""
        self._delta_tokens.pop(resource_path, None)

    async def get_with_delta(
        self,
        initial_path: str,
        resource_path: str,
    ) -> tuple[list[dict], bool]:
        """
        Get items using delta query if available.

        Args:
            initial_path: Path for initial full sync (e.g., /sites/{id}/drive/root/delta)
            resource_path: Key to store/retrieve delta token

        Returns:
            Tuple of (items, is_delta) where is_delta indicates if this was incremental
        """
        # Check for existing delta token
        delta_token = self.get_delta_token(resource_path)
        is_delta = delta_token is not None

        if delta_token:
            logger.info(f"Using delta query for {resource_path}")
            path = delta_token.delta_link
        else:
            logger.info(f"Performing full sync for {resource_path}")
            path = initial_path

        items = []
        while path:
            data = await self.get(path)
            items.extend(data.get("value", []))

            # Check for next page
            path = data.get("@odata.nextLink")

            # Store delta link when we reach the end
            if not path and "@odata.deltaLink" in data:
                self.store_delta_token(
                    resource_path,
                    data["@odata.deltaLink"],
                    item_count=len(items),
                )

        return items, is_delta

    # =========================================================================
    # Pagination Helper
    # =========================================================================

    async def get_all_pages(self, path: str) -> list[dict]:
        """Get all pages of a paginated response."""
        items = []
        while path:
            data = await self.get(path)
            items.extend(data.get("value", []))
            path = data.get("@odata.nextLink")
        return items

    def get_stats(self) -> dict:
        """Get client statistics."""
        return {
            **self.stats,
            "pool_size": self.pool_size,
            "rate_limit": self.rate_config.requests_per_second,
        }
