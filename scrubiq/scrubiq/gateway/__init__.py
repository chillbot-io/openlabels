"""BAA gateway client for LLM routing."""

import ipaddress
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)


def _is_private_ip(hostname: str) -> bool:
    """Check if hostname resolves to a private/internal IP address."""
    try:
        # Try to parse as IP address directly
        ip = ipaddress.ip_address(hostname)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast
        )
    except ValueError:
        # Not an IP address, check for localhost variants
        hostname_lower = hostname.lower()
        return hostname_lower in (
            'localhost', 'localhost.localdomain',
            '127.0.0.1', '::1', '0.0.0.0',
        ) or hostname_lower.endswith('.local')


def _validate_gateway_url(url: str) -> None:
    """
    Validate gateway URL to prevent SSRF attacks.

    Raises:
        ValueError: If URL is invalid or points to internal resources
    """
    parsed = urllib.parse.urlparse(url)

    # Require HTTPS in production
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Gateway URL must use HTTP/HTTPS, got {parsed.scheme}")

    if not parsed.hostname:
        raise ValueError("Gateway URL must have a hostname")

    # Block internal/private addresses (SSRF protection)
    if _is_private_ip(parsed.hostname):
        raise ValueError(
            f"Gateway URL cannot point to internal/private addresses: {parsed.hostname}"
        )


class GatewayError(Exception):
    """Gateway request failed."""
    pass


class GatewayTimeoutError(GatewayError):
    """Gateway request timed out."""
    pass


class GatewayAuthError(GatewayError):
    """Gateway authentication failed."""
    pass


class GatewayRateLimitError(GatewayError):
    """Gateway rate limited."""
    pass


class GatewayStubError(GatewayError):
    """Gateway client not configured (httpx missing)."""
    pass


@dataclass
class GatewayResponse:
    """Response from BAA gateway."""
    success: bool
    text: str
    model: str
    tokens_used: int
    latency_ms: float
    error: Optional[str] = None


# Default allowed models - can be overridden in GatewayClient
# Updated January 2025
DEFAULT_ALLOWED_MODELS = frozenset([
    # Claude 4 (current generation)
    "claude-opus-4",
    "claude-sonnet-4",
    "claude-haiku-4",
    # Claude 3.5 (aliases, map to Claude 4)
    "claude-3.5-sonnet",
    "claude-3.5-haiku",
    # Claude 3 (legacy)
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
])


def validate_model(model: str, allowed_models: frozenset = None) -> bool:
    """Check if model is in allowed list."""
    models = allowed_models or DEFAULT_ALLOWED_MODELS
    return model in models


class GatewayClient:
    """
    Client for BAA-protected LLM gateway.
    
    The gateway receives only tokenized text - PHI never leaves
    the local environment.
    
    API contract:
        POST /v1/chat
        {
            "messages": [{"role": "user", "content": "tokenized text"}],
            "model": "claude-3-sonnet",
            "user_id": "hashed_user_id"
        }
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 30,
        user_id: Optional[str] = None,
        api_key: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        allowed_models: frozenset = None,  # Configurable model list
        skip_url_validation: bool = False,  # For testing only
    ):
        # SECURITY: Validate URL to prevent SSRF attacks
        if not skip_url_validation:
            _validate_gateway_url(base_url)

        self.base_url = base_url.rstrip('/')
        self.timeout = timeout_seconds
        self.user_id = user_id
        self.api_key = api_key
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.allowed_models = allowed_models or DEFAULT_ALLOWED_MODELS
        self._client = None
        self._client_lock = threading.RLock()  # Thread-safe client access
        self._httpx_available = False

        try:
            import httpx
            self._client = httpx.Client(
                timeout=timeout_seconds,
                verify=True,  # Explicit SSL verification
            )
            self._httpx_available = True
        except ImportError:
            logger.warning("httpx not installed - gateway client will fail on requests")

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers including auth if configured."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _validate_response(self, data: dict) -> Optional[str]:
        """
        Validate response schema. Returns error message if invalid.
        
        Expected schema:
        {
            "content": str,
            "model": str (optional),
            "usage": {"total_tokens": int} (optional)
        }
        """
        if not isinstance(data, dict):
            return "Response is not a JSON object"
        
        if "content" not in data:
            return "Response missing 'content' field"
        
        if not isinstance(data.get("content"), str):
            return "Response 'content' is not a string"
        
        # Optional fields - validate type if present
        if "usage" in data:
            usage = data["usage"]
            if not isinstance(usage, dict):
                return "Response 'usage' is not an object"
            if "total_tokens" in usage and not isinstance(usage["total_tokens"], int):
                return "Response 'usage.total_tokens' is not an integer"
        
        return None  # Valid

    def _validate_messages(self, messages: List[Dict[str, str]]) -> None:
        """
        Validate messages parameter to prevent DoS and injection attacks.

        Raises:
            ValueError: If messages are invalid
        """
        if not isinstance(messages, list):
            raise ValueError("Messages must be a list")
        if len(messages) == 0:
            raise ValueError("At least one message is required")
        if len(messages) > 100:
            raise ValueError("Maximum 100 messages per request")

        total_content_size = 0
        max_content_size = 10 * 1024 * 1024  # 10MB total content limit

        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise ValueError(f"Message {i} must be a dict")
            if "role" not in msg:
                raise ValueError(f"Message {i} missing 'role' field")
            if "content" not in msg:
                raise ValueError(f"Message {i} missing 'content' field")
            if msg["role"] not in ("user", "assistant", "system"):
                raise ValueError(f"Invalid role in message {i}")
            content = msg.get("content", "")
            if not isinstance(content, str):
                raise ValueError(f"Message {i} content must be a string")
            if len(content) > 1_000_000:  # 1MB per message
                raise ValueError(f"Message {i} content too long (max 1MB)")
            total_content_size += len(content)

        if total_content_size > max_content_size:
            raise ValueError(f"Total message content too large (max 10MB)")

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: str = "claude-3-sonnet"
    ) -> GatewayResponse:
        """
        Send chat request to gateway with retry logic.

        Args:
            messages: List of {"role": "user"|"assistant", "content": "..."}
            model: Model to use (must be in ALLOWED_MODELS)

        Returns:
            GatewayResponse

        Raises:
            GatewayStubError: If httpx not installed
            GatewayAuthError: If authentication fails
            ValueError: If model not in allowed list or invalid messages
        """
        start = time.time()

        # SECURITY: Validate messages to prevent DoS/injection
        self._validate_messages(messages)

        # Use instance's allowed_models - SECURITY: Don't expose allowed list in error
        if not validate_model(model, self.allowed_models):
            raise ValueError(f"Model '{model}' is not available")

        if self._client is None:
            # Stub now raises exception instead of returning success=True
            latency = (time.time() - start) * 1000
            raise GatewayStubError(
                "Gateway client not configured (httpx not installed). "
                "Install with: pip install httpx"
            )

        last_error: Optional[Exception] = None
        rate_limit_count = 0
        
        for attempt in range(self.max_retries):
            try:
                # Import httpx types for proper exception handling
                import httpx

                # SECURITY: Thread-safe client access
                with self._client_lock:
                    response = self._client.post(
                        f"{self.base_url}/v1/chat",
                        headers=self._get_headers(),
                        json={
                            "messages": messages,
                            "model": model,
                            "user_id": self.user_id,
                        }
                    )
                
                # Handle specific HTTP errors
                if response.status_code == 401:
                    raise GatewayAuthError("Invalid API key")
                elif response.status_code == 429:
                    # Track rate limit errors properly
                    rate_limit_count += 1
                    wait_time = self.retry_delay * (2 ** attempt)
                    last_error = GatewayRateLimitError(
                        f"Rate limited ({rate_limit_count} times). "
                        f"Retry-After: {response.headers.get('Retry-After', 'unknown')}"
                    )
                    logger.warning(f"Rate limited, waiting {wait_time}s before retry")
                    time.sleep(wait_time)
                    continue
                elif response.status_code >= 500:
                    # Server error - retry
                    wait_time = self.retry_delay * (2 ** attempt)
                    last_error = GatewayError(f"Server error: HTTP {response.status_code}")
                    logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                data = response.json()

                # Validate response schema
                validation_error = self._validate_response(data)
                if validation_error:
                    last_error = GatewayError(f"Invalid response schema: {validation_error}")
                    logger.warning(f"Response validation failed: {validation_error}")
                    break  # Don't retry malformed responses

                latency = (time.time() - start) * 1000
                return GatewayResponse(
                    success=True,
                    text=data.get("content", ""),
                    model=data.get("model", model),
                    tokens_used=data.get("usage", {}).get("total_tokens", 0),
                    latency_ms=latency,
                )

            except GatewayAuthError:
                raise  # Don't retry auth errors
            except httpx.TimeoutException as e:
                # SECURITY: Log details server-side, return generic message
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_error = GatewayTimeoutError("Request timed out")
            except httpx.ConnectError as e:
                # SECURITY: Don't expose connection details (hostnames, ports)
                logger.warning(f"Connection error on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_error = GatewayError("Connection failed")
            except httpx.HTTPStatusError as e:
                logger.warning(f"HTTP error on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_error = GatewayError("HTTP request failed")
            except ValueError as e:
                # JSON decode error
                logger.warning(f"Invalid response: {e}")
                last_error = GatewayError("Invalid response from gateway")
                break  # Don't retry malformed responses

            # Wait before retry
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay * (2 ** attempt))

        # All retries exhausted - SECURITY: Return generic error to client
        latency = (time.time() - start) * 1000
        error_msg = str(last_error) if last_error else "Service unavailable"
        logger.error(f"Gateway request failed after {self.max_retries} attempts: {last_error}")

        return GatewayResponse(
            success=False,
            text="",
            model=model,
            tokens_used=0,
            latency_ms=latency,
            error="Gateway service unavailable",  # Generic message to client
        )

    def close(self):
        """Close the HTTP client."""
        if self._client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
