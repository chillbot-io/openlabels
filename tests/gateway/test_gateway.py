"""Tests for Gateway module - SSRF protection, validation, retry logic.

Tests the security-critical GatewayClient used for LLM routing.
"""

import importlib.util
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# Direct import of the gateway module bypassing scrubiq.__init__.py
# This avoids the SQLCipher import chain
_gateway_path = Path(__file__).parent.parent.parent / "scrubiq" / "gateway" / "__init__.py"
_spec = importlib.util.spec_from_file_location("scrubiq_gateway", _gateway_path)
_gateway_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gateway_module)

_is_private_ip = _gateway_module._is_private_ip
_validate_gateway_url = _gateway_module._validate_gateway_url
GatewayError = _gateway_module.GatewayError
GatewayTimeoutError = _gateway_module.GatewayTimeoutError
GatewayAuthError = _gateway_module.GatewayAuthError
GatewayRateLimitError = _gateway_module.GatewayRateLimitError
GatewayStubError = _gateway_module.GatewayStubError
GatewayResponse = _gateway_module.GatewayResponse
GatewayClient = _gateway_module.GatewayClient
validate_model = _gateway_module.validate_model
DEFAULT_ALLOWED_MODELS = _gateway_module.DEFAULT_ALLOWED_MODELS


# =============================================================================
# SSRF PROTECTION TESTS - _is_private_ip
# =============================================================================

class TestIsPrivateIp:
    """Tests for private IP detection (SSRF protection)."""

    def test_localhost_is_private(self):
        """localhost hostname is private."""
        assert _is_private_ip("localhost") is True

    def test_localhost_localdomain_is_private(self):
        """localhost.localdomain is private."""
        assert _is_private_ip("localhost.localdomain") is True

    def test_127_0_0_1_is_private(self):
        """127.0.0.1 is private (loopback)."""
        assert _is_private_ip("127.0.0.1") is True

    def test_ipv6_loopback_is_private(self):
        """::1 is private (IPv6 loopback)."""
        assert _is_private_ip("::1") is True

    def test_0_0_0_0_is_private(self):
        """0.0.0.0 is private."""
        assert _is_private_ip("0.0.0.0") is True

    def test_10_x_private_range(self):
        """10.x.x.x is private (RFC 1918)."""
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_172_16_private_range(self):
        """172.16-31.x.x is private (RFC 1918)."""
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True

    def test_192_168_private_range(self):
        """192.168.x.x is private (RFC 1918)."""
        assert _is_private_ip("192.168.0.1") is True
        assert _is_private_ip("192.168.255.255") is True

    def test_link_local_is_private(self):
        """169.254.x.x is private (link-local)."""
        assert _is_private_ip("169.254.1.1") is True

    def test_multicast_is_private(self):
        """224.x.x.x is private (multicast)."""
        assert _is_private_ip("224.0.0.1") is True

    def test_local_domain_suffix_is_private(self):
        """*.local hostnames are private."""
        assert _is_private_ip("myhost.local") is True
        assert _is_private_ip("printer.local") is True

    def test_public_ip_is_not_private(self):
        """Public IPs are not private."""
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False
        assert _is_private_ip("142.250.185.14") is False  # google.com

    def test_public_hostname_is_not_private(self):
        """Public hostnames are not private."""
        assert _is_private_ip("example.com") is False
        assert _is_private_ip("api.anthropic.com") is False

    def test_case_insensitive_localhost(self):
        """localhost check is case-insensitive."""
        assert _is_private_ip("LOCALHOST") is True
        assert _is_private_ip("LocalHost") is True

    def test_172_15_not_private(self):
        """172.15.x.x is not private (outside RFC 1918 range)."""
        assert _is_private_ip("172.15.255.255") is False

    def test_172_32_not_private(self):
        """172.32.x.x is not private (outside RFC 1918 range)."""
        assert _is_private_ip("172.32.0.1") is False


# =============================================================================
# SSRF PROTECTION TESTS - _validate_gateway_url
# =============================================================================

class TestValidateGatewayUrl:
    """Tests for gateway URL validation (SSRF protection)."""

    def test_https_url_accepted(self):
        """HTTPS URLs are accepted."""
        _validate_gateway_url("https://api.example.com")  # Should not raise

    def test_http_url_accepted(self):
        """HTTP URLs are accepted (for dev environments)."""
        _validate_gateway_url("http://api.example.com")  # Should not raise

    def test_ftp_url_rejected(self):
        """FTP URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("ftp://files.example.com")
        assert "HTTP/HTTPS" in str(exc_info.value)

    def test_file_url_rejected(self):
        """file:// URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("file:///etc/passwd")
        assert "HTTP/HTTPS" in str(exc_info.value)

    def test_missing_hostname_rejected(self):
        """URLs without hostname are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("https://")
        assert "hostname" in str(exc_info.value).lower()

    def test_localhost_rejected(self):
        """localhost URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("https://localhost/api")
        assert "internal" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()

    def test_127_0_0_1_rejected(self):
        """127.0.0.1 URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("https://127.0.0.1/api")
        assert "internal" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()

    def test_private_ip_rejected(self):
        """Private IP URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("https://192.168.1.1/api")
        assert "internal" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()

    def test_10_x_range_rejected(self):
        """10.x.x.x URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("https://10.0.0.1/api")
        assert "internal" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()

    def test_local_domain_rejected(self):
        """*.local URLs are rejected."""
        with pytest.raises(ValueError) as exc_info:
            _validate_gateway_url("https://internal.local/api")
        assert "internal" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()

    def test_public_url_accepted(self):
        """Public URLs are accepted."""
        _validate_gateway_url("https://api.anthropic.com/v1")
        _validate_gateway_url("https://gateway.example.com:443/chat")

    def test_url_with_port_validated(self):
        """URLs with port numbers are validated correctly."""
        _validate_gateway_url("https://api.example.com:8443/v1")  # Should not raise

        with pytest.raises(ValueError):
            _validate_gateway_url("https://localhost:8080/api")


# =============================================================================
# GATEWAY RESPONSE TESTS
# =============================================================================

class TestGatewayResponse:
    """Tests for GatewayResponse dataclass."""

    def test_successful_response(self):
        """GatewayResponse stores successful response data."""
        response = GatewayResponse(
            success=True,
            text="Hello, world!",
            model="claude-3-sonnet",
            tokens_used=100,
            latency_ms=150.5,
        )

        assert response.success is True
        assert response.text == "Hello, world!"
        assert response.model == "claude-3-sonnet"
        assert response.tokens_used == 100
        assert response.latency_ms == 150.5
        assert response.error is None

    def test_error_response(self):
        """GatewayResponse stores error data."""
        response = GatewayResponse(
            success=False,
            text="",
            model="claude-3-sonnet",
            tokens_used=0,
            latency_ms=50.0,
            error="Connection failed",
        )

        assert response.success is False
        assert response.text == ""
        assert response.error == "Connection failed"


# =============================================================================
# MODEL VALIDATION TESTS
# =============================================================================

class TestValidateModel:
    """Tests for model validation."""

    def test_claude_opus_4_allowed(self):
        """claude-opus-4 is in default allowed models."""
        assert validate_model("claude-opus-4") is True

    def test_claude_sonnet_4_allowed(self):
        """claude-sonnet-4 is in default allowed models."""
        assert validate_model("claude-sonnet-4") is True

    def test_claude_haiku_4_allowed(self):
        """claude-haiku-4 is in default allowed models."""
        assert validate_model("claude-haiku-4") is True

    def test_claude_3_5_sonnet_allowed(self):
        """claude-3.5-sonnet is in default allowed models."""
        assert validate_model("claude-3.5-sonnet") is True

    def test_claude_3_opus_allowed(self):
        """claude-3-opus is in default allowed models."""
        assert validate_model("claude-3-opus") is True

    def test_unknown_model_rejected(self):
        """Unknown models are rejected."""
        assert validate_model("gpt-4") is False
        assert validate_model("unknown-model") is False

    def test_custom_allowed_models(self):
        """Custom allowed models list works."""
        custom_models = frozenset(["my-model", "other-model"])

        assert validate_model("my-model", custom_models) is True
        assert validate_model("other-model", custom_models) is True
        assert validate_model("claude-sonnet-4", custom_models) is False


# =============================================================================
# GATEWAY CLIENT INITIALIZATION TESTS
# =============================================================================

class TestGatewayClientInit:
    """Tests for GatewayClient initialization."""

    def test_validates_url_on_init(self):
        """GatewayClient validates URL during initialization."""
        with pytest.raises(ValueError) as exc_info:
            GatewayClient(base_url="https://localhost/api")
        assert "internal" in str(exc_info.value).lower() or "private" in str(exc_info.value).lower()

    def test_skip_validation_for_testing(self):
        """skip_url_validation allows localhost for testing."""
        client = GatewayClient(
            base_url="https://localhost/api",
            skip_url_validation=True,
        )
        assert client.base_url == "https://localhost/api"

    def test_strips_trailing_slash(self):
        """GatewayClient strips trailing slash from base URL."""
        client = GatewayClient(
            base_url="https://api.example.com/",
            skip_url_validation=True,
        )
        assert client.base_url == "https://api.example.com"

    def test_stores_configuration(self):
        """GatewayClient stores configuration values."""
        client = GatewayClient(
            base_url="https://api.example.com",
            timeout_seconds=60,
            user_id="user123",
            api_key="sk-test",
            max_retries=5,
            retry_delay=2.0,
            skip_url_validation=True,
        )

        assert client.timeout == 60
        assert client.user_id == "user123"
        assert client.api_key == "sk-test"
        assert client.max_retries == 5
        assert client.retry_delay == 2.0

    def test_custom_allowed_models(self):
        """GatewayClient accepts custom allowed models."""
        custom_models = frozenset(["custom-model"])
        client = GatewayClient(
            base_url="https://api.example.com",
            allowed_models=custom_models,
            skip_url_validation=True,
        )

        assert client.allowed_models == custom_models


# =============================================================================
# GATEWAY CLIENT MESSAGE VALIDATION TESTS
# =============================================================================

class TestGatewayClientValidateMessages:
    """Tests for message validation in GatewayClient."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        return GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )

    def test_valid_messages_pass(self, client):
        """Valid messages pass validation."""
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]
        client._validate_messages(messages)  # Should not raise

    def test_empty_messages_rejected(self, client):
        """Empty message list is rejected."""
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages([])
        assert "At least one message" in str(exc_info.value)

    def test_non_list_messages_rejected(self, client):
        """Non-list messages are rejected."""
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages({"role": "user", "content": "test"})
        assert "must be a list" in str(exc_info.value)

    def test_too_many_messages_rejected(self, client):
        """More than 100 messages is rejected."""
        messages = [{"role": "user", "content": "test"}] * 101
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages(messages)
        assert "Maximum 100 messages" in str(exc_info.value)

    def test_message_missing_role_rejected(self, client):
        """Message without role is rejected."""
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages([{"content": "test"}])
        assert "missing 'role'" in str(exc_info.value)

    def test_message_missing_content_rejected(self, client):
        """Message without content is rejected."""
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages([{"role": "user"}])
        assert "missing 'content'" in str(exc_info.value)

    def test_invalid_role_rejected(self, client):
        """Invalid role is rejected."""
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages([{"role": "admin", "content": "test"}])
        assert "Invalid role" in str(exc_info.value)

    def test_valid_roles_accepted(self, client):
        """Valid roles (user, assistant, system) are accepted."""
        messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
        ]
        client._validate_messages(messages)  # Should not raise

    def test_non_string_content_rejected(self, client):
        """Non-string content is rejected."""
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages([{"role": "user", "content": 123}])
        assert "must be a string" in str(exc_info.value)

    def test_too_long_message_rejected(self, client):
        """Message over 1MB is rejected."""
        long_content = "x" * (1_000_001)  # Just over 1MB
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages([{"role": "user", "content": long_content}])
        assert "too long" in str(exc_info.value).lower()

    def test_total_content_too_large_rejected(self, client):
        """Total content over 10MB is rejected."""
        # 20 messages of 600KB each = 12MB > 10MB limit
        messages = [{"role": "user", "content": "x" * 600_000}] * 20
        with pytest.raises(ValueError) as exc_info:
            client._validate_messages(messages)
        assert "too large" in str(exc_info.value).lower()


# =============================================================================
# GATEWAY CLIENT RESPONSE VALIDATION TESTS
# =============================================================================

class TestGatewayClientValidateResponse:
    """Tests for response validation in GatewayClient."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        return GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )

    def test_valid_response_passes(self, client):
        """Valid response passes validation."""
        data = {
            "content": "Hello!",
            "model": "claude-3-sonnet",
            "usage": {"total_tokens": 100}
        }
        result = client._validate_response(data)
        assert result is None

    def test_minimal_valid_response(self, client):
        """Minimal valid response (just content) passes."""
        data = {"content": "Hello!"}
        result = client._validate_response(data)
        assert result is None

    def test_non_dict_response_fails(self, client):
        """Non-dict response fails validation."""
        result = client._validate_response("just a string")
        assert result is not None
        assert "not a JSON object" in result

    def test_missing_content_fails(self, client):
        """Response without content fails validation."""
        data = {"model": "claude-3-sonnet"}
        result = client._validate_response(data)
        assert result is not None
        assert "missing 'content'" in result

    def test_non_string_content_fails(self, client):
        """Non-string content fails validation."""
        data = {"content": 123}
        result = client._validate_response(data)
        assert result is not None
        assert "'content' is not a string" in result

    def test_invalid_usage_type_fails(self, client):
        """Non-dict usage fails validation."""
        data = {"content": "Hello", "usage": "100 tokens"}
        result = client._validate_response(data)
        assert result is not None
        assert "'usage' is not an object" in result

    def test_invalid_total_tokens_type_fails(self, client):
        """Non-int total_tokens fails validation."""
        data = {"content": "Hello", "usage": {"total_tokens": "100"}}
        result = client._validate_response(data)
        assert result is not None
        assert "'usage.total_tokens' is not an integer" in result


# =============================================================================
# GATEWAY CLIENT HEADERS TESTS
# =============================================================================

class TestGatewayClientHeaders:
    """Tests for header construction in GatewayClient."""

    def test_headers_without_api_key(self):
        """Headers without API key include only Content-Type."""
        client = GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )
        headers = client._get_headers()

        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_headers_with_api_key(self):
        """Headers with API key include Bearer token."""
        client = GatewayClient(
            base_url="https://api.example.com",
            api_key="sk-test-key",
            skip_url_validation=True,
        )
        headers = client._get_headers()

        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer sk-test-key"


# =============================================================================
# GATEWAY CLIENT CHAT TESTS (with mocked httpx)
# =============================================================================

class TestGatewayClientChat:
    """Tests for GatewayClient.chat method."""

    @pytest.fixture
    def mock_httpx(self):
        """Mock httpx for testing."""
        with patch.dict("sys.modules", {"httpx": MagicMock()}):
            import sys
            httpx_mock = sys.modules["httpx"]
            httpx_mock.TimeoutException = Exception
            httpx_mock.ConnectError = Exception
            httpx_mock.HTTPStatusError = Exception
            yield httpx_mock

    def test_chat_raises_on_invalid_model(self):
        """chat() raises ValueError for invalid model."""
        client = GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )
        client._client = MagicMock()
        client._httpx_available = True

        messages = [{"role": "user", "content": "Hello"}]

        with pytest.raises(ValueError) as exc_info:
            client.chat(messages, model="invalid-model")
        assert "not available" in str(exc_info.value)

    def test_chat_raises_stub_error_without_httpx(self):
        """chat() raises GatewayStubError when httpx not installed."""
        client = GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )
        client._client = None
        client._httpx_available = False

        messages = [{"role": "user", "content": "Hello"}]

        with pytest.raises(GatewayStubError) as exc_info:
            client.chat(messages, model="claude-sonnet-4")
        assert "httpx not installed" in str(exc_info.value)

    def test_chat_validates_messages_before_request(self):
        """chat() validates messages before making request."""
        client = GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )
        client._client = MagicMock()
        client._httpx_available = True

        # Empty messages should fail validation before request
        with pytest.raises(ValueError) as exc_info:
            client.chat([], model="claude-sonnet-4")
        assert "At least one message" in str(exc_info.value)


# =============================================================================
# GATEWAY ERROR TESTS
# =============================================================================

class TestGatewayErrors:
    """Tests for gateway error classes."""

    def test_gateway_error_base(self):
        """GatewayError is the base exception."""
        error = GatewayError("Something went wrong")
        assert str(error) == "Something went wrong"
        assert isinstance(error, Exception)

    def test_gateway_timeout_error(self):
        """GatewayTimeoutError inherits from GatewayError."""
        error = GatewayTimeoutError("Request timed out")
        assert isinstance(error, GatewayError)
        assert str(error) == "Request timed out"

    def test_gateway_auth_error(self):
        """GatewayAuthError inherits from GatewayError."""
        error = GatewayAuthError("Invalid API key")
        assert isinstance(error, GatewayError)
        assert str(error) == "Invalid API key"

    def test_gateway_rate_limit_error(self):
        """GatewayRateLimitError inherits from GatewayError."""
        error = GatewayRateLimitError("Too many requests")
        assert isinstance(error, GatewayError)
        assert str(error) == "Too many requests"

    def test_gateway_stub_error(self):
        """GatewayStubError inherits from GatewayError."""
        error = GatewayStubError("httpx not installed")
        assert isinstance(error, GatewayError)
        assert str(error) == "httpx not installed"


# =============================================================================
# GATEWAY CLIENT CONTEXT MANAGER TESTS
# =============================================================================

class TestGatewayClientContextManager:
    """Tests for GatewayClient context manager."""

    def test_context_manager_enters(self):
        """GatewayClient can be used as context manager."""
        with GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        ) as client:
            assert client is not None
            assert client.base_url == "https://api.example.com"

    def test_context_manager_closes_client(self):
        """Context manager calls close on exit."""
        client = GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )
        mock_client = MagicMock()
        client._client = mock_client

        with client:
            pass  # Enter and exit

        mock_client.close.assert_called_once()

    def test_close_without_client_is_safe(self):
        """close() is safe when _client is None."""
        client = GatewayClient(
            base_url="https://api.example.com",
            skip_url_validation=True,
        )
        client._client = None

        client.close()  # Should not raise


# =============================================================================
# DEFAULT ALLOWED MODELS TESTS
# =============================================================================

class TestDefaultAllowedModels:
    """Tests for the default allowed models list."""

    def test_contains_claude_4_models(self):
        """Default list contains Claude 4 models."""
        assert "claude-opus-4" in DEFAULT_ALLOWED_MODELS
        assert "claude-sonnet-4" in DEFAULT_ALLOWED_MODELS
        assert "claude-haiku-4" in DEFAULT_ALLOWED_MODELS

    def test_contains_claude_3_5_aliases(self):
        """Default list contains Claude 3.5 aliases."""
        assert "claude-3.5-sonnet" in DEFAULT_ALLOWED_MODELS
        assert "claude-3.5-haiku" in DEFAULT_ALLOWED_MODELS

    def test_contains_claude_3_legacy(self):
        """Default list contains Claude 3 legacy models."""
        assert "claude-3-opus" in DEFAULT_ALLOWED_MODELS
        assert "claude-3-sonnet" in DEFAULT_ALLOWED_MODELS
        assert "claude-3-haiku" in DEFAULT_ALLOWED_MODELS

    def test_is_frozenset(self):
        """Default list is a frozenset (immutable)."""
        assert isinstance(DEFAULT_ALLOWED_MODELS, frozenset)

    def test_does_not_contain_gpt_models(self):
        """Default list does not contain GPT models."""
        assert "gpt-4" not in DEFAULT_ALLOWED_MODELS
        assert "gpt-3.5-turbo" not in DEFAULT_ALLOWED_MODELS
