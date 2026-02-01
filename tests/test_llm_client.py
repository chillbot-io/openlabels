"""Tests for LLM client abstraction layer.

Tests for LLMResponse, create_client, AnthropicClient, and OpenAIClient.
"""

import os
import sys
from dataclasses import fields
from unittest.mock import MagicMock, patch

import pytest

from scrubiq.llm_client import (
    LLMResponse,
    create_client,
    AnthropicClient,
    OpenAIClient,
)


# =============================================================================
# LLMRESPONSE DATACLASS TESTS
# =============================================================================

class TestLLMResponse:
    """Tests for LLMResponse dataclass."""

    def test_creates_with_required_fields(self):
        """Creates response with required fields."""
        response = LLMResponse(
            success=True,
            text="Hello",
            model="claude-sonnet-4",
            provider="anthropic",
            tokens_used=100,
            latency_ms=150.5,
        )

        assert response.success is True
        assert response.text == "Hello"
        assert response.model == "claude-sonnet-4"
        assert response.provider == "anthropic"
        assert response.tokens_used == 100
        assert response.latency_ms == 150.5

    def test_error_defaults_to_none(self):
        """Error field defaults to None."""
        response = LLMResponse(
            success=True,
            text="OK",
            model="test",
            provider="test",
            tokens_used=0,
            latency_ms=0,
        )

        assert response.error is None

    def test_usage_defaults_to_none(self):
        """Usage field defaults to None."""
        response = LLMResponse(
            success=True,
            text="OK",
            model="test",
            provider="test",
            tokens_used=0,
            latency_ms=0,
        )

        assert response.usage is None

    def test_can_set_error(self):
        """Can set error message."""
        response = LLMResponse(
            success=False,
            text="",
            model="test",
            provider="test",
            tokens_used=0,
            latency_ms=0,
            error="API rate limit exceeded",
        )

        assert response.error == "API rate limit exceeded"

    def test_can_set_usage(self):
        """Can set usage dictionary."""
        usage = {"input_tokens": 50, "output_tokens": 100}
        response = LLMResponse(
            success=True,
            text="OK",
            model="test",
            provider="test",
            tokens_used=150,
            latency_ms=0,
            usage=usage,
        )

        assert response.usage == usage
        assert response.usage["input_tokens"] == 50
        assert response.usage["output_tokens"] == 100

    def test_is_dataclass(self):
        """LLMResponse is a dataclass."""
        response = LLMResponse(
            success=True,
            text="OK",
            model="test",
            provider="test",
            tokens_used=0,
            latency_ms=0,
        )

        # Should have __dataclass_fields__
        assert hasattr(response, "__dataclass_fields__")

    def test_has_expected_fields(self):
        """Has expected field names."""
        field_names = {f.name for f in fields(LLMResponse)}

        assert "success" in field_names
        assert "text" in field_names
        assert "model" in field_names
        assert "provider" in field_names
        assert "tokens_used" in field_names
        assert "latency_ms" in field_names
        assert "error" in field_names
        assert "usage" in field_names


# =============================================================================
# CREATE_CLIENT TESTS
# =============================================================================

class TestCreateClient:
    """Tests for create_client function."""

    def test_default_provider_is_anthropic(self):
        """Default provider is anthropic when not specified."""
        client = create_client(api_key="test-key")

        assert isinstance(client, AnthropicClient)

    def test_explicit_anthropic_provider(self):
        """Returns AnthropicClient for anthropic provider."""
        client = create_client(provider="anthropic", api_key="test-key")

        assert isinstance(client, AnthropicClient)

    def test_explicit_openai_provider(self):
        """Returns OpenAIClient for openai provider."""
        client = create_client(provider="openai", api_key="test-key")

        assert isinstance(client, OpenAIClient)

    def test_case_insensitive_provider(self):
        """Provider name is case insensitive."""
        client1 = create_client(provider="ANTHROPIC", api_key="test")
        client2 = create_client(provider="OpenAI", api_key="test")

        assert isinstance(client1, AnthropicClient)
        assert isinstance(client2, OpenAIClient)

    def test_auto_detect_claude_model(self):
        """Auto-detects anthropic from claude model name."""
        client = create_client(model="claude-sonnet-4", api_key="test")

        assert isinstance(client, AnthropicClient)

    def test_auto_detect_anthropic_model(self):
        """Auto-detects anthropic from model name starting with anthropic."""
        client = create_client(model="anthropic.claude-v2", api_key="test")

        assert isinstance(client, AnthropicClient)

    def test_auto_detect_gpt_model(self):
        """Auto-detects openai from gpt model name."""
        client = create_client(model="gpt-4o", api_key="test")

        assert isinstance(client, OpenAIClient)

    def test_auto_detect_o1_model(self):
        """Auto-detects openai from o1 model name."""
        client = create_client(model="o1-mini", api_key="test")

        assert isinstance(client, OpenAIClient)

    def test_auto_detect_davinci_model(self):
        """Auto-detects openai from davinci model name."""
        client = create_client(model="davinci-003", api_key="test")

        assert isinstance(client, OpenAIClient)

    def test_unknown_model_defaults_to_anthropic(self):
        """Unknown model name defaults to anthropic."""
        client = create_client(model="unknown-model-xyz", api_key="test")

        assert isinstance(client, AnthropicClient)

    def test_empty_provider_raises_error(self):
        """Empty string provider raises ValueError."""
        with pytest.raises(ValueError, match="cannot be an empty string"):
            create_client(provider="", api_key="test")

    def test_whitespace_provider_raises_error(self):
        """Whitespace-only provider raises ValueError."""
        with pytest.raises(ValueError, match="cannot be an empty string"):
            create_client(provider="   ", api_key="test")

    def test_unknown_provider_raises_error(self):
        """Unknown provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown provider"):
            create_client(provider="llama", api_key="test")

    def test_google_provider_not_implemented(self):
        """Google provider raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            create_client(provider="google", api_key="test")

    def test_gemini_provider_not_implemented(self):
        """Gemini provider raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            create_client(provider="gemini", api_key="test")

    def test_azure_provider_not_implemented(self):
        """Azure provider raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            create_client(provider="azure", api_key="test")

    def test_azure_openai_provider_not_implemented(self):
        """Azure OpenAI provider raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            create_client(provider="azure_openai", api_key="test")

    def test_passes_kwargs_to_anthropic(self):
        """Passes kwargs to AnthropicClient."""
        client = create_client(provider="anthropic", api_key="test", timeout=300)

        assert client.timeout == 300

    def test_passes_kwargs_to_openai(self):
        """Passes kwargs to OpenAIClient."""
        client = create_client(provider="openai", api_key="test", timeout=300)

        assert client.timeout == 300


# =============================================================================
# ANTHROPIC CLIENT INIT TESTS
# =============================================================================

class TestAnthropicClientInit:
    """Tests for AnthropicClient initialization."""

    def test_stores_api_key(self):
        """Stores provided API key."""
        client = AnthropicClient(api_key="test-key-123")

        assert client.api_key == "test-key-123"

    def test_falls_back_to_env_var(self):
        """Falls back to environment variable when no key provided."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}, clear=False):
            client = AnthropicClient()

        assert client.api_key == "env-key"

    def test_explicit_none_no_fallback(self):
        """Explicit None does not fall back to env var."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}, clear=False):
            client = AnthropicClient(api_key=None)

        assert client.api_key is None

    def test_empty_string_treated_as_none(self):
        """Empty string API key is treated as None."""
        client = AnthropicClient(api_key="")

        assert client.api_key is None

    def test_whitespace_string_treated_as_none(self):
        """Whitespace-only API key is treated as None."""
        client = AnthropicClient(api_key="   ")

        assert client.api_key is None

    def test_default_timeout(self):
        """Default timeout is 120 seconds."""
        client = AnthropicClient(api_key="test")

        assert client.timeout == 120

    def test_custom_timeout(self):
        """Custom timeout is stored."""
        client = AnthropicClient(api_key="test", timeout=300)

        assert client.timeout == 300

    def test_client_not_initialized(self):
        """Client is not initialized on construction."""
        client = AnthropicClient(api_key="test")

        assert client._client is None
        assert client._initialized is False

    def test_init_error_is_none(self):
        """Init error is None initially."""
        client = AnthropicClient(api_key="test")

        assert client._init_error is None


# =============================================================================
# ANTHROPIC CLIENT MODEL MAP TESTS
# =============================================================================

class TestAnthropicModelMap:
    """Tests for AnthropicClient model mapping."""

    def test_model_map_exists(self):
        """MODEL_MAP attribute exists."""
        assert hasattr(AnthropicClient, "MODEL_MAP")
        assert isinstance(AnthropicClient.MODEL_MAP, dict)

    def test_has_claude_opus_4(self):
        """Has claude-opus-4 mapping."""
        assert "claude-opus-4" in AnthropicClient.MODEL_MAP
        assert "claude-opus-4-" in AnthropicClient.MODEL_MAP["claude-opus-4"]

    def test_has_claude_sonnet_4(self):
        """Has claude-sonnet-4 mapping."""
        assert "claude-sonnet-4" in AnthropicClient.MODEL_MAP
        assert "claude-sonnet-4-" in AnthropicClient.MODEL_MAP["claude-sonnet-4"]

    def test_has_claude_haiku_4(self):
        """Has claude-haiku-4 mapping."""
        assert "claude-haiku-4" in AnthropicClient.MODEL_MAP
        assert "claude-haiku-4-" in AnthropicClient.MODEL_MAP["claude-haiku-4"]

    def test_claude_3_5_sonnet_maps_to_4(self):
        """Claude 3.5 sonnet maps to Claude 4 equivalent."""
        assert "claude-3.5-sonnet" in AnthropicClient.MODEL_MAP
        assert "sonnet-4" in AnthropicClient.MODEL_MAP["claude-3.5-sonnet"]

    def test_has_legacy_claude_3_models(self):
        """Has legacy Claude 3 models."""
        assert "claude-3-opus" in AnthropicClient.MODEL_MAP
        assert "claude-3-sonnet" in AnthropicClient.MODEL_MAP
        assert "claude-3-haiku" in AnthropicClient.MODEL_MAP


# =============================================================================
# ANTHROPIC CLIENT AVAILABILITY TESTS
# =============================================================================

class TestAnthropicClientAvailability:
    """Tests for AnthropicClient availability methods."""

    def test_is_available_with_key(self):
        """is_available returns True when API key is set."""
        client = AnthropicClient(api_key="test-key")

        assert client.is_available() is True

    def test_is_available_without_key(self):
        """is_available returns False when no API key."""
        client = AnthropicClient(api_key=None)

        assert client.is_available() is False

    def test_is_ready_before_init(self):
        """is_ready returns False before initialization."""
        client = AnthropicClient(api_key="test-key")

        assert client.is_ready() is False

    def test_list_models_returns_list(self):
        """list_models returns a list of model names."""
        client = AnthropicClient(api_key="test")

        models = client.list_models()

        assert isinstance(models, list)
        assert len(models) > 0

    def test_list_models_contains_sonnet(self):
        """list_models includes claude-sonnet-4."""
        client = AnthropicClient(api_key="test")

        models = client.list_models()

        assert "claude-sonnet-4" in models

    def test_list_models_contains_haiku(self):
        """list_models includes claude-haiku-4."""
        client = AnthropicClient(api_key="test")

        models = client.list_models()

        assert "claude-haiku-4" in models

    def test_list_models_contains_opus(self):
        """list_models includes claude-opus-4."""
        client = AnthropicClient(api_key="test")

        models = client.list_models()

        assert "claude-opus-4" in models


# =============================================================================
# ANTHROPIC CLIENT INITIALIZATION TESTS
# =============================================================================

class TestAnthropicClientEnsureClient:
    """Tests for AnthropicClient lazy initialization."""

    def test_ensure_client_returns_false_without_key(self):
        """_ensure_client returns False when no API key."""
        client = AnthropicClient(api_key=None)

        result = client._ensure_client()

        assert result is False
        assert client._init_error == "ANTHROPIC_API_KEY not set"

    def test_ensure_client_sets_initialized(self):
        """_ensure_client sets _initialized flag."""
        client = AnthropicClient(api_key=None)

        client._ensure_client()

        assert client._initialized is True

    def test_ensure_client_idempotent(self):
        """_ensure_client only runs once."""
        client = AnthropicClient(api_key=None)

        client._ensure_client()
        client._init_error = "First error"
        client._ensure_client()  # Should not overwrite

        # Second call should not change state
        assert client._init_error == "First error"

    def test_initialize_calls_ensure_client(self):
        """initialize() is alias for _ensure_client()."""
        client = AnthropicClient(api_key=None)

        result = client.initialize()

        assert result is False
        assert client._initialized is True

    @patch("scrubiq.llm_client.logger")
    def test_ensure_client_handles_import_error(self, mock_logger):
        """Handles ImportError when anthropic not installed."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = False

        # Mock the import to fail by patching builtins.__import__
        original_import = __import__

        def mock_import(name, *args, **kwargs):
            if name == "anthropic":
                raise ImportError("No module named 'anthropic'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = client._ensure_client()

        assert result is False
        assert "not installed" in client._init_error

    def test_is_ready_after_successful_init(self):
        """is_ready returns True after successful initialization."""
        client = AnthropicClient(api_key="test-key")

        # Mock successful init
        client._client = MagicMock()

        assert client.is_ready() is True


# =============================================================================
# ANTHROPIC CLIENT CHAT TESTS
# =============================================================================

class TestAnthropicClientChat:
    """Tests for AnthropicClient chat method."""

    def test_chat_returns_error_without_init(self):
        """chat returns error response when client not initialized."""
        client = AnthropicClient(api_key=None)

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.success is False
        assert response.error is not None
        assert response.tokens_used == 0

    def test_chat_returns_error_message(self):
        """chat error includes initialization error."""
        client = AnthropicClient(api_key=None)
        client._ensure_client()

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert "not set" in response.error or "not available" in response.error

    def test_chat_provider_is_anthropic(self):
        """chat response provider is anthropic."""
        client = AnthropicClient(api_key=None)

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.provider == "anthropic"

    def test_chat_preserves_model(self):
        """chat response includes requested model."""
        client = AnthropicClient(api_key=None)

        response = client.chat(
            [{"role": "user", "content": "Hello"}],
            model="claude-opus-4"
        )

        assert response.model == "claude-opus-4"

    def test_chat_includes_latency(self):
        """chat response includes latency measurement."""
        client = AnthropicClient(api_key=None)

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.latency_ms >= 0

    def test_chat_with_mock_client_success(self):
        """chat returns success with mocked API client."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        # Create mock response
        mock_content = MagicMock()
        mock_content.text = "Hello, world!"

        mock_usage = MagicMock()
        mock_usage.input_tokens = 10
        mock_usage.output_tokens = 20

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.success is True
        assert response.text == "Hello, world!"
        assert response.tokens_used == 30
        assert response.usage["input_tokens"] == 10
        assert response.usage["output_tokens"] == 20

    def test_chat_maps_model_name(self):
        """chat maps friendly model name to API model ID."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage = MagicMock(input_tokens=0, output_tokens=0)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        client._client = mock_client

        client.chat([{"role": "user", "content": "Hi"}], model="claude-sonnet-4")

        call_kwargs = mock_client.messages.create.call_args[1]
        assert "claude-sonnet-4-" in call_kwargs["model"]

    def test_chat_extracts_system_from_messages(self):
        """chat extracts system message from message list."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage = MagicMock(input_tokens=0, output_tokens=0)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        client._client = mock_client

        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hi"},
        ]
        client.chat(messages)

        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs["system"] == "You are helpful"
        # System should not be in messages
        assert all(m.get("role") != "system" for m in call_kwargs["messages"])

    def test_chat_explicit_system_overrides(self):
        """Explicit system parameter overrides message system."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage = MagicMock(input_tokens=0, output_tokens=0)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        client._client = mock_client

        messages = [
            {"role": "system", "content": "From messages"},
            {"role": "user", "content": "Hi"},
        ]
        client.chat(messages, system="Explicit system")

        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs["system"] == "Explicit system"

    def test_chat_handles_api_exception(self):
        """chat handles API exceptions gracefully."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API Error")
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hi"}])

        assert response.success is False
        assert "API Error" in response.error

    def test_chat_handles_empty_content(self):
        """chat handles empty response content."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage = MagicMock(input_tokens=0, output_tokens=0)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hi"}])

        assert response.success is True
        assert response.text == ""


# =============================================================================
# ANTHROPIC CLIENT STREAMING TESTS
# =============================================================================

class TestAnthropicClientChatStream:
    """Tests for AnthropicClient chat_stream method."""

    def test_stream_yields_none_without_init(self):
        """chat_stream yields None when client not initialized."""
        client = AnthropicClient(api_key=None)

        chunks = list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        assert chunks == [None]

    def test_stream_with_mock_client(self):
        """chat_stream yields text chunks."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_stream = MagicMock()
        mock_stream.text_stream = ["Hello", " ", "world", "!"]
        mock_stream.__enter__ = MagicMock(return_value=mock_stream)
        mock_stream.__exit__ = MagicMock(return_value=False)

        mock_client = MagicMock()
        mock_client.messages.stream.return_value = mock_stream
        client._client = mock_client

        chunks = list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        # Should yield chunks plus None at end
        assert chunks[:-1] == ["Hello", " ", "world", "!"]
        assert chunks[-1] is None

    def test_stream_extracts_system_message(self):
        """chat_stream extracts system from messages."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_stream = MagicMock()
        mock_stream.text_stream = []
        mock_stream.__enter__ = MagicMock(return_value=mock_stream)
        mock_stream.__exit__ = MagicMock(return_value=False)

        mock_client = MagicMock()
        mock_client.messages.stream.return_value = mock_stream
        client._client = mock_client

        messages = [
            {"role": "system", "content": "Be helpful"},
            {"role": "user", "content": "Hi"},
        ]
        list(client.chat_stream(messages))

        call_kwargs = mock_client.messages.stream.call_args[1]
        assert call_kwargs["system"] == "Be helpful"

    def test_stream_handles_exception(self):
        """chat_stream handles exceptions by yielding None."""
        client = AnthropicClient(api_key="test-key")
        client._initialized = True

        mock_client = MagicMock()
        mock_client.messages.stream.side_effect = Exception("Stream error")
        client._client = mock_client

        chunks = list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        assert chunks == [None]


# =============================================================================
# OPENAI CLIENT INIT TESTS
# =============================================================================

class TestOpenAIClientInit:
    """Tests for OpenAIClient initialization."""

    def test_stores_api_key(self):
        """Stores provided API key."""
        client = OpenAIClient(api_key="sk-test-key")

        assert client.api_key == "sk-test-key"

    def test_falls_back_to_env_var(self):
        """Falls back to environment variable when no key provided."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-key"}, clear=False):
            client = OpenAIClient()

        assert client.api_key == "sk-env-key"

    def test_explicit_none_no_fallback(self):
        """Explicit None does not fall back to env var."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env"}, clear=False):
            client = OpenAIClient(api_key=None)

        assert client.api_key is None

    def test_empty_string_treated_as_none(self):
        """Empty string API key is treated as None."""
        client = OpenAIClient(api_key="")

        assert client.api_key is None

    def test_default_timeout(self):
        """Default timeout is 120 seconds."""
        client = OpenAIClient(api_key="test")

        assert client.timeout == 120

    def test_client_not_initialized(self):
        """Client is not initialized on construction."""
        client = OpenAIClient(api_key="test")

        assert client._client is None
        assert client._initialized is False

    def test_provider_is_openai(self):
        """Provider attribute is openai."""
        assert OpenAIClient.provider == "openai"


# =============================================================================
# OPENAI CLIENT MODEL MAP TESTS
# =============================================================================

class TestOpenAIModelMap:
    """Tests for OpenAIClient model mapping."""

    def test_model_map_exists(self):
        """MODEL_MAP attribute exists."""
        assert hasattr(OpenAIClient, "MODEL_MAP")
        assert isinstance(OpenAIClient.MODEL_MAP, dict)

    def test_has_gpt4o(self):
        """Has gpt-4o mapping."""
        assert "gpt-4o" in OpenAIClient.MODEL_MAP

    def test_has_gpt4o_mini(self):
        """Has gpt-4o-mini mapping."""
        assert "gpt-4o-mini" in OpenAIClient.MODEL_MAP

    def test_has_o1_models(self):
        """Has o1 reasoning models."""
        assert "o1" in OpenAIClient.MODEL_MAP
        assert "o1-mini" in OpenAIClient.MODEL_MAP

    def test_has_gpt35_turbo(self):
        """Has gpt-3.5-turbo model."""
        assert "gpt-3.5-turbo" in OpenAIClient.MODEL_MAP


# =============================================================================
# OPENAI CLIENT AVAILABILITY TESTS
# =============================================================================

class TestOpenAIClientAvailability:
    """Tests for OpenAIClient availability methods."""

    def test_is_available_with_key(self):
        """is_available returns True when API key is set."""
        client = OpenAIClient(api_key="sk-test")

        assert client.is_available() is True

    def test_is_available_without_key(self):
        """is_available returns False when no API key."""
        client = OpenAIClient(api_key=None)

        assert client.is_available() is False

    def test_is_ready_before_init(self):
        """is_ready returns False before initialization."""
        client = OpenAIClient(api_key="sk-test")

        assert client.is_ready() is False

    def test_list_models_returns_list(self):
        """list_models returns a list of model names."""
        client = OpenAIClient(api_key="test")

        models = client.list_models()

        assert isinstance(models, list)
        assert len(models) > 0

    def test_list_models_contains_gpt4o(self):
        """list_models includes gpt-4o."""
        client = OpenAIClient(api_key="test")

        models = client.list_models()

        assert "gpt-4o" in models


# =============================================================================
# OPENAI CLIENT INITIALIZATION TESTS
# =============================================================================

class TestOpenAIClientEnsureClient:
    """Tests for OpenAIClient lazy initialization."""

    def test_ensure_client_returns_false_without_key(self):
        """_ensure_client returns False when no API key."""
        client = OpenAIClient(api_key=None)

        result = client._ensure_client()

        assert result is False
        assert client._init_error == "OPENAI_API_KEY not set"

    def test_ensure_client_sets_initialized(self):
        """_ensure_client sets _initialized flag."""
        client = OpenAIClient(api_key=None)

        client._ensure_client()

        assert client._initialized is True

    def test_initialize_calls_ensure_client(self):
        """initialize() is alias for _ensure_client()."""
        client = OpenAIClient(api_key=None)

        result = client.initialize()

        assert result is False
        assert client._initialized is True


# =============================================================================
# OPENAI CLIENT CHAT TESTS
# =============================================================================

class TestOpenAIClientChat:
    """Tests for OpenAIClient chat method."""

    def test_chat_returns_error_without_init(self):
        """chat returns error response when client not initialized."""
        client = OpenAIClient(api_key=None)

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.success is False
        assert response.error is not None

    def test_chat_provider_is_openai(self):
        """chat response provider is openai."""
        client = OpenAIClient(api_key=None)

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.provider == "openai"

    def test_chat_preserves_model(self):
        """chat response includes requested model."""
        client = OpenAIClient(api_key=None)

        response = client.chat(
            [{"role": "user", "content": "Hello"}],
            model="gpt-4o"
        )

        assert response.model == "gpt-4o"

    def test_chat_with_mock_client_success(self):
        """chat returns success with mocked API client."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        # Create mock response
        mock_message = MagicMock()
        mock_message.content = "Hello from GPT!"

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 15
        mock_usage.completion_tokens = 25

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hello"}])

        assert response.success is True
        assert response.text == "Hello from GPT!"
        assert response.tokens_used == 40
        assert response.usage["input_tokens"] == 15
        assert response.usage["output_tokens"] == 25

    def test_chat_adds_system_message(self):
        """chat adds explicit system message to front."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.choices = []
        mock_response.usage = MagicMock(prompt_tokens=0, completion_tokens=0)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        client._client = mock_client

        client.chat(
            [{"role": "user", "content": "Hi"}],
            system="You are helpful"
        )

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "You are helpful"

    def test_chat_skips_duplicate_system(self):
        """chat skips system in messages when explicit system provided."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.choices = []
        mock_response.usage = MagicMock(prompt_tokens=0, completion_tokens=0)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        client._client = mock_client

        messages = [
            {"role": "system", "content": "From messages"},
            {"role": "user", "content": "Hi"},
        ]
        client.chat(messages, system="Explicit")

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        sent_messages = call_kwargs["messages"]
        # Should only have one system message (explicit)
        system_messages = [m for m in sent_messages if m["role"] == "system"]
        assert len(system_messages) == 1
        assert system_messages[0]["content"] == "Explicit"

    def test_chat_handles_api_exception(self):
        """chat handles API exceptions gracefully."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Rate limited")
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hi"}])

        assert response.success is False
        assert "Rate limited" in response.error

    def test_chat_handles_empty_choices(self):
        """chat handles empty choices list."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_response = MagicMock()
        mock_response.choices = []
        mock_response.usage = MagicMock(prompt_tokens=0, completion_tokens=0)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hi"}])

        assert response.success is True
        assert response.text == ""

    def test_chat_handles_none_content(self):
        """chat handles None content in response."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_message = MagicMock()
        mock_message.content = None

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = MagicMock(prompt_tokens=0, completion_tokens=0)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        client._client = mock_client

        response = client.chat([{"role": "user", "content": "Hi"}])

        assert response.success is True
        assert response.text == ""


# =============================================================================
# OPENAI CLIENT STREAMING TESTS
# =============================================================================

class TestOpenAIClientChatStream:
    """Tests for OpenAIClient chat_stream method."""

    def test_stream_yields_none_without_init(self):
        """chat_stream yields None when client not initialized."""
        client = OpenAIClient(api_key=None)

        chunks = list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        assert chunks == [None]

    def test_stream_with_mock_client(self):
        """chat_stream yields text chunks."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        # Create mock chunks
        def create_chunk(text):
            delta = MagicMock()
            delta.content = text
            choice = MagicMock()
            choice.delta = delta
            chunk = MagicMock()
            chunk.choices = [choice]
            return chunk

        mock_chunks = [
            create_chunk("Hello"),
            create_chunk(" there"),
            create_chunk("!"),
        ]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = iter(mock_chunks)
        client._client = mock_client

        chunks = list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        # Should yield text plus None at end
        assert chunks[:-1] == ["Hello", " there", "!"]
        assert chunks[-1] is None

    def test_stream_adds_system_message(self):
        """chat_stream adds explicit system message."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = iter([])
        client._client = mock_client

        list(client.chat_stream(
            [{"role": "user", "content": "Hi"}],
            system="Be helpful"
        ))

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "Be helpful"

    def test_stream_handles_exception(self):
        """chat_stream handles exceptions by yielding None."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Error")
        client._client = mock_client

        chunks = list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        assert chunks == [None]

    def test_stream_sets_stream_flag(self):
        """chat_stream passes stream=True to API."""
        client = OpenAIClient(api_key="sk-test")
        client._initialized = True

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = iter([])
        client._client = mock_client

        list(client.chat_stream([{"role": "user", "content": "Hi"}]))

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["stream"] is True


# =============================================================================
# PROVIDER ATTRIBUTE TESTS
# =============================================================================

class TestProviderAttributes:
    """Tests for provider class attributes."""

    def test_anthropic_provider_attribute(self):
        """AnthropicClient has provider = 'anthropic'."""
        assert AnthropicClient.provider == "anthropic"

    def test_openai_provider_attribute(self):
        """OpenAIClient has provider = 'openai'."""
        assert OpenAIClient.provider == "openai"

    def test_anthropic_use_env_sentinel(self):
        """AnthropicClient has _USE_ENV sentinel."""
        assert hasattr(AnthropicClient, "_USE_ENV")
        assert AnthropicClient._USE_ENV is not None

    def test_openai_use_env_sentinel(self):
        """OpenAIClient has _USE_ENV sentinel."""
        assert hasattr(OpenAIClient, "_USE_ENV")
        assert OpenAIClient._USE_ENV is not None

    def test_sentinels_are_unique(self):
        """Each client has its own _USE_ENV sentinel."""
        # They should be different objects
        assert AnthropicClient._USE_ENV is not OpenAIClient._USE_ENV
