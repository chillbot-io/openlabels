"""Tests for LLM client management mixin.

Tests for LLMMixin class.
"""

from unittest.mock import MagicMock

import pytest

from scrubiq.mixins.llm import LLMMixin


# =============================================================================
# TEST CLASS SETUP
# =============================================================================

class MockLLMMixin(LLMMixin):
    """Mock class using LLMMixin for testing."""

    def __init__(self):
        self._llm_client = None
        self._openai_client = None
        self._llm_loading = False


# =============================================================================
# HAS_LLM TESTS
# =============================================================================

class TestHasLLM:
    """Tests for has_llm method."""

    def test_returns_false_when_no_client(self):
        """Returns False when no LLM client."""
        mixin = MockLLMMixin()

        assert mixin.has_llm() is False

    def test_returns_false_when_not_available(self):
        """Returns False when client not available."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = False

        assert mixin.has_llm() is False

    def test_returns_true_when_available(self):
        """Returns True when client available."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        assert mixin.has_llm() is True


# =============================================================================
# LIST_LLM_PROVIDERS TESTS
# =============================================================================

class TestListLLMProviders:
    """Tests for list_llm_providers method."""

    def test_returns_empty_when_no_clients(self):
        """Returns empty list when no clients."""
        mixin = MockLLMMixin()

        result = mixin.list_llm_providers()

        assert result == []

    def test_returns_anthropic_when_available(self):
        """Returns anthropic when client available."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        result = mixin.list_llm_providers()

        assert "anthropic" in result

    def test_returns_openai_when_available(self):
        """Returns openai when client available."""
        mixin = MockLLMMixin()
        mixin._openai_client = MagicMock()
        mixin._openai_client.is_available.return_value = True

        result = mixin.list_llm_providers()

        assert "openai" in result

    def test_returns_both_when_available(self):
        """Returns both providers when available."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True
        mixin._openai_client = MagicMock()
        mixin._openai_client.is_available.return_value = True

        result = mixin.list_llm_providers()

        assert "anthropic" in result
        assert "openai" in result

    def test_excludes_unavailable_providers(self):
        """Excludes providers that are not available."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True
        mixin._openai_client = MagicMock()
        mixin._openai_client.is_available.return_value = False

        result = mixin.list_llm_providers()

        assert "anthropic" in result
        assert "openai" not in result


# =============================================================================
# LIST_LLM_MODELS TESTS
# =============================================================================

class TestListLLMModels:
    """Tests for list_llm_models method."""

    def test_returns_empty_when_no_clients(self):
        """Returns empty dict when no clients."""
        mixin = MockLLMMixin()

        result = mixin.list_llm_models()

        assert result == {}

    def test_returns_anthropic_models(self):
        """Returns models from anthropic client."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True
        mixin._llm_client.list_models.return_value = ["claude-3-opus", "claude-3-sonnet"]

        result = mixin.list_llm_models()

        assert "anthropic" in result
        assert "claude-3-opus" in result["anthropic"]

    def test_returns_openai_models(self):
        """Returns models from openai client."""
        mixin = MockLLMMixin()
        mixin._openai_client = MagicMock()
        mixin._openai_client.is_available.return_value = True
        mixin._openai_client.list_models.return_value = ["gpt-4", "gpt-3.5-turbo"]

        result = mixin.list_llm_models()

        assert "openai" in result
        assert "gpt-4" in result["openai"]

    def test_returns_both_providers_models(self):
        """Returns models from both providers."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True
        mixin._llm_client.list_models.return_value = ["claude-3"]
        mixin._openai_client = MagicMock()
        mixin._openai_client.is_available.return_value = True
        mixin._openai_client.list_models.return_value = ["gpt-4"]

        result = mixin.list_llm_models()

        assert len(result) == 2
        assert "anthropic" in result
        assert "openai" in result


# =============================================================================
# GET_LLM_CLIENT TESTS
# =============================================================================

class TestGetLLMClient:
    """Tests for get_llm_client method."""

    def test_returns_anthropic_by_default(self):
        """Returns anthropic client by default."""
        mixin = MockLLMMixin()
        mock_anthropic = MagicMock()
        mixin._llm_client = mock_anthropic

        result = mixin.get_llm_client()

        assert result is mock_anthropic

    def test_returns_anthropic_for_provider(self):
        """Returns anthropic client when specified."""
        mixin = MockLLMMixin()
        mock_anthropic = MagicMock()
        mixin._llm_client = mock_anthropic

        result = mixin.get_llm_client(provider="anthropic")

        assert result is mock_anthropic

    def test_returns_openai_for_provider(self):
        """Returns openai client when specified."""
        mixin = MockLLMMixin()
        mock_openai = MagicMock()
        mixin._openai_client = mock_openai

        result = mixin.get_llm_client(provider="openai")

        assert result is mock_openai

    def test_infers_anthropic_from_claude_model(self):
        """Infers anthropic provider from claude model name."""
        mixin = MockLLMMixin()
        mock_anthropic = MagicMock()
        mixin._llm_client = mock_anthropic

        result = mixin.get_llm_client(model="claude-3-opus")

        assert result is mock_anthropic

    def test_infers_openai_from_gpt_model(self):
        """Infers openai provider from gpt model name."""
        mixin = MockLLMMixin()
        mock_openai = MagicMock()
        mixin._openai_client = mock_openai

        result = mixin.get_llm_client(model="gpt-4")

        assert result is mock_openai

    def test_infers_openai_from_o1_model(self):
        """Infers openai provider from o1 model name."""
        mixin = MockLLMMixin()
        mock_openai = MagicMock()
        mixin._openai_client = mock_openai

        result = mixin.get_llm_client(model="o1-preview")

        assert result is mock_openai

    def test_defaults_to_anthropic_for_unknown_model(self):
        """Defaults to anthropic for unknown model."""
        mixin = MockLLMMixin()
        mock_anthropic = MagicMock()
        mixin._llm_client = mock_anthropic

        result = mixin.get_llm_client(model="some-unknown-model")

        assert result is mock_anthropic

    def test_provider_is_case_insensitive(self):
        """Provider name is case insensitive."""
        mixin = MockLLMMixin()
        mock_openai = MagicMock()
        mixin._openai_client = mock_openai

        result = mixin.get_llm_client(provider="OpenAI")

        assert result is mock_openai

    def test_returns_anthropic_for_unknown_provider(self):
        """Returns anthropic for unknown provider."""
        mixin = MockLLMMixin()
        mock_anthropic = MagicMock()
        mixin._llm_client = mock_anthropic

        result = mixin.get_llm_client(provider="unknown")

        assert result is mock_anthropic


# =============================================================================
# IS_LLM_READY TESTS
# =============================================================================

class TestIsLLMReady:
    """Tests for is_llm_ready method."""

    def test_returns_false_when_no_client(self):
        """Returns False when no client."""
        mixin = MockLLMMixin()

        assert mixin.is_llm_ready() is False

    def test_returns_false_when_not_ready(self):
        """Returns False when client not ready."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_ready.return_value = False

        assert mixin.is_llm_ready() is False

    def test_returns_true_when_ready(self):
        """Returns True when client is ready."""
        mixin = MockLLMMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_ready.return_value = True

        assert mixin.is_llm_ready() is True
