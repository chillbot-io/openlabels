"""LLM client management mixin for ScrubIQ."""

from typing import List, Dict, Optional


class LLMMixin:
    """
    LLM provider management.
    
    Requires these attributes on the class:
        _llm_client: Optional[AnthropicClient]
        _openai_client: Optional[OpenAIClient]
        _llm_loading: bool
    """

    def has_llm(self) -> bool:
        """Check if LLM provider is available."""
        return self._llm_client is not None and self._llm_client.is_available()

    def list_llm_providers(self) -> List[str]:
        """List available LLM providers."""
        providers = []
        if self._llm_client is not None and self._llm_client.is_available():
            providers.append("anthropic")
        if self._openai_client is not None and self._openai_client.is_available():
            providers.append("openai")
        return providers

    def list_llm_models(self, provider: Optional[str] = None) -> Dict[str, List[str]]:
        """List available models by provider."""
        models = {}
        if self._llm_client is not None and self._llm_client.is_available():
            models["anthropic"] = self._llm_client.list_models()
        if self._openai_client is not None and self._openai_client.is_available():
            models["openai"] = self._openai_client.list_models()
        return models
    
    def get_llm_client(self, provider: Optional[str] = None, model: Optional[str] = None):
        """Get the appropriate LLM client for a provider/model."""
        if provider is None and model:
            model_lower = model.lower()
            if model_lower.startswith(("claude", "anthropic")):
                provider = "anthropic"
            elif model_lower.startswith(("gpt", "o1", "davinci", "curie")):
                provider = "openai"
            else:
                provider = "anthropic"
        
        provider = (provider or "anthropic").lower()
        
        if provider == "anthropic":
            return self._llm_client
        elif provider == "openai":
            return self._openai_client
        else:
            return self._llm_client

    def is_llm_ready(self) -> bool:
        """Check if LLM client is initialized and ready."""
        return self._llm_client is not None and self._llm_client.is_ready()
