"""LLM client abstraction layer.

Supports multiple providers with a unified interface.
LAZY LOADING: Heavy SDKs are deferred until first use.
"""

import time
import os
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict

from .constants import LLM_MAX_OUTPUT_TOKENS

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM."""
    success: bool
    text: str
    model: str
    provider: str
    tokens_used: int
    latency_ms: float
    error: Optional[str] = None
    usage: Optional[Dict[str, int]] = None  # {"input_tokens": N, "output_tokens": N}


def create_client(
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs,
) -> "AnthropicClient":
    """
    Create an LLM client for the specified provider.
    
    Args:
        provider: Provider name (anthropic, openai, etc.). Auto-detected from model if not specified.
        api_key: API key. Falls back to environment variable.
        model: Model name (used to auto-detect provider)
        **kwargs: Additional provider-specific options
    
    Returns:
        LLM client instance
    
    Example:
        client = create_client(api_key="sk-...")
        response = client.chat([{"role": "user", "content": "Hello"}])
    """
    # Auto-detect provider from model name if not specified
    if provider is None and model:
        model_lower = model.lower()
        if model_lower.startswith(("claude", "anthropic")):
            provider = "anthropic"
        elif model_lower.startswith(("gpt", "o1", "davinci", "curie")):
            provider = "openai"
        elif model_lower.startswith("gemini"):
            provider = "google"
        else:
            provider = "anthropic"  # Default
    
    # Empty string is invalid - must be None (auto-detect) or a valid provider name
    if provider is not None and not provider.strip():
        raise ValueError("Provider cannot be an empty string")
    
    provider = (provider or "anthropic").lower()
    
    if provider == "anthropic":
        return AnthropicClient(api_key=api_key, **kwargs)
    elif provider == "openai":
        return OpenAIClient(api_key=api_key, **kwargs)
    elif provider in ("google", "gemini", "azure", "azure_openai"):
        raise NotImplementedError(f"Provider '{provider}' not yet implemented")
    else:
        raise ValueError(f"Unknown provider: {provider}")


class AnthropicClient:
    """Direct Anthropic Claude API client.
    
    LAZY LOADING: SDK is imported on first _ensure_client() call, not in __init__.
    This is called either explicitly via initialize() or implicitly on first chat().
    """
    
    provider = "anthropic"
    
    # Sentinel to distinguish "not provided" from "explicitly None"
    _USE_ENV = object()
    
    # Model mapping: friendly names to API model IDs
    # Updated January 2025
    MODEL_MAP = {
        # Claude 4 models (current generation - recommended)
        "claude-opus-4": "claude-opus-4-20250514",
        "claude-sonnet-4": "claude-sonnet-4-20250514",
        "claude-haiku-4": "claude-haiku-4-20250514",

        # Claude 3.5 models (aliases → map to Claude 4 equivalents)
        "claude-3.5-sonnet": "claude-sonnet-4-20250514",
        "claude-3-5-sonnet": "claude-sonnet-4-20250514",
        "claude-3.5-haiku": "claude-haiku-4-20250514",
        "claude-3-5-haiku": "claude-haiku-4-20250514",
        "claude-3-5-sonnet-latest": "claude-sonnet-4-20250514",
        "claude-3.5-sonnet-latest": "claude-sonnet-4-20250514",

        # Claude 3 models (legacy - still available)
        "claude-3-opus": "claude-3-opus-20240229",
        "claude-3-sonnet": "claude-3-sonnet-20240229",
        "claude-3-haiku": "claude-3-haiku-20240307",
    }
    
    def __init__(self, api_key=_USE_ENV, timeout: int = 120):
        # Only fall back to env var if api_key was not provided at all
        if api_key is AnthropicClient._USE_ENV:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        elif api_key and str(api_key).strip():
            self.api_key = api_key
        else:
            # Explicitly None or empty string = no key
            self.api_key = None
        self.timeout = timeout
        self._client = None
        self._initialized = False
        self._init_error: Optional[str] = None
    
    def initialize(self) -> bool:
        """
        Explicitly initialize the client (import SDK, create client).
        
        Call this from a background thread to avoid blocking.
        Returns True if successful.
        """
        return self._ensure_client()
    
    def _ensure_client(self) -> bool:
        """Lazy-initialize the client. Thread-safe for single init."""
        if self._initialized:
            return self._client is not None
        
        self._initialized = True
        
        if not self.api_key:
            self._init_error = "ANTHROPIC_API_KEY not set"
            logger.warning(self._init_error)
            return False
        
        try:
            logger.info("Importing anthropic SDK...")
            import anthropic
            logger.info("Creating Anthropic client...")
            self._client = anthropic.Anthropic(
                api_key=self.api_key,
                timeout=self.timeout,
            )
            logger.info("Anthropic client ready")
            return True
        except ImportError:
            self._init_error = "anthropic package not installed: pip install anthropic"
            logger.warning(self._init_error)
            return False
        except Exception as e:
            self._init_error = str(e)
            logger.error(f"Anthropic client init failed: {e}")
            return False
    
    def is_available(self) -> bool:
        """Check if client is configured (has API key)."""
        return bool(self.api_key)
    
    def is_ready(self) -> bool:
        """Check if client is fully initialized and ready to use."""
        return self._client is not None
    
    def list_models(self) -> List[str]:
        """Return models for dropdown (current generation, recommended order)."""
        return [
            "claude-sonnet-4",   # Best balance of speed/quality (recommended)
            "claude-haiku-4",    # Fastest, most affordable
            "claude-opus-4",     # Most capable, highest quality
        ]
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        model: str = "claude-sonnet-4",
        system: Optional[str] = None,
    ) -> LLMResponse:
        """Send chat messages to Anthropic API and return response."""
        start = time.time()
        
        # Ensure client is initialized (will be instant if already done)
        if not self._ensure_client():
            return LLMResponse(
                success=False,
                text="",
                model=model,
                provider=self.provider,
                tokens_used=0,
                latency_ms=(time.time() - start) * 1000,
                error=self._init_error or "Anthropic client not available",
            )
        
        # Map friendly name to API model ID
        api_model = self.MODEL_MAP.get(model, model)
        
        # Extract system message from messages if not provided directly
        system_content = system
        chat_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                # Only use from messages if not provided directly
                if system_content is None:
                    system_content = msg.get("content", "")
            else:
                chat_messages.append(msg)
        
        try:
            # Build request kwargs
            request_kwargs = {
                "model": api_model,
                "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                "messages": chat_messages,
            }
            if system_content:
                request_kwargs["system"] = system_content
            
            response = self._client.messages.create(**request_kwargs)
            
            latency = (time.time() - start) * 1000
            text = response.content[0].text if response.content else ""
            input_tokens = response.usage.input_tokens if response.usage else 0
            output_tokens = response.usage.output_tokens if response.usage else 0
            tokens_used = input_tokens + output_tokens
            
            return LLMResponse(
                success=True,
                text=text,
                model=model,
                provider=self.provider,
                tokens_used=tokens_used,
                latency_ms=latency,
                usage={
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": tokens_used,
                },
            )
            
        except Exception as e:
            latency = (time.time() - start) * 1000
            logger.error(f"Anthropic API error: {e}")
            return LLMResponse(
                success=False,
                text="",
                model=model,
                provider=self.provider,
                tokens_used=0,
                latency_ms=latency,
                error=str(e),
            )
    
    def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: str = "claude-sonnet-4"
    ):
        """
        Stream chat response from Claude.
        
        Yields text chunks as they arrive.
        Final chunk will be None to signal completion.
        """
        # Ensure client is initialized
        if not self._ensure_client():
            yield None
            return
        
        # Map friendly name to API model ID
        api_model = self.MODEL_MAP.get(model, model)
        
        # Extract system message
        system_content = None
        chat_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system_content = msg.get("content", "")
            else:
                chat_messages.append(msg)
        
        try:
            # Build request kwargs
            request_kwargs = {
                "model": api_model,
                "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                "messages": chat_messages,
            }
            if system_content:
                request_kwargs["system"] = system_content
            
            # Use streaming API
            with self._client.messages.stream(**request_kwargs) as stream:
                for text in stream.text_stream:
                    yield text
            
            # Signal completion
            yield None
            
        except Exception as e:
            logger.error(f"Anthropic streaming error: {e}")
            yield None


class OpenAIClient:
    """OpenAI API client.
    
    LAZY LOADING: SDK is imported on first _ensure_client() call.
    Supports GPT-4, GPT-4o, o1, and other OpenAI models.
    """
    
    provider = "openai"
    
    # Sentinel to distinguish "not provided" from "explicitly None"
    _USE_ENV = object()
    
    # Model mapping: friendly names to API model IDs
    # Updated January 2025
    MODEL_MAP = {
        # GPT-4o family (current flagship)
        "gpt-4o": "gpt-4o",
        "gpt-4o-mini": "gpt-4o-mini",

        # o-series reasoning models
        "o1": "o1",
        "o1-mini": "o1-mini",
        "o1-pro": "o1-pro",
        "o3-mini": "o3-mini",  # Newest reasoning model (Jan 2025)

        # GPT-4 legacy models
        "gpt-4-turbo": "gpt-4-turbo",
        "gpt-4": "gpt-4",

        # GPT-3.5 (budget option)
        "gpt-3.5-turbo": "gpt-3.5-turbo",
    }
    
    def __init__(self, api_key=_USE_ENV, timeout: int = 120):
        # Only fall back to env var if api_key was not provided at all
        if api_key is OpenAIClient._USE_ENV:
            self.api_key = os.environ.get("OPENAI_API_KEY")
        elif api_key and str(api_key).strip():
            self.api_key = api_key
        else:
            # Explicitly None or empty string = no key
            self.api_key = None
        self.timeout = timeout
        self._client = None
        self._initialized = False
        self._init_error: Optional[str] = None
    
    def initialize(self) -> bool:
        """Explicitly initialize the client."""
        return self._ensure_client()
    
    def _ensure_client(self) -> bool:
        """Lazy-initialize the client."""
        if self._initialized:
            return self._client is not None
        
        self._initialized = True
        
        if not self.api_key:
            self._init_error = "OPENAI_API_KEY not set"
            logger.warning(self._init_error)
            return False
        
        try:
            logger.info("Importing openai SDK...")
            import openai
            logger.info("Creating OpenAI client...")
            self._client = openai.OpenAI(
                api_key=self.api_key,
                timeout=self.timeout,
            )
            logger.info("OpenAI client ready")
            return True
        except ImportError:
            self._init_error = "openai package not installed: pip install openai"
            logger.warning(self._init_error)
            return False
        except Exception as e:
            self._init_error = str(e)
            logger.error(f"OpenAI client init failed: {e}")
            return False
    
    def is_available(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)

    def is_ready(self) -> bool:
        """Check if client is initialized and ready."""
        return self._client is not None
    
    def list_models(self) -> List[str]:
        """Return models for dropdown (current generation, recommended order)."""
        return [
            "gpt-4o",        # Best balance of speed/quality (recommended)
            "gpt-4o-mini",   # Fastest, most affordable
            "o1",            # Advanced reasoning
            "o1-mini",       # Reasoning, affordable
            "o3-mini",       # Newest reasoning model
        ]
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4o",
        system: Optional[str] = None,
    ) -> LLMResponse:
        """Send chat messages to OpenAI API and return response."""
        start = time.time()

        if not self._ensure_client():
            return LLMResponse(
                success=False,
                text="",
                model=model,
                provider=self.provider,
                tokens_used=0,
                latency_ms=(time.time() - start) * 1000,
                error=self._init_error or "OpenAI client not available",
            )
        
        api_model = self.MODEL_MAP.get(model, model)
        
        # Build messages with system
        chat_messages = []
        if system:
            chat_messages.append({"role": "system", "content": system})
        
        for msg in messages:
            if msg.get("role") == "system" and system:
                continue
            chat_messages.append(msg)
        
        try:
            response = self._client.chat.completions.create(
                model=api_model,
                messages=chat_messages,
                max_tokens=LLM_MAX_OUTPUT_TOKENS,
            )
            
            latency = (time.time() - start) * 1000
            text = response.choices[0].message.content if response.choices else ""
            input_tokens = response.usage.prompt_tokens if response.usage else 0
            output_tokens = response.usage.completion_tokens if response.usage else 0
            tokens_used = input_tokens + output_tokens
            
            return LLMResponse(
                success=True,
                text=text or "",
                model=model,
                provider=self.provider,
                tokens_used=tokens_used,
                latency_ms=latency,
                usage={
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": tokens_used,
                },
            )
            
        except Exception as e:
            latency = (time.time() - start) * 1000
            logger.error(f"OpenAI API error: {e}")
            return LLMResponse(
                success=False,
                text="",
                model=model,
                provider=self.provider,
                tokens_used=0,
                latency_ms=latency,
                error=str(e),
            )
    
    def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4o",
        system: Optional[str] = None,
    ):
        """
        Stream chat response from OpenAI.
        
        Yields text chunks as they arrive.
        Final chunk will be None to signal completion.
        """
        if not self._ensure_client():
            yield None
            return
        
        api_model = self.MODEL_MAP.get(model, model)
        
        chat_messages = []
        if system:
            chat_messages.append({"role": "system", "content": system})
        
        for msg in messages:
            if msg.get("role") == "system" and system:
                continue
            chat_messages.append(msg)
        
        try:
            stream = self._client.chat.completions.create(
                model=api_model,
                messages=chat_messages,
                max_tokens=LLM_MAX_OUTPUT_TOKENS,
                stream=True,
            )
            
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
            
            yield None
            
        except Exception as e:
            logger.error(f"OpenAI streaming error: {e}")
            yield None
