"""
Configuration provider service.

Centralizes all ScrubIQ configuration with:
- Grouped settings by category
- Rich metadata (type, description, allowed values, etc.)
- Runtime update support (where safe)
- Validation
- Serialization for API exposure

Usage:
    from scrubiq.services import ConfigProvider

    provider = ConfigProvider(config)

    # Get all settings with metadata
    all_settings = provider.get_all()

    # Get specific setting
    value = provider.get("detection.min_confidence")

    # Update setting (if allowed)
    provider.set("detection.min_confidence", 0.6)
"""

import logging
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union

from ..config import Config, FaceRedactionMethod, DeviceMode

logger = logging.getLogger(__name__)


class SettingCategory(str, Enum):
    """Configuration setting categories."""
    SECURITY = "security"
    DETECTION = "detection"
    PIPELINE = "pipeline"
    API = "api"
    STORAGE = "storage"
    LLM = "llm"
    FILES = "files"
    RATE_LIMITS = "rate_limits"


@dataclass
class SettingMetadata:
    """Metadata for a configuration setting."""
    key: str  # Dot-notation key (e.g., "detection.min_confidence")
    category: SettingCategory
    description: str
    value_type: str  # "float", "int", "bool", "str", "set", "enum"
    default: Any
    current: Any = None  # Populated at runtime
    allowed_values: Optional[List[Any]] = None  # For enums
    min_value: Optional[Union[int, float]] = None  # For numeric
    max_value: Optional[Union[int, float]] = None  # For numeric
    requires_restart: bool = False  # If True, changes need app restart
    runtime_editable: bool = True  # If False, can't be changed via API
    sensitive: bool = False  # If True, value hidden in API responses


# Registry of all configuration settings with metadata
SETTINGS_REGISTRY: Dict[str, SettingMetadata] = {}


def _register_setting(
    key: str,
    attr_name: str,
    category: SettingCategory,
    description: str,
    value_type: str,
    default: Any,
    allowed_values: Optional[List[Any]] = None,
    min_value: Optional[Union[int, float]] = None,
    max_value: Optional[Union[int, float]] = None,
    requires_restart: bool = False,
    runtime_editable: bool = True,
    sensitive: bool = False,
) -> None:
    """Register a setting in the global registry."""
    SETTINGS_REGISTRY[key] = SettingMetadata(
        key=key,
        category=category,
        description=description,
        value_type=value_type,
        default=default,
        allowed_values=allowed_values,
        min_value=min_value,
        max_value=max_value,
        requires_restart=requires_restart,
        runtime_editable=runtime_editable,
        sensitive=sensitive,
    )


# --- REGISTER ALL SETTINGS ---

# Security settings
# Note: PIN auth removed in API key refactor. Keeping session timeout.
_register_setting(
    "security.session_timeout_minutes", "session_timeout_minutes",
    SettingCategory.SECURITY,
    "Session inactivity timeout (minutes)",
    "int", 15,
    min_value=1, max_value=1440,
)
_register_setting(
    "security.scrypt_memory_mb", "scrypt_memory_mb",
    SettingCategory.SECURITY,
    "Memory cost for key derivation (MB). Higher = more secure but slower unlock.",
    "int", 16,
    min_value=8, max_value=256,
    requires_restart=True,
)
_register_setting(
    "security.encryption_enabled", "encryption_enabled",
    SettingCategory.SECURITY,
    "Enable encryption for stored tokens",
    "bool", True,
    runtime_editable=False,  # Can't disable encryption at runtime
)

# Detection settings
_register_setting(
    "detection.min_confidence", "min_confidence",
    SettingCategory.DETECTION,
    "Minimum confidence threshold for PHI detection (0.0-1.0)",
    "float", 0.50,
    min_value=0.0, max_value=1.0,
)
_register_setting(
    "detection.review_threshold", "review_threshold",
    SettingCategory.DETECTION,
    "Confidence threshold below which detections are flagged for human review",
    "float", 0.95,
    min_value=0.0, max_value=1.0,
)
_register_setting(
    "detection.disabled_detectors", "disabled_detectors",
    SettingCategory.DETECTION,
    "Set of detector names to disable (e.g., 'phi_bert', 'patterns')",
    "set", set(),
)

# Pipeline settings
_register_setting(
    "pipeline.coref_enabled", "coref_enabled",
    SettingCategory.PIPELINE,
    "Enable coreference resolution for pronouns",
    "bool", True,
)
_register_setting(
    "pipeline.coref_window_sentences", "coref_window_sentences",
    SettingCategory.PIPELINE,
    "Number of sentences to look back for coreference anchors",
    "int", 2,
    min_value=1, max_value=10,
)
_register_setting(
    "pipeline.coref_max_expansions", "coref_max_expansions",
    SettingCategory.PIPELINE,
    "Maximum coreference expansions per anchor",
    "int", 3,
    min_value=1, max_value=20,
)
_register_setting(
    "pipeline.coref_min_anchor_confidence", "coref_min_anchor_confidence",
    SettingCategory.PIPELINE,
    "Minimum confidence for coreference anchors",
    "float", 0.85,
    min_value=0.0, max_value=1.0,
)
_register_setting(
    "pipeline.coref_confidence_decay", "coref_confidence_decay",
    SettingCategory.PIPELINE,
    "Confidence decay factor for coreference expansions",
    "float", 0.90,
    min_value=0.5, max_value=1.0,
)
_register_setting(
    "pipeline.safe_harbor_enabled", "safe_harbor_enabled",
    SettingCategory.PIPELINE,
    "Enable Safe Harbor de-identification",
    "bool", True,
)
_register_setting(
    "pipeline.entity_resolution_enabled", "entity_resolution_enabled",
    SettingCategory.PIPELINE,
    "Enable entity resolution (same person → same token across mentions)",
    "bool", True,
)

# API settings
_register_setting(
    "api.host", "api_host",
    SettingCategory.API,
    "API server host address",
    "str", "127.0.0.1",
    requires_restart=True,
)
_register_setting(
    "api.port", "api_port",
    SettingCategory.API,
    "API server port",
    "int", 8741,
    min_value=1, max_value=65535,
    requires_restart=True,
)

# Storage settings
_register_setting(
    "storage.audit_retention_days", "audit_retention_days",
    SettingCategory.STORAGE,
    "Days to retain audit logs (HIPAA requires 6 years)",
    "int", 2190,
    min_value=365, max_value=7300,
)
_register_setting(
    "storage.max_upload_size_mb", "max_upload_size_mb",
    SettingCategory.STORAGE,
    "Maximum file upload size (MB)",
    "int", 50,
    min_value=1, max_value=500,
)

# LLM settings
_register_setting(
    "llm.enable_verification", "enable_llm_verification",
    SettingCategory.LLM,
    "Enable LLM-based verification for false positive filtering",
    "bool", False,
)
_register_setting(
    "llm.verification_model", "llm_verification_model",
    SettingCategory.LLM,
    "LLM model for verification (requires Ollama)",
    "str", "qwen2.5:3b",
    allowed_values=["qwen2.5:3b", "qwen2.5:7b", "phi3:mini", "llama3.2:3b"],
)
_register_setting(
    "llm.ollama_url", "llm_ollama_url",
    SettingCategory.LLM,
    "Ollama API endpoint URL",
    "str", "http://localhost:11434",
    sensitive=True,  # SECURITY: URLs may contain credentials or expose internal network
)
_register_setting(
    "llm.gateway_url", "gateway_url",
    SettingCategory.LLM,
    "Gateway URL for multi-agent mode",
    "str", None,
    sensitive=True,  # SECURITY: URLs may contain credentials or expose internal network
)
_register_setting(
    "llm.gateway_timeout_seconds", "gateway_timeout_seconds",
    SettingCategory.LLM,
    "Gateway request timeout (seconds)",
    "int", 30,
    min_value=5, max_value=300,
)

# File processing settings
_register_setting(
    "files.enable_face_detection", "enable_face_detection",
    SettingCategory.FILES,
    "Enable face detection and redaction in images",
    "bool", True,
)
_register_setting(
    "files.enable_metadata_stripping", "enable_metadata_stripping",
    SettingCategory.FILES,
    "Strip EXIF/metadata from images",
    "bool", True,
)
_register_setting(
    "files.face_redaction_method", "face_redaction_method",
    SettingCategory.FILES,
    "Method for face redaction",
    "enum", "blur",
    allowed_values=["blur", "pixelate", "fill"],
)
_register_setting(
    "files.device", "device",
    SettingCategory.FILES,
    "Compute device for ML models",
    "enum", "auto",
    allowed_values=["auto", "cuda", "cpu"],
    requires_restart=True,
)
_register_setting(
    "files.cuda_device_id", "cuda_device_id",
    SettingCategory.FILES,
    "CUDA device ID for multi-GPU systems",
    "int", 0,
    min_value=0, max_value=7,
    requires_restart=True,
)

# Model loading settings
_register_setting(
    "files.model_timeout_seconds", "model_timeout_seconds",
    SettingCategory.FILES,
    "Timeout for model loading (seconds)",
    "int", 45,
    min_value=10, max_value=300,
)
_register_setting(
    "files.on_model_timeout", "on_model_timeout",
    SettingCategory.FILES,
    "Behavior when model loading times out",
    "enum", "error",
    allowed_values=["error", "degraded"],
)


# Mapping from setting key to Config attribute name
_KEY_TO_ATTR: Dict[str, str] = {}
for key, meta in SETTINGS_REGISTRY.items():
    # Extract attr name from the key (e.g., "detection.min_confidence" → "min_confidence")
    parts = key.split(".")
    attr_name = parts[-1] if len(parts) > 1 else key
    # Handle special cases where attr name differs from key suffix
    _KEY_TO_ATTR[key] = {
        "security.session_timeout_minutes": "session_timeout_minutes",
        "security.scrypt_memory_mb": "scrypt_memory_mb",
        "security.encryption_enabled": "encryption_enabled",
        "detection.min_confidence": "min_confidence",
        "detection.review_threshold": "review_threshold",
        "detection.disabled_detectors": "disabled_detectors",
        "pipeline.coref_enabled": "coref_enabled",
        "pipeline.coref_window_sentences": "coref_window_sentences",
        "pipeline.coref_max_expansions": "coref_max_expansions",
        "pipeline.coref_min_anchor_confidence": "coref_min_anchor_confidence",
        "pipeline.coref_confidence_decay": "coref_confidence_decay",
        "pipeline.safe_harbor_enabled": "safe_harbor_enabled",
        "pipeline.entity_resolution_enabled": "entity_resolution_enabled",
        "api.host": "api_host",
        "api.port": "api_port",
        "storage.audit_retention_days": "audit_retention_days",
        "storage.max_upload_size_mb": "max_upload_size_mb",
        "llm.enable_verification": "enable_llm_verification",
        "llm.verification_model": "llm_verification_model",
        "llm.ollama_url": "llm_ollama_url",
        "llm.gateway_url": "gateway_url",
        "llm.gateway_timeout_seconds": "gateway_timeout_seconds",
        "files.enable_face_detection": "enable_face_detection",
        "files.enable_metadata_stripping": "enable_metadata_stripping",
        "files.face_redaction_method": "face_redaction_method",
        "files.device": "device",
        "files.cuda_device_id": "cuda_device_id",
        "files.model_timeout_seconds": "model_timeout_seconds",
        "files.on_model_timeout": "on_model_timeout",
    }.get(key, attr_name)


class ConfigProvider:
    """
    Configuration provider that centralizes all ScrubIQ settings.

    Provides:
    - Unified access to all configuration values
    - Rich metadata for each setting (type, description, constraints)
    - Runtime updates with validation
    - Serialization for API exposure
    """

    def __init__(self, config: Config):
        """
        Initialize with a Config instance.

        Args:
            config: The Config dataclass instance to wrap
        """
        self._config = config
        self._change_callbacks: List[Callable[[str, Any, Any], None]] = []
        # RLock allows re-entrant locking (callbacks may read config)
        self._lock = threading.RLock()

    @property
    def config(self) -> Config:
        """Get the underlying Config instance."""
        return self._config

    def on_change(self, callback: Callable[[str, Any, Any], None]) -> None:
        """
        Register a callback for configuration changes.

        Callback signature: callback(key: str, old_value: Any, new_value: Any)

        Thread-safe: Uses internal lock to protect callback list modification.
        """
        with self._lock:
            self._change_callbacks.append(callback)

    def _notify_change(self, key: str, old_value: Any, new_value: Any) -> None:
        """Notify all registered callbacks of a change."""
        for callback in self._change_callbacks:
            try:
                callback(key, old_value, new_value)
            except Exception as e:
                logger.warning(f"Config change callback failed: {e}")

    def get(self, key: str) -> Any:
        """
        Get a configuration value by key.

        Args:
            key: Dot-notation key (e.g., "detection.min_confidence")

        Returns:
            The current value

        Raises:
            KeyError: If key not found in registry
        """
        if key not in SETTINGS_REGISTRY:
            raise KeyError(f"Unknown configuration key: {key}")

        attr_name = _KEY_TO_ATTR.get(key)
        if attr_name and hasattr(self._config, attr_name):
            return getattr(self._config, attr_name)

        return SETTINGS_REGISTRY[key].default

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.

        Args:
            key: Dot-notation key
            value: New value

        Raises:
            KeyError: If key not found
            ValueError: If value fails validation
            RuntimeError: If setting is not runtime editable

        Thread-safe: Uses internal lock to protect config modification.
        """
        if key not in SETTINGS_REGISTRY:
            raise KeyError(f"Unknown configuration key: {key}")

        meta = SETTINGS_REGISTRY[key]

        if not meta.runtime_editable:
            raise RuntimeError(f"Setting '{key}' cannot be changed at runtime")

        # Validate value (outside lock - validation is read-only)
        self._validate_value(meta, value)

        # Thread-safe config update
        with self._lock:
            # Get old value for callback
            attr_name = _KEY_TO_ATTR.get(key)
            old_value = getattr(self._config, attr_name) if attr_name else None

            # Update config
            if attr_name and hasattr(self._config, attr_name):
                setattr(self._config, attr_name, value)

            # Notify callbacks (inside lock to ensure consistency)
            self._notify_change(key, old_value, value)

        logger.info(f"Configuration updated: {key} = {value}")

    def _validate_value(self, meta: SettingMetadata, value: Any) -> None:
        """Validate a value against setting metadata."""
        # Type validation
        if meta.value_type == "int":
            if not isinstance(value, int):
                raise ValueError(f"Expected int, got {type(value).__name__}")
        elif meta.value_type == "float":
            if not isinstance(value, (int, float)):
                raise ValueError(f"Expected float, got {type(value).__name__}")
            value = float(value)
        elif meta.value_type == "bool":
            if not isinstance(value, bool):
                raise ValueError(f"Expected bool, got {type(value).__name__}")
        elif meta.value_type == "str":
            if value is not None and not isinstance(value, str):
                raise ValueError(f"Expected str, got {type(value).__name__}")
        elif meta.value_type == "set":
            if not isinstance(value, (set, list)):
                raise ValueError(f"Expected set or list, got {type(value).__name__}")
        elif meta.value_type == "enum":
            if meta.allowed_values and value not in meta.allowed_values:
                raise ValueError(
                    f"Invalid value '{value}'. Allowed: {meta.allowed_values}"
                )

        # Range validation for numeric types
        if meta.value_type in ("int", "float"):
            if meta.min_value is not None and value < meta.min_value:
                raise ValueError(f"Value {value} below minimum {meta.min_value}")
            if meta.max_value is not None and value > meta.max_value:
                raise ValueError(f"Value {value} above maximum {meta.max_value}")

        # Allowed values validation
        if meta.allowed_values and value not in meta.allowed_values:
            raise ValueError(
                f"Invalid value '{value}'. Allowed: {meta.allowed_values}"
            )

    def get_metadata(self, key: str) -> Optional[SettingMetadata]:
        """Get metadata for a setting."""
        if key not in SETTINGS_REGISTRY:
            return None

        meta = SETTINGS_REGISTRY[key]
        # Populate current value
        meta.current = self.get(key)
        return meta

    def get_all(self) -> Dict[str, Any]:
        """
        Get all settings as a dictionary.

        Returns:
            Dict with dot-notation keys and current values
        """
        result = {}
        for key in SETTINGS_REGISTRY:
            try:
                result[key] = self.get(key)
            except Exception:
                result[key] = SETTINGS_REGISTRY[key].default
        return result

    def get_all_with_metadata(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all settings with full metadata.

        Returns:
            Dict with setting keys mapping to metadata dicts
        """
        result = {}
        for key, meta in SETTINGS_REGISTRY.items():
            current = self.get(key)
            result[key] = {
                "key": key,
                "category": meta.category.value,
                "description": meta.description,
                "type": meta.value_type,
                "default": meta.default,
                "current": current if not meta.sensitive else "***",
                "allowed_values": meta.allowed_values,
                "min_value": meta.min_value,
                "max_value": meta.max_value,
                "requires_restart": meta.requires_restart,
                "runtime_editable": meta.runtime_editable,
            }
        return result

    def get_by_category(self, category: SettingCategory) -> Dict[str, Any]:
        """
        Get all settings in a category.

        Args:
            category: The category to filter by

        Returns:
            Dict with setting keys and current values
        """
        result = {}
        for key, meta in SETTINGS_REGISTRY.items():
            if meta.category == category:
                result[key] = self.get(key)
        return result

    def get_categories(self) -> List[str]:
        """Get list of all setting categories."""
        return [c.value for c in SettingCategory]

    # SECURITY: Settings that may contain sensitive data (URLs with credentials,
    # internal network addresses, etc.) should be excluded from export
    SENSITIVE_SETTING_PATTERNS = {
        "gateway_url",  # May contain internal network addresses or auth tokens
        "ollama_url",   # Internal service endpoint
        "api_key",      # Any API key settings
        "secret",       # Any secret settings
        "password",     # Any password settings
        "token",        # Any token settings
    }

    def export_to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Export configuration to a serializable dict.

        SECURITY: By default, excludes settings that may contain sensitive data
        such as URLs (which could contain credentials or expose internal network
        topology), API keys, and other secrets.

        Args:
            include_sensitive: If True, include all settings including sensitive ones.
                              Should only be used for admin operations with proper authorization.

        Returns:
            Dict that can be JSON serialized and used to recreate config
        """
        result = {}
        for key in SETTINGS_REGISTRY:
            meta = SETTINGS_REGISTRY[key]

            # Skip settings marked as sensitive
            if meta.sensitive and not include_sensitive:
                continue

            # SECURITY: Skip settings with sensitive-looking names
            # (URLs may contain credentials, internal addresses expose topology)
            if not include_sensitive:
                key_lower = key.lower()
                if any(pattern in key_lower for pattern in self.SENSITIVE_SETTING_PATTERNS):
                    continue

            try:
                result[key] = self.get(key)
            except Exception:
                result[key] = meta.default

        return result

    def import_from_dict(self, data: Dict[str, Any]) -> List[str]:
        """
        Import configuration from a dict.

        Args:
            data: Dict with setting keys and values

        Returns:
            List of keys that were updated
        """
        updated = []
        for key, value in data.items():
            if key in SETTINGS_REGISTRY:
                try:
                    self.set(key, value)
                    updated.append(key)
                except Exception as e:
                    logger.warning(f"Failed to import {key}: {e}")
        return updated
