"""
ScrubIQ Services Layer.

Services encapsulate domain logic and provide clean interfaces for the core orchestrator.
This layer sits between the core (ScrubIQ) and the low-level components (crypto, storage, etc.).
"""

from .session import SessionService, SessionState, UnlockResult
from .config_provider import ConfigProvider, SettingCategory, SettingMetadata
from .api_keys import APIKeyService, APIKeyMetadata
from .entity_registry import (
    EntityRegistry,
    EntityCandidate,
    RegisteredEntity,
    MergeCandidate,
    MergeConfidence,
)

__all__ = [
    "SessionService",
    "SessionState",
    "UnlockResult",
    "ConfigProvider",
    "SettingCategory",
    "SettingMetadata",
    "APIKeyService",
    "APIKeyMetadata",
    "EntityRegistry",
    "EntityCandidate",
    "RegisteredEntity",
    "MergeCandidate",
    "MergeConfidence",
]
