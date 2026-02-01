"""
ScrubIQ SDK - Privacy Infrastructure That Just Works.

Simple API (3 lines to value):
    from scrubiq import redact
    
    safe = redact("Patient John Smith, SSN 123-45-6789")
    print(safe)  # "Patient [NAME_1], SSN [SSN_1]"

The result behaves like a string but has superpowers:
    safe.restore()      # Get original back
    safe.entities       # What was found
    safe.has_phi        # Quick check

Full control:
    from scrubiq import Redactor
    
    r = Redactor(
        confidence_threshold=0.85,
        allowlist=["Mayo Clinic", "Tylenol"],
        safe_harbor=True,
    )
    result = r.redact(text)

Power user:
    r = Redactor(
        confidence_threshold=0.85,
        thresholds={"SSN": 0.99, "NAME": 0.6},
        entity_types=["NAME", "SSN", "DOB"],
        exclude_types=["EMAIL"],
        allowlist=["Mayo Clinic"],
        allowlist_file="~/allowlist.txt",
        patterns={"MRN": r"MRN-\\d{8}"},
        safe_harbor=True,
        coreference=True,
        device="cuda",
        workers=4,
        data_dir="~/.scrubiq",
    )
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import tempfile
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Set, Union, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from scrubiq.types import Span as CoreSpan, PrivacyMode
    from scrubiq.core import ScrubIQ

from .constants import MODEL_LOAD_TIMEOUT, DEFAULT_ANTHROPIC_MODEL

logger = logging.getLogger(__name__)


# --- ENVIRONMENT HELPERS ---
def _env_bool(key: str, default: bool = False) -> bool:
    """Get boolean from environment variable."""
    val = os.environ.get(key, "").lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default


def _env_float(key: str, default: float) -> float:
    """Get float from environment variable."""
    val = os.environ.get(key)
    if val:
        try:
            return float(val)
        except ValueError:
            pass
    return default


def _env_int(key: str, default: int) -> int:
    """Get int from environment variable."""
    val = os.environ.get(key)
    if val:
        try:
            return int(val)
        except ValueError:
            pass
    return default


def _env_list(key: str, default: Optional[List[str]] = None) -> Optional[List[str]]:
    """Get comma-separated list from environment variable."""
    val = os.environ.get(key)
    if val:
        return [item.strip() for item in val.split(",") if item.strip()]
    return default


# --- CONFIGURATION ---
@dataclass
class RedactorConfig:
    """
    Redactor configuration with sensible defaults.
    
    All settings can be overridden via environment variables prefixed with
    SCRUBIQ_, e.g. SCRUBIQ_THRESHOLD=0.9
    """
    # Detection thresholds
    confidence_threshold: float = 0.85
    thresholds: Optional[Dict[str, float]] = None  # Per-type: {"NAME": 0.7, "SSN": 0.99}
    
    # What to detect
    entity_types: Optional[List[str]] = None  # None = all types
    exclude_types: Optional[List[str]] = None  # Exclude specific types
    
    # Allowlist (skip these values)
    allowlist: Optional[List[str]] = None
    allowlist_file: Optional[str] = None
    
    # Custom patterns (highest priority)
    patterns: Optional[Dict[str, str]] = None  # {"MRN": r"MRN-\d{8}"}
    
    # Behavior
    safe_harbor: bool = True  # Apply HIPAA Safe Harbor transforms
    coreference: bool = True  # Resolve pronouns
    
    # Performance
    device: str = "auto"  # "auto", "cuda", "cpu"
    workers: int = 1  # Parallel inference workers
    
    # Review queue
    review_threshold: float = 0.7  # Flag uncertain detections
    
    @classmethod
    def from_env(cls) -> "RedactorConfig":
        """Load configuration from environment variables."""
        return cls(
            confidence_threshold=_env_float("SCRUBIQ_THRESHOLD", 0.85),
            safe_harbor=_env_bool("SCRUBIQ_SAFE_HARBOR", True),
            coreference=_env_bool("SCRUBIQ_COREFERENCE", True),
            device=os.environ.get("SCRUBIQ_DEVICE", "auto"),
            workers=_env_int("SCRUBIQ_WORKERS", 1),
            review_threshold=_env_float("SCRUBIQ_REVIEW_THRESHOLD", 0.7),
            allowlist=_env_list("SCRUBIQ_ALLOWLIST"),
            entity_types=_env_list("SCRUBIQ_ENTITY_TYPES"),
            exclude_types=_env_list("SCRUBIQ_EXCLUDE_TYPES"),
        )


# --- ENTITY - Friendly wrapper for detected PHI ---
@dataclass
class Entity:
    """
    A detected PHI/PII entity.
    
    Attributes:
        text: The original text that was detected
        type: Entity type (NAME, SSN, DOB, etc.)
        confidence: Detection confidence (0.0 to 1.0)
        token: The token it was replaced with, e.g. "[NAME_1]"
        start: Start position in normalized text
        end: End position in normalized text
        detector: Which detector found it
    """
    text: str
    type: str
    confidence: float
    token: Optional[str] = None
    start: int = 0
    end: int = 0
    detector: str = ""
    
    @classmethod
    def from_span(cls, span: "CoreSpan") -> "Entity":
        """Create Entity from internal Span object."""
        return cls(
            text=span.text,
            type=span.entity_type,
            confidence=span.confidence,
            token=span.token,
            start=span.start,
            end=span.end,
            detector=span.detector,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "text": self.text,
            "type": self.type,
            "confidence": self.confidence,
            "token": self.token,
            "start": self.start,
            "end": self.end,
            "detector": self.detector,
        }

    @property
    def entity_type(self) -> str:
        """Alias for type (backward compatibility)."""
        return self.type
    
    def __repr__(self) -> str:
        return f"Entity({self.type}: {self.text!r} @ {self.confidence:.0%})"


# --- REVIEW ITEM - Items needing human review ---
@dataclass
class ReviewItem:
    """
    An item flagged for human review.
    
    Attributes:
        id: Unique identifier for this review item
        token: The token assigned (e.g., "[NAME_1]")
        type: Entity type
        confidence: Detection confidence
        reason: Why it was flagged (low_confidence, ambiguous_context, etc.)
        context: Surrounding text (redacted) for context
        suggested_action: Suggested resolution (approve, reject, review)
    """
    id: str
    token: str
    type: str
    confidence: float
    reason: str
    context: str
    suggested_action: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "token": self.token,
            "type": self.type,
            "confidence": self.confidence,
            "reason": self.reason,
            "context": self.context,
            "suggested_action": self.suggested_action,
        }


# --- RESULT - Smart result object that behaves like a string ---
class RedactionResult:
    """
    Result of redacting text. Behaves like a string but has superpowers.
    
    String-like behavior:
        print(result)           # Prints redacted text
        len(result)             # Length of redacted text
        "[NAME_1]" in result    # Check if token present
        str(result)             # Get redacted text
    
    Properties:
        result.text         # Redacted text
        result.entities     # List of Entity objects
        result.tokens       # List of tokens created
        result.has_phi      # True if PHI was found
        result.needs_review # Items flagged for human review
        result.stats        # Processing statistics
    
    Methods:
        result.restore()                    # Get original text back
        result.restore(mode="safe_harbor")  # Get Safe Harbor version
        result.to_dict()                    # Serialize to dict
        result.to_json()                    # Serialize to JSON
    """
    
    def __init__(
        self,
        text: str,
        entities: List[Entity],
        tokens: List[str],
        needs_review: List[ReviewItem],
        stats: Dict[str, Any],
        # Internal references for restore
        _redactor: Optional["Redactor"] = None,
        _mapping: Optional[Dict[str, str]] = None,
        _normalized_input: str = "",
        _input_hash: str = "",
        error: Optional[str] = None,
        warning: Optional[str] = None,
    ):
        self._text = text
        self._entities = entities
        self._tokens = tokens
        self._needs_review = needs_review
        self._stats = stats
        self._redactor = _redactor
        self._mapping = _mapping or {}
        self._normalized_input = _normalized_input
        self._input_hash = _input_hash
        self._error = error
        self._warning = warning
    
    # ─── String-like behavior ───
    
    def __str__(self) -> str:
        return self._text
    
    def __repr__(self) -> str:
        preview = self._text[:50] + "..." if len(self._text) > 50 else self._text
        return f"RedactionResult({preview!r}, entities={len(self._entities)})"
    
    def __len__(self) -> int:
        return len(self._text)
    
    def __contains__(self, item: str) -> bool:
        return item in self._text
    
    def __iter__(self) -> Iterator[str]:
        return iter(self._text)
    
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self._text == other
        if isinstance(other, RedactionResult):
            return self._text == other._text
        return False
    
    def __hash__(self) -> int:
        return hash(self._text)
    
    def __add__(self, other: str) -> str:
        return self._text + other
    
    def __radd__(self, other: str) -> str:
        return other + self._text
    
    # ─── Properties ───
    
    @property
    def text(self) -> str:
        """The redacted text with tokens like [NAME_1]."""
        return self._text

    @property
    def redacted(self) -> str:
        """Alias for text (backward compatibility)."""
        return self._text

    @property
    def entities(self) -> List[Entity]:
        """List of detected PHI/PII entities."""
        return self._entities
    
    @property
    def spans(self) -> List[Entity]:
        """Alias for entities (backward compatibility)."""
        return self._entities
    
    @property
    def tokens(self) -> List[str]:
        """List of tokens created, e.g. ['[NAME_1]', '[SSN_1]']."""
        return self._tokens
    
    @property
    def has_phi(self) -> bool:
        """True if any PHI/PII was detected."""
        return len(self._entities) > 0
    
    @property
    def needs_review(self) -> List[ReviewItem]:
        """Items flagged for human review due to uncertainty."""
        return self._needs_review
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Processing statistics (time_ms, entities_found, etc.)."""
        return self._stats
    
    @property
    def mapping(self) -> Dict[str, str]:
        """
        Token to original value mapping (for manual restore).

        SECURITY NOTE: This returns encrypted/hashed references only.
        Use restore() method to get original values through proper channels.
        Direct PHI access is intentionally restricted.
        """
        # Return token keys only, not PHI values - prevents accidental PHI exposure
        return {token: f"[REDACTED:{token}]" for token in self._mapping.keys()}
    
    @property
    def error(self) -> Optional[str]:
        """Error message if processing failed."""
        return self._error
    
    @property
    def warning(self) -> Optional[str]:
        """Warning message (non-fatal issues)."""
        return self._warning
    
    @property
    def entity_types(self) -> Set[str]:
        """Set of entity types found."""
        return {e.type for e in self._entities}
    
    @property
    def spans(self) -> List[Entity]:
        """Alias for entities (backward compatibility)."""
        return self._entities
    
    # ─── Methods ───
    
    def restore(self, mode: str = "original") -> str:
        """
        Restore tokens to original values.
        
        Args:
            mode: "original" (default) or "safe_harbor" (HIPAA-compliant dates)
        
        Returns:
            Text with tokens replaced by original (or Safe Harbor) values
        """
        if self._redactor is not None:
            from scrubiq.types import PrivacyMode
            privacy_mode = PrivacyMode.SAFE_HARBOR if mode == "safe_harbor" else PrivacyMode.RESEARCH
            result = self._redactor._cr.restore(self._text, privacy_mode)
            return result.restored
        
        # Fallback to local mapping
        result = self._text
        for token, value in self._mapping.items():
            result = result.replace(token, value)
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        SECURITY NOTE: PHI mappings are excluded to prevent accidental exposure.
        Use restore() method to recover original values.
        """
        return {
            "text": self._text,
            "entities": [e.to_dict() for e in self._entities],
            "spans": [e.to_dict() for e in self._entities],  # Backward compat
            "tokens": self._tokens,
            "has_phi": self.has_phi,
            # SECURITY: Don't serialize PHI mappings - use restore() instead
            "token_count": len(self._mapping),
            "needs_review": [r.to_dict() for r in self._needs_review],
            "stats": self._stats,
            "error": self._error,
            "warning": self._warning,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


# --- SCAN RESULT - Detection without tokenization ---
class ScanResult:
    """
    Result of scanning text for PHI (detection only, no tokenization).
    
    Properties:
        result.has_phi      # True if PHI found
        result.entities     # List of Entity objects
        result.entity_types # Set of types found
        result.stats        # Processing statistics
    """
    
    def __init__(
        self,
        entities: List[Entity],
        stats: Dict[str, Any],
        error: Optional[str] = None,
        warning: Optional[str] = None,
    ):
        self._entities = entities
        self._stats = stats
        self._error = error
        self._warning = warning
    
    @property
    def has_phi(self) -> bool:
        """True if any PHI/PII was detected."""
        return len(self._entities) > 0
    
    @property
    def entities(self) -> List[Entity]:
        """List of detected entities."""
        return self._entities
    
    @property
    def spans(self) -> List[Entity]:
        """Alias for entities (backward compatibility)."""
        return self._entities
    
    @property
    def entity_types(self) -> Set[str]:
        """Set of entity types found."""
        return {e.type for e in self._entities}
    
    @property
    def types_found(self) -> Set[str]:
        """Alias for entity_types (backward compatibility)."""
        return self.entity_types
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Processing statistics."""
        return self._stats
    
    @property
    def error(self) -> Optional[str]:
        """Error message if processing failed."""
        return self._error

    @property
    def warning(self) -> Optional[str]:
        """Warning message (non-fatal issues)."""
        return self._warning

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "has_phi": self.has_phi,
            "entities": [e.to_dict() for e in self._entities],
            "spans": [e.to_dict() for e in self._entities],  # Backward compat
            "entity_types": list(self.entity_types),
            "stats": self._stats,
            "error": self._error,
            "warning": self._warning,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    def __repr__(self) -> str:
        return f"ScanResult(has_phi={self.has_phi}, entities={len(self._entities)})"
    
    def __bool__(self) -> bool:
        """ScanResult is truthy if PHI was found."""
        return self.has_phi


# --- CHAT RESULT - LLM interaction result ---
@dataclass
class ChatResult:
    """
    Result of redact → LLM → restore chat flow.
    
    Attributes:
        response: The restored response (with original PHI)
        redacted_prompt: What was sent to the LLM
        redacted_response: Raw LLM response (with tokens)
        model: Model used
        provider: LLM provider
        tokens_used: Token count from LLM
        latency_ms: Total processing time
        entities: PHI detected in user message
        conversation_id: Conversation ID for multi-turn
    """
    response: str
    redacted_prompt: str
    redacted_response: str
    model: str
    provider: str
    tokens_used: int
    latency_ms: float
    entities: List[Entity]
    conversation_id: Optional[str] = None
    error: Optional[str] = None
    
    # Backward compatibility aliases
    @property
    def spans(self) -> List[Entity]:
        """Alias for entities (backward compatibility)."""
        return self.entities
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "response": self.response,
            "redacted_prompt": self.redacted_prompt,
            "redacted_response": self.redacted_response,
            "model": self.model,
            "provider": self.provider,
            "tokens_used": self.tokens_used,
            "latency_ms": self.latency_ms,
            "entities": [e.to_dict() for e in self.entities],
            "spans": [e.to_dict() for e in self.entities],  # Backward compat
            "conversation_id": self.conversation_id,
            "error": self.error,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    def __repr__(self) -> str:
        return f"ChatResult(model={self.model!r}, tokens={self.tokens_used})"


# --- FILE RESULT - File processing result ---
@dataclass
class FileResult:
    """
    Result of processing a file (PDF, image, etc.).
    
    Attributes:
        text: Extracted and redacted text
        entities: PHI detected
        tokens: Tokens created
        pages: Number of pages processed
        job_id: Job ID for async operations
        filename: Original filename
    """
    text: str
    entities: List[Entity]
    tokens: List[str]
    pages: int
    job_id: str
    filename: str
    stats: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    @property
    def has_phi(self) -> bool:
        return len(self.entities) > 0
    
    @property
    def spans(self) -> List[Entity]:
        """Alias for entities (backward compatibility)."""
        return self.entities
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "entities": [e.to_dict() for e in self.entities],
            "spans": [e.to_dict() for e in self.entities],  # Backward compat
            "tokens": self.tokens,
            "pages": self.pages,
            "job_id": self.job_id,
            "filename": self.filename,
            "has_phi": self.has_phi,
            "stats": self.stats,
            "error": self.error,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# --- SUB-INTERFACES - Conversations, Review, Memory, Audit ---
class ConversationsInterface:
    """Interface for conversation management."""
    
    def __init__(self, redactor: "Redactor"):
        self._redactor = redactor
    
    def create(self, title: str = "New conversation") -> Dict[str, Any]:
        """Create a new conversation."""
        conv = self._redactor._cr.create_conversation(title)
        return {"id": conv.id, "title": conv.title, "created_at": conv.created_at.isoformat()}
    
    def list(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List conversations, most recent first."""
        convs = self._redactor._cr.list_conversations(limit=limit, offset=offset)
        return [{"id": c.id, "title": c.title, "created_at": c.created_at.isoformat()} for c in convs]
    
    def get(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """Get a conversation by ID."""
        conv = self._redactor._cr.get_conversation(conversation_id)
        if not conv:
            return None
        return {
            "id": conv.id,
            "title": conv.title,
            "created_at": conv.created_at.isoformat(),
            "messages": [
                {"role": m.role, "content": m.redacted_content, "created_at": m.created_at.isoformat()}
                for m in (conv.messages or [])
            ],
        }
    
    def delete(self, conversation_id: str) -> bool:
        """Delete a conversation."""
        return self._redactor._cr.delete_conversation(conversation_id)
    
    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search across conversations."""
        return self._redactor._cr.search_conversations(query, limit=limit)


class ReviewInterface:
    """Interface for human review queue."""
    
    def __init__(self, redactor: "Redactor"):
        self._redactor = redactor
    
    @property
    def pending(self) -> List[ReviewItem]:
        """Get items awaiting review."""
        items = self._redactor._cr.get_pending_reviews()
        return [
            ReviewItem(
                id=item["id"],
                token=item["token"],
                type=item["type"],
                confidence=item["confidence"],
                reason=item["reason"],
                context=item["context_redacted"],
                suggested_action=item["suggested"],
            )
            for item in items
        ]
    
    @property
    def count(self) -> int:
        """Number of pending reviews."""
        return self._redactor._cr.get_review_count()
    
    def approve(self, item_id: str) -> bool:
        """Approve a review item (confirm detection is correct)."""
        return self._redactor._cr.approve_review(item_id)
    
    def reject(self, item_id: str) -> bool:
        """Reject a review item (mark as false positive)."""
        return self._redactor._cr.reject_review(item_id)


class MemoryInterface:
    """Interface for Claude-like memory system."""
    
    def __init__(self, redactor: "Redactor"):
        self._redactor = redactor
    
    def _get_memory_store(self):
        """Get memory store if available."""
        if not hasattr(self._redactor._cr, '_memory') or not self._redactor._cr._memory:
            return None
        return self._redactor._cr._memory
    
    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search across message content using full-text search."""
        store = self._get_memory_store()
        if not store:
            return []
        results = store.search_messages(query, limit=limit)
        # SearchResult doesn't have to_dict, so convert manually
        return [
            {
                "content": r.content,
                "conversation_id": r.conversation_id,
                "conversation_title": r.conversation_title,
                "role": r.role,
                "relevance": r.relevance,
                "created_at": r.created_at.isoformat() if hasattr(r.created_at, 'isoformat') else str(r.created_at),
            }
            for r in results
        ]
    
    def get_for_entity(self, token: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get memories for a specific entity token."""
        store = self._get_memory_store()
        if not store:
            return []
        results = store.get_memories(entity_token=token, limit=limit)
        return [r.to_dict() for r in results]
    
    def get_all(self, limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all memories, optionally filtered by category."""
        store = self._get_memory_store()
        if not store:
            return []
        results = store.get_memories(category=category, limit=limit)
        return [r.to_dict() for r in results]
    
    def add(self, fact: str, entity_token: Optional[str] = None, category: str = "general", confidence: float = 0.9) -> bool:
        """
        Add a memory.
        
        Args:
            fact: The fact to store (must use tokens, not raw PHI)
            entity_token: Optional entity token this relates to (e.g., "[NAME_1]")
            category: Category (general, medical, preference, action, relationship)
            confidence: Confidence score (0.0 to 1.0)
        
        Returns:
            True if added successfully
        """
        store = self._get_memory_store()
        if not store:
            return False
        try:
            store.add_memory(
                conversation_id=self._redactor._cr._current_conversation_id or "sdk",
                fact=fact,
                category=category,
                entity_token=entity_token,
                confidence=confidence,
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to add memory: {e}")
            return False
    
    def delete(self, memory_id: str) -> bool:
        """Delete a specific memory."""
        store = self._get_memory_store()
        if not store:
            return False
        return store.delete_memory(memory_id)
    
    @property
    def count(self) -> int:
        """Get total number of memories."""
        store = self._get_memory_store()
        if not store:
            return 0
        return store.count_memories()
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        store = self._get_memory_store()
        if not store:
            return {}
        return store.get_memory_stats()


class AuditInterface:
    """Interface for audit log."""
    
    def __init__(self, redactor: "Redactor"):
        self._redactor = redactor
    
    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit entries."""
        return self._redactor._cr.get_audit_entries(limit=limit)
    
    def verify(self) -> bool:
        """Verify audit chain integrity."""
        valid, _ = self._redactor._cr.verify_audit_chain()
        return valid
    
    def export(self, start: str, end: str, format: str = "json") -> str:
        """Export audit entries (returns JSON or CSV string)."""
        entries = self.recent(limit=10000)  # Get all
        
        # Filter by date
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
        filtered = [
            e for e in entries
            if start_dt <= datetime.fromisoformat(e["timestamp"]) <= end_dt
        ]
        
        if format == "csv":
            lines = ["sequence,event,timestamp,data"]
            for e in filtered:
                lines.append(f'{e["sequence"]},{e["event"]},{e["timestamp"]},"{json.dumps(e["data"])}"')
            return "\n".join(lines)
        
        return json.dumps(filtered)


class TokensInterface:
    """
    Interface for token management.

    Provides methods for managing PHI/PII tokens. This interface is iterable
    for backward compatibility (you can use `list(redactor.tokens)` or
    `for token in redactor.tokens`).

    Example:
        # List all tokens
        for token in redactor.tokens:
            print(token)

        # Or use the list() method
        all_tokens = redactor.tokens.list()

        # Lookup token info
        info = redactor.tokens.lookup("[NAME_1]")

        # Delete a false positive
        redactor.tokens.delete("[NAME_1]")

        # Get token → original mapping
        mapping = redactor.tokens.map()

        # Clear all tokens
        redactor.tokens.clear()
    """

    def __init__(self, redactor: "Redactor"):
        self._redactor = redactor

    def __iter__(self):
        """Iterate over token strings (backward compatibility)."""
        return iter(t["token"] for t in self._redactor._cr.get_tokens())

    def __len__(self) -> int:
        """Number of tokens (backward compatibility)."""
        return self._redactor._cr.get_token_count()

    def __contains__(self, token: str) -> bool:
        """Check if token exists."""
        return any(t["token"] == token for t in self._redactor._cr.get_tokens())

    def list(self) -> List[str]:
        """Get list of all token strings."""
        return [t["token"] for t in self._redactor._cr.get_tokens()]

    @property
    def count(self) -> int:
        """Number of tokens stored."""
        return self._redactor._cr.get_token_count()

    def lookup(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Look up token information (without exposing original PHI).

        Args:
            token: Token string like "[NAME_1]"

        Returns:
            Dict with token, type, safe_harbor or None if not found
        """
        tokens = self._redactor._cr.get_tokens()
        for t in tokens:
            if t["token"] == token:
                return {
                    "token": t["token"],
                    "type": t["type"],
                    "safe_harbor": t.get("safe_harbor"),
                }
        return None

    def delete(self, token: str) -> bool:
        """
        Delete a token (for false positive correction).

        Args:
            token: Token string to delete

        Returns:
            True if deleted, False if not found
        """
        return self._redactor._cr.delete_token(token)

    def clear(self) -> int:
        """
        Clear all tokens. Returns count of tokens cleared.

        This creates a new conversation to get a fresh token store.
        """
        count = self.count
        self._redactor._cr.create_conversation("SDK Session (cleared)")
        return count

    def map(self) -> Dict[str, str]:
        """
        Get mapping of tokens to original values.

        Returns:
            Dict mapping token strings to original PHI values
        """
        tokens = self._redactor._cr.get_tokens()
        return {t.get("token", ""): t.get("original", "") for t in tokens}

    def entities(self) -> List["Entity"]:
        """
        Get all entities detected in this session.

        Returns:
            List of Entity objects representing all detected PHI
        """
        tokens = self._redactor._cr.get_tokens()
        return [
            Entity(
                text=t.get("original", ""),
                type=t.get("type", "UNKNOWN"),
                start=0,  # Position not tracked in token store
                end=0,
                confidence=t.get("confidence", 1.0),
                token=t.get("token", ""),
            )
            for t in tokens
        ]


# --- REDACTOR - Main SDK class ---
class Redactor:
    """
    Privacy infrastructure that just works.
    
    Basic usage:
        r = Redactor()
        result = r.redact("Patient John Smith, SSN 123-45-6789")
        print(result)  # "Patient [NAME_1], SSN [SSN_1]"
    
    Configuration:
        r = Redactor(
            confidence_threshold=0.85,             # Global confidence threshold
            thresholds={"SSN": 0.99, "NAME": 0.6}, # Per-type thresholds
            allowlist=["Mayo Clinic", "Tylenol"],  # Don't redact these
            allowlist_file="~/allowlist.txt",      # Load from file
            entity_types=["NAME", "SSN", "DOB"],   # Only detect these
            exclude_types=["EMAIL"],               # Never detect these
            patterns={"MRN": r"MRN-\\d{8}"},       # Custom patterns
            safe_harbor=True,                      # HIPAA date transforms
            coreference=True,                      # Resolve pronouns
            device="cuda",                         # "auto", "cuda", "cpu"
            workers=4,                             # Parallel workers
            data_dir="~/.scrubiq",          # Storage location
        )
    
    All settings can also be set via environment variables:
        SCRUBIQ_THRESHOLD=0.85
        SCRUBIQ_SAFE_HARBOR=true
        SCRUBIQ_ALLOWLIST=Mayo Clinic,Tylenol
        SCRUBIQ_DEVICE=cuda
        SCRUBIQ_WORKERS=4
    """
    
    def __init__(
        self,
        # Thresholds (support both names for backward compatibility)
        confidence_threshold: Optional[float] = None,
        threshold: Optional[float] = None,  # Alias for confidence_threshold
        thresholds: Optional[Dict[str, float]] = None,
        
        # What to detect
        entity_types: Optional[List[str]] = None,
        exclude_types: Optional[List[str]] = None,
        
        # Allowlist
        allowlist: Optional[List[str]] = None,
        allowlist_file: Optional[str] = None,
        
        # Custom patterns
        patterns: Optional[Dict[str, str]] = None,
        
        # Pipeline behavior
        safe_harbor: Optional[bool] = None,
        coreference: Optional[bool] = None,
        
        # Performance
        device: Optional[str] = None,
        workers: Optional[int] = None,
        
        # Review
        review_threshold: Optional[float] = None,
        
        # Storage
        data_dir: Optional[Union[str, Path]] = None,
        encryption_key: Optional[str] = None,
        
        # Callbacks
        on_redact: Optional[callable] = None,
        on_error: Optional[callable] = None,
        
        # Or pass a complete config
        config: Optional[RedactorConfig] = None,
    ):
        """
        Initialize Redactor.
        
        Configuration priority: Constructor args → Environment → Defaults
        """
        from scrubiq.config import Config
        from scrubiq.core import ScrubIQ
        
        # Build config - start with provided or environment
        self._config = config or RedactorConfig.from_env()
        
        # Override with constructor args (support both threshold names)
        effective_threshold = confidence_threshold or threshold
        if effective_threshold is not None:
            self._config.confidence_threshold = effective_threshold
        
        self._threshold = self._config.confidence_threshold
        self._thresholds = thresholds if thresholds is not None else self._config.thresholds
        self._entity_types = entity_types if entity_types is not None else self._config.entity_types
        self._exclude_types = exclude_types if exclude_types is not None else self._config.exclude_types
        self._safe_harbor = safe_harbor if safe_harbor is not None else self._config.safe_harbor
        self._coreference = coreference if coreference is not None else self._config.coreference
        self._device = device if device is not None else self._config.device
        self._workers = workers if workers is not None else self._config.workers
        self._review_threshold = review_threshold if review_threshold is not None else self._config.review_threshold
        self._patterns = patterns if patterns is not None else self._config.patterns
        
        # Sync overrides back to config for property access
        self._config.thresholds = self._thresholds
        self._config.entity_types = self._entity_types
        self._config.exclude_types = self._exclude_types
        self._config.safe_harbor = self._safe_harbor
        self._config.coreference = self._coreference
        self._config.device = self._device
        self._config.workers = self._workers
        self._config.review_threshold = self._review_threshold
        self._config.patterns = self._patterns
        
        # Allowlist
        self._allowlist: Set[str] = set(allowlist or self._config.allowlist or [])
        env_allowlist = _env_list("SCRUBIQ_ALLOWLIST")
        if env_allowlist:
            self._allowlist.update(env_allowlist)
        
        effective_allowlist_file = allowlist_file or self._config.allowlist_file
        if effective_allowlist_file:
            self._load_allowlist_file(effective_allowlist_file)
        
        # Compile custom patterns
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        if self._patterns:
            for name, pattern in self._patterns.items():
                try:
                    self._compiled_patterns[name] = re.compile(pattern)
                except re.error as e:
                    logger.warning(f"Invalid pattern for {name}: {e}")
        
        # Callbacks
        self._on_redact = on_redact
        self._on_error = on_error
        
        # Storage location
        # Priority: data_dir param > SCRUBIQ_HOME > SCRUBIQ_DATA_DIR > temp
        if data_dir:
            data_path = Path(data_dir).expanduser()
        else:
            env_dir = os.environ.get("SCRUBIQ_HOME") or os.environ.get("SCRUBIQ_DATA_DIR")
            if env_dir:
                data_path = Path(env_dir).expanduser()
            else:
                data_path = Path(tempfile.mkdtemp(prefix="scrubiq_"))
                self._temp_dir = data_path  # Track for cleanup

        # Encryption key: param > env var > auto-generate
        # SECURITY: Use secrets.token_hex(32) for proper 256-bit entropy
        # Previous implementation used only ~53 bits (16 decimal digits)
        self._encryption_key = encryption_key or os.environ.get("SCRUBIQ_KEY") or secrets.token_hex(32)

        # Create core config
        core_config = Config(
            data_dir=data_path,
            min_confidence=self._threshold,
            safe_harbor_enabled=self._safe_harbor,
            coref_enabled=self._coreference,
        )

        # Initialize ScrubIQ
        self._cr = ScrubIQ(config=core_config, key_material=self._encryption_key)
        
        # Wait for models to load
        self._wait_for_models()
        
        # Create a default conversation
        self._cr.create_conversation("SDK Session")
        
        # Sub-interfaces
        self._conversations = ConversationsInterface(self)
        self._review = ReviewInterface(self)
        self._memory = MemoryInterface(self)
        self._audit = AuditInterface(self)
        self._tokens_interface = TokensInterface(self)
        
        # Stats tracking
        self._stats = {
            "redactions_performed": 0,
            "entities_detected": 0,
            "errors": 0,
            "session_start": datetime.now(timezone.utc).isoformat(),
        }
        self._stats_by_type: Dict[str, int] = {}
        
        # Thread pool for async
        self._executor: Optional[ThreadPoolExecutor] = None
    
    def _load_allowlist_file(self, path: str) -> None:
        """Load allowlist entries from file."""
        try:
            filepath = Path(path).expanduser()
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._allowlist.add(line)
            logger.info(f"Loaded {len(self._allowlist)} allowlist entries from {path}")
        except Exception as e:
            logger.warning(f"Failed to load allowlist file {path}: {e}")
    
    def _wait_for_models(self, timeout: float = MODEL_LOAD_TIMEOUT) -> None:
        """Wait for models to load."""
        import time
        start = time.time()
        while time.time() - start < timeout:
            if self._cr.is_models_ready():
                return
            time.sleep(0.1)
        logger.warning("Model loading timed out")
    
    # ─── Properties ───
    
    @property
    def is_ready(self) -> bool:
        """True if models are loaded and system is ready."""
        return self._cr.is_models_ready() and self._cr.is_unlocked
    
    @property
    def is_healthy(self) -> bool:
        """True if system is healthy (no errors, operational)."""
        return self.is_ready and self._stats["errors"] == 0
    
    @property
    def status(self) -> Dict[str, Any]:
        """Detailed status information."""
        return {
            "ready": self.is_ready,
            "healthy": self.is_healthy,
            "models_loaded": self._cr.is_models_ready(),
            "storage_connected": True,
            "storage_encrypted": True,
            "session_start": self._stats["session_start"],
        }
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Processing statistics."""
        return {
            **self._stats,
            "tokens_stored": self._cr.get_token_count(),
            "by_type": self._stats_by_type.copy(),
        }
    
    @property
    def token_count(self) -> int:
        """Number of tokens in storage."""
        return self._tokens_interface.count
    
    @property
    def tokens(self) -> TokensInterface:
        """
        Token management interface.

        Iterable for backward compatibility - you can use `list(redactor.tokens)`
        or `for token in redactor.tokens`.

        Also provides methods: list(), lookup(), delete(), clear(), map(), entities()
        """
        return self._tokens_interface
    
    @property
    def detectors(self) -> List[Dict[str, Any]]:
        """Information about loaded detectors."""
        if self._cr._detectors is None:
            return []
        return self._cr._detectors.get_detector_info()
    
    @property
    def config(self) -> RedactorConfig:
        """Current configuration."""
        return self._config
    
    @property
    def supported_types(self) -> List[str]:
        """List of supported entity types."""
        from scrubiq.types import KNOWN_ENTITY_TYPES
        return sorted(KNOWN_ENTITY_TYPES)
    
    @property
    def conversations(self) -> ConversationsInterface:
        """Conversation management interface."""
        return self._conversations
    
    @property
    def review(self) -> ReviewInterface:
        """Human review queue interface."""
        return self._review
    
    @property
    def memory(self) -> MemoryInterface:
        """Memory system interface."""
        return self._memory
    
    @property
    def audit(self) -> AuditInterface:
        """Audit log interface."""
        return self._audit
    
    # ─── Core Methods ───
    
    def redact(
        self,
        text: str,
        *,
        confidence_threshold: Optional[float] = None,
        threshold: Optional[float] = None,  # Alias
        allowlist: Optional[List[str]] = None,
        entity_types: Optional[List[str]] = None,
        exclude_types: Optional[List[str]] = None,
        safe_harbor: Optional[bool] = None,
    ) -> RedactionResult:
        """
        Redact PHI/PII from text.
        
        Args:
            text: Input text to redact
            confidence_threshold: Override confidence threshold for this call
            threshold: Alias for confidence_threshold
            allowlist: Additional allowlist entries for this call
            entity_types: Override entity types to detect
            exclude_types: Override types to exclude
            safe_harbor: Override safe harbor setting
        
        Returns:
            RedactionResult with redacted text and metadata
        
        Example:
            result = r.redact("Patient John Smith, SSN 123-45-6789")
            print(result)  # "Patient [NAME_1], SSN [SSN_1]"
        """
        import time
        start = time.perf_counter()
        
        # Support both parameter names
        effective_threshold = confidence_threshold or threshold
        
        try:
            # Handle empty input
            if not text:
                return RedactionResult(
                    text="",
                    entities=[],
                    tokens=[],
                    needs_review=[],
                    stats={"time_ms": 0},
                    warning="Empty input",
                )
            
            # Apply custom patterns first
            custom_spans = self._detect_custom_patterns(text)
            
            # Call core redaction
            core_result = self._cr.redact(text)
            
            # Convert spans to entities
            all_entities = [Entity.from_span(s) for s in core_result.spans]
            
            # Add custom pattern matches
            for span in custom_spans:
                all_entities.append(Entity(
                    text=span["text"],
                    type=span["type"],
                    confidence=1.0,
                    start=span["start"],
                    end=span["end"],
                    detector="custom_pattern",
                ))
            
            # Apply filters (constructor settings + per-call overrides) and restore filtered-out tokens
            result_text = core_result.redacted
            entities = self._filter_entities(
                all_entities,
                threshold=effective_threshold,
                allowlist=allowlist,
                entity_types=entity_types,
                exclude_types=exclude_types,
            )
            
            # Find tokens that were filtered out and restore them
            kept_tokens = {e.token for e in entities if e.token}
            for entity in all_entities:
                if entity.token and entity.token not in kept_tokens:
                    result_text = result_text.replace(entity.token, entity.text)
            
            # Build token mapping - keep the longest text for each token
            # This handles coreference where "John Smith" and "Smith" share a token
            mapping = {}
            for entity in entities:
                if entity.token:
                    existing = mapping.get(entity.token)
                    if existing is None or len(entity.text) > len(existing):
                        mapping[entity.token] = entity.text
            
            # Convert review items
            review_items = [
                ReviewItem(
                    id=item["id"],
                    token=item["token"],
                    type=item["type"],
                    confidence=item["confidence"],
                    reason=item["reason"],
                    context=item["context_redacted"],
                    suggested_action=item["suggested"],
                )
                for item in core_result.needs_review
            ]
            
            elapsed = (time.perf_counter() - start) * 1000
            
            # Update stats
            self._stats["redactions_performed"] += 1
            self._stats["entities_detected"] += len(entities)
            for entity in entities:
                self._stats_by_type[entity.type] = self._stats_by_type.get(entity.type, 0) + 1
            
            result = RedactionResult(
                text=result_text,
                entities=entities,
                tokens=core_result.tokens_created,
                needs_review=review_items,
                stats={
                    "time_ms": round(elapsed, 2),
                    "entities_found": len(entities),
                },
                _redactor=self,
                _mapping=mapping,
                _normalized_input=core_result.normalized_input,
                _input_hash=core_result.input_hash,
            )
            
            # Callback
            if self._on_redact:
                try:
                    self._on_redact(result)
                except Exception as e:
                    logger.warning(f"on_redact callback failed: {e}")
            
            return result
            
        except Exception as e:
            self._stats["errors"] += 1

            if self._on_error:
                try:
                    self._on_error(e, {"operation": "redact", "text_length": len(text)})
                except Exception as callback_err:
                    # Log but don't propagate callback errors
                    logger.warning(f"Error callback raised exception: {callback_err}")

            logger.exception(f"Redaction failed: {e}")
            # SECURITY: Do not return original PHI on error - return placeholder
            # This prevents PHI exposure when redaction fails
            return RedactionResult(
                text="[REDACTION_FAILED]",
                entities=[],
                tokens=[],
                needs_review=[],
                stats={"time_ms": 0},
                error=str(e),
            )
    
    def _detect_custom_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Detect matches from custom patterns."""
        spans = []
        for name, pattern in self._compiled_patterns.items():
            for match in pattern.finditer(text):
                spans.append({
                    "text": match.group(),
                    "type": name,
                    "start": match.start(),
                    "end": match.end(),
                })
        return spans
    
    def _filter_entities(
        self,
        entities: List[Entity],
        threshold: Optional[float] = None,
        allowlist: Optional[List[str]] = None,
        entity_types: Optional[List[str]] = None,
        exclude_types: Optional[List[str]] = None,
    ) -> List[Entity]:
        """Filter entities based on constructor settings + per-call overrides."""
        result = []

        # Combine constructor allowlist with per-call allowlist
        combined_allowlist = self._allowlist.copy()
        if allowlist:
            combined_allowlist.update(allowlist)

        # Normalize allowlist entries: lowercase, collapse whitespace, strip
        def normalize(s: str) -> str:
            return ' '.join(s.lower().split())

        allowlist_normalized = {normalize(a) for a in combined_allowlist}

        # Use constructor defaults if per-call not specified
        effective_threshold = threshold if threshold is not None else self._threshold
        effective_entity_types = entity_types if entity_types is not None else self._entity_types
        effective_exclude_types = exclude_types if exclude_types is not None else self._exclude_types

        def _in_allowlist(entity_text: str) -> bool:
            """Check if entity text should be allowed (not redacted).

            Matches if:
            1. Entity text exactly matches an allowlist entry (after normalization)
            2. Entity text is a component of a multi-word allowlist entry
               (e.g., "Mayo" matches allowlist entry "Mayo Clinic")
            """
            normalized_text = normalize(entity_text)

            # Exact match
            if normalized_text in allowlist_normalized:
                return True

            # Check if entity is part of a multi-word allowlist entry
            # This handles cases where "Mayo Clinic" is in allowlist but
            # model detects "Mayo" and "Clinic" as separate entities
            for entry in allowlist_normalized:
                # Check if entity is a word within the allowlist entry
                entry_words = entry.split()
                if len(entry_words) > 1 and normalized_text in entry_words:
                    return True

            return False

        for entity in entities:
            # Threshold filter
            if effective_threshold and entity.confidence < effective_threshold:
                continue

            # Type include filter (only keep entities matching these types)
            if effective_entity_types and entity.type not in effective_entity_types:
                continue

            # Type exclude filter (remove entities matching these types)
            if effective_exclude_types and entity.type in effective_exclude_types:
                continue

            # Allowlist filter
            if _in_allowlist(entity.text):
                continue

            result.append(entity)

        return result
    
    def restore(self, text: str, mapping: Optional[Dict[str, str]] = None, mode: str = "original") -> str:
        """
        Restore tokens to original values.
        
        Args:
            text: Text with tokens like [NAME_1]
            mapping: Token to value mapping (uses token store if None)
            mode: "original" or "safe_harbor"
        
        Returns:
            Text with tokens replaced
        """
        if mapping:
            # Use provided mapping directly
            # Sort by token length (longest first) to avoid substring collisions
            # e.g., [NAME_10] must be replaced before [NAME_1]
            result = text
            for token in sorted(mapping.keys(), key=len, reverse=True):
                result = result.replace(token, mapping[token])
            return result
        
        from scrubiq.types import PrivacyMode
        privacy_mode = PrivacyMode.SAFE_HARBOR if mode == "safe_harbor" else PrivacyMode.RESEARCH
        result = self._cr.restore(text, privacy_mode)
        return result.restored
    
    def scan(
        self,
        text: str,
        *,
        confidence_threshold: Optional[float] = None,
        threshold: Optional[float] = None,  # Alias
        entity_types: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Scan text for PHI without tokenization.
        
        Faster than redact() when you only need to detect, not replace.
        
        Args:
            text: Text to scan
            confidence_threshold: Minimum confidence
            threshold: Alias for confidence_threshold
            entity_types: Only detect these types
        
        Returns:
            ScanResult with detected entities
        """
        import time
        start = time.perf_counter()
        
        effective_threshold = confidence_threshold or threshold
        
        if not text:
            return ScanResult(
                entities=[],
                stats={"time_ms": 0},
                warning="Empty input",
            )
        
        try:
            # Use detection pipeline directly
            from scrubiq.pipeline.normalizer import normalize_text
            from scrubiq.pipeline.merger import merge_spans
            
            normalized = normalize_text(text)
            raw_spans = self._cr._detectors.detect(normalized)
            merged = merge_spans(raw_spans, effective_threshold or self._threshold, text=normalized)
            
            entities = [Entity.from_span(s) for s in merged]
            
            # Add custom pattern matches
            for span in self._detect_custom_patterns(text):
                entities.append(Entity(
                    text=span["text"],
                    type=span["type"],
                    confidence=1.0,
                    start=span["start"],
                    end=span["end"],
                    detector="custom_pattern",
                ))
            
            # Apply type filter
            if entity_types:
                entities = [e for e in entities if e.type in entity_types]
            
            elapsed = (time.perf_counter() - start) * 1000
            
            return ScanResult(
                entities=entities,
                stats={"time_ms": round(elapsed, 2), "entities_found": len(entities)},
            )
            
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            return ScanResult(
                entities=[],
                stats={"time_ms": 0},
                error=str(e),
            )
    
    def chat(
        self,
        message: str,
        *,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> ChatResult:
        """
        Send message through redact → LLM → restore pipeline.
        
        Args:
            message: User message
            model: LLM model to use
            provider: LLM provider (anthropic, openai, etc.)
            api_key: API key (or use env var)
            conversation_id: Continue existing conversation
        
        Returns:
            ChatResult with restored response
        """
        try:
            core_result = self._cr.chat(
                message=message,
                model=model,
                conversation_id=conversation_id,
            )
            
            entities = [Entity.from_span(s) for s in core_result.spans]
            
            return ChatResult(
                response=core_result.restored_response,
                redacted_prompt=core_result.redacted_request,
                redacted_response=core_result.response_text,
                model=core_result.model,
                provider=core_result.provider,
                tokens_used=core_result.tokens_used,
                latency_ms=core_result.latency_ms,
                entities=entities,
                conversation_id=core_result.conversation_id,
                error=core_result.error,
            )
            
        except Exception as e:
            logger.exception(f"Chat failed: {e}")
            return ChatResult(
                response="",
                redacted_prompt=message,
                redacted_response="",
                model=model,
                provider=provider or "unknown",
                tokens_used=0,
                latency_ms=0,
                entities=[],
                error=str(e),
            )
    
    def redact_file(
        self,
        file: Union[str, Path, bytes],
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> FileResult:
        """
        Process and redact a file (PDF, image, etc.).
        
        Args:
            file: File path or bytes
            filename: Original filename (required if passing bytes)
            content_type: MIME type (auto-detected if not provided)
        
        Returns:
            FileResult with redacted text
        """
        try:
            if isinstance(file, (str, Path)):
                filepath = Path(file)
                filename = filename or filepath.name
                content = filepath.read_bytes()
            else:
                content = file
                if not filename:
                    raise ValueError("filename required when passing bytes")
            
            result = self._cr.process_file(
                content=content,
                filename=filename,
                content_type=content_type,
            )
            
            entities = []
            if result.get("spans"):
                for s in result["spans"]:
                    entities.append(Entity(
                        text=s.get("text", ""),
                        type=s.get("entity_type", ""),
                        confidence=s.get("confidence", 0),
                        token=s.get("token"),
                        start=s.get("start", 0),
                        end=s.get("end", 0),
                        detector=s.get("detector", ""),
                    ))
            
            return FileResult(
                text=result.get("redacted_text", ""),
                entities=entities,
                tokens=result.get("tokens_created", []),
                pages=result.get("pages", 1),
                job_id=result.get("job_id", ""),
                filename=filename,
                stats={"processing_time_ms": result.get("processing_time_ms", 0)},
            )
            
        except Exception as e:
            logger.exception(f"File processing failed: {e}")
            return FileResult(
                text="",
                entities=[],
                tokens=[],
                pages=0,
                job_id="",
                filename=filename or "unknown",
                error=str(e),
            )
    
    # ─── Token Management (delegates to TokensInterface) ───

    def lookup(self, token: str) -> Optional[Dict[str, Any]]:
        """Look up token information. Prefer: redactor.tokens.lookup()"""
        return self._tokens_interface.lookup(token)

    def delete_token(self, token: str) -> bool:
        """Delete a token. Prefer: redactor.tokens.delete()"""
        return self._tokens_interface.delete(token)

    def clear_tokens(self) -> int:
        """Clear all tokens. Prefer: redactor.tokens.clear()"""
        return self._tokens_interface.clear()

    # ─── Backward Compatibility (Session API) ───

    def get_entities(self) -> List[Entity]:
        """Get all entities. Prefer: redactor.tokens.entities()"""
        return self._tokens_interface.entities()

    def get_token_map(self) -> Dict[str, str]:
        """Get token mapping. Prefer: redactor.tokens.map()"""
        return self._tokens_interface.map()

    def clear(self) -> None:
        """Clear session state. Prefer: redactor.tokens.clear()"""
        self._tokens_interface.clear()

    # ─── Async Methods ───
    
    async def aredact(self, text: str, **kwargs) -> RedactionResult:
        """Async version of redact()."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._get_executor(),
            lambda: self.redact(text, **kwargs),
        )
    
    async def arestore(self, text: str, mapping: Optional[Dict[str, str]] = None) -> str:
        """Async version of restore()."""
        # restore() is fast, no need for executor
        return self.restore(text, mapping)
    
    async def ascan(self, text: str, **kwargs) -> ScanResult:
        """Async version of scan()."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._get_executor(),
            lambda: self.scan(text, **kwargs),
        )
    
    async def achat(self, message: str, **kwargs) -> ChatResult:
        """Async version of chat()."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._get_executor(),
            lambda: self.chat(message, **kwargs),
        )
    
    def _get_executor(self) -> ThreadPoolExecutor:
        """Get or create thread pool executor."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self._workers,
                thread_name_prefix="scrubiq-",
            )
        return self._executor
    
    # ─── Lifecycle ───
    
    def close(self) -> None:
        """Clean up resources."""
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None
        
        if self._cr:
            self._cr.close()
        
        # Clean up temp directory if we created one
        if hasattr(self, '_temp_dir') and self._temp_dir:
            import shutil
            try:
                shutil.rmtree(self._temp_dir)
            except OSError as e:
                # Log but don't fail - temp cleanup is best-effort
                logger.debug(f"Failed to cleanup temp directory {self._temp_dir}: {e}")
    
    def __enter__(self) -> "Redactor":
        return self
    
    def __exit__(self, *args) -> None:
        self.close()


# --- MODULE-LEVEL CONVENIENCE FUNCTIONS ---
_default_redactor: Optional[Redactor] = None
_default_redactor_lock = threading.Lock()  # Thread-safe singleton initialization


def _get_default() -> Redactor:
    """Get or create the default Redactor instance (thread-safe)."""
    global _default_redactor
    if _default_redactor is None:
        with _default_redactor_lock:
            # Double-check after acquiring lock
            if _default_redactor is None:
                _default_redactor = Redactor()
    return _default_redactor


def _reset_default() -> None:
    """Reset the default Redactor instance. Used for test isolation."""
    global _default_redactor
    if _default_redactor is not None:
        try:
            _default_redactor.close()
        except Exception as e:
            # Log but continue - we still want to reset the reference
            logger.debug(f"Error closing default redactor during reset: {e}")
        _default_redactor = None


def redact(
    text: str,
    *,
    confidence_threshold: Optional[float] = None,
    threshold: Optional[float] = None,
    allowlist: Optional[List[str]] = None,
    entity_types: Optional[List[str]] = None,
    exclude_types: Optional[List[str]] = None,
    safe_harbor: Optional[bool] = None,
) -> RedactionResult:
    """
    Redact PHI/PII from text.
    
    This is the simplest way to use ScrubIQ:
    
        from scrubiq import redact
        
        result = redact("Patient John Smith, SSN 123-45-6789")
        print(result)  # "Patient [NAME_1], SSN [SSN_1]"
    
    The result behaves like a string but has superpowers:
    
        result.restore()    # Get original back
        result.entities     # What was found
        result.has_phi      # Quick check
    
    For more control, use the Redactor class directly.
    """
    return _get_default().redact(
        text,
        confidence_threshold=confidence_threshold,
        threshold=threshold,
        allowlist=allowlist,
        entity_types=entity_types,
        exclude_types=exclude_types,
        safe_harbor=safe_harbor,
    )


def restore(text: str, mapping: Optional[Dict[str, str]] = None) -> str:
    """
    Restore tokens to original values.
    
        original = restore(result.text, result.mapping)
    
    Args:
        text: Text with tokens like [NAME_1]
        mapping: Token to value mapping (uses default store if None)
    
    Returns:
        Text with original values restored
    """
    return _get_default().restore(text, mapping)


def scan(
    text: str,
    *,
    confidence_threshold: Optional[float] = None,
    threshold: Optional[float] = None,
    entity_types: Optional[List[str]] = None,
) -> ScanResult:
    """
    Scan text for PHI without tokenization.
    
        if scan("some text").has_phi:
            print("Found PHI!")
    
    Faster than redact() when you only need to detect.
    """
    return _get_default().scan(
        text,
        confidence_threshold=confidence_threshold,
        threshold=threshold,
        entity_types=entity_types,
    )


def chat(
    message: str,
    *,
    model: str = DEFAULT_ANTHROPIC_MODEL,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
) -> ChatResult:
    """
    Send message through redact → LLM → restore pipeline.
    
        result = chat("What medications is John Smith taking?")
        print(result.response)  # Response with "John Smith" restored
    """
    return _get_default().chat(message, model=model, provider=provider, api_key=api_key)


def preload(on_progress: Optional[callable] = None) -> None:
    """
    Preload models for faster first request.
    
    Call during server startup:
    
        from scrubiq import preload
        preload()  # Blocks until ready
        
        # Or with progress callback
        preload(on_progress=lambda pct, msg: print(f"{pct}% - {msg}"))
    """
    from scrubiq.core import ScrubIQ
    
    if on_progress:
        on_progress(10, "Starting model preload")
    
    ScrubIQ.preload_models_async()
    
    if on_progress:
        on_progress(50, "Loading detectors")
    
    ScrubIQ.wait_for_preload(timeout=MODEL_LOAD_TIMEOUT)
    
    if on_progress:
        on_progress(100, "Ready")


async def preload_async() -> None:
    """Async version of preload()."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, preload)


# --- BACKWARD COMPATIBILITY ALIASES ---

# Session is an alias for Redactor (used in multi-turn scenarios)
Session = Redactor

# redact_full is an alias for redact (returns full RedactionResult)
redact_full = redact


# --- EXPORTS ---
__all__ = [
    # Main class
    "Redactor",
    "RedactorConfig",
    "Session",  # Alias for Redactor
    # Result types
    "RedactionResult",
    "ScanResult",
    "ChatResult",
    "FileResult",
    "Entity",
    "ReviewItem",
    # Top-level functions
    "redact",
    "redact_full",  # Alias for redact
    "restore",
    "scan",
    "chat",
    "preload",
    "preload_async",
    # Sub-interfaces
    "ConversationsInterface",
    "ReviewInterface",
    "MemoryInterface",
    "AuditInterface",
]
