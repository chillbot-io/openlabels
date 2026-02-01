"""ScrubIQ core orchestrator."""

import hashlib
import logging
import threading
import time

from typing import Optional, List, Dict

from .config import Config
from .types import (
    Span, PrivacyMode, AuditEventType, UploadResult,
    RedactionResult, RestorationResult, ChatResult,
)
from .prompts import SYSTEM_PROMPT
from .constants import (
    MAX_TEXT_LENGTH,
    PRELOAD_WAIT_TIMEOUT,
    MEMORY_EXTRACTION_ENABLED,
)
from .mixins import (
    ConversationMixin,
    TokenMixin,
    FileMixin,
    ChatMixin,
    LLMMixin,
)
from .services import SessionService

# Re-export for backward compatibility (tests import from core)
__all__ = [
    "ScrubIQ",
    "RedactionResult",
    "RestorationResult",
    "ChatResult",
    "SYSTEM_PROMPT",
]

logger = logging.getLogger(__name__)

# Imports for core functionality
from .storage import (
    Database, TokenStore, AuditLog, ConversationStore,
    Conversation, Message, MemoryStore, MemoryExtractor,
)
from .pipeline.normalizer import normalize_text
from .pipeline.merger import merge_spans, normalize_name_types
from .pipeline.repeats import expand_repeated_values
from .pipeline.geo_signals import load_geo_signals
from .pipeline.safe_harbor import apply_safe_harbor
from .pipeline.allowlist import apply_allowlist
from .pipeline.tokenizer import tokenize, tokenize_entities
from .pipeline.entity_resolver import EntityResolver, resolve_entities
from .pipeline.restorer import restore
from .pipeline.entity_graph import EntityGraph  # Legacy, to be removed
from .pipeline.conversation_context import ConversationContext
from .pipeline.gender import infer_gender, is_name_entity_type
from .services.entity_registry import EntityRegistry, EntityCandidate
from .gateway import GatewayClient
from .llm_client import OpenAIClient, AnthropicClient, LLMResponse
from .review import ReviewQueue

# Type hints for lazy-loaded classes
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .detectors.orchestrator import DetectorOrchestrator
    from .files import FileProcessor, OCREngine


class ScrubIQ(LLMMixin, ChatMixin, ConversationMixin, TokenMixin, FileMixin):
    """
    Main orchestrator for PHI/PII detection and redaction.
    
    Coordinates all pipeline stages:
    1. Text normalization
    2. Detection (checksum, pattern, ML)
    3. Span merging
    4. Coreference resolution
    5. Safe Harbor transforms
    6. Allowlist filtering
    7. Tokenization
    8. Entity graph registration
    9. Restoration
    
    Also manages:
    - Encrypted token storage
    - Hash-chained audit logging
    - Human review queue
    - Session authentication
    - Memory system (Claude-like recall)
    - Entity graph (pronoun resolution, relationships)
    """
    
    # Class-level preloading state (thread-safe)
    _preload_lock = threading.Lock()
    _preload_started = False
    _preload_complete = threading.Event()
    _preloaded_detectors: Optional["DetectorOrchestrator"] = None
    _preloaded_ocr: Optional["OCREngine"] = None
    _preload_error: Optional[str] = None

    @classmethod
    def preload_models_async(cls, config: Optional[Config] = None):
        """Start loading ML models in background during app startup.

        Thread-safe: uses lock to prevent multiple preload threads.
        """
        with cls._preload_lock:
            if cls._preload_started:
                return
            cls._preload_started = True

        def _preload():
            detectors = None
            ocr = None
            try:
                cfg = config or Config()

                logger.debug("Preloading DetectorOrchestrator...")
                from .detectors.orchestrator import DetectorOrchestrator
                detectors = DetectorOrchestrator(cfg)

                logger.debug("Preloading OCREngine...")
                try:
                    from .files import OCREngine
                    ocr = OCREngine(cfg.models_dir)
                    if ocr and ocr.is_available:
                        ocr.warm_up()
                except Exception as e:
                    logger.warning(f"OCR preload failed: {e}")
                    ocr = None

                # Only assign to class after successful load (atomic from reader's perspective)
                cls._preloaded_detectors = detectors
                cls._preloaded_ocr = ocr
                logger.info("Model preloading complete")

            except Exception as e:
                cls._preload_error = str(e)
                logger.error(f"Model preloading failed: {e}", exc_info=True)
            finally:
                cls._preload_complete.set()

        thread = threading.Thread(target=_preload, daemon=True, name="model-preloader")
        thread.start()

    @classmethod
    def is_preload_complete(cls) -> bool:
        """Check if model preloading is complete."""
        return cls._preload_complete.is_set()

    @classmethod
    def wait_for_preload(cls, timeout: float = 30.0) -> bool:
        """Wait for model preloading to complete."""
        return cls._preload_complete.wait(timeout=timeout)

    def __init__(
        self,
        config: Optional[Config] = None,
        key_material: Optional[str] = None,
    ):
        self.config = config or Config()
        self.config.ensure_directories()

        self._db = Database(self.config.db_path)
        self._db.connect()

        # Session service handles key management
        self._session = SessionService(
            self._db,
            session_timeout_minutes=self.config.session_timeout_minutes,
            scrypt_memory_mb=self.config.scrypt_memory_mb,
        )

        # Components (initialized on unlock)
        self._store: Optional[TokenStore] = None
        self._entity_graph: Optional[EntityGraph] = None  # Legacy, to be removed
        self._entity_registry: Optional[EntityRegistry] = None  # Single source of entity identity
        self._conversation_context: Optional[ConversationContext] = None  # Focus/salience tracking
        self._audit: Optional[AuditLog] = None
        self._detectors: Optional["DetectorOrchestrator"] = None
        self._gateway: Optional[GatewayClient] = None
        self._llm_client: Optional[AnthropicClient] = None
        self._openai_client: Optional[OpenAIClient] = None
        self._conversations: Optional[ConversationStore] = None
        self._file_processor: Optional["FileProcessor"] = None
        self._ocr_engine: Optional["OCREngine"] = None
        self._review_queue = ReviewQueue(self.config.review_threshold)
        self._privacy_mode = PrivacyMode.REDACTED
        self._current_conversation_id: Optional[str] = None

        # Memory system (Claude-like recall)
        self._memory: Optional[MemoryStore] = None
        self._memory_extractor: Optional[MemoryExtractor] = None

        # Use RLock (reentrant) because redact() acquires lock then calls create_conversation()
        self._conversation_lock = threading.RLock()
        # Lock for thread-safe access to components set by background threads
        self._components_lock = threading.Lock()
        self._models_loading = False
        self._models_ready_event = threading.Event()  # Signaled when models finish loading
        self._models_ready_event.set()  # Initially set (not loading)
        self._llm_loading = False
        self._background_threads: List[threading.Thread] = []
        self._model_load_semaphore = threading.Semaphore(1)
        self._shutting_down = False  # Flag to signal threads to stop

        # Cached geo signals (loaded once on first redact)
        self._geo_signals_cache = None
        self._geo_signals_loaded = False

        if key_material:
            self.unlock(key_material)

    # =========================================================================
    # PROPERTIES (delegated to SessionService)
    # =========================================================================

    @property
    def session_id(self) -> str:
        return self._session.session_id

    @property
    def is_unlocked(self) -> bool:
        return self._session.is_unlocked

    @property
    def _keys(self):
        """
        Get key manager from session service.

        Provides backward compatibility for mixins that access self._keys.
        Returns None if session is locked.
        """
        return self._session.get_key_manager()

    @property
    def privacy_mode(self) -> PrivacyMode:
        return self._privacy_mode

    @property
    def has_keys_stored(self) -> bool:
        return self._session.has_keys_stored

    @property
    def has_gateway(self) -> bool:
        return self._gateway is not None

    @property
    def vault_needs_upgrade(self) -> bool:
        return self._session.vault_needs_upgrade

    @property
    def is_new_vault(self) -> bool:
        return self._session.is_new_vault

    @property
    def entity_graph(self) -> Optional[EntityGraph]:
        """Get the current entity graph (legacy, for backward compatibility)."""
        return self._entity_graph

    @property
    def entity_registry(self) -> Optional[EntityRegistry]:
        """Get the entity registry (single source of truth for entity identity)."""
        return self._entity_registry

    @property
    def conversation_context(self) -> Optional[ConversationContext]:
        """Get conversation context (focus/salience tracking for pronoun hints)."""
        return self._conversation_context

    def get_timeout_remaining(self) -> Optional[int]:
        return self._session.get_timeout_remaining()

    def is_models_ready(self) -> bool:
        with self._components_lock:
            return self._detectors is not None and not self._models_loading

    def is_models_loading(self) -> bool:
        with self._components_lock:
            return self._models_loading or self._llm_loading

    def _wait_for_models(self, timeout: float = None) -> bool:
        """
        Block until models are loaded or timeout.

        Args:
            timeout: Seconds to wait (default: config.model_timeout_seconds)

        Returns:
            True if models ready, False if degraded mode

        Raises:
            TimeoutError: If timeout and on_model_timeout == "error"
        """
        if timeout is None:
            timeout = self.config.model_timeout_seconds

        with self._components_lock:
            if not self._models_loading:
                return True

        # Use Event.wait() instead of polling - much more efficient
        ready = self._models_ready_event.wait(timeout=timeout)

        with self._components_lock:
            still_loading = self._models_loading

        if not ready or still_loading:
            # Timeout occurred
            if self.config.on_model_timeout == "error":
                raise TimeoutError(
                    f"Models failed to load within {timeout}s. "
                    "Set on_model_timeout='degraded' to continue with pattern-based detection."
                )
            else:
                logger.warning(
                    f"Models not loaded after {timeout}s, continuing in degraded mode "
                    "(pattern-based detection only)"
                )
                return False

        return True

    def get_token_count(self) -> int:
        if self._store is None:
            return 0
        return self._store.count()

    def get_review_count(self) -> int:
        return len(self._review_queue)

    def _require_unlock(self):
        """Ensure session is unlocked, check for timeout."""
        if not self._session.is_unlocked:
            raise RuntimeError("Session not unlocked - call unlock() first")
        # Check for timeout on each sensitive operation
        if self._session.check_timeout():
            raise RuntimeError("Session timed out - please unlock again")

    def _clear_redaction_cache(self):
        """
        Clear any cached redaction-related state for PHI isolation.

        SECURITY: Called when switching conversations to ensure PHI from one
        conversation doesn't leak into another through cached state.

        Currently no redaction caching is implemented, but this method
        provides a hook for future caching mechanisms.
        """
        # Currently no-op - implement cache clearing when caching is added
        pass

    # =========================================================================
    # KEY MANAGEMENT (delegated to SessionService)
    # =========================================================================

    def unlock(self, key_material: str) -> bool:
        """
        Unlock session with key material.

        With API key auth, this is called with an encryption key derived from the API key.
        Delegates to SessionService for key management, then initializes components.

        Args:
            key_material: Encryption key material (derived from API key)

        Returns:
            True if unlock successful

        Raises:
            ValueError: If key material is invalid
        """
        # Delegate to SessionService (handles timing jitter)
        result = self._session.unlock(key_material)

        if not result.success:
            raise ValueError(result.error or "Invalid key")

        # Auth successful - initialize components
        self._initialize_components_on_unlock()

        return True

    def _initialize_components_on_unlock(self) -> None:
        """Initialize all components after successful unlock."""
        self._audit = AuditLog(self._db, self._session.session_id)
        self._conversations = ConversationStore(self._db)

        # Save previous conversation to restore after unlock
        _prev_conv_id = self._current_conversation_id

        self._current_conversation_id = None
        self._store = None
        self._entity_graph = None  # Legacy, reset
        self._entity_registry = None  # Reset entity identity tracker
        self._conversation_context = None  # Reset focus/salience tracker

        # Initialize memory system (Claude-like recall)
        self._memory = MemoryStore(self._db)
        self._memory_extractor = None  # Initialized after LLM loads

        if self.config.gateway_url:
            self._gateway = GatewayClient(
                self.config.gateway_url,
                timeout_seconds=self.config.gateway_timeout_seconds,
            )

        self._llm_client = AnthropicClient()
        self._openai_client = OpenAIClient()
        self._ocr_engine = None
        self._file_processor = None

        self._audit.log(AuditEventType.SESSION_UNLOCK, {"session_id": self._session.session_id})

        self._models_loading = True
        self._models_ready_event.clear()  # Clear event while loading
        self._llm_loading = True
        self._background_threads = []

        for name, target in [
            ("llm-loader", self._load_llm_background),
            ("detector-loader", self._load_detectors_background),
            ("ocr-loader", self._load_ocr_background),
        ]:
            t = threading.Thread(target=target, daemon=True, name=name)
            self._background_threads.append(t)
            t.start()

        # Restore previous conversation if there was one
        if _prev_conv_id is not None:
            try:
                self.set_current_conversation(_prev_conv_id)
            except (KeyError, ValueError) as e:
                # Conversation may have been deleted - this is expected
                logger.debug(f"Could not restore conversation {_prev_conv_id}: {e}")

    def lock(self):
        """Lock session, clear keys from memory."""
        if self._audit:
            self._audit.log(AuditEventType.SESSION_LOCK, {"session_id": self._session.session_id})

        # Delegate to SessionService
        self._session.lock()

        # Clear components
        self._entity_graph = None  # Legacy
        self._entity_registry = None
        self._conversation_context = None
        self._memory = None
        self._memory_extractor = None

    def set_privacy_mode(self, mode: PrivacyMode):
        """Set display mode for restored text."""
        self._privacy_mode = mode

    # =========================================================================
    # BACKGROUND LOADERS
    # =========================================================================

    def _load_llm_background(self):
        try:
            if self._shutting_down:
                return
            if self._llm_client and self._llm_client.is_available():
                self._llm_client.initialize()
            if self._shutting_down:
                return
            if self._openai_client and self._openai_client.is_available():
                self._openai_client.initialize()

            # Initialize memory extractor after LLM is ready
            if MEMORY_EXTRACTION_ENABLED and self._llm_client and self._llm_client.is_available():
                if self._memory:
                    with self._components_lock:
                        if not self._shutting_down:
                            self._memory_extractor = MemoryExtractor(self._memory, self._llm_client)
                    logger.info("Memory extractor initialized")
        except Exception as e:
            logger.error(f"LLM init failed: {e}", exc_info=True)
        finally:
            with self._components_lock:
                self._llm_loading = False

    def _load_detectors_background(self):
        try:
            if self._shutting_down:
                return

            logger.debug(
                f"_load_detectors_background: preloaded={ScrubIQ._preloaded_detectors is not None}, "
                f"preload_started={ScrubIQ._preload_started}, "
                f"preload_complete={ScrubIQ._preload_complete.is_set()}"
            )

            if ScrubIQ._preloaded_detectors is not None:
                with self._components_lock:
                    if not self._shutting_down:
                        self._detectors = ScrubIQ._preloaded_detectors
                        self._models_loading = False
                        self._models_ready_event.set()
                logger.debug("Using preloaded detectors")
                return

            # Preload was started but detectors not available - wait or check event
            if ScrubIQ._preload_started:
                if not ScrubIQ._preload_complete.is_set():
                    logger.debug("Waiting for preload to complete...")
                    ScrubIQ._preload_complete.wait(timeout=PRELOAD_WAIT_TIMEOUT)

                if self._shutting_down:
                    return

                # Check again after event is set
                if ScrubIQ._preloaded_detectors is not None:
                    with self._components_lock:
                        if not self._shutting_down:
                            self._detectors = ScrubIQ._preloaded_detectors
                            self._models_loading = False
                            self._models_ready_event.set()
                    logger.debug("Using preloaded detectors after wait")
                    return

                # Preload failed - log prominently and fall through to sync load
                if ScrubIQ._preload_error:
                    logger.error(
                        f"Model preload FAILED: {ScrubIQ._preload_error}. "
                        f"Falling back to synchronous load (slower startup)."
                    )
                else:
                    logger.warning(
                        "Preload complete but detectors not available. "
                        "Falling back to synchronous load."
                    )

            # Try to acquire semaphore with timeout to avoid deadlock
            SEMAPHORE_TIMEOUT = 60.0  # 60 seconds max wait
            logger.debug("Attempting fresh detector load (no preload available)...")
            acquired = self._model_load_semaphore.acquire(blocking=True, timeout=SEMAPHORE_TIMEOUT)
            if not acquired:
                # CRITICAL: Do NOT signal ready if we failed to load
                # This prevents silent degradation to broken state
                logger.error(
                    f"Failed to acquire model load semaphore after {SEMAPHORE_TIMEOUT}s - "
                    "detectors will not be available"
                )
                with self._components_lock:
                    self._models_loading = False
                    # Don't set _models_ready_event - leave it unset so callers know loading failed
                return

            try:
                if self._shutting_down:
                    return
                logger.debug("Loading detectors...")
                from .detectors.orchestrator import DetectorOrchestrator
                from .pipeline.coref import resolve_coreferences
                detectors = DetectorOrchestrator(self.config)
                with self._components_lock:
                    if not self._shutting_down:
                        self._detectors = detectors
                logger.info("Detectors loaded successfully")
            except Exception as e:
                logger.error(f"Detector load failed: {e}", exc_info=True)
            finally:
                with self._components_lock:
                    self._models_loading = False
                    self._models_ready_event.set()
                self._model_load_semaphore.release()
        except Exception as e:
            # Catch any unexpected exception in the entire method
            logger.error(f"_load_detectors_background crashed: {e}", exc_info=True)
            with self._components_lock:
                self._models_loading = False
                self._models_ready_event.set()

    def _load_ocr_background(self):
        if self._shutting_down:
            return

        ocr_engine = None
        if ScrubIQ._preloaded_ocr is not None:
            ocr_engine = ScrubIQ._preloaded_ocr
        else:
            if ScrubIQ._preload_started and not ScrubIQ._preload_complete.is_set():
                ScrubIQ._preload_complete.wait(timeout=PRELOAD_WAIT_TIMEOUT)
                if self._shutting_down:
                    return
                if ScrubIQ._preloaded_ocr is not None:
                    ocr_engine = ScrubIQ._preloaded_ocr

            if ocr_engine is None:
                try:
                    from .files import OCREngine
                    ocr_engine = OCREngine(self.config.models_dir)
                    if ocr_engine and ocr_engine.is_available:
                        ocr_engine.warm_up()
                except Exception as e:
                    logger.warning(f"OCR init failed: {e}")
                    ocr_engine = None

        if self._shutting_down:
            return

        with self._components_lock:
            if not self._shutting_down:
                self._ocr_engine = ocr_engine

        try:
            from .files import FileProcessor
            file_processor = FileProcessor(
                scrubiq=self,
                ocr_engine=ocr_engine,
                enable_face_detection=self.config.enable_face_detection,
                enable_metadata_stripping=self.config.enable_metadata_stripping,
                face_redaction_method=self.config.face_redaction_method,
            )
            with self._components_lock:
                if not self._shutting_down:
                    self._file_processor = file_processor
        except Exception as e:
            logger.warning(f"FileProcessor init failed: {e}")
            with self._components_lock:
                self._file_processor = None

    # =========================================================================
    # ENTITY GRAPH MANAGEMENT
    # =========================================================================

    def _ensure_entity_graph(self):
        """Ensure entity tracking is initialized for current conversation."""
        with self._components_lock:
            # Initialize EntityRegistry (single source of truth for identity)
            if self._entity_registry is None:
                self._entity_registry = EntityRegistry(
                    review_callback=self._on_entity_merge_review,
                )

            # Initialize ConversationContext (focus/salience tracking)
            if self._conversation_context is None and self._current_conversation_id:
                self._conversation_context = ConversationContext(
                    session_id=self.session_id,
                    conversation_id=self._current_conversation_id,
                )

            # Legacy EntityGraph (for backward compatibility during migration)
            if self._entity_graph is None and self._store is not None:
                self._entity_graph = EntityGraph(
                    session_id=self._current_conversation_id,
                    token_store=self._store,
                )

    def _on_entity_merge_review(self, merge_candidate) -> bool:
        """Callback for EntityRegistry when a merge needs review."""
        # For now, just log it. Could integrate with ReviewQueue later.
        logger.info(
            f"Entity merge flagged for review: {merge_candidate.reason} "
            f"(confidence={merge_candidate.confidence:.2f})"
        )
        return True  # Auto-approve for now; human review integration TODO

    def _register_entities_in_graph(self, spans: List[Span], text: str):
        """
        Register detected entities in tracking systems (legacy v1).

        Updates both:
        - ConversationContext: Focus/salience tracking for pronoun hints
        - Legacy EntityGraph: For backward compatibility

        Thread-safe: Protected by _components_lock.
        """
        with self._components_lock:
            for span in spans:
                if not hasattr(span, 'token') or not span.token:
                    continue

                # Build metadata
                metadata = {
                    "detector": span.detector if hasattr(span, 'detector') else None,
                    "confidence": span.confidence,
                }

                # Infer gender for name types
                if is_name_entity_type(span.entity_type):
                    gender = infer_gender(span.text)
                    if gender:
                        metadata["gender"] = gender

                # Register in ConversationContext (new system)
                if self._conversation_context is not None:
                    self._conversation_context.observe(
                        token=span.token,
                        entity_type=span.entity_type,
                        metadata=metadata,
                    )

                # Register in legacy EntityGraph (backward compatibility)
                if self._entity_graph is not None:
                    if span.token not in self._entity_graph.tokens:
                        self._entity_graph.tokens.add(span.token)
                        self._entity_graph.token_metadata[span.token] = {
                            "type": span.entity_type,
                            "turn": self._entity_graph.current_turn,
                            **{k: v for k, v in metadata.items() if v is not None}
                        }
                    self._entity_graph._update_focus(span.token, span.entity_type)

    def _register_entities_in_graph_v2(self, entities: List, text: str):
        """
        Register resolved entities in tracking systems (Phase 2).

        Updates both:
        - ConversationContext: Focus/salience tracking for pronoun hints
        - Legacy EntityGraph: For backward compatibility

        Thread-safe: Protected by _components_lock.

        Args:
            entities: List of Entity objects from EntityResolver
            text: Original text (for context)
        """
        with self._components_lock:
            for entity in entities:
                if not entity.token:
                    continue

                # Build metadata from entity
                metadata = {
                    "entity_id": entity.id,
                    "confidence": entity.highest_confidence,
                    "roles": list(entity.roles),
                }

                # Infer gender for name types
                if entity.entity_type in ("NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE"):
                    gender = infer_gender(entity.canonical_value)
                    if gender:
                        metadata["gender"] = gender

                # Register in ConversationContext (new system)
                if self._conversation_context is not None:
                    self._conversation_context.observe(
                        token=entity.token,
                        entity_type=entity.entity_type,
                        metadata=metadata,
                    )

                # Register in legacy EntityGraph (backward compatibility)
                if self._entity_graph is not None:
                    if entity.token not in self._entity_graph.tokens:
                        self._entity_graph.tokens.add(entity.token)
                        self._entity_graph.token_metadata[entity.token] = {
                            "type": entity.entity_type,
                            "turn": self._entity_graph.current_turn,
                            **{k: v for k, v in metadata.items() if v is not None}
                        }
                    self._entity_graph._update_focus(entity.token, entity.entity_type)

    def advance_conversation_turn(self):
        """Advance turn counters (call between user messages)."""
        with self._conversation_lock:
            # Advance ConversationContext
            if self._conversation_context is not None:
                self._conversation_context.advance_turn()
            # Advance legacy EntityGraph
            if self._entity_graph is not None:
                self._entity_graph.advance_turn()

    def resolve_pronoun(self, pronoun: str) -> Optional[str]:
        """
        Resolve a pronoun to a token using conversation context.

        Args:
            pronoun: "he", "she", "they", "it", etc.

        Returns:
            Token like [NAME_1] or None
        """
        # Try ConversationContext first (new system)
        if self._conversation_context is not None:
            p = pronoun.lower().strip()
            if p in ("he", "him", "his", "himself"):
                return self._conversation_context.get_recent_by_gender("M")
            elif p in ("she", "her", "hers", "herself"):
                return self._conversation_context.get_recent_by_gender("F")
            elif p in ("they", "them", "their", "theirs", "themselves"):
                # Could be org or person
                org = self._conversation_context.get_focus("ORG")
                person = self._conversation_context.get_focus("PERSON")
                return org or person
            elif p in ("it", "its", "itself"):
                return self._conversation_context.get_focus("ORG")
            elif p in ("there", "here"):
                return self._conversation_context.get_focus("LOCATION")

        # Fallback to legacy EntityGraph
        if self._entity_graph is not None:
            return self._entity_graph.resolve_pronoun(pronoun)

        return None

    def get_entity_graph_state(self) -> Optional[dict]:
        """Get serialized entity tracking state (zero PHI)."""
        result = {}

        # Include ConversationContext state
        if self._conversation_context is not None:
            result["conversation_context"] = self._conversation_context.to_dict()

        # Include legacy EntityGraph state
        if self._entity_graph is not None:
            result["entity_graph"] = self._entity_graph.to_dict()

        return result if result else None

    # =========================================================================
    # CORE PIPELINE: REDACT
    # =========================================================================

    def _get_geo_signals(self):
        """Get cached geo signals (loaded once on first call)."""
        if not self._geo_signals_loaded:
            self._geo_signals_cache = load_geo_signals(self.config.dictionaries_dir)
            self._geo_signals_loaded = True
        return self._geo_signals_cache

    def redact(self, text: str) -> RedactionResult:
        """Detect and redact PHI/PII from text."""
        self._require_unlock()

        # Start operation to prevent timeout during redaction
        if not self._session.start_operation():
            raise RuntimeError("Session locked - cannot perform redaction")

        try:
            return self._redact_impl(text)
        finally:
            self._session.end_operation()

    def _redact_impl(self, text: str) -> RedactionResult:
        """Implementation of redact(), protected by operation guard."""
        
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > MAX_TEXT_LENGTH:
            raise ValueError(
                f"Text length {len(text):,} exceeds maximum of {MAX_TEXT_LENGTH:,} characters."
            )
        
        if self._current_conversation_id is None or self._store is None:
            with self._conversation_lock:
                if self._current_conversation_id is None or self._store is None:
                    self.create_conversation("New conversation")
        
        # Ensure entity graph exists
        self._ensure_entity_graph()
        
        start = time.time()

        self._wait_for_models()
        with self._components_lock:
            detectors = self._detectors
        if detectors is None:
            raise RuntimeError("Detectors not initialized")

        input_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
        normalized = normalize_text(text)

        # Get known entities from TokenStore for entity persistence
        # This allows detection to recognize previously-identified names
        known_entities = None
        if self._store is not None:
            try:
                known_entities = self._store.get_name_token_mappings()
            except Exception as e:
                logger.warning(f"Failed to get known entities: {e}")

        # Run detection with entity awareness
        raw_spans = detectors.detect(normalized, known_entities=known_entities)

        merged = merge_spans(raw_spans, self.config.min_confidence, text=normalized)
        merged = normalize_name_types(merged, normalized)
        merged = expand_repeated_values(normalized, merged, min_confidence=self.config.min_confidence)

        # NOTE: FACILITY geo_signals filter removed - was too restrictive (56% recall)
        # FACILITY spans already validated by is_valid_healthcare_facility() in merger
        # Healthcare facilities should always be redacted for privacy

        if self.config.coref_enabled:
            from .pipeline.coref import resolve_coreferences
            merged = resolve_coreferences(
                normalized, merged,
                window_sentences=self.config.coref_window_sentences,
                max_expansions_per_anchor=self.config.coref_max_expansions,
                min_anchor_confidence=self.config.coref_min_anchor_confidence,
                confidence_decay=self.config.coref_confidence_decay,
            )

        if self.config.safe_harbor_enabled:
            merged = apply_safe_harbor(merged, self._session_id)

        merged = apply_allowlist(normalized, merged)
        merged = [s for s in merged if s.confidence > 0]

        # Phase 2: Entity Resolution
        # Resolve spans into entities (groups mentions of the same real-world entity)
        # This fixes the core identity problem where entity_type was used as part of identity
        if getattr(self.config, 'entity_resolution_enabled', True):
            try:
                # Get known entities for cross-message persistence
                entity_known = None
                if self._store is not None:
                    entity_known = self._store.get_name_token_mappings()
                    # Convert token -> (value, type) to entity_id -> (value, type)
                    # For now, use token as entity_id for backward compatibility
                    if entity_known:
                        entity_known = {
                            k: (v[0], v[1]) for k, v in entity_known.items()
                        }

                # Resolve spans into entities
                entities = resolve_entities(merged, known_entities=entity_known)

                # Tokenize using entity-based identity (Phase 2 API)
                redacted, merged = tokenize_entities(normalized, entities, self._store)

                # Register entities in graph with entity_ids
                self._register_entities_in_graph_v2(entities, normalized)

            except Exception as e:
                # Fall back to legacy tokenization if entity resolution fails
                logger.warning(f"Entity resolution failed, using legacy tokenization: {e}")
                redacted, merged = tokenize(normalized, merged, self._store)
                self._register_entities_in_graph(merged, normalized)
        else:
            # Legacy tokenization (Phase 1 behavior)
            redacted, merged = tokenize(normalized, merged, self._store)
            self._register_entities_in_graph(merged, normalized)
        
        tokens = self._store.list_tokens()
        review_items = self._review_queue.flag_spans(merged, normalized, tokens)
        processing_ms = (time.time() - start) * 1000

        self._audit.log_detection(text, merged, processing_ms)
        self._audit.log_redaction(text, redacted, tokens)
        self._db.conn.commit()

        return RedactionResult(
            redacted=redacted,
            spans=merged,
            tokens_created=tokens,
            needs_review=[{
                "id": r.id, "token": r.token, "type": r.entity_type,
                "confidence": r.confidence, "reason": r.reason.value,
                "context_redacted": r.context, "suggested": r.suggested_action,
            } for r in review_items],
            processing_time_ms=processing_ms,
            input_hash=input_hash,
            normalized_input=normalized,
        )

    def detect_for_visual_redaction(self, text: str) -> List[Span]:
        """Detect PHI for visual redaction (image black boxes)."""
        self._require_unlock()

        self._wait_for_models()
        with self._components_lock:
            detectors = self._detectors
        if detectors is None:
            raise RuntimeError("Detectors not initialized")

        normalized = normalize_text(text)

        # Get known entities for cross-document entity persistence
        known_entities = None
        if self._store is not None:
            try:
                known_entities = self._store.get_name_token_mappings()
            except Exception as e:
                logger.warning(f"Failed to get known entities: {e}")

        # Run detection with entity awareness
        raw_spans = detectors.detect(normalized, known_entities=known_entities)

        merged = merge_spans(raw_spans, self.config.min_confidence, text=normalized)
        merged = normalize_name_types(merged, normalized)
        merged = expand_repeated_values(normalized, merged, min_confidence=self.config.min_confidence)
        return [s for s in merged if s.confidence > 0]

    # =========================================================================
    # CORE PIPELINE: RESTORE
    # =========================================================================

    def restore(self, text: str, mode: Optional[PrivacyMode] = None) -> RestorationResult:
        """Restore tokens to original or Safe Harbor values."""
        self._require_unlock()
        self._session.touch()

        if not isinstance(text, str):
            raise TypeError("text must be a string")

        mode = mode or self._privacy_mode
        use_safe_harbor = mode == PrivacyMode.SAFE_HARBOR

        if mode == PrivacyMode.REDACTED:
            return RestorationResult(
                original=text, restored=text,
                tokens_found=[], tokens_unknown=[],
            )

        if self._store is None:
            return RestorationResult(
                original=text, restored=text,
                tokens_found=[], tokens_unknown=[],
            )

        restored, found, unknown = restore(text, self._store, use_safe_harbor)
        self._audit.log_restoration(found, unknown)

        return RestorationResult(
            original=text, restored=restored,
            tokens_found=found, tokens_unknown=unknown,
        )

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    def close(self):
        """Clean shutdown with key destruction."""
        # Signal background threads to stop
        self._shutting_down = True

        # Wait for background threads to finish (with timeout)
        for t in self._background_threads:
            if t.is_alive():
                t.join(timeout=5.0)
                if t.is_alive():
                    logger.warning(f"Background thread {t.name} did not stop in time")
        self._background_threads = []

        # Now safe to clean up components
        with self._components_lock:
            if self._file_processor:
                self._file_processor.shutdown()
                self._file_processor = None
            self._detectors = None
            self._ocr_engine = None
            self._llm_client = None
            self._openai_client = None
            self._memory_extractor = None

        # Destroy session (clears key material)
        self._session.destroy()

        if self._gateway:
            self._gateway.close()
        if self._db:
            self._db.close()

        # Clear entity tracking
        self._entity_graph = None  # Legacy
        self._entity_registry = None
        self._conversation_context = None

        # Clear memory system
        self._memory = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
