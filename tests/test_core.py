"""Tests for core.py - the main ScrubIQ redaction engine.

Tests cover:
- ScrubIQ class initialization and lifecycle
- Preloading functionality
- Session management (unlock/lock/timeout)
- Core redact() functionality
- Core restore() functionality
- Entity graph management
- Background loading
- Properties and accessors
"""

import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Set up environment for testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"


# =============================================================================
# MOCK SETUP - Must be done before importing scrubiq modules
# =============================================================================

def _setup_mocks():
    """Set up storage mocks to avoid SQLCipher dependency."""
    _mock_storage = MagicMock()
    _mock_storage.Database = MagicMock()
    _mock_storage.TokenStore = MagicMock()
    _mock_storage.AuditLog = MagicMock()
    _mock_storage.ConversationStore = MagicMock()
    _mock_storage.Conversation = MagicMock()
    _mock_storage.Message = MagicMock()
    _mock_storage.MemoryStore = MagicMock()
    _mock_storage.MemoryExtractor = MagicMock()

    _mock_database = MagicMock()
    _mock_database.Database = MagicMock()

    _mock_tokens = MagicMock()
    _mock_tokens.TokenStore = MagicMock()

    _mock_audit = MagicMock()
    _mock_audit.AuditLog = MagicMock()

    _mock_conversations = MagicMock()
    _mock_conversations.ConversationStore = MagicMock()

    _mock_memory = MagicMock()
    _mock_memory.MemoryStore = MagicMock()
    _mock_memory.MemoryExtractor = MagicMock()

    _mock_images = MagicMock()
    _mock_images.ImageStore = MagicMock()

    for mod_name, mock_mod in [
        ("scrubiq.storage", _mock_storage),
        ("scrubiq.storage.database", _mock_database),
        ("scrubiq.storage.tokens", _mock_tokens),
        ("scrubiq.storage.audit", _mock_audit),
        ("scrubiq.storage.conversations", _mock_conversations),
        ("scrubiq.storage.memory", _mock_memory),
        ("scrubiq.storage.images", _mock_images),
    ]:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = mock_mod

_setup_mocks()

from scrubiq.types import Span, Tier, PrivacyMode, RedactionResult, RestorationResult


# =============================================================================
# PRELOAD TESTS
# =============================================================================

class TestPreload:
    """Tests for model preloading functionality."""

    def test_preload_models_async_starts_thread(self):
        """preload_models_async starts background thread."""
        from scrubiq.core import ScrubIQ

        # Reset preload state
        ScrubIQ._preload_started = False
        ScrubIQ._preload_complete = threading.Event()
        ScrubIQ._preloaded_detectors = None
        ScrubIQ._preloaded_ocr = None
        ScrubIQ._preload_error = None

        with patch('scrubiq.core.DetectorOrchestrator') as mock_detector:
            with patch('scrubiq.core.OCREngine', side_effect=ImportError("No OCR")):
                mock_detector.return_value = MagicMock()

                ScrubIQ.preload_models_async()

                # Wait for preload to complete
                assert ScrubIQ._preload_started is True
                ScrubIQ._preload_complete.wait(timeout=5.0)

    def test_preload_only_runs_once(self):
        """Multiple calls to preload_models_async only run once."""
        from scrubiq.core import ScrubIQ

        # Reset preload state
        ScrubIQ._preload_started = False
        ScrubIQ._preload_complete = threading.Event()
        ScrubIQ._preloaded_detectors = MagicMock()

        # Mark as started
        ScrubIQ._preload_started = True

        # Second call should be a no-op
        ScrubIQ.preload_models_async()

        # State should be unchanged
        assert ScrubIQ._preload_started is True

    def test_is_preload_complete(self):
        """is_preload_complete returns event state."""
        from scrubiq.core import ScrubIQ

        ScrubIQ._preload_complete = threading.Event()
        assert ScrubIQ.is_preload_complete() is False

        ScrubIQ._preload_complete.set()
        assert ScrubIQ.is_preload_complete() is True

    def test_wait_for_preload(self):
        """wait_for_preload blocks until complete."""
        from scrubiq.core import ScrubIQ

        ScrubIQ._preload_complete = threading.Event()

        # Set the event in a thread
        def set_event():
            time.sleep(0.1)
            ScrubIQ._preload_complete.set()

        t = threading.Thread(target=set_event)
        t.start()

        result = ScrubIQ.wait_for_preload(timeout=2.0)
        assert result is True
        t.join()

    def test_wait_for_preload_timeout(self):
        """wait_for_preload returns False on timeout."""
        from scrubiq.core import ScrubIQ

        ScrubIQ._preload_complete = threading.Event()

        result = ScrubIQ.wait_for_preload(timeout=0.1)
        assert result is False


# =============================================================================
# INITIALIZATION TESTS
# =============================================================================

class TestScrubIQInit:
    """Tests for ScrubIQ initialization."""

    def test_init_default_config(self):
        """ScrubIQ initializes with default config."""
        with patch('scrubiq.core.Database') as mock_db:
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config') as mock_config:
                    mock_config_instance = MagicMock()
                    mock_config.return_value = mock_config_instance
                    mock_db_instance = MagicMock()
                    mock_db.return_value = mock_db_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    assert scrubiq.config == mock_config_instance
                    mock_config_instance.ensure_directories.assert_called_once()
                    mock_db_instance.connect.assert_called_once()

    def test_init_with_key_material_unlocks(self):
        """ScrubIQ unlocks when key_material provided."""
        with patch('scrubiq.core.Database') as mock_db:
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config') as mock_config:
                    mock_session_instance = MagicMock()
                    mock_session_instance.unlock.return_value = MagicMock(success=True)
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.session_id = "test-session"
                    mock_session_instance.get_key_manager.return_value = MagicMock()
                    mock_session.return_value = mock_session_instance

                    mock_config_instance = MagicMock()
                    mock_config_instance.gateway_url = None
                    mock_config.return_value = mock_config_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ(key_material="test-key")

                    mock_session_instance.unlock.assert_called_once_with("test-key")


# =============================================================================
# PROPERTY TESTS
# =============================================================================

class TestScrubIQProperties:
    """Tests for ScrubIQ properties."""

    @pytest.fixture
    def mock_scrubiq(self):
        """Create a mocked ScrubIQ instance."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config') as mock_config:
                    mock_session_instance = MagicMock()
                    mock_session_instance.session_id = "test-session-123"
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.has_keys_stored = True
                    mock_session_instance.vault_needs_upgrade = False
                    mock_session_instance.is_new_vault = False
                    mock_session_instance.get_key_manager.return_value = MagicMock()
                    mock_session.return_value = mock_session_instance

                    mock_config_instance = MagicMock()
                    mock_config_instance.gateway_url = None
                    mock_config.return_value = mock_config_instance

                    from scrubiq.core import ScrubIQ
                    yield ScrubIQ()

    def test_session_id(self, mock_scrubiq):
        """session_id returns session service session_id."""
        assert mock_scrubiq.session_id == "test-session-123"

    def test_is_unlocked(self, mock_scrubiq):
        """is_unlocked returns session service state."""
        assert mock_scrubiq.is_unlocked is True

    def test_privacy_mode_default(self, mock_scrubiq):
        """privacy_mode defaults to REDACTED."""
        assert mock_scrubiq.privacy_mode == PrivacyMode.REDACTED

    def test_set_privacy_mode(self, mock_scrubiq):
        """set_privacy_mode updates privacy mode."""
        mock_scrubiq.set_privacy_mode(PrivacyMode.SAFE_HARBOR)
        assert mock_scrubiq.privacy_mode == PrivacyMode.SAFE_HARBOR

    def test_has_keys_stored(self, mock_scrubiq):
        """has_keys_stored delegates to session service."""
        assert mock_scrubiq.has_keys_stored is True

    def test_has_gateway_without_gateway(self, mock_scrubiq):
        """has_gateway returns False when no gateway configured."""
        assert mock_scrubiq.has_gateway is False

    def test_vault_needs_upgrade(self, mock_scrubiq):
        """vault_needs_upgrade delegates to session service."""
        assert mock_scrubiq.vault_needs_upgrade is False

    def test_is_new_vault(self, mock_scrubiq):
        """is_new_vault delegates to session service."""
        assert mock_scrubiq.is_new_vault is False


# =============================================================================
# UNLOCK/LOCK TESTS
# =============================================================================

class TestUnlockLock:
    """Tests for unlock/lock functionality."""

    def test_unlock_success(self):
        """unlock() returns True on success."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config') as mock_config:
                    mock_session_instance = MagicMock()
                    mock_session_instance.unlock.return_value = MagicMock(success=True, error=None)
                    mock_session_instance.session_id = "test-session"
                    mock_session_instance.get_key_manager.return_value = MagicMock()
                    mock_session.return_value = mock_session_instance

                    mock_config_instance = MagicMock()
                    mock_config_instance.gateway_url = None
                    mock_config.return_value = mock_config_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    result = scrubiq.unlock("test-key")

                    assert result is True

    def test_unlock_failure_raises(self):
        """unlock() raises ValueError on failure."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.unlock.return_value = MagicMock(success=False, error="Bad key")
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(ValueError, match="Bad key"):
                        scrubiq.unlock("wrong-key")

    def test_lock_clears_components(self):
        """lock() clears sensitive components."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config') as mock_config:
                    mock_session_instance = MagicMock()
                    mock_session.return_value = mock_session_instance

                    mock_config_instance = MagicMock()
                    mock_config_instance.gateway_url = None
                    mock_config.return_value = mock_config_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._entity_graph = MagicMock()
                    scrubiq._entity_registry = MagicMock()
                    scrubiq._audit = MagicMock()

                    scrubiq.lock()

                    mock_session_instance.lock.assert_called_once()
                    assert scrubiq._entity_graph is None
                    assert scrubiq._entity_registry is None


# =============================================================================
# REQUIRE_UNLOCK TESTS
# =============================================================================

class TestRequireUnlock:
    """Tests for _require_unlock guard."""

    def test_require_unlock_raises_when_locked(self):
        """_require_unlock raises when session locked."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = False
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(RuntimeError, match="Session not unlocked"):
                        scrubiq._require_unlock()

    def test_require_unlock_raises_on_timeout(self):
        """_require_unlock raises when session timed out."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.check_timeout.return_value = True  # Timed out
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(RuntimeError, match="Session timed out"):
                        scrubiq._require_unlock()


# =============================================================================
# MODELS LOADING TESTS
# =============================================================================

class TestModelsLoading:
    """Tests for model loading functionality."""

    def test_is_models_ready_false_when_loading(self):
        """is_models_ready returns False while loading."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._detectors = None
                    scrubiq._models_loading = True

                    assert scrubiq.is_models_ready() is False

    def test_is_models_ready_true_when_loaded(self):
        """is_models_ready returns True when detectors loaded."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._detectors = MagicMock()
                    scrubiq._models_loading = False

                    assert scrubiq.is_models_ready() is True

    def test_is_models_loading(self):
        """is_models_loading returns True while loading."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._models_loading = True
                    scrubiq._llm_loading = False

                    assert scrubiq.is_models_loading() is True

    def test_wait_for_models_timeout_error_mode(self):
        """_wait_for_models raises TimeoutError when configured."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config') as mock_config:
                    mock_config_instance = MagicMock()
                    mock_config_instance.model_timeout_seconds = 0.1
                    mock_config_instance.on_model_timeout = "error"
                    mock_config.return_value = mock_config_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._models_loading = True
                    scrubiq._models_ready_event = threading.Event()  # Not set

                    with pytest.raises(TimeoutError):
                        scrubiq._wait_for_models(timeout=0.1)

    def test_wait_for_models_degraded_mode(self):
        """_wait_for_models returns False in degraded mode."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config') as mock_config:
                    mock_config_instance = MagicMock()
                    mock_config_instance.model_timeout_seconds = 0.1
                    mock_config_instance.on_model_timeout = "degraded"
                    mock_config.return_value = mock_config_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._models_loading = True
                    scrubiq._models_ready_event = threading.Event()  # Not set

                    result = scrubiq._wait_for_models(timeout=0.1)
                    assert result is False


# =============================================================================
# TOKEN COUNT TESTS
# =============================================================================

class TestTokenCount:
    """Tests for token counting."""

    def test_get_token_count_no_store(self):
        """get_token_count returns 0 when no store."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._store = None

                    assert scrubiq.get_token_count() == 0

    def test_get_token_count_with_store(self):
        """get_token_count returns store count."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    mock_store = MagicMock()
                    mock_store.count.return_value = 42
                    scrubiq._store = mock_store

                    assert scrubiq.get_token_count() == 42


# =============================================================================
# REVIEW QUEUE TESTS
# =============================================================================

class TestReviewQueue:
    """Tests for review queue functionality."""

    def test_get_review_count(self):
        """get_review_count returns review queue length."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    with patch('scrubiq.core.ReviewQueue') as mock_queue_class:
                        mock_queue = MagicMock()
                        mock_queue.__len__ = MagicMock(return_value=5)
                        mock_queue_class.return_value = mock_queue

                        from scrubiq.core import ScrubIQ
                        scrubiq = ScrubIQ()

                        assert scrubiq.get_review_count() == 5


# =============================================================================
# ENTITY GRAPH TESTS
# =============================================================================

class TestEntityGraph:
    """Tests for entity graph management."""

    def test_entity_graph_property(self):
        """entity_graph property returns _entity_graph."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    mock_graph = MagicMock()
                    scrubiq._entity_graph = mock_graph

                    assert scrubiq.entity_graph == mock_graph

    def test_entity_registry_property(self):
        """entity_registry property returns _entity_registry."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    mock_registry = MagicMock()
                    scrubiq._entity_registry = mock_registry

                    assert scrubiq.entity_registry == mock_registry

    def test_conversation_context_property(self):
        """conversation_context property returns _conversation_context."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    mock_context = MagicMock()
                    scrubiq._conversation_context = mock_context

                    assert scrubiq.conversation_context == mock_context

    def test_ensure_entity_graph_creates_registry(self):
        """_ensure_entity_graph creates EntityRegistry."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    with patch('scrubiq.core.EntityRegistry') as mock_registry_class:
                        mock_registry = MagicMock()
                        mock_registry_class.return_value = mock_registry

                        from scrubiq.core import ScrubIQ
                        scrubiq = ScrubIQ()
                        scrubiq._entity_registry = None

                        scrubiq._ensure_entity_graph()

                        mock_registry_class.assert_called_once()
                        assert scrubiq._entity_registry == mock_registry

    def test_advance_conversation_turn(self):
        """advance_conversation_turn increments turn counters."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    mock_context = MagicMock()
                    mock_graph = MagicMock()
                    scrubiq._conversation_context = mock_context
                    scrubiq._entity_graph = mock_graph

                    scrubiq.advance_conversation_turn()

                    mock_context.advance_turn.assert_called_once()
                    mock_graph.advance_turn.assert_called_once()

    def test_resolve_pronoun_he(self):
        """resolve_pronoun resolves 'he' to male entity."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    mock_context = MagicMock()
                    mock_context.get_recent_by_gender.return_value = "[NAME_1]"
                    scrubiq._conversation_context = mock_context

                    result = scrubiq.resolve_pronoun("he")

                    mock_context.get_recent_by_gender.assert_called_once_with("M")
                    assert result == "[NAME_1]"

    def test_resolve_pronoun_she(self):
        """resolve_pronoun resolves 'she' to female entity."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    mock_context = MagicMock()
                    mock_context.get_recent_by_gender.return_value = "[NAME_2]"
                    scrubiq._conversation_context = mock_context

                    result = scrubiq.resolve_pronoun("her")

                    mock_context.get_recent_by_gender.assert_called_once_with("F")
                    assert result == "[NAME_2]"

    def test_resolve_pronoun_it(self):
        """resolve_pronoun resolves 'it' to organization."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    mock_context = MagicMock()
                    mock_context.get_focus.return_value = "[ORG_1]"
                    scrubiq._conversation_context = mock_context

                    result = scrubiq.resolve_pronoun("it")

                    mock_context.get_focus.assert_called_with("ORG")
                    assert result == "[ORG_1]"

    def test_resolve_pronoun_there(self):
        """resolve_pronoun resolves 'there' to location."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    mock_context = MagicMock()
                    mock_context.get_focus.return_value = "[LOCATION_1]"
                    scrubiq._conversation_context = mock_context

                    result = scrubiq.resolve_pronoun("there")

                    mock_context.get_focus.assert_called_with("LOCATION")
                    assert result == "[LOCATION_1]"

    def test_resolve_pronoun_fallback_to_legacy(self):
        """resolve_pronoun falls back to legacy EntityGraph."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    scrubiq._conversation_context = None
                    mock_graph = MagicMock()
                    mock_graph.resolve_pronoun.return_value = "[NAME_3]"
                    scrubiq._entity_graph = mock_graph

                    result = scrubiq.resolve_pronoun("he")

                    mock_graph.resolve_pronoun.assert_called_once_with("he")
                    assert result == "[NAME_3]"

    def test_get_entity_graph_state(self):
        """get_entity_graph_state returns combined state."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    mock_context = MagicMock()
                    mock_context.to_dict.return_value = {"turn": 1}
                    scrubiq._conversation_context = mock_context

                    mock_graph = MagicMock()
                    mock_graph.to_dict.return_value = {"tokens": []}
                    scrubiq._entity_graph = mock_graph

                    result = scrubiq.get_entity_graph_state()

                    assert result == {
                        "conversation_context": {"turn": 1},
                        "entity_graph": {"tokens": []}
                    }

    def test_get_entity_graph_state_returns_none_when_empty(self):
        """get_entity_graph_state returns None when no state."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    scrubiq._conversation_context = None
                    scrubiq._entity_graph = None

                    result = scrubiq.get_entity_graph_state()

                    assert result is None


# =============================================================================
# CLOSE/LIFECYCLE TESTS
# =============================================================================

class TestLifecycle:
    """Tests for ScrubIQ lifecycle management."""

    def test_close_stops_background_threads(self):
        """close() signals and waits for background threads."""
        with patch('scrubiq.core.Database') as mock_db:
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_db_instance = MagicMock()
                    mock_db.return_value = mock_db_instance

                    mock_session_instance = MagicMock()
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    # Add a mock thread
                    mock_thread = MagicMock()
                    mock_thread.is_alive.return_value = False
                    scrubiq._background_threads = [mock_thread]

                    scrubiq.close()

                    assert scrubiq._shutting_down is True
                    mock_session_instance.destroy.assert_called_once()
                    mock_db_instance.close.assert_called_once()

    def test_close_clears_components(self):
        """close() clears all components."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    scrubiq._entity_graph = MagicMock()
                    scrubiq._entity_registry = MagicMock()
                    scrubiq._conversation_context = MagicMock()
                    scrubiq._memory = MagicMock()
                    scrubiq._detectors = MagicMock()

                    scrubiq.close()

                    assert scrubiq._entity_graph is None
                    assert scrubiq._entity_registry is None
                    assert scrubiq._conversation_context is None
                    assert scrubiq._memory is None
                    assert scrubiq._detectors is None

    def test_context_manager(self):
        """ScrubIQ works as context manager."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ

                    with ScrubIQ() as scrubiq:
                        assert scrubiq is not None

                    # close() should have been called
                    assert scrubiq._shutting_down is True


# =============================================================================
# REDACT TESTS
# =============================================================================

class TestRedact:
    """Tests for redact() functionality."""

    def test_redact_requires_unlock(self):
        """redact() requires unlocked session."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = False
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(RuntimeError, match="Session not unlocked"):
                        scrubiq.redact("test text")

    def test_redact_validates_string_input(self):
        """redact() validates input is string."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.check_timeout.return_value = False
                    mock_session_instance.start_operation.return_value = True
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(TypeError, match="text must be a string"):
                        scrubiq.redact(12345)

    def test_redact_validates_max_length(self):
        """redact() validates max text length."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    with patch('scrubiq.core.MAX_TEXT_LENGTH', 100):
                        mock_session_instance = MagicMock()
                        mock_session_instance.is_unlocked = True
                        mock_session_instance.check_timeout.return_value = False
                        mock_session_instance.start_operation.return_value = True
                        mock_session.return_value = mock_session_instance

                        from scrubiq.core import ScrubIQ
                        scrubiq = ScrubIQ()

                        with pytest.raises(ValueError, match="exceeds maximum"):
                            scrubiq.redact("x" * 101)


# =============================================================================
# RESTORE TESTS
# =============================================================================

class TestRestore:
    """Tests for restore() functionality."""

    def test_restore_requires_unlock(self):
        """restore() requires unlocked session."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = False
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(RuntimeError, match="Session not unlocked"):
                        scrubiq.restore("test text")

    def test_restore_validates_string_input(self):
        """restore() validates input is string."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.check_timeout.return_value = False
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    with pytest.raises(TypeError, match="text must be a string"):
                        scrubiq.restore(12345)

    def test_restore_redacted_mode_returns_unchanged(self):
        """restore() in REDACTED mode returns text unchanged."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.check_timeout.return_value = False
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._privacy_mode = PrivacyMode.REDACTED

                    result = scrubiq.restore("[NAME_1] visited [LOCATION_1]")

                    assert result.restored == "[NAME_1] visited [LOCATION_1]"
                    assert result.tokens_found == []
                    assert result.tokens_unknown == []

    def test_restore_no_store_returns_unchanged(self):
        """restore() without store returns text unchanged."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.is_unlocked = True
                    mock_session_instance.check_timeout.return_value = False
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()
                    scrubiq._privacy_mode = PrivacyMode.ORIGINAL
                    scrubiq._store = None

                    result = scrubiq.restore("[NAME_1] visited [LOCATION_1]")

                    assert result.restored == "[NAME_1] visited [LOCATION_1]"


# =============================================================================
# GEO SIGNALS TESTS
# =============================================================================

class TestGeoSignals:
    """Tests for geo signals caching."""

    def test_get_geo_signals_caches(self):
        """_get_geo_signals caches result."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config') as mock_config:
                    with patch('scrubiq.core.load_geo_signals') as mock_load:
                        mock_config_instance = MagicMock()
                        mock_config_instance.dictionaries_dir = "/test/dicts"
                        mock_config.return_value = mock_config_instance

                        mock_load.return_value = {"cities": ["NYC"]}

                        from scrubiq.core import ScrubIQ
                        scrubiq = ScrubIQ()

                        # First call loads
                        result1 = scrubiq._get_geo_signals()
                        assert result1 == {"cities": ["NYC"]}

                        # Second call uses cache
                        result2 = scrubiq._get_geo_signals()
                        assert result2 == {"cities": ["NYC"]}

                        # load_geo_signals only called once
                        mock_load.assert_called_once()


# =============================================================================
# TIMEOUT TESTS
# =============================================================================

class TestTimeout:
    """Tests for session timeout functionality."""

    def test_get_timeout_remaining(self):
        """get_timeout_remaining delegates to session service."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService') as mock_session:
                with patch('scrubiq.core.Config'):
                    mock_session_instance = MagicMock()
                    mock_session_instance.get_timeout_remaining.return_value = 300
                    mock_session.return_value = mock_session_instance

                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    result = scrubiq.get_timeout_remaining()

                    assert result == 300


# =============================================================================
# CLEAR REDACTION CACHE TESTS
# =============================================================================

class TestClearRedactionCache:
    """Tests for _clear_redaction_cache."""

    def test_clear_redaction_cache_is_noop(self):
        """_clear_redaction_cache is currently a no-op."""
        with patch('scrubiq.core.Database'):
            with patch('scrubiq.core.SessionService'):
                with patch('scrubiq.core.Config'):
                    from scrubiq.core import ScrubIQ
                    scrubiq = ScrubIQ()

                    # Should not raise
                    scrubiq._clear_redaction_cache()
