"""Comprehensive tests for core.py and sdk.py to improve coverage to 80%+.

These tests cover edge cases, error paths, and scenarios not covered by
the basic tests.
"""

import asyncio
import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock, AsyncMock

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"


# =============================================================================
# SDK ENVIRONMENT HELPER TESTS
# =============================================================================

class TestSDKEnvHelpers:
    """Tests for SDK environment helper functions."""

    def test_env_bool_true_values(self):
        """_env_bool returns True for truthy values."""
        from scrubiq.sdk import _env_bool

        for val in ("1", "true", "yes", "on", "TRUE", "Yes", "ON"):
            os.environ["TEST_BOOL"] = val
            assert _env_bool("TEST_BOOL") is True

        del os.environ["TEST_BOOL"]

    def test_env_bool_false_values(self):
        """_env_bool returns False for falsy values."""
        from scrubiq.sdk import _env_bool

        for val in ("0", "false", "no", "off", "FALSE", "No", "OFF"):
            os.environ["TEST_BOOL"] = val
            assert _env_bool("TEST_BOOL") is False

        del os.environ["TEST_BOOL"]

    def test_env_bool_default(self):
        """_env_bool returns default for missing/unknown values."""
        from scrubiq.sdk import _env_bool

        # Missing key
        assert _env_bool("NONEXISTENT_KEY") is False
        assert _env_bool("NONEXISTENT_KEY", True) is True

        # Unknown value
        os.environ["TEST_BOOL"] = "maybe"
        assert _env_bool("TEST_BOOL") is False
        assert _env_bool("TEST_BOOL", True) is True
        del os.environ["TEST_BOOL"]

    def test_env_float_valid(self):
        """_env_float parses valid floats."""
        from scrubiq.sdk import _env_float

        os.environ["TEST_FLOAT"] = "0.85"
        assert _env_float("TEST_FLOAT", 0.5) == 0.85

        os.environ["TEST_FLOAT"] = "1"
        assert _env_float("TEST_FLOAT", 0.5) == 1.0

        del os.environ["TEST_FLOAT"]

    def test_env_float_invalid(self):
        """_env_float returns default for invalid values."""
        from scrubiq.sdk import _env_float

        os.environ["TEST_FLOAT"] = "not_a_float"
        assert _env_float("TEST_FLOAT", 0.5) == 0.5

        del os.environ["TEST_FLOAT"]

    def test_env_float_missing(self):
        """_env_float returns default for missing key."""
        from scrubiq.sdk import _env_float

        assert _env_float("NONEXISTENT_KEY", 0.5) == 0.5

    def test_env_int_valid(self):
        """_env_int parses valid integers."""
        from scrubiq.sdk import _env_int

        os.environ["TEST_INT"] = "42"
        assert _env_int("TEST_INT", 10) == 42

        del os.environ["TEST_INT"]

    def test_env_int_invalid(self):
        """_env_int returns default for invalid values."""
        from scrubiq.sdk import _env_int

        os.environ["TEST_INT"] = "not_an_int"
        assert _env_int("TEST_INT", 10) == 10

        del os.environ["TEST_INT"]

    def test_env_list_valid(self):
        """_env_list parses comma-separated lists."""
        from scrubiq.sdk import _env_list

        os.environ["TEST_LIST"] = "a,b,c"
        assert _env_list("TEST_LIST") == ["a", "b", "c"]

        os.environ["TEST_LIST"] = "  a , b , c  "
        assert _env_list("TEST_LIST") == ["a", "b", "c"]

        del os.environ["TEST_LIST"]

    def test_env_list_empty(self):
        """_env_list handles empty entries."""
        from scrubiq.sdk import _env_list

        os.environ["TEST_LIST"] = "a,,b"
        assert _env_list("TEST_LIST") == ["a", "b"]

        del os.environ["TEST_LIST"]

    def test_env_list_missing(self):
        """_env_list returns default for missing key."""
        from scrubiq.sdk import _env_list

        assert _env_list("NONEXISTENT_KEY") is None
        assert _env_list("NONEXISTENT_KEY", ["default"]) == ["default"]


# =============================================================================
# SDK ENTITY TESTS
# =============================================================================

class TestSDKEntity:
    """Tests for SDK Entity dataclass."""

    def test_entity_creation(self):
        """Can create Entity."""
        from scrubiq.sdk import Entity

        entity = Entity(
            text="John Smith",
            type="NAME",
            confidence=0.95,
            token="[NAME_1]",
            start=0,
            end=10,
            detector="ml",
        )

        assert entity.text == "John Smith"
        assert entity.type == "NAME"
        assert entity.entity_type == "NAME"  # Alias
        assert entity.confidence == 0.95

    def test_entity_to_dict(self):
        """Entity.to_dict() serializes correctly."""
        from scrubiq.sdk import Entity

        entity = Entity(
            text="John",
            type="NAME",
            confidence=0.9,
            token="[NAME_1]",
            start=0,
            end=4,
            detector="ml",
        )

        d = entity.to_dict()

        assert d["text"] == "John"
        assert d["type"] == "NAME"
        assert d["confidence"] == 0.9
        assert d["token"] == "[NAME_1]"

    def test_entity_repr(self):
        """Entity.__repr__() is informative."""
        from scrubiq.sdk import Entity

        entity = Entity(text="John", type="NAME", confidence=0.95)
        repr_str = repr(entity)

        assert "NAME" in repr_str
        assert "John" in repr_str
        assert "95%" in repr_str


# =============================================================================
# SDK REVIEW ITEM TESTS
# =============================================================================

class TestSDKReviewItem:
    """Tests for SDK ReviewItem dataclass."""

    def test_review_item_creation(self):
        """Can create ReviewItem."""
        from scrubiq.sdk import ReviewItem

        item = ReviewItem(
            id="review-1",
            token="[NAME_1]",
            type="NAME",
            confidence=0.7,
            reason="low_confidence",
            context="...called [NAME_1] today...",
            suggested_action="review",
        )

        assert item.id == "review-1"
        assert item.token == "[NAME_1]"
        assert item.reason == "low_confidence"

    def test_review_item_to_dict(self):
        """ReviewItem.to_dict() serializes correctly."""
        from scrubiq.sdk import ReviewItem

        item = ReviewItem(
            id="review-1",
            token="[NAME_1]",
            type="NAME",
            confidence=0.7,
            reason="low_confidence",
            context="context",
            suggested_action="approve",
        )

        d = item.to_dict()

        assert d["id"] == "review-1"
        assert d["token"] == "[NAME_1]"
        assert d["suggested_action"] == "approve"


# =============================================================================
# SDK REDACTION RESULT TESTS
# =============================================================================

class TestSDKRedactionResult:
    """Tests for SDK RedactionResult string-like behavior."""

    def test_result_string_methods(self):
        """RedactionResult has string-like methods."""
        from scrubiq.sdk import RedactionResult, Entity

        result = RedactionResult(
            text="Hello [NAME_1]",
            entities=[Entity(text="John", type="NAME", confidence=0.9)],
            tokens=["[NAME_1]"],
            needs_review=[],
            stats={"time_ms": 10},
        )

        # String representation
        assert str(result) == "Hello [NAME_1]"
        assert len(result) == 14
        assert "[NAME_1]" in result
        assert "Hello" in result
        assert "Goodbye" not in result

    def test_result_iteration(self):
        """RedactionResult is iterable."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="abc",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        chars = list(result)
        assert chars == ["a", "b", "c"]

    def test_result_equality(self):
        """RedactionResult equality comparison."""
        from scrubiq.sdk import RedactionResult

        result1 = RedactionResult(
            text="test",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        result2 = RedactionResult(
            text="test",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        result3 = RedactionResult(
            text="other",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        assert result1 == "test"
        assert result1 == result2
        assert result1 != result3
        assert result1 != 123

    def test_result_hash(self):
        """RedactionResult is hashable."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="test",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        # Should be hashable
        assert hash(result) == hash("test")
        # Can be used in sets/dicts
        s = {result}
        assert result in s

    def test_result_concatenation(self):
        """RedactionResult concatenation."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="Hello",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        assert result + " World" == "Hello World"
        assert "Say: " + result == "Say: Hello"

    def test_result_properties(self):
        """RedactionResult properties work correctly."""
        from scrubiq.sdk import RedactionResult, Entity

        entity = Entity(text="John", type="NAME", confidence=0.9, token="[NAME_1]")
        result = RedactionResult(
            text="Hello [NAME_1]",
            entities=[entity],
            tokens=["[NAME_1]"],
            needs_review=[],
            stats={"time_ms": 10},
            _mapping={"[NAME_1]": "John"},
            error="Test error",
            warning="Test warning",
        )

        assert result.text == "Hello [NAME_1]"
        assert result.redacted == "Hello [NAME_1]"
        assert result.has_phi is True
        assert result.entity_types == {"NAME"}
        assert result.error == "Test error"
        assert result.warning == "Test warning"
        assert len(result.tokens) == 1

    def test_result_to_dict(self):
        """RedactionResult.to_dict() excludes PHI mapping."""
        from scrubiq.sdk import RedactionResult, Entity

        entity = Entity(text="John", type="NAME", confidence=0.9, token="[NAME_1]")
        result = RedactionResult(
            text="Hello [NAME_1]",
            entities=[entity],
            tokens=["[NAME_1]"],
            needs_review=[],
            stats={"time_ms": 10},
            _mapping={"[NAME_1]": "John"},
        )

        d = result.to_dict()

        assert "text" in d
        assert "entities" in d
        # PHI mappings should be excluded for security
        assert d["token_count"] == 1

    def test_result_to_json(self):
        """RedactionResult.to_json() returns valid JSON."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="test",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={"time_ms": 5},
        )

        json_str = result.to_json()
        parsed = json.loads(json_str)

        assert parsed["text"] == "test"

    def test_result_repr(self):
        """RedactionResult.__repr__() is informative."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="Hello [NAME_1], how are you today?",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        repr_str = repr(result)

        assert "RedactionResult" in repr_str
        assert "entities=" in repr_str


# =============================================================================
# SDK SCAN RESULT TESTS
# =============================================================================

class TestSDKScanResult:
    """Tests for SDK ScanResult."""

    def test_scan_result_properties(self):
        """ScanResult properties work correctly."""
        from scrubiq.sdk import ScanResult, Entity

        entity = Entity(text="SSN", type="SSN", confidence=0.99)
        result = ScanResult(
            entities=[entity],
            stats={"time_ms": 5},
            error="Test error",
            warning="Test warning",
        )

        assert result.has_phi is True
        assert result.entities == [entity]
        assert result.spans == [entity]  # Alias
        assert result.entity_types == {"SSN"}
        assert result.types_found == {"SSN"}  # Alias
        assert result.error == "Test error"
        assert result.warning == "Test warning"

    def test_scan_result_bool(self):
        """ScanResult is truthy if PHI found."""
        from scrubiq.sdk import ScanResult, Entity

        result_with_phi = ScanResult(
            entities=[Entity(text="x", type="NAME", confidence=0.9)],
            stats={},
        )
        result_without_phi = ScanResult(entities=[], stats={})

        assert bool(result_with_phi) is True
        assert bool(result_without_phi) is False

    def test_scan_result_to_dict(self):
        """ScanResult.to_dict() works correctly."""
        from scrubiq.sdk import ScanResult

        result = ScanResult(
            entities=[],
            stats={"time_ms": 10},
        )

        d = result.to_dict()

        assert d["has_phi"] is False
        assert d["entities"] == []


# =============================================================================
# SDK CHAT RESULT TESTS
# =============================================================================

class TestSDKChatResult:
    """Tests for SDK ChatResult."""

    def test_chat_result_properties(self):
        """ChatResult properties work correctly."""
        from scrubiq.sdk import ChatResult, Entity

        entity = Entity(text="John", type="NAME", confidence=0.9)
        result = ChatResult(
            response="Hello John",
            redacted_prompt="Tell me about [NAME_1]",
            redacted_response="Hello [NAME_1]",
            model="claude-3-opus",
            provider="anthropic",
            tokens_used=100,
            latency_ms=500,
            entities=[entity],
            conversation_id="conv-123",
            error="Test error",
        )

        assert result.response == "Hello John"
        assert result.spans == [entity]  # Alias
        assert result.conversation_id == "conv-123"
        assert result.error == "Test error"

    def test_chat_result_to_dict(self):
        """ChatResult.to_dict() works correctly."""
        from scrubiq.sdk import ChatResult

        result = ChatResult(
            response="Hello",
            redacted_prompt="Hello",
            redacted_response="Hello",
            model="claude-3",
            provider="anthropic",
            tokens_used=50,
            latency_ms=100,
            entities=[],
        )

        d = result.to_dict()

        assert d["response"] == "Hello"
        assert d["model"] == "claude-3"


# =============================================================================
# SDK FILE RESULT TESTS
# =============================================================================

class TestSDKFileResult:
    """Tests for SDK FileResult."""

    def test_file_result_properties(self):
        """FileResult properties work correctly."""
        from scrubiq.sdk import FileResult, Entity

        entity = Entity(text="John", type="NAME", confidence=0.9)
        result = FileResult(
            text="Document text",
            entities=[entity],
            tokens=["[NAME_1]"],
            pages=5,
            job_id="job-123",
            filename="doc.pdf",
            stats={"time_ms": 1000},
            error="Test error",
        )

        assert result.text == "Document text"
        assert result.has_phi is True
        assert result.spans == [entity]  # Alias
        assert result.pages == 5

    def test_file_result_to_dict(self):
        """FileResult.to_dict() works correctly."""
        from scrubiq.sdk import FileResult

        result = FileResult(
            text="text",
            entities=[],
            tokens=[],
            pages=1,
            job_id="job-1",
            filename="test.pdf",
        )

        d = result.to_dict()

        assert d["text"] == "text"
        assert d["has_phi"] is False


# =============================================================================
# SDK REDACTOR CONFIG TESTS
# =============================================================================

class TestSDKRedactorConfig:
    """Tests for SDK RedactorConfig."""

    def test_config_from_env(self):
        """RedactorConfig.from_env() reads environment."""
        from scrubiq.sdk import RedactorConfig

        # Set some env vars
        os.environ["SCRUBIQ_THRESHOLD"] = "0.9"
        os.environ["SCRUBIQ_SAFE_HARBOR"] = "false"
        os.environ["SCRUBIQ_WORKERS"] = "4"

        try:
            config = RedactorConfig.from_env()

            assert config.confidence_threshold == 0.9
            assert config.safe_harbor is False
            assert config.workers == 4
        finally:
            # Cleanup
            del os.environ["SCRUBIQ_THRESHOLD"]
            del os.environ["SCRUBIQ_SAFE_HARBOR"]
            del os.environ["SCRUBIQ_WORKERS"]

    def test_config_defaults(self):
        """RedactorConfig has sensible defaults."""
        from scrubiq.sdk import RedactorConfig

        config = RedactorConfig()

        assert config.confidence_threshold == 0.85
        assert config.safe_harbor is True
        assert config.coreference is True
        assert config.device == "auto"
        assert config.workers == 1


# =============================================================================
# SDK TOKENS INTERFACE TESTS
# =============================================================================

class TestSDKTokensInterface:
    """Tests for SDK TokensInterface."""

    def test_tokens_interface_iteration(self):
        """TokensInterface is iterable."""
        from scrubiq.sdk import TokensInterface

        mock_redactor = MagicMock()
        mock_redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]"},
            {"token": "[SSN_1]"},
        ]

        interface = TokensInterface(mock_redactor)

        tokens = list(interface)

        assert tokens == ["[NAME_1]", "[SSN_1]"]

    def test_tokens_interface_len(self):
        """TokensInterface.__len__() works."""
        from scrubiq.sdk import TokensInterface

        mock_redactor = MagicMock()
        mock_redactor._cr.get_token_count.return_value = 5

        interface = TokensInterface(mock_redactor)

        assert len(interface) == 5

    def test_tokens_interface_contains(self):
        """TokensInterface.__contains__() works."""
        from scrubiq.sdk import TokensInterface

        mock_redactor = MagicMock()
        mock_redactor._cr.get_tokens.return_value = [{"token": "[NAME_1]"}]

        interface = TokensInterface(mock_redactor)

        assert "[NAME_1]" in interface
        assert "[SSN_1]" not in interface

    def test_tokens_interface_lookup(self):
        """TokensInterface.lookup() works."""
        from scrubiq.sdk import TokensInterface

        mock_redactor = MagicMock()
        mock_redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "type": "NAME", "safe_harbor": "John D."}
        ]

        interface = TokensInterface(mock_redactor)

        result = interface.lookup("[NAME_1]")

        assert result["token"] == "[NAME_1]"
        assert result["type"] == "NAME"

    def test_tokens_interface_lookup_not_found(self):
        """TokensInterface.lookup() returns None if not found."""
        from scrubiq.sdk import TokensInterface

        mock_redactor = MagicMock()
        mock_redactor._cr.get_tokens.return_value = []

        interface = TokensInterface(mock_redactor)

        result = interface.lookup("[NONEXISTENT]")

        assert result is None


# =============================================================================
# CORE PRELOAD TESTS
# =============================================================================

class TestCorePreload:
    """Tests for ScrubIQ model preloading."""

    def test_preload_models_async_starts_thread(self):
        """preload_models_async() starts background thread."""
        from scrubiq.core import ScrubIQ

        # Reset preload state
        ScrubIQ._preload_started = False
        ScrubIQ._preload_complete.clear()
        ScrubIQ._preloaded_detectors = None

        ScrubIQ.preload_models_async()

        # Should have started
        assert ScrubIQ._preload_started is True

        # Wait a bit for thread to start
        time.sleep(0.1)

    def test_preload_models_async_idempotent(self):
        """preload_models_async() is idempotent."""
        from scrubiq.core import ScrubIQ

        ScrubIQ._preload_started = True

        # Calling again should be no-op
        ScrubIQ.preload_models_async()

        # Still True
        assert ScrubIQ._preload_started is True

    def test_is_preload_complete(self):
        """is_preload_complete() reflects event state."""
        from scrubiq.core import ScrubIQ

        ScrubIQ._preload_complete.clear()
        assert ScrubIQ.is_preload_complete() is False

        ScrubIQ._preload_complete.set()
        assert ScrubIQ.is_preload_complete() is True

    def test_wait_for_preload_timeout(self):
        """wait_for_preload() respects timeout."""
        from scrubiq.core import ScrubIQ

        ScrubIQ._preload_complete.clear()

        start = time.time()
        result = ScrubIQ.wait_for_preload(timeout=0.1)
        elapsed = time.time() - start

        assert result is False
        assert elapsed < 0.5  # Should timeout quickly


# =============================================================================
# CORE ENTITY GRAPH TESTS
# =============================================================================

class TestCoreEntityGraph:
    """Tests for ScrubIQ entity graph management."""

    def test_resolve_pronoun_he(self):
        """resolve_pronoun() resolves 'he' pronouns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                # Mock conversation context with male entity
                scrubiq._conversation_context = MagicMock()
                scrubiq._conversation_context.get_recent_by_gender.return_value = "[NAME_1]"

                result = scrubiq.resolve_pronoun("he")

                assert result == "[NAME_1]"
            finally:
                scrubiq.close()

    def test_resolve_pronoun_she(self):
        """resolve_pronoun() resolves 'she' pronouns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                scrubiq._conversation_context = MagicMock()
                scrubiq._conversation_context.get_recent_by_gender.return_value = "[NAME_2]"

                result = scrubiq.resolve_pronoun("her")

                assert result == "[NAME_2]"
            finally:
                scrubiq.close()

    def test_resolve_pronoun_they(self):
        """resolve_pronoun() resolves 'they' pronouns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                scrubiq._conversation_context = MagicMock()
                scrubiq._conversation_context.get_focus.return_value = "[ORG_1]"

                result = scrubiq.resolve_pronoun("they")

                assert result == "[ORG_1]"
            finally:
                scrubiq.close()

    def test_resolve_pronoun_it(self):
        """resolve_pronoun() resolves 'it' pronouns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                scrubiq._conversation_context = MagicMock()
                scrubiq._conversation_context.get_focus.return_value = "[ORG_1]"

                result = scrubiq.resolve_pronoun("it")

                assert result == "[ORG_1]"
            finally:
                scrubiq.close()

    def test_resolve_pronoun_there(self):
        """resolve_pronoun() resolves 'there' pronouns to locations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                scrubiq._conversation_context = MagicMock()
                scrubiq._conversation_context.get_focus.return_value = "[LOCATION_1]"

                result = scrubiq.resolve_pronoun("there")

                assert result == "[LOCATION_1]"
            finally:
                scrubiq.close()

    def test_resolve_pronoun_fallback_to_entity_graph(self):
        """resolve_pronoun() falls back to entity graph."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                scrubiq._conversation_context = None
                scrubiq._entity_graph = MagicMock()
                scrubiq._entity_graph.resolve_pronoun.return_value = "[NAME_1]"

                result = scrubiq.resolve_pronoun("he")

                assert result == "[NAME_1]"
            finally:
                scrubiq.close()

    def test_get_entity_graph_state(self):
        """get_entity_graph_state() returns combined state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                scrubiq._conversation_context = MagicMock()
                scrubiq._conversation_context.to_dict.return_value = {"context": "data"}

                scrubiq._entity_graph = MagicMock()
                scrubiq._entity_graph.to_dict.return_value = {"graph": "data"}

                state = scrubiq.get_entity_graph_state()

                assert "conversation_context" in state
                assert "entity_graph" in state
            finally:
                scrubiq.close()


# =============================================================================
# CORE SESSION TESTS
# =============================================================================

class TestCoreSession:
    """Tests for ScrubIQ session management."""

    def test_unlock_with_key_material(self):
        """unlock() initializes components."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config)

            try:
                assert scrubiq.is_unlocked is False

                scrubiq.unlock("test_key_123")

                assert scrubiq.is_unlocked is True
            finally:
                scrubiq.close()

    def test_lock_clears_components(self):
        """lock() clears keys and components."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                assert scrubiq.is_unlocked is True

                scrubiq.lock()

                assert scrubiq.is_unlocked is False
                assert scrubiq._entity_graph is None
                assert scrubiq._entity_registry is None
            finally:
                scrubiq.close()

    def test_require_unlock_raises_when_locked(self):
        """_require_unlock() raises when locked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config)

            try:
                with pytest.raises(RuntimeError, match="not unlocked"):
                    scrubiq._require_unlock()
            finally:
                scrubiq.close()

    def test_set_privacy_mode(self):
        """set_privacy_mode() changes mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ
            from scrubiq.types import PrivacyMode

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                assert scrubiq.privacy_mode == PrivacyMode.REDACTED

                scrubiq.set_privacy_mode(PrivacyMode.SAFE_HARBOR)

                assert scrubiq.privacy_mode == PrivacyMode.SAFE_HARBOR
            finally:
                scrubiq.close()


# =============================================================================
# CORE PROPERTIES TESTS
# =============================================================================

class TestCoreProperties:
    """Tests for ScrubIQ properties."""

    def test_session_id_property(self):
        """session_id property returns ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                assert scrubiq.session_id is not None
            finally:
                scrubiq.close()

    def test_has_gateway_property(self):
        """has_gateway property reflects gateway state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                assert scrubiq.has_gateway is False
            finally:
                scrubiq.close()

    def test_token_count_property(self):
        """get_token_count() returns count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                # Should be 0 initially
                assert scrubiq.get_token_count() == 0
            finally:
                scrubiq.close()

    def test_review_count_property(self):
        """get_review_count() returns count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                assert scrubiq.get_review_count() == 0
            finally:
                scrubiq.close()


# =============================================================================
# CORE RESTORE TESTS
# =============================================================================

class TestCoreRestore:
    """Tests for ScrubIQ restore functionality."""

    def test_restore_redacted_mode_returns_unchanged(self):
        """restore() in REDACTED mode returns text unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ
            from scrubiq.types import PrivacyMode

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                text = "Hello [NAME_1]"
                result = scrubiq.restore(text, PrivacyMode.REDACTED)

                assert result.restored == text
                assert result.tokens_found == []
            finally:
                scrubiq.close()

    def test_restore_with_no_store_returns_unchanged(self):
        """restore() with no store returns text unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ
            from scrubiq.types import PrivacyMode

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            try:
                # Clear store
                scrubiq._store = None

                text = "Hello [NAME_1]"
                result = scrubiq.restore(text, PrivacyMode.RESEARCH)

                assert result.restored == text
            finally:
                scrubiq.close()


# =============================================================================
# CORE LIFECYCLE TESTS
# =============================================================================

class TestCoreLifecycle:
    """Tests for ScrubIQ lifecycle management."""

    def test_context_manager(self):
        """ScrubIQ works as context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)

            with ScrubIQ(config=config, key_material="test_key_123") as scrubiq:
                assert scrubiq.is_unlocked is True

            # After context, should be closed
            # Note: We don't test is_unlocked here as close() destroys session

    def test_close_stops_background_threads(self):
        """close() stops background threads."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.config import Config
            from scrubiq.core import ScrubIQ

            config = Config(data_dir=tmpdir)
            scrubiq = ScrubIQ(config=config, key_material="test_key_123")

            # Track background threads
            threads_before = len(scrubiq._background_threads)

            scrubiq.close()

            # All threads should be stopped
            assert scrubiq._shutting_down is True


# =============================================================================
# SDK REDACTOR ERROR HANDLING TESTS
# =============================================================================

class TestSDKRedactorErrorHandling:
    """Tests for SDK Redactor error handling."""

    def test_redact_empty_input(self):
        """redact() handles empty input."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor()
                result = r.redact("")

                assert str(result) == ""
                assert result.warning == "Empty input"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_redact_with_on_redact_callback(self):
        """redact() calls on_redact callback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            callback_results = []

            def on_redact(result):
                callback_results.append(result)

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(on_redact=on_redact)
                r.redact("Hello world")

                assert len(callback_results) == 1
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_redact_with_callback_error(self):
        """redact() handles callback errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            def failing_callback(result):
                raise ValueError("Callback error")

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(on_redact=failing_callback)
                # Should not raise
                result = r.redact("Hello world")

                assert result is not None
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]


# =============================================================================
# SDK REDACTOR ALLOWLIST TESTS
# =============================================================================

class TestSDKRedactorAllowlist:
    """Tests for SDK Redactor allowlist functionality."""

    def test_allowlist_from_constructor(self):
        """Allowlist from constructor is applied."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(allowlist=["Mayo Clinic"])

                assert "mayo clinic" in {a.lower() for a in r._allowlist}
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_allowlist_from_file(self):
        """Allowlist from file is loaded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            # Create allowlist file
            allowlist_path = Path(tmpdir) / "allowlist.txt"
            allowlist_path.write_text("Test Hospital\n# Comment\nAnother Entry")

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(allowlist_file=str(allowlist_path))

                assert "test hospital" in {a.lower() for a in r._allowlist}
                assert "another entry" in {a.lower() for a in r._allowlist}
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_allowlist_file_not_found(self):
        """Non-existent allowlist file is handled gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                # Should not raise
                r = Redactor(allowlist_file="/nonexistent/path.txt")
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]


# =============================================================================
# SDK REDACTOR CUSTOM PATTERNS TESTS
# =============================================================================

class TestSDKRedactorCustomPatterns:
    """Tests for SDK Redactor custom patterns."""

    def test_custom_patterns_compiled(self):
        """Custom patterns are compiled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(patterns={"MRN": r"MRN-\d{8}"})

                assert "MRN" in r._compiled_patterns
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_invalid_pattern_handled(self):
        """Invalid regex patterns are handled gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                # Invalid regex
                r = Redactor(patterns={"BAD": r"[invalid("})

                # Should not be in compiled patterns
                assert "BAD" not in r._compiled_patterns
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_detect_custom_patterns(self):
        """Custom patterns are detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(patterns={"MRN": r"MRN-\d{8}"})

                spans = r._detect_custom_patterns("Patient MRN-12345678")

                assert len(spans) == 1
                assert spans[0]["type"] == "MRN"
                assert spans[0]["text"] == "MRN-12345678"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]


# =============================================================================
# SDK REDACTOR FILTER TESTS
# =============================================================================

class TestSDKRedactorFilter:
    """Tests for SDK Redactor entity filtering."""

    def test_filter_by_threshold(self):
        """Entities below threshold are filtered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor, Entity

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(confidence_threshold=0.9)

                entities = [
                    Entity(text="John", type="NAME", confidence=0.95),
                    Entity(text="123", type="SSN", confidence=0.7),  # Below threshold
                ]

                filtered = r._filter_entities(entities)

                assert len(filtered) == 1
                assert filtered[0].text == "John"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_filter_by_entity_types(self):
        """Only specified entity types are kept."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor, Entity

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(entity_types=["NAME"])

                entities = [
                    Entity(text="John", type="NAME", confidence=0.9),
                    Entity(text="123-45-6789", type="SSN", confidence=0.99),
                ]

                filtered = r._filter_entities(entities)

                assert len(filtered) == 1
                assert filtered[0].type == "NAME"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_filter_by_exclude_types(self):
        """Excluded entity types are removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor, Entity

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(exclude_types=["EMAIL"])

                entities = [
                    Entity(text="John", type="NAME", confidence=0.9),
                    Entity(text="john@test.com", type="EMAIL", confidence=0.99),
                ]

                filtered = r._filter_entities(entities)

                assert len(filtered) == 1
                assert filtered[0].type == "NAME"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    def test_filter_by_allowlist(self):
        """Allowlisted values are not filtered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor, Entity

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor(allowlist=["Mayo Clinic"])

                entities = [
                    Entity(text="John", type="NAME", confidence=0.9),
                    Entity(text="Mayo Clinic", type="ORG", confidence=0.95),
                ]

                filtered = r._filter_entities(entities)

                assert len(filtered) == 1
                assert filtered[0].text == "John"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]


# =============================================================================
# SDK ASYNC METHODS TESTS
# =============================================================================

class TestSDKAsyncMethods:
    """Tests for SDK async methods."""

    @pytest.mark.asyncio
    async def test_aredact(self):
        """aredact() works correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor()
                result = await r.aredact("Hello world")

                assert result is not None
                assert "world" in str(result)
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]

    @pytest.mark.asyncio
    async def test_arestore(self):
        """arestore() works correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from scrubiq.sdk import Redactor

            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                r = Redactor()
                result = await r.arestore("Hello world")

                assert result == "Hello world"
                r.close()
            finally:
                del os.environ["SCRUBIQ_HOME"]


# =============================================================================
# SDK MODULE LEVEL FUNCTIONS TESTS
# =============================================================================

class TestSDKModuleFunctions:
    """Tests for SDK module-level functions."""

    def test_reset_default_redactor(self):
        """_reset_default() clears default redactor."""
        from scrubiq.sdk import _reset_default, _default_redactor, _get_default

        # Force creation of default
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["SCRUBIQ_HOME"] = tmpdir

            try:
                _reset_default()
                _get_default()  # Creates default
                _reset_default()

                # Import to check state
                import scrubiq.sdk as sdk
                assert sdk._default_redactor is None
            finally:
                if "SCRUBIQ_HOME" in os.environ:
                    del os.environ["SCRUBIQ_HOME"]
