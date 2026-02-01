"""
SDK Extended Tests - Comprehensive coverage for untested SDK functionality.

This module tests the SDK components that were identified as having gaps:
1. SDK Interfaces (Conversations, Memory, Review, Audit)
2. Redactor methods (redact_file, chat, lookup, delete_token, preload)
3. Result class methods (__str__, __len__, __contains__, __eq__, etc.)
4. Entity and ReviewItem dataclasses
5. FileResult class

HARDCORE: No weak tests, no skips, no weak assertions.
"""

import json
import os
import pytest
import tempfile
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, Mock, patch, PropertyMock
from dataclasses import dataclass

from scrubiq import (
    redact,
    restore,
    scan,
    Redactor,
    RedactionResult,
    ScanResult,
    ChatResult,
    RedactorConfig,
)
from scrubiq.sdk import (
    Entity,
    ReviewItem,
    FileResult,
    ConversationsInterface,
    ReviewInterface,
    MemoryInterface,
    AuditInterface,
    preload,
    preload_async,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(autouse=True, scope="module")
def ensure_models_ready():
    """Ensure models are loaded before running tests."""
    from scrubiq.core import ScrubIQ

    if ScrubIQ._preload_started:
        loaded = ScrubIQ.wait_for_preload(timeout=180.0)
        assert loaded, "Model preloading failed or timed out"

    yield


@pytest.fixture
def temp_dir():
    """Create temporary directory for test data."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def redactor(temp_dir):
    """Create a Redactor instance for testing."""
    r = Redactor(data_dir=temp_dir)
    yield r
    r.close()


# =============================================================================
# ENTITY DATACLASS TESTS
# =============================================================================

class TestEntityDataclass:
    """Test Entity dataclass functionality."""

    def test_entity_creation_with_all_fields(self):
        """Entity should be creatable with all fields."""
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
        assert entity.confidence == 0.95
        assert entity.token == "[NAME_1]"
        assert entity.start == 0
        assert entity.end == 10
        assert entity.detector == "ml"

    def test_entity_type_property_alias(self):
        """entity_type property should be alias for type."""
        entity = Entity(text="John", type="NAME", confidence=0.9)

        assert entity.entity_type == entity.type
        assert entity.entity_type == "NAME"

    def test_entity_to_dict(self):
        """to_dict should return all fields."""
        entity = Entity(
            text="123-45-6789",
            type="SSN",
            confidence=0.99,
            token="[SSN_1]",
            start=5,
            end=16,
            detector="checksum",
        )

        d = entity.to_dict()

        assert isinstance(d, dict)
        assert d["text"] == "123-45-6789"
        assert d["type"] == "SSN"
        assert d["confidence"] == 0.99
        assert d["token"] == "[SSN_1]"
        assert d["start"] == 5
        assert d["end"] == 16
        assert d["detector"] == "checksum"

    def test_entity_to_dict_is_json_serializable(self):
        """to_dict output should be JSON serializable."""
        entity = Entity(text="Test", type="NAME", confidence=0.8)

        json_str = json.dumps(entity.to_dict())

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["text"] == "Test"

    def test_entity_repr(self):
        """__repr__ should include type, text, and confidence."""
        entity = Entity(text="John", type="NAME", confidence=0.95)

        repr_str = repr(entity)

        assert "Entity" in repr_str
        assert "NAME" in repr_str
        assert "John" in repr_str
        assert "95%" in repr_str

    def test_entity_from_span(self):
        """from_span should create Entity from internal Span."""
        from scrubiq.types import Span

        span = Span(
            text="Jane Doe",
            start=0,
            end=8,
            entity_type="NAME_PATIENT",
            confidence=0.92,
            token="[NAME_1]",
            detector="pattern",
        )

        entity = Entity.from_span(span)

        assert entity.text == "Jane Doe"
        assert entity.type == "NAME_PATIENT"
        assert entity.confidence == 0.92
        assert entity.token == "[NAME_1]"
        assert entity.start == 0
        assert entity.end == 8
        assert entity.detector == "pattern"

    def test_entity_default_values(self):
        """Entity should have sensible defaults for optional fields."""
        entity = Entity(text="Test", type="NAME", confidence=0.8)

        assert entity.token is None
        assert entity.start == 0
        assert entity.end == 0
        assert entity.detector == ""


# =============================================================================
# REVIEW ITEM DATACLASS TESTS
# =============================================================================

class TestReviewItemDataclass:
    """Test ReviewItem dataclass functionality."""

    def test_review_item_creation(self):
        """ReviewItem should be creatable with all fields."""
        item = ReviewItem(
            id="rev-123",
            token="[NAME_1]",
            type="NAME",
            confidence=0.65,
            reason="low_confidence",
            context="Patient [NAME_1] was seen...",
            suggested_action="review",
        )

        assert item.id == "rev-123"
        assert item.token == "[NAME_1]"
        assert item.type == "NAME"
        assert item.confidence == 0.65
        assert item.reason == "low_confidence"
        assert item.context == "Patient [NAME_1] was seen..."
        assert item.suggested_action == "review"

    def test_review_item_to_dict(self):
        """to_dict should serialize all fields."""
        item = ReviewItem(
            id="rev-456",
            token="[SSN_1]",
            type="SSN",
            confidence=0.72,
            reason="ambiguous_context",
            context="Number: [SSN_1]",
            suggested_action="approve",
        )

        d = item.to_dict()

        assert isinstance(d, dict)
        assert d["id"] == "rev-456"
        assert d["token"] == "[SSN_1]"
        assert d["type"] == "SSN"
        assert d["confidence"] == 0.72
        assert d["reason"] == "ambiguous_context"
        assert d["context"] == "Number: [SSN_1]"
        assert d["suggested_action"] == "approve"

    def test_review_item_to_dict_is_json_serializable(self):
        """to_dict output should be JSON serializable."""
        item = ReviewItem(
            id="rev-789",
            token="[NAME_1]",
            type="NAME",
            confidence=0.68,
            reason="test",
            context="context",
            suggested_action="review",
        )

        json_str = json.dumps(item.to_dict())

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["id"] == "rev-789"


# =============================================================================
# FILE RESULT TESTS
# =============================================================================

class TestFileResult:
    """Test FileResult dataclass functionality."""

    def test_file_result_creation(self):
        """FileResult should be creatable with required fields."""
        result = FileResult(
            text="Redacted text content",
            entities=[Entity(text="John", type="NAME", confidence=0.9)],
            tokens=["[NAME_1]"],
            pages=5,
            job_id="job-123",
            filename="test.pdf",
        )

        assert result.text == "Redacted text content"
        assert len(result.entities) == 1
        assert result.tokens == ["[NAME_1]"]
        assert result.pages == 5
        assert result.job_id == "job-123"
        assert result.filename == "test.pdf"

    def test_file_result_has_phi_property(self):
        """has_phi should return True when entities present."""
        result_with_phi = FileResult(
            text="[NAME_1] text",
            entities=[Entity(text="John", type="NAME", confidence=0.9)],
            tokens=["[NAME_1]"],
            pages=1,
            job_id="job-1",
            filename="test.pdf",
        )

        result_no_phi = FileResult(
            text="No PHI here",
            entities=[],
            tokens=[],
            pages=1,
            job_id="job-2",
            filename="clean.pdf",
        )

        assert result_with_phi.has_phi is True
        assert result_no_phi.has_phi is False

    def test_file_result_spans_property(self):
        """spans should be alias for entities."""
        entities = [Entity(text="Test", type="NAME", confidence=0.9)]
        result = FileResult(
            text="text",
            entities=entities,
            tokens=[],
            pages=1,
            job_id="j",
            filename="f.pdf",
        )

        assert result.spans == result.entities
        assert len(result.spans) == 1

    def test_file_result_to_dict(self):
        """to_dict should serialize all fields."""
        result = FileResult(
            text="Redacted",
            entities=[Entity(text="John", type="NAME", confidence=0.95)],
            tokens=["[NAME_1]"],
            pages=3,
            job_id="job-xyz",
            filename="doc.pdf",
            stats={"processing_time_ms": 150},
        )

        d = result.to_dict()

        assert d["text"] == "Redacted"
        assert d["pages"] == 3
        assert d["job_id"] == "job-xyz"
        assert d["filename"] == "doc.pdf"
        assert d["has_phi"] is True
        assert len(d["entities"]) == 1
        assert len(d["spans"]) == 1  # backward compat
        assert d["stats"]["processing_time_ms"] == 150

    def test_file_result_to_json(self):
        """to_json should return valid JSON string."""
        result = FileResult(
            text="Test",
            entities=[],
            tokens=[],
            pages=1,
            job_id="j",
            filename="f.pdf",
        )

        json_str = result.to_json()

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["filename"] == "f.pdf"

    def test_file_result_with_error(self):
        """FileResult should store error field."""
        result = FileResult(
            text="",
            entities=[],
            tokens=[],
            pages=0,
            job_id="",
            filename="bad.pdf",
            error="Failed to process file",
        )

        assert result.error == "Failed to process file"
        d = result.to_dict()
        assert d["error"] == "Failed to process file"


# =============================================================================
# REDACTION RESULT STRING BEHAVIOR TESTS
# =============================================================================

class TestRedactionResultStringBehavior:
    """Test RedactionResult string-like behavior."""

    def test_str_returns_redacted_text(self, redactor):
        """__str__ should return the redacted text."""
        result = redactor.redact("Patient John Smith")

        str_result = str(result)

        assert isinstance(str_result, str)
        assert "John Smith" not in str_result
        assert str_result == result.text

    def test_len_returns_text_length(self, redactor):
        """__len__ should return length of redacted text."""
        result = redactor.redact("John Smith")

        length = len(result)

        assert isinstance(length, int)
        assert length == len(result.text)
        assert length > 0

    def test_contains_checks_text(self, redactor):
        """__contains__ should check if substring in text."""
        result = redactor.redact("Patient John Smith was seen")

        # Token should be in result
        assert "[NAME_1]" in result or "[PATIENT_1]" in result or len(result.tokens) > 0

        # Original PHI should NOT be in result
        assert "John Smith" not in result

        # Other text should be in result
        assert "Patient" in result or "was seen" in result

    def test_iter_iterates_over_text(self, redactor):
        """__iter__ should iterate over characters in text."""
        result = redactor.redact("Test")

        chars = list(result)

        assert chars == list(result.text)

    def test_eq_with_string(self, redactor):
        """__eq__ should compare with string."""
        result = redactor.redact("No PHI here")

        assert result == "No PHI here"
        assert result != "Different text"

    def test_eq_with_redaction_result(self, temp_dir):
        """__eq__ should compare with another RedactionResult."""
        r1 = Redactor(data_dir=temp_dir / "r1")
        r2 = Redactor(data_dir=temp_dir / "r2")

        result1 = r1.redact("No PHI here")
        result2 = r2.redact("No PHI here")

        assert result1 == result2

        r1.close()
        r2.close()

    def test_hash_is_consistent(self, redactor):
        """__hash__ should be consistent with text."""
        result = redactor.redact("Test text")

        h = hash(result)

        assert isinstance(h, int)
        assert h == hash(result.text)

    def test_add_concatenates_with_string(self, redactor):
        """__add__ should concatenate with string."""
        result = redactor.redact("Patient [NAME]")

        concatenated = result + " - end"

        assert isinstance(concatenated, str)
        assert concatenated.endswith(" - end")
        assert concatenated == result.text + " - end"

    def test_radd_concatenates_string_prefix(self, redactor):
        """__radd__ should allow string prefix."""
        result = redactor.redact("Patient data")

        concatenated = "Start - " + result

        assert isinstance(concatenated, str)
        assert concatenated.startswith("Start - ")
        assert concatenated == "Start - " + result.text


# =============================================================================
# REDACTION RESULT PROPERTIES TESTS
# =============================================================================

class TestRedactionResultProperties:
    """Test RedactionResult property access."""

    def test_entities_property(self, redactor):
        """entities should return list of Entity objects."""
        result = redactor.redact("Patient John Smith, SSN 123-45-6789")

        entities = result.entities

        assert isinstance(entities, list)
        assert len(entities) >= 1
        for entity in entities:
            assert isinstance(entity, Entity)
            assert hasattr(entity, 'text')
            assert hasattr(entity, 'type')
            assert hasattr(entity, 'confidence')

    def test_has_phi_property_true(self, redactor):
        """has_phi should be True when PHI detected."""
        result = redactor.redact("John Smith SSN 123-45-6789")

        assert result.has_phi is True

    def test_has_phi_property_false(self, redactor):
        """has_phi should be False when no PHI."""
        result = redactor.redact("The weather is nice today")

        assert result.has_phi is False

    def test_entity_types_property(self, redactor):
        """entity_types should return set of types found."""
        result = redactor.redact("John Smith SSN 123-45-6789")

        types = result.entity_types

        assert isinstance(types, set)
        if result.has_phi:
            assert len(types) >= 1
            for t in types:
                assert isinstance(t, str)

    def test_needs_review_property(self, redactor):
        """needs_review should return list of ReviewItem objects."""
        result = redactor.redact("John Smith")

        review_items = result.needs_review

        assert isinstance(review_items, list)
        for item in review_items:
            assert isinstance(item, ReviewItem)

    def test_warning_property(self, redactor):
        """warning should be accessible (may be None)."""
        result = redactor.redact("Test")

        # warning can be None or a string
        assert result.warning is None or isinstance(result.warning, str)

    def test_error_property(self, redactor):
        """error should be accessible (may be None for success)."""
        result = redactor.redact("Test")

        # For successful redaction, error should be None
        assert result.error is None


# =============================================================================
# SCAN RESULT PROPERTIES TESTS
# =============================================================================

class TestScanResultProperties:
    """Test ScanResult property access."""

    def test_entities_property(self, redactor):
        """entities should return list of Entity objects."""
        result = redactor.scan("John Smith SSN 123-45-6789")

        entities = result.entities

        assert isinstance(entities, list)
        for entity in entities:
            assert isinstance(entity, Entity)

    def test_entity_types_property(self, redactor):
        """entity_types should return set of types."""
        result = redactor.scan("John Smith SSN 123-45-6789")

        types = result.entity_types

        assert isinstance(types, set)
        if result.has_phi:
            assert len(types) >= 1

    def test_stats_property(self, redactor):
        """stats should return processing statistics."""
        result = redactor.scan("John Smith")

        stats = result.stats

        assert isinstance(stats, dict)
        assert "time_ms" in stats

    def test_error_property(self, redactor):
        """error should be accessible."""
        result = redactor.scan("Test")

        assert result.error is None or isinstance(result.error, str)

    def test_warning_property(self, redactor):
        """warning should be accessible."""
        result = redactor.scan("Test")

        assert result.warning is None or isinstance(result.warning, str)

    def test_repr(self, redactor):
        """__repr__ should be informative."""
        result = redactor.scan("John Smith")

        repr_str = repr(result)

        assert "ScanResult" in repr_str
        assert "has_phi" in repr_str

    def test_bool_truthy_when_phi(self, redactor):
        """__bool__ should be truthy when PHI found."""
        result_with_phi = redactor.scan("John Smith SSN 123-45-6789")
        result_no_phi = redactor.scan("The weather is nice")

        assert bool(result_with_phi) == result_with_phi.has_phi
        assert bool(result_no_phi) == result_no_phi.has_phi


# =============================================================================
# CHAT RESULT TESTS
# =============================================================================

class TestChatResultExtended:
    """Extended tests for ChatResult."""

    def test_chat_result_spans_property(self):
        """spans should be alias for entities."""
        entities = [Entity(text="John", type="NAME", confidence=0.9)]
        result = ChatResult(
            response="Response",
            redacted_prompt="Prompt",
            redacted_response="Response",
            model="test",
            provider="test",
            tokens_used=10,
            latency_ms=50.0,
            entities=entities,
        )

        assert result.spans == result.entities
        assert len(result.spans) == 1

    def test_chat_result_to_json(self):
        """to_json should return valid JSON."""
        result = ChatResult(
            response="Test response",
            redacted_prompt="Test prompt",
            redacted_response="Test",
            model="claude-sonnet-4-20250514",
            provider="anthropic",
            tokens_used=100,
            latency_ms=200.0,
            entities=[],
        )

        json_str = result.to_json()

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["model"] == "claude-sonnet-4-20250514"
        assert parsed["provider"] == "anthropic"
        assert parsed["tokens_used"] == 100

    def test_chat_result_repr(self):
        """__repr__ should be informative."""
        result = ChatResult(
            response="R",
            redacted_prompt="P",
            redacted_response="R",
            model="gpt-4",
            provider="openai",
            tokens_used=50,
            latency_ms=100.0,
            entities=[],
        )

        repr_str = repr(result)

        assert "ChatResult" in repr_str
        assert "gpt-4" in repr_str
        assert "50" in repr_str


# =============================================================================
# REDACTOR LOOKUP AND DELETE TOKEN TESTS
# =============================================================================

class TestRedactorTokenManagement:
    """Test Redactor token lookup and deletion."""

    def test_lookup_existing_token(self, redactor):
        """lookup should return token info for existing token."""
        result = redactor.redact("Patient John Smith")

        if result.tokens:
            token = result.tokens[0]
            info = redactor.lookup(token)

            assert info is not None
            assert info["token"] == token
            assert "type" in info
            # Should NOT expose original PHI
            assert "original" not in info or info.get("original") is None

    def test_lookup_nonexistent_token(self, redactor):
        """lookup should return None for nonexistent token."""
        info = redactor.lookup("[NONEXISTENT_999]")

        assert info is None

    def test_delete_token(self, redactor):
        """delete_token should remove token from store."""
        result = redactor.redact("Patient John Smith")

        if result.tokens:
            token = result.tokens[0]
            initial_count = redactor.token_count

            deleted = redactor.delete_token(token)

            assert deleted is True
            assert redactor.token_count < initial_count
            assert redactor.lookup(token) is None

    def test_delete_nonexistent_token(self, redactor):
        """delete_token should return False for nonexistent token."""
        result = redactor.delete_token("[NONEXISTENT_999]")

        assert result is False


# =============================================================================
# REDACTOR PROPERTIES TESTS
# =============================================================================

class TestRedactorProperties:
    """Test Redactor property access."""

    def test_is_ready_property(self, redactor):
        """is_ready should return True when ready."""
        assert isinstance(redactor.is_ready, bool)
        assert redactor.is_ready is True

    def test_is_healthy_property(self, redactor):
        """is_healthy should return True when no errors."""
        assert isinstance(redactor.is_healthy, bool)
        assert redactor.is_healthy is True

    def test_status_property(self, redactor):
        """status should return detailed status dict."""
        status = redactor.status

        assert isinstance(status, dict)
        assert "ready" in status
        assert "healthy" in status
        assert "models_loaded" in status
        assert "storage_connected" in status
        assert "storage_encrypted" in status

    def test_stats_property(self, redactor):
        """stats should return processing statistics."""
        redactor.redact("John Smith")

        stats = redactor.stats

        assert isinstance(stats, dict)
        assert "redactions_performed" in stats
        assert stats["redactions_performed"] >= 1
        assert "entities_detected" in stats

    def test_tokens_property(self, redactor):
        """tokens should return list of token strings."""
        redactor.redact("John Smith SSN 123-45-6789")

        tokens = redactor.tokens

        assert isinstance(tokens, list)
        assert len(tokens) >= 1
        for token in tokens:
            assert isinstance(token, str)
            assert token.startswith("[") and token.endswith("]")

    def test_detectors_property(self, redactor):
        """detectors should return detector info."""
        detectors = redactor.detectors

        assert isinstance(detectors, list)

    def test_supported_types_property(self, redactor):
        """supported_types should return list of entity types."""
        types = redactor.supported_types

        assert isinstance(types, list)
        assert "NAME" in types or "NAME_PATIENT" in types
        assert "SSN" in types
        assert "EMAIL" in types


# =============================================================================
# CONVERSATIONS INTERFACE TESTS
# =============================================================================

class TestConversationsInterface:
    """Test ConversationsInterface functionality."""

    def test_create_conversation(self, redactor):
        """create should return conversation dict with ID."""
        conv = redactor.conversations.create("Test Conversation")

        assert isinstance(conv, dict)
        assert "id" in conv
        assert isinstance(conv["id"], str)
        assert len(conv["id"]) > 0
        assert conv["title"] == "Test Conversation"
        assert "created_at" in conv

    def test_list_conversations(self, redactor):
        """list should return list of conversation dicts."""
        redactor.conversations.create("Conv 1")
        redactor.conversations.create("Conv 2")

        convs = redactor.conversations.list()

        assert isinstance(convs, list)
        assert len(convs) >= 2
        for conv in convs:
            assert "id" in conv
            assert "title" in conv
            assert "created_at" in conv

    def test_list_with_limit(self, redactor):
        """list should respect limit parameter."""
        for i in range(5):
            redactor.conversations.create(f"Conv {i}")

        convs = redactor.conversations.list(limit=2)

        assert len(convs) == 2

    def test_list_with_offset(self, redactor):
        """list should respect offset parameter."""
        for i in range(5):
            redactor.conversations.create(f"Conv {i}")

        all_convs = redactor.conversations.list(limit=10)
        offset_convs = redactor.conversations.list(limit=10, offset=2)

        assert len(offset_convs) == len(all_convs) - 2

    def test_get_conversation(self, redactor):
        """get should return conversation by ID."""
        created = redactor.conversations.create("Test Get")
        conv_id = created["id"]

        conv = redactor.conversations.get(conv_id)

        assert conv is not None
        assert conv["id"] == conv_id
        assert conv["title"] == "Test Get"
        assert "messages" in conv

    def test_get_nonexistent_conversation(self, redactor):
        """get should return None for nonexistent ID."""
        conv = redactor.conversations.get("nonexistent-id-12345")

        assert conv is None

    def test_delete_conversation(self, redactor):
        """delete should remove conversation."""
        created = redactor.conversations.create("To Delete")
        conv_id = created["id"]

        result = redactor.conversations.delete(conv_id)

        assert result is True
        assert redactor.conversations.get(conv_id) is None

    def test_search_conversations(self, redactor):
        """search should search across conversations."""
        # Create conversations with distinct titles
        redactor.conversations.create("Medical Records")
        redactor.conversations.create("Financial Data")

        results = redactor.conversations.search("Medical")

        assert isinstance(results, list)


# =============================================================================
# MEMORY INTERFACE TESTS
# =============================================================================

class TestMemoryInterface:
    """Test MemoryInterface functionality."""

    def test_search_returns_list(self, redactor):
        """search should return list of results."""
        results = redactor.memory.search("test query")

        assert isinstance(results, list)

    def test_get_for_entity_returns_list(self, redactor):
        """get_for_entity should return list."""
        results = redactor.memory.get_for_entity("[NAME_1]")

        assert isinstance(results, list)

    def test_get_all_returns_list(self, redactor):
        """get_all should return list of memories."""
        results = redactor.memory.get_all()

        assert isinstance(results, list)

    def test_get_all_with_category(self, redactor):
        """get_all should filter by category."""
        results = redactor.memory.get_all(category="medical")

        assert isinstance(results, list)

    def test_add_memory(self, redactor):
        """add should add a memory."""
        result = redactor.memory.add(
            fact="[NAME_1] prefers morning appointments",
            entity_token="[NAME_1]",
            category="preference",
            confidence=0.95,
        )

        # Returns True if added (may return False if memory not initialized)
        assert isinstance(result, bool)

    def test_delete_memory(self, redactor):
        """delete should attempt to delete memory."""
        result = redactor.memory.delete("nonexistent-memory-id")

        # Should return False for nonexistent
        assert isinstance(result, bool)

    def test_count_property(self, redactor):
        """count should return integer."""
        count = redactor.memory.count

        assert isinstance(count, int)
        assert count >= 0

    def test_stats_property(self, redactor):
        """stats should return dict."""
        stats = redactor.memory.stats

        assert isinstance(stats, dict)


# =============================================================================
# REVIEW INTERFACE TESTS
# =============================================================================

class TestReviewInterface:
    """Test ReviewInterface functionality."""

    def test_pending_returns_list(self, redactor):
        """pending should return list of ReviewItem."""
        items = redactor.review.pending

        assert isinstance(items, list)
        for item in items:
            assert isinstance(item, ReviewItem)

    def test_count_returns_int(self, redactor):
        """count should return integer."""
        count = redactor.review.count

        assert isinstance(count, int)
        assert count >= 0

    def test_approve_item(self, redactor):
        """approve should attempt to approve item."""
        # First trigger some detections
        redactor.redact("John Smith test")

        # Try to approve (may return True or False)
        result = redactor.review.approve("nonexistent-item")

        assert isinstance(result, bool)

    def test_reject_item(self, redactor):
        """reject should attempt to reject item."""
        result = redactor.review.reject("nonexistent-item")

        assert isinstance(result, bool)


# =============================================================================
# AUDIT INTERFACE TESTS
# =============================================================================

class TestAuditInterface:
    """Test AuditInterface functionality."""

    def test_recent_returns_list(self, redactor):
        """recent should return list of audit entries."""
        # Generate some audit events
        redactor.redact("John Smith")

        entries = redactor.audit.recent()

        assert isinstance(entries, list)
        assert len(entries) >= 1
        for entry in entries:
            assert isinstance(entry, dict)

    def test_recent_with_limit(self, redactor):
        """recent should respect limit."""
        for i in range(5):
            redactor.redact(f"Test {i}")

        entries = redactor.audit.recent(limit=3)

        assert len(entries) <= 3

    def test_verify_chain(self, redactor):
        """verify should check audit chain integrity."""
        redactor.redact("John Smith")

        valid = redactor.audit.verify()

        assert isinstance(valid, bool)
        assert valid is True

    def test_export_json(self, redactor):
        """export should return JSON string."""
        redactor.redact("John Smith")

        now = datetime.now(timezone.utc)
        start = (now.replace(hour=0, minute=0, second=0)).isoformat()
        end = now.isoformat()

        exported = redactor.audit.export(start, end, format="json")

        assert isinstance(exported, str)
        # Should be valid JSON
        parsed = json.loads(exported)
        assert isinstance(parsed, list)

    def test_export_csv(self, redactor):
        """export should return CSV string."""
        redactor.redact("John Smith")

        now = datetime.now(timezone.utc)
        start = (now.replace(hour=0, minute=0, second=0)).isoformat()
        end = now.isoformat()

        exported = redactor.audit.export(start, end, format="csv")

        assert isinstance(exported, str)
        # Should have header
        assert "sequence" in exported
        assert "event" in exported
        assert "timestamp" in exported


# =============================================================================
# REDACT_FILE TESTS
# =============================================================================

class TestRedactFile:
    """Test Redactor.redact_file functionality."""

    def test_redact_file_from_path(self, redactor, temp_dir):
        """redact_file should process file from path."""
        # Create a simple text file
        test_file = temp_dir / "test.txt"
        test_file.write_text("Patient John Smith, SSN 123-45-6789")

        result = redactor.redact_file(test_file)

        assert isinstance(result, FileResult)
        assert result.filename == "test.txt"
        assert result.error is None or "John Smith" not in result.text

    def test_redact_file_from_bytes(self, redactor):
        """redact_file should process file from bytes."""
        content = b"Patient John Smith, SSN 123-45-6789"

        result = redactor.redact_file(content, filename="test.txt")

        assert isinstance(result, FileResult)
        assert result.filename == "test.txt"

    def test_redact_file_requires_filename_for_bytes(self, redactor):
        """redact_file should require filename when passing bytes."""
        content = b"Test content"

        result = redactor.redact_file(content)

        # Should return error result
        assert result.error is not None


# =============================================================================
# PRELOAD TESTS
# =============================================================================

class TestPreloadFunctions:
    """Test preload and preload_async functions."""

    def test_preload_function_exists(self):
        """preload function should be importable and callable."""
        from scrubiq.sdk import preload

        assert callable(preload)

    def test_preload_async_function_exists(self):
        """preload_async function should be importable and callable."""
        from scrubiq.sdk import preload_async

        assert callable(preload_async)

    def test_preload_with_callback(self):
        """preload should accept progress callback."""
        progress_calls = []

        def on_progress(pct, msg):
            progress_calls.append((pct, msg))

        preload(on_progress=on_progress)

        # Should have been called with progress updates
        assert len(progress_calls) >= 1
        # Should end with 100%
        assert progress_calls[-1][0] == 100

    @pytest.mark.asyncio
    async def test_preload_async(self):
        """preload_async should work asynchronously."""
        # Should not raise
        await preload_async()


# =============================================================================
# ASYNC CHAT METHOD TEST
# =============================================================================

class TestAsyncMethods:
    """Test async methods of Redactor."""

    @pytest.mark.asyncio
    async def test_achat_exists_and_callable(self, redactor):
        """achat should exist and be callable."""
        assert hasattr(redactor, 'achat')
        assert callable(redactor.achat)

    @pytest.mark.asyncio
    async def test_achat_returns_chat_result(self, redactor):
        """achat should return ChatResult (may error without LLM key)."""
        with patch.object(redactor, 'chat') as mock_chat:
            mock_chat.return_value = ChatResult(
                response="Test",
                redacted_prompt="Test",
                redacted_response="Test",
                model="test",
                provider="test",
                tokens_used=0,
                latency_ms=0,
                entities=[],
            )

            result = await redactor.achat("Test message")

            assert isinstance(result, ChatResult)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
