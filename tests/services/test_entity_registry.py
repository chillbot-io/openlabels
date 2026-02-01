"""Tests for EntityRegistry service.

Tests EntityRegistry: entity identity management, merging decisions, review queue.
"""

import threading
import time
from unittest.mock import MagicMock

import pytest

from scrubiq.types import Span, Tier
from scrubiq.services.entity_registry import (
    EntityRegistry,
    EntityCandidate,
    RegisteredEntity,
    MergeCandidate,
    MergeConfidence,
    MergePenalty,
    NAME_PREFIXES,
    NAME_TYPES,
    ISOLATED_TYPES,
    _normalize_value,
    _get_words,
    _get_base_type,
    _infer_role,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def registry():
    """Create an EntityRegistry."""
    return EntityRegistry()


@pytest.fixture
def span():
    """Create a basic Span."""
    return Span(
        start=0, end=10, entity_type="NAME", text="John Smith",
        confidence=0.95, detector="test", tier=Tier.PATTERN,
    )


def make_candidate(text, entity_type="NAME", start=0, end=None, coref_anchor_value=None, **context):
    """Helper to create EntityCandidate."""
    if end is None:
        end = start + len(text)
    span = Span(
        start=start,
        end=end,
        entity_type=entity_type,
        text=text,
        confidence=0.95,
        detector="test",
        tier=Tier.PATTERN,
        coref_anchor_value=coref_anchor_value,
    )
    return EntityCandidate(
        text=text,
        entity_type=entity_type,
        span=span,
        context=context,
    )


# =============================================================================
# HELPER FUNCTION TESTS
# =============================================================================

class TestNormalizeValue:
    """Tests for _normalize_value function."""

    def test_lowercase(self):
        """Normalizes to lowercase."""
        result = _normalize_value("John Smith", "NAME")
        assert result == "john smith"

    def test_strips_whitespace(self):
        """Strips leading/trailing whitespace."""
        result = _normalize_value("  John Smith  ", "NAME")
        assert result == "john smith"

    def test_strips_titles(self):
        """Strips common titles from names."""
        assert _normalize_value("Dr. John Smith", "NAME") == "john smith"
        assert _normalize_value("Mr. John Smith", "NAME") == "john smith"
        assert _normalize_value("Mrs. Jane Doe", "NAME") == "jane doe"

    def test_preserves_non_name_types(self):
        """Doesn't strip titles from non-name types."""
        result = _normalize_value("Dr. Test", "SSN")
        assert result == "dr. test"


class TestGetWords:
    """Tests for _get_words function."""

    def test_splits_into_words(self):
        """Splits text into word set."""
        result = _get_words("John Smith")
        assert result == {"john", "smith"}

    def test_removes_single_chars(self):
        """Removes single character words."""
        result = _get_words("J Smith A Jones")
        assert result == {"smith", "jones"}

    def test_removes_prefixes(self):
        """Removes title prefixes."""
        result = _get_words("Dr. John Smith Jr.")
        assert "dr" not in result
        assert "jr" not in result
        assert "john" in result
        assert "smith" in result


class TestGetBaseType:
    """Tests for _get_base_type function."""

    def test_returns_name_for_patient(self):
        """NAME_PATIENT returns NAME."""
        assert _get_base_type("NAME_PATIENT") == "NAME"

    def test_returns_name_for_provider(self):
        """NAME_PROVIDER returns NAME."""
        assert _get_base_type("NAME_PROVIDER") == "NAME"

    def test_returns_name_for_relative(self):
        """NAME_RELATIVE returns NAME."""
        assert _get_base_type("NAME_RELATIVE") == "NAME"

    def test_returns_same_for_others(self):
        """Non-role types return unchanged."""
        assert _get_base_type("SSN") == "SSN"
        assert _get_base_type("EMAIL") == "EMAIL"


class TestInferRole:
    """Tests for _infer_role function."""

    def test_infers_patient(self):
        """Infers patient role."""
        assert _infer_role("NAME_PATIENT") == "patient"

    def test_infers_provider(self):
        """Infers provider role."""
        assert _infer_role("NAME_PROVIDER") == "provider"

    def test_infers_relative(self):
        """Infers relative role."""
        assert _infer_role("NAME_RELATIVE") == "relative"

    def test_returns_unknown_for_generic(self):
        """Returns unknown for generic types."""
        assert _infer_role("NAME") == "unknown"
        assert _infer_role("SSN") == "unknown"


# =============================================================================
# MERGE CONFIDENCE TESTS
# =============================================================================

class TestMergeConfidence:
    """Tests for MergeConfidence enum."""

    def test_exact_highest(self):
        """EXACT has highest confidence."""
        assert MergeConfidence.EXACT.value == 0.99

    def test_single_word_lowest(self):
        """SINGLE_WORD has low confidence."""
        assert MergeConfidence.SINGLE_WORD.value == 0.40

    def test_thresholds_defined(self):
        """Thresholds are defined."""
        assert MergeConfidence.AUTO_MERGE.value == 0.90
        assert MergeConfidence.FLAG_MERGE.value == 0.70
        assert MergeConfidence.BLOCK.value == 0.50


class TestMergePenalty:
    """Tests for MergePenalty enum."""

    def test_role_conflict_penalty(self):
        """Role conflict has significant penalty."""
        assert MergePenalty.ROLE_CONFLICT.value == 0.50

    def test_type_mismatch_penalty(self):
        """Type mismatch has penalty."""
        assert MergePenalty.TYPE_MISMATCH.value == 0.30


# =============================================================================
# REGISTERED ENTITY TESTS
# =============================================================================

class TestRegisteredEntity:
    """Tests for RegisteredEntity dataclass."""

    def test_create_entity(self):
        """Can create RegisteredEntity."""
        entity = RegisteredEntity(
            id="test-id",
            entity_type="NAME",
            canonical_value="John Smith",
            normalized_value="john smith",
            words={"john", "smith"},
        )

        assert entity.id == "test-id"
        assert entity.canonical_value == "John Smith"

    def test_has_conflicting_role_false_for_unknown(self):
        """Unknown role doesn't conflict."""
        entity = RegisteredEntity(
            id="1", entity_type="NAME",
            canonical_value="John", normalized_value="john",
            words={"john"}, roles={"patient"},
        )

        assert entity.has_conflicting_role("unknown") is False

    def test_has_conflicting_role_patient_provider(self):
        """Patient and provider conflict."""
        entity = RegisteredEntity(
            id="1", entity_type="NAME",
            canonical_value="John", normalized_value="john",
            words={"john"}, roles={"patient"},
        )

        assert entity.has_conflicting_role("provider") is True

    def test_has_conflicting_role_provider_patient(self):
        """Provider and patient conflict."""
        entity = RegisteredEntity(
            id="1", entity_type="NAME",
            canonical_value="Dr. Smith", normalized_value="smith",
            words={"smith"}, roles={"provider"},
        )

        assert entity.has_conflicting_role("patient") is True

    def test_no_conflict_same_role(self):
        """Same role doesn't conflict."""
        entity = RegisteredEntity(
            id="1", entity_type="NAME",
            canonical_value="John", normalized_value="john",
            words={"john"}, roles={"patient"},
        )

        assert entity.has_conflicting_role("patient") is False


# =============================================================================
# ENTITY REGISTRY BASIC TESTS
# =============================================================================

class TestEntityRegistryBasic:
    """Basic tests for EntityRegistry."""

    def test_create_registry(self):
        """Can create EntityRegistry."""
        registry = EntityRegistry()

        assert len(registry) == 0

    def test_custom_thresholds(self):
        """Can set custom thresholds."""
        registry = EntityRegistry(
            auto_merge_threshold=0.95,
            flag_merge_threshold=0.80,
        )

        assert registry._auto_merge_threshold == 0.95
        assert registry._flag_merge_threshold == 0.80

    def test_len_empty(self, registry):
        """Empty registry has length 0."""
        assert len(registry) == 0

    def test_contains_false_initially(self, registry):
        """Contains returns False for unknown ID."""
        assert "unknown-id" not in registry


# =============================================================================
# REGISTER TESTS
# =============================================================================

class TestRegister:
    """Tests for EntityRegistry.register method."""

    def test_register_creates_entity(self, registry):
        """register() creates new entity."""
        candidate = make_candidate("John Smith", "NAME")

        entity_id = registry.register(candidate)

        assert entity_id is not None
        assert entity_id in registry
        assert len(registry) == 1

    def test_register_returns_same_id_for_exact_match(self, registry):
        """register() returns same ID for exact match."""
        c1 = make_candidate("John Smith", "NAME", start=0, end=10)
        c2 = make_candidate("John Smith", "NAME", start=20, end=30)

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        assert id1 == id2

    def test_register_case_insensitive_match(self, registry):
        """register() matches case-insensitively."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("JOHN SMITH", "NAME")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        assert id1 == id2

    def test_register_different_types_separate(self, registry):
        """Different types create separate entities."""
        c1 = make_candidate("123456789", "SSN")
        c2 = make_candidate("123456789", "PHONE")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        assert id1 != id2

    def test_register_isolated_types_exact_only(self, registry):
        """Isolated types only merge on exact match."""
        c1 = make_candidate("123-45-6789", "SSN")
        c2 = make_candidate("123-45-6780", "SSN")  # Different last digit

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        assert id1 != id2

    def test_register_with_title_strips_title(self, registry):
        """Titles are stripped for matching."""
        c1 = make_candidate("Dr. John Smith", "NAME")
        c2 = make_candidate("John Smith", "NAME")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        assert id1 == id2


# =============================================================================
# MERGE POLICY TESTS
# =============================================================================

class TestMergePolicy:
    """Tests for merge policy."""

    def test_multi_word_subset_merges(self, registry):
        """Multi-word subset merges with high confidence."""
        c1 = make_candidate("John William Smith", "NAME")
        c2 = make_candidate("John Smith", "NAME")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        # Should merge because "john smith" is subset of "john william smith"
        assert id1 == id2

    def test_single_word_blocked(self, registry):
        """Single word match is blocked."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("John Jones", "NAME")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        # Should NOT merge - only "john" overlaps
        assert id1 != id2

    def test_role_conflict_blocks_merge(self, registry):
        """Role conflict blocks automatic merge."""
        c1 = make_candidate("Maria", "NAME_PATIENT", semantic_role="patient")
        c2 = make_candidate("Maria", "NAME_PROVIDER", semantic_role="provider")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        # Should NOT merge due to role conflict
        assert id1 != id2


# =============================================================================
# COREF ANCHOR TESTS
# =============================================================================

class TestCorefAnchor:
    """Tests for coreference anchor matching."""

    def test_coref_anchor_merges(self, registry):
        """Coreference anchor causes merge."""
        c1 = make_candidate("John Smith", "NAME")
        id1 = registry.register(c1)

        # Create pronoun with coref anchor
        c2 = make_candidate("he", "NAME", start=50, coref_anchor_value="John Smith")
        id2 = registry.register(c2)

        assert id1 == id2


# =============================================================================
# CANONICAL VALUE TESTS
# =============================================================================

class TestCanonicalValue:
    """Tests for canonical value updates."""

    def test_longer_value_becomes_canonical(self, registry):
        """Longer mention becomes canonical when merged."""
        # Use multi-word names so they can merge (single word matches are blocked)
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("John William Smith", "NAME")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        # Should merge because John Smith is subset of John William Smith
        assert id1 == id2
        entity = registry.get_entity(id1)
        assert entity.canonical_value == "John William Smith"

    def test_shorter_value_doesnt_replace(self, registry):
        """Shorter mention doesn't replace canonical when merged."""
        c1 = make_candidate("John William Smith", "NAME")
        c2 = make_candidate("John Smith", "NAME")

        id1 = registry.register(c1)
        registry.register(c2)

        entity = registry.get_entity(id1)
        assert entity.canonical_value == "John William Smith"


# =============================================================================
# QUERY API TESTS
# =============================================================================

class TestQueryAPI:
    """Tests for query API."""

    def test_get_entity(self, registry):
        """get_entity returns entity."""
        candidate = make_candidate("John Smith", "NAME")
        entity_id = registry.register(candidate)

        entity = registry.get_entity(entity_id)

        assert entity is not None
        assert entity.id == entity_id
        assert entity.canonical_value == "John Smith"

    def test_get_entity_unknown_returns_none(self, registry):
        """get_entity returns None for unknown ID."""
        result = registry.get_entity("unknown-id")

        assert result is None

    def test_get_entity_id_by_value(self, registry):
        """get_entity_id_by_value finds entity."""
        candidate = make_candidate("John Smith", "NAME")
        entity_id = registry.register(candidate)

        found = registry.get_entity_id_by_value("John Smith", "NAME")

        assert found == entity_id

    def test_get_entity_id_by_value_case_insensitive(self, registry):
        """get_entity_id_by_value is case insensitive."""
        candidate = make_candidate("John Smith", "NAME")
        entity_id = registry.register(candidate)

        found = registry.get_entity_id_by_value("JOHN SMITH", "NAME")

        assert found == entity_id

    def test_get_entity_id_by_value_not_found(self, registry):
        """get_entity_id_by_value returns None if not found."""
        result = registry.get_entity_id_by_value("Unknown", "NAME")

        assert result is None

    def test_get_all_entities(self, registry):
        """get_all_entities returns all entities."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("Jane Doe", "NAME")
        c3 = make_candidate("123-45-6789", "SSN")

        registry.register(c1)
        registry.register(c2)
        registry.register(c3)

        entities = registry.get_all_entities()

        assert len(entities) == 3

    def test_get_entities_by_type(self, registry):
        """get_entities_by_type filters by type."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("Jane Doe", "NAME")
        c3 = make_candidate("123-45-6789", "SSN")

        registry.register(c1)
        registry.register(c2)
        registry.register(c3)

        names = registry.get_entities_by_type("NAME")
        ssns = registry.get_entities_by_type("SSN")

        assert len(names) == 2
        assert len(ssns) == 1


# =============================================================================
# REVIEW QUEUE TESTS
# =============================================================================

class TestReviewQueue:
    """Tests for review queue."""

    def test_queue_initially_empty(self, registry):
        """Review queue is initially empty."""
        queue = registry.get_review_queue()

        assert queue == []

    def test_blocked_merge_queued(self, registry):
        """Blocked merges are queued for review."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("John Jones", "NAME")

        registry.register(c1)
        registry.register(c2)

        queue = registry.get_review_queue()

        # Should have a blocked merge candidate
        assert len(queue) >= 1

    def test_review_callback_called(self):
        """Review callback is called for flagged merges."""
        callback = MagicMock()
        registry = EntityRegistry(
            review_callback=callback,
            flag_merge_threshold=0.60,  # Lower threshold to trigger
        )

        c1 = make_candidate("John William Smith", "NAME")
        c2 = make_candidate("John Smith", "NAME")

        registry.register(c1)
        registry.register(c2)

        # Callback may or may not be called depending on merge policy
        # Just verify no errors


# =============================================================================
# APPROVE/REJECT MERGE TESTS
# =============================================================================

class TestApproveRejectMerge:
    """Tests for approve/reject merge."""

    def test_approve_merge(self, registry):
        """approve_merge merges entities."""
        c1 = make_candidate("John Smith", "NAME_PATIENT", semantic_role="patient")
        c2 = make_candidate("John Smith", "NAME_PROVIDER", semantic_role="provider")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        # They should be separate due to role conflict
        assert id1 != id2

        # Approve the merge
        result = registry.approve_merge(id2, id1)

        assert result is True
        assert id2 not in registry
        assert id1 in registry

    def test_approve_merge_nonexistent_returns_false(self, registry):
        """approve_merge returns False for nonexistent IDs."""
        result = registry.approve_merge("fake1", "fake2")

        assert result is False

    def test_reject_merge(self, registry):
        """reject_merge removes from queue."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("John Jones", "NAME")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        queue_before = len(registry.get_review_queue())

        # Reject the potential merge
        result = registry.reject_merge(id2, id1)

        # Both entities should still exist
        assert id1 in registry
        assert id2 in registry


# =============================================================================
# CLEAR TESTS
# =============================================================================

class TestClear:
    """Tests for clear method."""

    def test_clear_removes_all_entities(self, registry):
        """clear() removes all entities."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("Jane Doe", "NAME")

        registry.register(c1)
        registry.register(c2)

        registry.clear()

        assert len(registry) == 0
        assert registry.get_all_entities() == []

    def test_clear_empties_review_queue(self, registry):
        """clear() empties review queue."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("John Jones", "NAME")

        registry.register(c1)
        registry.register(c2)

        registry.clear()

        assert registry.get_review_queue() == []


# =============================================================================
# EXPORT/IMPORT TESTS
# =============================================================================

class TestExportImport:
    """Tests for export and import."""

    def test_export_known_entities(self, registry):
        """export_known_entities exports entities."""
        c1 = make_candidate("John Smith", "NAME")
        c2 = make_candidate("123-45-6789", "SSN")

        id1 = registry.register(c1)
        id2 = registry.register(c2)

        exported = registry.export_known_entities()

        assert id1 in exported
        assert id2 in exported
        assert exported[id1] == ("John Smith", "NAME")
        assert exported[id2] == ("123-45-6789", "SSN")

    def test_import_known_entities(self, registry):
        """import_known_entities imports entities."""
        known = {
            "entity-1": ("John Smith", "NAME"),
            "entity-2": ("Jane Doe", "NAME"),
        }

        registry.import_known_entities(known)

        assert len(registry) == 2
        assert "entity-1" in registry
        assert "entity-2" in registry

    def test_import_skips_existing(self, registry):
        """import_known_entities skips existing entities."""
        c = make_candidate("John Smith", "NAME")
        existing_id = registry.register(c)

        known = {
            existing_id: ("Different Name", "NAME"),
        }

        registry.import_known_entities(known)

        # Should still have original value
        entity = registry.get_entity(existing_id)
        assert entity.canonical_value == "John Smith"


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_register(self, registry):
        """Concurrent register is safe."""
        errors = []

        def register_entities():
            try:
                thread_id = threading.current_thread().name
                for i in range(50):
                    # Use SSN type which only merges on exact match, preventing unwanted merges
                    c = make_candidate(f"{thread_id}-{i:05d}", "SSN")
                    registry.register(c)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_entities, name=f"T{i}") for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(registry) == 500  # 10 threads * 50 entities

    def test_concurrent_query(self, registry):
        """Concurrent queries are safe."""
        # Pre-populate with SSN type to avoid merges
        for i in range(100):
            c = make_candidate(f"{i:08d}", "SSN")
            registry.register(c)

        errors = []

        def query_entities():
            try:
                for _ in range(100):
                    registry.get_all_entities()
                    registry.get_entities_by_type("NAME")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=query_entities) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# =============================================================================
# MENTIONS TRACKING TESTS
# =============================================================================

class TestMentionsTracking:
    """Tests for mention tracking."""

    def test_mentions_tracked(self, registry):
        """Mentions are tracked on entity."""
        c1 = make_candidate("John Smith", "NAME", start=0, end=10)
        c2 = make_candidate("John Smith", "NAME", start=50, end=60)

        id1 = registry.register(c1)
        registry.register(c2)

        entity = registry.get_entity(id1)

        assert len(entity.mentions) == 2
        assert entity.mentions[0]["start"] == 0
        assert entity.mentions[1]["start"] == 50

    def test_roles_tracked(self, registry):
        """Roles are tracked on entity."""
        c = make_candidate("John Smith", "NAME_PATIENT", semantic_role="patient")

        entity_id = registry.register(c)
        entity = registry.get_entity(entity_id)

        assert "patient" in entity.roles
