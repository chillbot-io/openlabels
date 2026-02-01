"""Tests for PHI tokenization in tokenizer.py.

Tests token assignment, partial name matching, leakage detection,
and entity-based tokenization (Phase 2).
"""

import sys
import pytest
from unittest.mock import MagicMock, patch

# Mock the storage module before importing tokenizer to avoid SQLCipher dependency
mock_token_store = MagicMock()
sys.modules['scrubiq.storage'] = MagicMock()
sys.modules['scrubiq.storage.tokens'] = MagicMock()
sys.modules['scrubiq.storage.tokens'].TokenStore = mock_token_store

from scrubiq.types import Span, Tier, Entity, Mention
from scrubiq.pipeline.tokenizer import (
    _validate_and_fix_leakage,
    _normalize_name,
    _is_partial_name_match,
    _find_matching_token,
    tokenize,
    tokenize_entities,
    entities_to_spans,
    NAME_TYPES,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test",
              tier=2, safe_harbor_value=None, token=None, coref_anchor_value=None):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        safe_harbor_value=safe_harbor_value or text,
        token=token,
        coref_anchor_value=coref_anchor_value,
    )


class MockTokenStore:
    """Mock TokenStore for testing tokenization logic."""

    def __init__(self):
        self._tokens = {}  # (value, type) -> token
        self._entity_tokens = {}  # entity_id -> token
        self._counter = {}  # entity_type -> count
        self._name_mappings = {}  # token -> (value, type)
        self._variants = []  # list of (entity_id, variant, type)

    def get_or_create(self, value, entity_type, safe_harbor_value=None):
        """Get or create token for (value, entity_type) pair."""
        key = (value.lower(), entity_type)
        if key in self._tokens:
            return self._tokens[key]

        # Create new token
        count = self._counter.get(entity_type, 0) + 1
        self._counter[entity_type] = count

        # Get prefix from entity type
        prefix = entity_type.replace("NAME_", "").replace("_", "")
        token = f"[{prefix}_{count}]"

        self._tokens[key] = token
        if entity_type.startswith("NAME"):
            self._name_mappings[token] = (value, entity_type)

        return token

    def get_name_token_mappings(self):
        """Return all NAME-type token mappings."""
        return self._name_mappings.copy()

    def get_or_create_by_entity(self, entity_id, value, entity_type, safe_harbor_value=None):
        """Get or create token for entity_id."""
        if entity_id in self._entity_tokens:
            return self._entity_tokens[entity_id]

        # Create new token
        count = self._counter.get(entity_type, 0) + 1
        self._counter[entity_type] = count

        prefix = entity_type.replace("NAME_", "").replace("_", "")
        token = f"[{prefix}_{count}]"

        self._entity_tokens[entity_id] = token
        return token

    def register_entity_variant(self, entity_id, variant_value, entity_type):
        """Record variant registration call."""
        self._variants.append((entity_id, variant_value, entity_type))


# =============================================================================
# LEAKAGE DETECTION TESTS
# =============================================================================

class TestValidateAndFixLeakage:
    """Tests for _validate_and_fix_leakage()."""

    def test_no_leakage_unchanged(self):
        """Clean text without leakage passes through unchanged."""
        text = "Hello [NAME_1], your code is [MRN_1]."
        result = _validate_and_fix_leakage(text)
        assert result == text

    def test_leakage_after_token_masked(self):
        """Alphanumeric chars after token are masked with asterisks."""
        text = "Hello [NAME_1]son"
        result = _validate_and_fix_leakage(text)
        assert result == "Hello [NAME_1]***"

    def test_leakage_before_token_masked(self):
        """Alphanumeric chars before token are masked."""
        text = "Joh[NAME_1] is here"
        result = _validate_and_fix_leakage(text)
        assert result == "***[NAME_1] is here"

    def test_possessive_after_token_masked(self):
        """Possessive forms like 's after token are masked."""
        text = "[NAME_1]'s house"
        result = _validate_and_fix_leakage(text)
        assert result == "[NAME_1]** house"

    def test_multiple_leakages_all_fixed(self):
        """Multiple leakages in same text are all fixed."""
        text = "Jo[NAME_1]son and M[DOB_1]"
        result = _validate_and_fix_leakage(text)
        assert result == "**[NAME_1]*** and *[DOB_1]"

    def test_numeric_leakage_masked(self):
        """Numeric characters adjacent to tokens are masked."""
        text = "[MRN_1]789"
        result = _validate_and_fix_leakage(text)
        assert result == "[MRN_1]***"

    def test_space_between_tokens_ok(self):
        """Spaces between tokens don't trigger leakage detection."""
        text = "[NAME_1] [DATE_1] [SSN_1]"
        result = _validate_and_fix_leakage(text)
        assert result == text

    def test_punctuation_after_token_ok(self):
        """Non-alphanumeric punctuation after token is OK."""
        text = "[NAME_1], [DATE_1]. [SSN_1]!"
        result = _validate_and_fix_leakage(text)
        assert result == text


# =============================================================================
# NAME NORMALIZATION TESTS
# =============================================================================

class TestNormalizeName:
    """Tests for _normalize_name()."""

    def test_lowercase(self):
        """Name is lowercased."""
        assert _normalize_name("John Smith") == "john smith"

    def test_strips_whitespace(self):
        """Leading/trailing whitespace is stripped."""
        assert _normalize_name("  John Smith  ") == "john smith"

    def test_preserves_internal_spaces(self):
        """Internal spaces are preserved."""
        assert _normalize_name("John  Paul  Smith") == "john  paul  smith"


# =============================================================================
# PARTIAL NAME MATCHING TESTS
# =============================================================================

class TestIsPartialNameMatch:
    """Tests for _is_partial_name_match()."""

    def test_exact_match(self):
        """Exact names match."""
        assert _is_partial_name_match("John Smith", "John Smith") is True

    def test_case_insensitive(self):
        """Matching is case-insensitive."""
        assert _is_partial_name_match("JOHN SMITH", "john smith") is True

    def test_first_name_matches_full(self):
        """First name matches full name."""
        assert _is_partial_name_match("John", "John Smith") is True

    def test_last_name_matches_full(self):
        """Last name matches full name."""
        assert _is_partial_name_match("Smith", "John Smith") is True

    def test_full_matches_partial(self):
        """Full name matches partial name (symmetric)."""
        assert _is_partial_name_match("John Smith", "Smith") is True

    def test_no_word_overlap(self):
        """Names without word overlap don't match."""
        assert _is_partial_name_match("Johnson", "John Smith") is False

    def test_partial_word_no_match(self):
        """Partial word matches don't count."""
        assert _is_partial_name_match("Jo", "John") is False

    def test_different_names(self):
        """Completely different names don't match."""
        assert _is_partial_name_match("Alice Brown", "John Smith") is False

    def test_middle_name_match(self):
        """Middle name can create match."""
        assert _is_partial_name_match("Paul", "John Paul Smith") is True


# =============================================================================
# FIND MATCHING TOKEN TESTS
# =============================================================================

class TestFindMatchingToken:
    """Tests for _find_matching_token()."""

    def test_exact_match_found(self):
        """Exact match returns existing token."""
        existing = {("john smith", "NAME"): "[NAME_1]"}
        value_for_token = {"[NAME_1]": "john smith"}

        result = _find_matching_token("John Smith", "NAME", existing, value_for_token)
        assert result == "[NAME_1]"

    def test_partial_name_match_found(self):
        """Partial name match returns existing token."""
        existing = {("john smith", "NAME"): "[NAME_1]"}
        value_for_token = {"[NAME_1]": "john smith"}

        result = _find_matching_token("Smith", "NAME", existing, value_for_token)
        assert result == "[NAME_1]"

    def test_non_name_type_exact_only(self):
        """Non-NAME types require exact match."""
        existing = {("123-45-6789", "SSN"): "[SSN_1]"}
        value_for_token = {"[SSN_1]": "123-45-6789"}

        # Exact match works
        result = _find_matching_token("123-45-6789", "SSN", existing, value_for_token)
        assert result == "[SSN_1]"

        # Partial doesn't match for SSN
        result = _find_matching_token("6789", "SSN", existing, value_for_token)
        assert result is None

    def test_no_match_returns_none(self):
        """No match returns None."""
        existing = {("john smith", "NAME"): "[NAME_1]"}
        value_for_token = {"[NAME_1]": "john smith"}

        result = _find_matching_token("Alice Brown", "NAME", existing, value_for_token)
        assert result is None

    def test_name_patient_partial_match(self):
        """NAME_PATIENT also supports partial matching."""
        existing = {("dr. jones", "NAME_PROVIDER"): "[PROVIDER_1]"}
        value_for_token = {"[PROVIDER_1]": "dr. jones"}

        result = _find_matching_token("Jones", "NAME_PROVIDER", existing, value_for_token)
        assert result == "[PROVIDER_1]"


# =============================================================================
# TOKENIZE FUNCTION TESTS
# =============================================================================

class TestTokenize:
    """Tests for tokenize()."""

    def test_empty_spans_returns_text(self):
        """Empty span list returns original text."""
        store = MockTokenStore()
        text = "Hello world"

        result_text, result_spans = tokenize(text, [], store)

        assert result_text == text
        assert result_spans == []

    def test_single_span_tokenized(self):
        """Single span is replaced with token."""
        store = MockTokenStore()
        text = "Hello John Smith, how are you?"
        span = make_span("John Smith", start=6, entity_type="NAME")

        result_text, result_spans = tokenize(text, [span], store)

        assert "[NAME_1]" in result_text
        assert "John Smith" not in result_text
        assert result_spans[0].token == "[NAME_1]"

    def test_multiple_spans_tokenized(self):
        """Multiple spans are replaced with tokens."""
        store = MockTokenStore()
        text = "John Smith's SSN is 123-45-6789"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("123-45-6789", start=20, entity_type="SSN"),
        ]

        result_text, result_spans = tokenize(text, spans, store)

        assert "[NAME_1]" in result_text
        assert "[SSN_1]" in result_text
        assert "John Smith" not in result_text
        assert "123-45-6789" not in result_text

    def test_same_value_same_token(self):
        """Same value gets same token (deduplication)."""
        store = MockTokenStore()
        text = "John said hello. Then John left."
        spans = [
            make_span("John", start=0, entity_type="NAME"),
            make_span("John", start=22, entity_type="NAME"),
        ]

        result_text, result_spans = tokenize(text, spans, store)

        # Both should have same token
        assert result_spans[0].token == result_spans[1].token
        # Should only be one token number
        assert result_text.count("[NAME_1]") == 2

    def test_tokens_assigned_in_text_order(self):
        """First occurrence in text gets lower token number."""
        store = MockTokenStore()
        text = "Alice met Bob then Carol"
        spans = [
            make_span("Alice", start=0, entity_type="NAME"),
            make_span("Bob", start=10, entity_type="NAME"),
            make_span("Carol", start=19, entity_type="NAME"),
        ]

        result_text, result_spans = tokenize(text, spans, store)

        # Tokens should be assigned in text order
        assert result_spans[0].token == "[NAME_1]"  # Alice
        assert result_spans[1].token == "[NAME_2]"  # Bob
        assert result_spans[2].token == "[NAME_3]"  # Carol

    def test_partial_name_gets_same_token(self):
        """Partial name like "Smith" gets same token as "John Smith"."""
        store = MockTokenStore()
        text = "John Smith is here. Smith left."
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Smith", start=20, entity_type="NAME"),
        ]

        result_text, result_spans = tokenize(text, spans, store)

        # Smith should get same token as John Smith
        assert result_spans[0].token == result_spans[1].token

    def test_coref_anchor_value_used(self):
        """Coref anchor value is used for token lookup."""
        store = MockTokenStore()
        text = "John said he would go"
        spans = [
            make_span("John", start=0, entity_type="NAME"),
            make_span("he", start=10, entity_type="NAME", coref_anchor_value="John"),
        ]

        result_text, result_spans = tokenize(text, spans, store)

        # "he" should get same token as "John" via coref anchor
        assert result_spans[0].token == result_spans[1].token

    def test_leakage_after_replacement_fixed(self):
        """Leakage introduced during replacement is fixed."""
        store = MockTokenStore()
        # Span boundary issue - span doesn't include 'son' suffix
        text = "Johnson is here"
        span = make_span("John", start=0, entity_type="NAME")  # Missing 'son'

        result_text, _ = tokenize(text, [span], store)

        # The 'son' should be masked, not left as plaintext
        assert "son" not in result_text or "[NAME_1]***" in result_text


class TestTokenizePreservesSafeHarborValue:
    """Tests that safe_harbor_value is preserved through tokenization."""

    def test_safe_harbor_value_preserved(self):
        """Safe harbor value on span is preserved."""
        store = MockTokenStore()
        text = "DOB: 03/15/1985"
        span = make_span("03/15/1985", start=5, entity_type="DATE", safe_harbor_value="1985")

        _, result_spans = tokenize(text, [span], store)

        assert result_spans[0].safe_harbor_value == "1985"


# =============================================================================
# ENTITY-BASED TOKENIZATION TESTS (PHASE 2)
# =============================================================================

class TestTokenizeEntities:
    """Tests for tokenize_entities() - Phase 2 entity-based tokenization."""

    def make_entity(self, entity_id, entity_type, canonical_value, mentions_data):
        """Helper to create Entity with Mentions."""
        entity = Entity(
            id=entity_id,
            entity_type=entity_type,
            canonical_value=canonical_value,
        )
        for text, start in mentions_data:
            span = make_span(text, start=start, entity_type=entity_type)
            mention = Mention(span=span)
            entity.add_mention(mention)
        return entity

    def test_empty_entities_returns_text(self):
        """Empty entity list returns original text."""
        store = MockTokenStore()
        text = "Hello world"

        result_text, result_spans = tokenize_entities(text, [], store)

        assert result_text == text
        assert result_spans == []

    def test_single_entity_single_mention(self):
        """Single entity with one mention is tokenized."""
        store = MockTokenStore()
        text = "Hello John Smith"
        entity = self.make_entity("e1", "NAME", "John Smith", [("John Smith", 6)])

        result_text, result_spans = tokenize_entities(text, [entity], store)

        assert "John Smith" not in result_text
        assert "[NAME_1]" in result_text
        assert len(result_spans) == 1
        assert result_spans[0].token == "[NAME_1]"

    def test_entity_multiple_mentions_same_token(self):
        """Multiple mentions of same entity get same token."""
        store = MockTokenStore()
        text = "John Smith is here. Smith left."
        entity = self.make_entity(
            "e1", "NAME", "John Smith",
            [("John Smith", 0), ("Smith", 20)]
        )

        result_text, result_spans = tokenize_entities(text, [entity], store)

        # Both mentions should have same token
        assert result_spans[0].token == result_spans[1].token == "[NAME_1]"
        assert result_text.count("[NAME_1]") == 2

    def test_multiple_entities_different_tokens(self):
        """Different entities get different tokens."""
        store = MockTokenStore()
        text = "John met Alice today"
        entity1 = self.make_entity("e1", "NAME", "John", [("John", 0)])
        entity2 = self.make_entity("e2", "NAME", "Alice", [("Alice", 10)])

        result_text, result_spans = tokenize_entities(text, [entity1, entity2], store)

        # Different entities = different tokens
        tokens = {s.token for s in result_spans}
        assert len(tokens) == 2

    def test_entity_id_is_key_not_type(self):
        """Same person with different semantic roles gets same token (entity_id is key)."""
        store = MockTokenStore()
        text = "Dr. John (patient) and Dr. John (provider)"
        # Same entity_id = same real person
        entity = self.make_entity(
            "same-person", "NAME", "Dr. John",
            [("Dr. John", 0), ("Dr. John", 24)]
        )

        result_text, result_spans = tokenize_entities(text, [entity], store)

        # Same entity_id → same token regardless of context
        assert result_spans[0].token == result_spans[1].token

    def test_variants_registered(self):
        """Variant values are registered with store."""
        store = MockTokenStore()
        text = "John Smith and Smith"
        entity = self.make_entity(
            "e1", "NAME", "John Smith",
            [("John Smith", 0), ("Smith", 15)]
        )

        tokenize_entities(text, [entity], store)

        # "Smith" should be registered as variant
        assert ("e1", "Smith", "NAME") in store._variants

    def test_safe_harbor_from_mention(self):
        """Safe harbor value is extracted from mentions."""
        store = MockTokenStore()
        text = "DOB: 03/15/1985"
        span = make_span("03/15/1985", start=5, entity_type="DATE", safe_harbor_value="1985")
        entity = Entity(id="e1", entity_type="DATE", canonical_value="03/15/1985")
        mention = Mention(span=span)
        entity.add_mention(mention)

        _, result_spans = tokenize_entities(text, [entity], store)

        # Safe harbor value should be preserved
        assert result_spans[0].safe_harbor_value == "1985"


# =============================================================================
# ENTITIES TO SPANS UTILITY
# =============================================================================

class TestEntitiesToSpans:
    """Tests for entities_to_spans() utility."""

    def test_extracts_all_spans(self):
        """Extracts spans from all entities."""
        entity1 = Entity(id="e1", entity_type="NAME", canonical_value="John")
        entity1.add_mention(Mention(span=make_span("John", start=0)))

        entity2 = Entity(id="e2", entity_type="SSN", canonical_value="123-45-6789")
        entity2.add_mention(Mention(span=make_span("123-45-6789", start=10)))

        result = entities_to_spans([entity1, entity2])

        assert len(result) == 2

    def test_sorted_by_position(self):
        """Result is sorted by start position."""
        entity = Entity(id="e1", entity_type="NAME", canonical_value="John")
        entity.add_mention(Mention(span=make_span("John", start=20)))
        entity.add_mention(Mention(span=make_span("John", start=5)))

        result = entities_to_spans([entity])

        assert result[0].start == 5
        assert result[1].start == 20

    def test_empty_entities_returns_empty(self):
        """Empty entity list returns empty span list."""
        result = entities_to_spans([])
        assert result == []


# =============================================================================
# NAME_TYPES CONSTANT
# =============================================================================

class TestNameTypesConstant:
    """Tests for NAME_TYPES constant."""

    def test_contains_expected_types(self):
        """NAME_TYPES contains expected entity types."""
        assert "NAME" in NAME_TYPES
        assert "NAME_PATIENT" in NAME_TYPES
        assert "NAME_PROVIDER" in NAME_TYPES
        assert "NAME_RELATIVE" in NAME_TYPES

    def test_does_not_contain_non_names(self):
        """NAME_TYPES doesn't contain non-name types."""
        assert "SSN" not in NAME_TYPES
        assert "DATE" not in NAME_TYPES
        assert "MRN" not in NAME_TYPES


# =============================================================================
# EDGE CASES AND ERROR HANDLING
# =============================================================================

class TestEdgeCases:
    """Edge cases and error handling."""

    def test_unicode_names_handled(self):
        """Unicode characters in names are handled."""
        store = MockTokenStore()
        text = "Hello José García"
        span = make_span("José García", start=6, entity_type="NAME")

        result_text, result_spans = tokenize(text, [span], store)

        assert "José García" not in result_text
        assert result_spans[0].token is not None

    def test_empty_text_with_spans(self):
        """Empty text with no spans works."""
        store = MockTokenStore()
        text = ""

        result_text, result_spans = tokenize(text, [], store)

        assert result_text == ""
        assert result_spans == []

    def test_overlapping_token_format(self):
        """Token format is consistent [TYPE_N]."""
        store = MockTokenStore()
        text = "John Smith at 123 Main St"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("123 Main St", start=14, entity_type="ADDRESS"),
        ]

        _, result_spans = tokenize(text, spans, store)

        # Tokens match expected format
        for span in result_spans:
            assert span.token.startswith("[")
            assert span.token.endswith("]")
            assert "_" in span.token


class TestCrossMessageNameMatching:
    """Tests for cross-message partial name matching."""

    def test_preloaded_names_enable_partial_match(self):
        """Pre-loaded NAME tokens enable cross-message partial matching."""
        store = MockTokenStore()

        # Simulate message 1: "John Smith"
        text1 = "Hello John Smith"
        span1 = make_span("John Smith", start=6, entity_type="NAME")
        tokenize(text1, [span1], store)

        # Message 2: just "Smith" should match
        text2 = "Smith called"
        span2 = make_span("Smith", start=0, entity_type="NAME")
        _, result_spans = tokenize(text2, [span2], store)

        # Should reuse NAME_1 from previous message
        assert result_spans[0].token == "[NAME_1]"

    def test_different_entities_different_tokens(self):
        """Different entities across messages get different tokens."""
        store = MockTokenStore()

        # Message 1: John
        text1 = "Hello John"
        span1 = make_span("John", start=6, entity_type="NAME")
        tokenize(text1, [span1], store)

        # Message 2: Alice (different person)
        text2 = "Hello Alice"
        span2 = make_span("Alice", start=6, entity_type="NAME")
        _, result_spans = tokenize(text2, [span2], store)

        # Alice should get different token
        assert result_spans[0].token == "[NAME_2]"
