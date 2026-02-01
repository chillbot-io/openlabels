"""Tests for Review module - human review queue for uncertain detections.

Tests the ReviewQueue class used for PHI handling and review workflow.
"""

import importlib.util
import sys
from datetime import datetime
from pathlib import Path

import pytest

# Import types first (no relative imports)
_types_path = Path(__file__).parent.parent.parent / "scrubiq" / "types.py"
_types_spec = importlib.util.spec_from_file_location("scrubiq.types", _types_path)
_types_module = importlib.util.module_from_spec(_types_spec)
sys.modules["scrubiq.types"] = _types_module
_types_spec.loader.exec_module(_types_module)

Span = _types_module.Span
ReviewItem = _types_module.ReviewItem
ReviewReason = _types_module.ReviewReason
Tier = _types_module.Tier

# Create a mock parent package for relative imports
class MockScrubiq:
    types = _types_module

sys.modules["scrubiq"] = MockScrubiq()

# Now import the review module
_review_path = Path(__file__).parent.parent.parent / "scrubiq" / "review" / "__init__.py"
_spec = importlib.util.spec_from_file_location("scrubiq.review", _review_path)
_review_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_review_module)

ReviewQueue = _review_module.ReviewQueue


# =============================================================================
# REVIEW QUEUE INITIALIZATION TESTS
# =============================================================================

class TestReviewQueueInit:
    """Tests for ReviewQueue initialization."""

    def test_default_threshold(self):
        """Default confidence threshold is 0.95."""
        queue = ReviewQueue()
        assert queue.threshold == 0.95

    def test_custom_threshold(self):
        """Custom confidence threshold is stored."""
        queue = ReviewQueue(confidence_threshold=0.8)
        assert queue.threshold == 0.8

    def test_starts_empty(self):
        """Queue starts empty."""
        queue = ReviewQueue()
        assert len(queue) == 0
        assert queue.get_pending() == []


# =============================================================================
# REVIEW QUEUE ID GENERATION TESTS
# =============================================================================

class TestReviewQueueIdGeneration:
    """Tests for unique ID generation."""

    def test_generates_unique_ids(self):
        """Generated IDs are unique."""
        queue = ReviewQueue()
        ids = set()

        for _ in range(100):
            new_id = queue._generate_id()
            assert new_id not in ids, f"Duplicate ID generated: {new_id}"
            ids.add(new_id)

    def test_id_format_is_uuid(self):
        """Generated IDs are full UUIDs."""
        queue = ReviewQueue()
        new_id = queue._generate_id()

        # UUID format: 8-4-4-4-12 hex chars with dashes
        parts = new_id.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12


# =============================================================================
# CHECK SPAN TESTS
# =============================================================================

class TestReviewQueueCheckSpan:
    """Tests for check_span method."""

    @pytest.fixture
    def queue(self):
        """Create a test queue with default threshold."""
        return ReviewQueue(confidence_threshold=0.95)

    @pytest.fixture
    def low_confidence_span(self):
        """Create a low confidence span."""
        return Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.7,
            detector="ml",
            tier=Tier.ML,
        )

    @pytest.fixture
    def high_confidence_span(self):
        """Create a high confidence span."""
        return Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.99,
            detector="pattern",
            tier=Tier.PATTERN,
        )

    def test_null_span_returns_none(self, queue):
        """check_span returns None for null span."""
        result = queue.check_span(None, "test text")
        assert result is None

    def test_null_text_returns_none(self, queue, low_confidence_span):
        """check_span returns None for null text."""
        result = queue.check_span(low_confidence_span, None)
        assert result is None

    def test_low_confidence_flagged(self, queue):
        """Low confidence spans are flagged for review."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.7,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "John Smith lives in NYC")

        assert result is not None
        assert isinstance(result, ReviewItem)
        assert result.reason == ReviewReason.LOW_CONFIDENCE

    def test_very_low_confidence_suggests_review(self, queue):
        """Very low confidence (<0.70) suggests review action."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.6,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "John Smith lives here")

        assert result is not None
        assert result.suggested_action == "review"

    def test_medium_low_confidence_suggests_approve(self, queue):
        """Medium-low confidence (0.70-0.95) suggests approve action."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.85,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "John Smith lives here")

        assert result is not None
        assert result.suggested_action == "approve"

    def test_high_confidence_not_flagged(self, queue, high_confidence_span):
        """High confidence spans are not flagged."""
        result = queue.check_span(high_confidence_span, "John Smith lives in NYC")
        assert result is None

    def test_ml_only_detection_flagged(self, queue):
        """ML-only detections without needs_review are flagged."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.99,  # High confidence
            detector="ml",
            tier=Tier.ML,  # ML tier
            needs_review=False,
        )

        result = queue.check_span(span, "John Smith lives in NYC")

        assert result is not None
        assert result.reason == ReviewReason.ML_ONLY

    def test_already_flagged_span(self, queue):
        """Spans with needs_review=True are flagged."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.99,
            detector="pattern",
            tier=Tier.PATTERN,
            needs_review=True,
            review_reason="ambiguous_context",  # Use lowercase enum value
        )

        result = queue.check_span(span, "John Smith lives in NYC")

        assert result is not None
        assert result.reason == ReviewReason.AMBIGUOUS_CONTEXT

    def test_context_is_redacted(self, queue):
        """Context in review item contains redacted token, not PHI."""
        span = Span(
            start=5,
            end=15,
            text="John Smith",
            entity_type="NAME",
            confidence=0.7,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "Hi, John Smith here!", token="[NAME_1]")

        assert result is not None
        assert "John Smith" not in result.context
        assert "[NAME_1]" in result.context

    def test_context_includes_surrounding_text(self, queue):
        """Context includes text around the span."""
        span = Span(
            start=9,  # "Patient: " is 9 chars
            end=19,   # "John Smith" is 10 chars
            text="John Smith",
            entity_type="NAME",
            confidence=0.7,
            detector="ml",
            tier=Tier.ML,
        )

        text = "Patient: John Smith, DOB: 01/01/1990"
        result = queue.check_span(span, text, token="[NAME_1]", context_window=10)

        assert result is not None
        # Context should contain surrounding text with token replacing PHI
        assert "[NAME_1]" in result.context
        # Prefix should be visible
        assert "Patient:" in result.context or "atient:" in result.context

    def test_adds_item_to_queue(self, queue, low_confidence_span):
        """check_span adds flagged items to queue."""
        assert len(queue) == 0

        queue.check_span(low_confidence_span, "John Smith lives here")

        assert len(queue) == 1

    def test_stores_entity_type(self, queue):
        """Review item stores correct entity type."""
        span = Span(
            start=5,  # After "SSN: "
            end=16,   # "123-45-6789" is 11 chars
            text="123-45-6789",
            entity_type="SSN",
            confidence=0.7,
            detector="pattern",
            tier=Tier.PATTERN,
        )

        result = queue.check_span(span, "SSN: 123-45-6789", token="[SSN_1]")

        assert result.entity_type == "SSN"

    def test_stores_confidence(self, queue):
        """Review item stores correct confidence."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.72,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "John Smith", token="[NAME_1]")

        assert result.confidence == 0.72

    def test_fallback_token_display(self, queue):
        """Uses [ENTITY_TYPE] as token if none provided."""
        span = Span(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.7,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "John Smith here")  # No token provided

        assert result.token == "[NAME]"


# =============================================================================
# FLAG SPANS TESTS
# =============================================================================

class TestReviewQueueFlagSpans:
    """Tests for flag_spans method."""

    @pytest.fixture
    def queue(self):
        """Create a test queue."""
        return ReviewQueue(confidence_threshold=0.95)

    def test_flags_multiple_spans(self, queue):
        """flag_spans can flag multiple spans."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.7, detector="ml", tier=Tier.ML),
            Span(start=15, end=26, text="123-45-6789", entity_type="SSN",
                 confidence=0.6, detector="pattern", tier=Tier.PATTERN),
        ]

        result = queue.flag_spans(spans, "John Smith SSN 123-45-6789")

        assert len(result) == 2
        assert len(queue) == 2

    def test_returns_only_flagged_items(self, queue):
        """flag_spans returns only items that were flagged."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.7, detector="ml", tier=Tier.ML),  # Low confidence - flagged
            Span(start=15, end=26, text="123-45-6789", entity_type="SSN",
                 confidence=0.99, detector="pattern", tier=Tier.PATTERN),  # High confidence - not flagged
        ]

        result = queue.flag_spans(spans, "John Smith SSN 123-45-6789")

        assert len(result) == 1
        assert result[0].entity_type == "NAME"

    def test_uses_provided_tokens(self, queue):
        """flag_spans uses provided token list."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.7, detector="ml", tier=Tier.ML),
        ]
        tokens = ["[NAME_42]"]

        result = queue.flag_spans(spans, "John Smith here", tokens=tokens)

        assert result[0].token == "[NAME_42]"

    def test_handles_empty_spans(self, queue):
        """flag_spans handles empty span list."""
        result = queue.flag_spans([], "some text")
        assert result == []

    def test_handles_mismatched_tokens_list(self, queue):
        """flag_spans handles tokens list shorter than spans."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.7, detector="ml", tier=Tier.ML),
            Span(start=15, end=23, text="Jane Doe", entity_type="NAME",
                 confidence=0.7, detector="ml", tier=Tier.ML),
        ]
        tokens = ["[NAME_1]"]  # Only one token for two spans

        result = queue.flag_spans(spans, "John Smith and Jane Doe", tokens=tokens)

        assert len(result) == 2
        assert result[0].token == "[NAME_1]"
        assert result[1].token == "[NAME]"  # Falls back to entity type


# =============================================================================
# GET PENDING TESTS
# =============================================================================

class TestReviewQueueGetPending:
    """Tests for get_pending method."""

    @pytest.fixture
    def queue_with_items(self):
        """Create queue with some items."""
        queue = ReviewQueue(confidence_threshold=0.95)
        span1 = Span(start=0, end=10, text="John Smith", entity_type="NAME",
                     confidence=0.7, detector="ml", tier=Tier.ML)
        span2 = Span(start=15, end=23, text="Jane Doe", entity_type="NAME",
                     confidence=0.6, detector="ml", tier=Tier.ML)

        queue.check_span(span1, "John Smith here", token="[NAME_1]")
        queue.check_span(span2, "and also Jane Doe", token="[NAME_2]")
        return queue

    def test_returns_all_undecided(self, queue_with_items):
        """get_pending returns all undecided items."""
        pending = queue_with_items.get_pending()
        assert len(pending) == 2

    def test_excludes_approved_items(self, queue_with_items):
        """get_pending excludes approved items."""
        pending = queue_with_items.get_pending()
        queue_with_items.approve(pending[0].id)

        pending = queue_with_items.get_pending()
        assert len(pending) == 1

    def test_excludes_rejected_items(self, queue_with_items):
        """get_pending excludes rejected items."""
        pending = queue_with_items.get_pending()
        queue_with_items.reject(pending[0].id)

        pending = queue_with_items.get_pending()
        assert len(pending) == 1


# =============================================================================
# GET ITEM TESTS
# =============================================================================

class TestReviewQueueGetItem:
    """Tests for get_item method."""

    @pytest.fixture
    def queue_with_item(self):
        """Create queue with one item."""
        queue = ReviewQueue(confidence_threshold=0.95)
        span = Span(start=0, end=10, text="John Smith", entity_type="NAME",
                    confidence=0.7, detector="ml", tier=Tier.ML)
        item = queue.check_span(span, "John Smith here", token="[NAME_1]")
        return queue, item

    def test_returns_item_by_id(self, queue_with_item):
        """get_item returns correct item by ID."""
        queue, item = queue_with_item
        result = queue.get_item(item.id)

        assert result is not None
        assert result.id == item.id
        assert result.token == item.token

    def test_returns_none_for_unknown_id(self, queue_with_item):
        """get_item returns None for unknown ID."""
        queue, _ = queue_with_item
        result = queue.get_item("unknown-id-12345")

        assert result is None


# =============================================================================
# APPROVE TESTS
# =============================================================================

class TestReviewQueueApprove:
    """Tests for approve method."""

    @pytest.fixture
    def queue_with_item(self):
        """Create queue with one item."""
        queue = ReviewQueue(confidence_threshold=0.95)
        span = Span(start=0, end=10, text="John Smith", entity_type="NAME",
                    confidence=0.7, detector="ml", tier=Tier.ML)
        item = queue.check_span(span, "John Smith here", token="[NAME_1]")
        return queue, item

    def test_approve_returns_true(self, queue_with_item):
        """approve returns True on success."""
        queue, item = queue_with_item
        result = queue.approve(item.id)

        assert result is True

    def test_approve_sets_decision(self, queue_with_item):
        """approve sets decision to 'approved'."""
        queue, item = queue_with_item
        queue.approve(item.id)

        updated = queue.get_item(item.id)
        assert updated.decision == "approved"

    def test_approve_sets_timestamp(self, queue_with_item):
        """approve sets decided_at timestamp."""
        queue, item = queue_with_item
        before = datetime.now()
        queue.approve(item.id)
        after = datetime.now()

        updated = queue.get_item(item.id)
        assert updated.decided_at is not None
        assert before <= updated.decided_at <= after

    def test_approve_unknown_returns_false(self, queue_with_item):
        """approve returns False for unknown ID."""
        queue, _ = queue_with_item
        result = queue.approve("unknown-id")

        assert result is False

    def test_cannot_approve_twice(self, queue_with_item):
        """Cannot approve an already decided item."""
        queue, item = queue_with_item
        queue.approve(item.id)
        result = queue.approve(item.id)

        assert result is False

    def test_cannot_approve_rejected(self, queue_with_item):
        """Cannot approve a rejected item."""
        queue, item = queue_with_item
        queue.reject(item.id)
        result = queue.approve(item.id)

        assert result is False


# =============================================================================
# REJECT TESTS
# =============================================================================

class TestReviewQueueReject:
    """Tests for reject method."""

    @pytest.fixture
    def queue_with_item(self):
        """Create queue with one item."""
        queue = ReviewQueue(confidence_threshold=0.95)
        span = Span(start=0, end=10, text="John Smith", entity_type="NAME",
                    confidence=0.7, detector="ml", tier=Tier.ML)
        item = queue.check_span(span, "John Smith here", token="[NAME_1]")
        return queue, item

    def test_reject_returns_true(self, queue_with_item):
        """reject returns True on success."""
        queue, item = queue_with_item
        result = queue.reject(item.id)

        assert result is True

    def test_reject_sets_decision(self, queue_with_item):
        """reject sets decision to 'rejected'."""
        queue, item = queue_with_item
        queue.reject(item.id)

        updated = queue.get_item(item.id)
        assert updated.decision == "rejected"

    def test_reject_sets_timestamp(self, queue_with_item):
        """reject sets decided_at timestamp."""
        queue, item = queue_with_item
        before = datetime.now()
        queue.reject(item.id)
        after = datetime.now()

        updated = queue.get_item(item.id)
        assert updated.decided_at is not None
        assert before <= updated.decided_at <= after

    def test_reject_unknown_returns_false(self, queue_with_item):
        """reject returns False for unknown ID."""
        queue, _ = queue_with_item
        result = queue.reject("unknown-id")

        assert result is False

    def test_cannot_reject_twice(self, queue_with_item):
        """Cannot reject an already decided item."""
        queue, item = queue_with_item
        queue.reject(item.id)
        result = queue.reject(item.id)

        assert result is False

    def test_cannot_reject_approved(self, queue_with_item):
        """Cannot reject an approved item."""
        queue, item = queue_with_item
        queue.approve(item.id)
        result = queue.reject(item.id)

        assert result is False


# =============================================================================
# CLEAR DECIDED TESTS
# =============================================================================

class TestReviewQueueClearDecided:
    """Tests for clear_decided method."""

    @pytest.fixture
    def queue_with_mixed_items(self):
        """Create queue with pending and decided items."""
        queue = ReviewQueue(confidence_threshold=0.95)

        # Add 3 items
        for i in range(3):
            span = Span(start=i*10, end=i*10+5, text=f"name{i}", entity_type="NAME",
                        confidence=0.7, detector="ml", tier=Tier.ML)
            queue.check_span(span, f"name{i} text", token=f"[NAME_{i}]")

        # Approve first, reject second, leave third pending
        pending = queue.get_pending()
        queue.approve(pending[0].id)
        queue.reject(pending[1].id)

        return queue

    def test_clears_decided_items(self, queue_with_mixed_items):
        """clear_decided removes approved and rejected items."""
        queue = queue_with_mixed_items

        # Before: 1 pending, 2 decided
        assert len(queue._items) == 3
        assert len(queue.get_pending()) == 1

        queue.clear_decided()

        # After: only 1 pending remains
        assert len(queue._items) == 1
        assert len(queue.get_pending()) == 1

    def test_returns_count_removed(self, queue_with_mixed_items):
        """clear_decided returns count of removed items."""
        queue = queue_with_mixed_items
        count = queue.clear_decided()

        assert count == 2

    def test_clears_nothing_if_all_pending(self):
        """clear_decided returns 0 if all items are pending."""
        queue = ReviewQueue()
        span = Span(start=0, end=4, text="name", entity_type="NAME",
                    confidence=0.7, detector="ml", tier=Tier.ML)
        queue.check_span(span, "name here")

        count = queue.clear_decided()

        assert count == 0
        assert len(queue) == 1


# =============================================================================
# LEN TESTS
# =============================================================================

class TestReviewQueueLen:
    """Tests for __len__ method."""

    def test_len_returns_pending_count(self):
        """__len__ returns count of pending items only."""
        queue = ReviewQueue(confidence_threshold=0.95)

        # Add 3 items
        for i in range(3):
            span = Span(start=i*10, end=i*10+5, text=f"name{i}", entity_type="NAME",
                        confidence=0.7, detector="ml", tier=Tier.ML)
            queue.check_span(span, f"name{i} text")

        assert len(queue) == 3

        # Approve one
        pending = queue.get_pending()
        queue.approve(pending[0].id)

        assert len(queue) == 2

    def test_len_zero_for_empty_queue(self):
        """__len__ returns 0 for empty queue."""
        queue = ReviewQueue()
        assert len(queue) == 0


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestReviewQueueIntegration:
    """Integration tests for ReviewQueue workflow."""

    def test_full_review_workflow(self):
        """Test complete review workflow: add, review, clear."""
        queue = ReviewQueue(confidence_threshold=0.95)

        # Add spans for review (ensure end - start == len(text))
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.7, detector="ml", tier=Tier.ML),
            Span(start=15, end=26, text="123-45-6789", entity_type="SSN",
                 confidence=0.6, detector="pattern", tier=Tier.PATTERN),
            Span(start=27, end=35, text="Jane Doe", entity_type="NAME",
                 confidence=0.8, detector="ml", tier=Tier.ML),
        ]
        tokens = ["[NAME_1]", "[SSN_1]", "[NAME_2]"]

        items = queue.flag_spans(spans, "John Smith SSN 123-45-6789 Jane Doe", tokens=tokens)

        # All 3 should be flagged (all below threshold)
        assert len(items) == 3
        assert len(queue) == 3

        # Review decisions
        queue.approve(items[0].id)  # NAME_1 is correct
        queue.reject(items[1].id)   # SSN_1 is false positive
        # Leave NAME_2 pending

        assert len(queue) == 1

        # Clear decided
        cleared = queue.clear_decided()
        assert cleared == 2
        assert len(queue) == 1

        # Final decision
        pending = queue.get_pending()
        assert len(pending) == 1
        assert pending[0].token == "[NAME_2]"

    def test_context_never_contains_phi(self):
        """Verify the span's own PHI is never exposed in its review item context."""
        queue = ReviewQueue()

        # Test that each span's own PHI is redacted in its context
        # Note: check_span only redacts the current span being checked
        span = Span(
            start=8,
            end=18,
            text="John Smith",
            entity_type="NAME",
            confidence=0.7,
            detector="ml",
            tier=Tier.ML,
        )

        result = queue.check_span(span, "Patient John Smith was seen today", token="[NAME_1]")

        assert result is not None
        # The span's own PHI should be replaced with token
        assert "John Smith" not in result.context
        assert "[NAME_1]" in result.context

    def test_each_span_redacts_its_own_phi(self):
        """Each span's review item has its own PHI redacted."""
        queue = ReviewQueue()

        span1 = Span(start=0, end=10, text="John Smith", entity_type="NAME",
                     confidence=0.7, detector="ml", tier=Tier.ML)
        span2 = Span(start=15, end=26, text="123-45-6789", entity_type="SSN",
                     confidence=0.7, detector="pattern", tier=Tier.PATTERN)

        result1 = queue.check_span(span1, "John Smith SSN 123-45-6789", token="[NAME_1]")
        result2 = queue.check_span(span2, "John Smith SSN 123-45-6789", token="[SSN_1]")

        # Each span's own PHI is redacted
        assert "John Smith" not in result1.context
        assert "[NAME_1]" in result1.context

        assert "123-45-6789" not in result2.context
        assert "[SSN_1]" in result2.context
