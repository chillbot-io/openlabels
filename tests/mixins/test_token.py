"""Tests for token and review management mixin.

Tests for TokenMixin class.
"""

from unittest.mock import MagicMock, patch

import pytest

from scrubiq.mixins.token import TokenMixin
from scrubiq.types import AuditEventType


# =============================================================================
# TEST CLASS SETUP
# =============================================================================

class MockTokenMixin(TokenMixin):
    """Mock class using TokenMixin for testing."""

    def __init__(self):
        self._unlocked = True
        self._store = None
        self._review_queue = MagicMock()
        self._audit = MagicMock()

    def _require_unlock(self):
        if not self._unlocked:
            raise RuntimeError("Session locked")


# =============================================================================
# GET_TOKENS TESTS
# =============================================================================

class TestGetTokens:
    """Tests for get_tokens method."""

    def test_returns_empty_list_when_no_store(self):
        """Returns empty list when store is None."""
        mixin = MockTokenMixin()
        mixin._store = None

        result = mixin.get_tokens()

        assert result == []

    def test_returns_tokens_from_store(self):
        """Returns tokens from store."""
        mixin = MockTokenMixin()
        mock_store = MagicMock()
        mock_store.list_tokens.return_value = ["[NAME_1]", "[NAME_2]"]

        mock_entry1 = MagicMock()
        mock_entry1.token = "[NAME_1]"
        mock_entry1.entity_type = "PERSON"
        mock_entry1.safe_harbor_value = "Patient"

        mock_entry2 = MagicMock()
        mock_entry2.token = "[NAME_2]"
        mock_entry2.entity_type = "PERSON"
        mock_entry2.safe_harbor_value = "Provider"

        mock_store.get_entry.side_effect = [mock_entry1, mock_entry2]
        mixin._store = mock_store

        result = mixin.get_tokens()

        assert len(result) == 2
        assert result[0]["token"] == "[NAME_1]"
        assert result[0]["type"] == "PERSON"
        assert result[0]["safe_harbor"] == "Patient"

    def test_skips_entries_not_found(self):
        """Skips tokens where entry is not found."""
        mixin = MockTokenMixin()
        mock_store = MagicMock()
        mock_store.list_tokens.return_value = ["[NAME_1]", "[NAME_2]"]
        mock_store.get_entry.side_effect = [None, MagicMock(
            token="[NAME_2]",
            entity_type="PERSON",
            safe_harbor_value="Name",
        )]
        mixin._store = mock_store

        result = mixin.get_tokens()

        assert len(result) == 1

    def test_does_not_expose_original_phi(self):
        """Token dict does not include original PHI."""
        mixin = MockTokenMixin()
        mock_store = MagicMock()
        mock_store.list_tokens.return_value = ["[NAME_1]"]

        mock_entry = MagicMock()
        mock_entry.token = "[NAME_1]"
        mock_entry.entity_type = "PERSON"
        mock_entry.safe_harbor_value = "Patient"
        mock_entry.original = "John Doe"  # Should NOT be exposed

        mock_store.get_entry.return_value = mock_entry
        mixin._store = mock_store

        result = mixin.get_tokens()

        assert "original" not in result[0]

    def test_requires_unlock(self):
        """Raises if session is locked."""
        mixin = MockTokenMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_tokens()


# =============================================================================
# DELETE_TOKEN TESTS
# =============================================================================

class TestDeleteToken:
    """Tests for delete_token method."""

    def test_returns_false_when_no_store(self):
        """Returns False when store is None."""
        mixin = MockTokenMixin()
        mixin._store = None

        result = mixin.delete_token("[NAME_1]")

        assert result is False

    def test_calls_store_delete(self):
        """Calls store.delete with token."""
        mixin = MockTokenMixin()
        mock_store = MagicMock()
        mock_store.delete.return_value = True
        mixin._store = mock_store

        result = mixin.delete_token("[NAME_1]")

        mock_store.delete.assert_called_once_with("[NAME_1]")
        assert result is True

    def test_returns_store_result(self):
        """Returns result from store.delete."""
        mixin = MockTokenMixin()
        mock_store = MagicMock()
        mock_store.delete.return_value = False
        mixin._store = mock_store

        result = mixin.delete_token("[NAME_1]")

        assert result is False

    def test_requires_unlock(self):
        """Raises if session is locked."""
        mixin = MockTokenMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.delete_token("[NAME_1]")


# =============================================================================
# GET_PENDING_REVIEWS TESTS
# =============================================================================

class TestGetPendingReviews:
    """Tests for get_pending_reviews method."""

    def test_returns_pending_reviews(self):
        """Returns formatted pending reviews."""
        mixin = MockTokenMixin()

        mock_review = MagicMock()
        mock_review.id = "review-123"
        mock_review.token = "[PHONE_1]"
        mock_review.entity_type = "PHONE"
        mock_review.confidence = 0.75
        mock_review.reason.value = "low_confidence"
        mock_review.context = "Call me at [PHONE_1]"
        mock_review.suggested_action = "approve"

        mixin._review_queue.get_pending.return_value = [mock_review]

        result = mixin.get_pending_reviews()

        assert len(result) == 1
        assert result[0]["id"] == "review-123"
        assert result[0]["token"] == "[PHONE_1]"
        assert result[0]["type"] == "PHONE"
        assert result[0]["confidence"] == 0.75
        assert result[0]["reason"] == "low_confidence"
        assert result[0]["suggested"] == "approve"

    def test_returns_empty_when_no_pending(self):
        """Returns empty list when no pending reviews."""
        mixin = MockTokenMixin()
        mixin._review_queue.get_pending.return_value = []

        result = mixin.get_pending_reviews()

        assert result == []


# =============================================================================
# APPROVE_REVIEW TESTS
# =============================================================================

class TestApproveReview:
    """Tests for approve_review method."""

    def test_calls_queue_approve(self):
        """Calls review queue approve."""
        mixin = MockTokenMixin()
        mixin._review_queue.approve.return_value = True

        result = mixin.approve_review("review-123")

        mixin._review_queue.approve.assert_called_once_with("review-123")
        assert result is True

    def test_logs_audit_on_success(self):
        """Logs audit event on successful approve."""
        mixin = MockTokenMixin()
        mixin._review_queue.approve.return_value = True

        mixin.approve_review("review-123")

        mixin._audit.log.assert_called_once_with(
            AuditEventType.REVIEW_APPROVED,
            {"item_id": "review-123"}
        )

    def test_no_audit_on_failure(self):
        """Does not log audit on failed approve."""
        mixin = MockTokenMixin()
        mixin._review_queue.approve.return_value = False

        mixin.approve_review("review-123")

        mixin._audit.log.assert_not_called()

    def test_returns_false_on_failure(self):
        """Returns False when approve fails."""
        mixin = MockTokenMixin()
        mixin._review_queue.approve.return_value = False

        result = mixin.approve_review("review-123")

        assert result is False


# =============================================================================
# REJECT_REVIEW TESTS
# =============================================================================

class TestRejectReview:
    """Tests for reject_review method."""

    def test_calls_queue_reject(self):
        """Calls review queue reject."""
        mixin = MockTokenMixin()
        mixin._review_queue.reject.return_value = True

        result = mixin.reject_review("review-123")

        mixin._review_queue.reject.assert_called_once_with("review-123")
        assert result is True

    def test_logs_audit_on_success(self):
        """Logs audit event on successful reject."""
        mixin = MockTokenMixin()
        mixin._review_queue.reject.return_value = True

        mixin.reject_review("review-123")

        mixin._audit.log.assert_called_once_with(
            AuditEventType.REVIEW_REJECTED,
            {"item_id": "review-123"}
        )

    def test_no_audit_on_failure(self):
        """Does not log audit on failed reject."""
        mixin = MockTokenMixin()
        mixin._review_queue.reject.return_value = False

        mixin.reject_review("review-123")

        mixin._audit.log.assert_not_called()


# =============================================================================
# VERIFY_AUDIT_CHAIN TESTS
# =============================================================================

class TestVerifyAuditChain:
    """Tests for verify_audit_chain method."""

    def test_returns_audit_verify_result(self):
        """Returns result from audit.verify_chain."""
        mixin = MockTokenMixin()
        mixin._audit.verify_chain.return_value = (True, 100, "OK")

        result = mixin.verify_audit_chain()

        assert result == (True, 100, "OK")

    def test_requires_unlock(self):
        """Raises if session is locked."""
        mixin = MockTokenMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.verify_audit_chain()


# =============================================================================
# GET_AUDIT_ENTRIES TESTS
# =============================================================================

class TestGetAuditEntries:
    """Tests for get_audit_entries method."""

    def test_returns_formatted_entries(self):
        """Returns formatted audit entries."""
        mixin = MockTokenMixin()

        mock_entry = MagicMock()
        mock_entry.sequence = 1
        mock_entry.event_type.value = "session_start"
        mock_entry.timestamp.isoformat.return_value = "2024-01-01T00:00:00"
        mock_entry.data = {"key": "value"}

        mixin._audit.get_entries.return_value = [mock_entry]

        result = mixin.get_audit_entries()

        assert len(result) == 1
        assert result[0]["sequence"] == 1
        assert result[0]["event"] == "session_start"
        assert result[0]["timestamp"] == "2024-01-01T00:00:00"
        assert result[0]["data"] == {"key": "value"}

    def test_passes_limit_to_audit(self):
        """Passes limit parameter to audit.get_entries."""
        mixin = MockTokenMixin()
        mixin._audit.get_entries.return_value = []

        mixin.get_audit_entries(limit=50)

        mixin._audit.get_entries.assert_called_once_with(limit=50)

    def test_default_limit_is_100(self):
        """Default limit is 100."""
        mixin = MockTokenMixin()
        mixin._audit.get_entries.return_value = []

        mixin.get_audit_entries()

        mixin._audit.get_entries.assert_called_once_with(limit=100)

    def test_requires_unlock(self):
        """Raises if session is locked."""
        mixin = MockTokenMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_audit_entries()
