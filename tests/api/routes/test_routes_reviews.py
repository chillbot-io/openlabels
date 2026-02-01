"""Tests for review and audit routes.

Tests human review queue and audit log endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import reviews as routes_reviews
    SCRUBIQ_AVAILABLE = True
except (ImportError, RuntimeError):
    SCRUBIQ_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not SCRUBIQ_AVAILABLE,
    reason="ScrubIQ package not available (missing SQLCipher or other dependencies)"
)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_scrubiq():
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()

    # Review items
    mock.get_pending_reviews.return_value = [
        {
            "id": "rev-123",
            "token": "[NAME_1]",
            "type": "NAME",
            "confidence": 0.72,
            "reason": "LOW_CONFIDENCE",
            "context_redacted": "Patient [NAME_1] visited...",
            "suggested": "review",
        },
    ]
    mock.approve_review.return_value = True
    mock.reject_review.return_value = True

    # Audit entries
    mock.get_audit_entries.return_value = [
        {
            "sequence": 1,
            "event": "REDACT",
            "timestamp": "2024-01-15T10:30:00",
            "data": {"phi_count": 5},
        },
        {
            "sequence": 2,
            "event": "RESTORE",
            "timestamp": "2024-01-15T10:31:00",
            "data": {"tokens_restored": 3},
        },
    ]
    mock.verify_audit_chain.return_value = (True, None)

    return mock


@pytest.fixture
def client(mock_scrubiq):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.reviews import router
    from scrubiq.api.dependencies import require_unlocked
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.reviews.check_rate_limit"):
        yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# LIST REVIEWS TESTS
# =============================================================================

class TestListReviews:
    """Tests for GET /reviews endpoint."""

    def test_list_success(self, client, mock_scrubiq):
        """List reviews returns pending items."""
        response = client.get("/reviews")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_list_review_structure(self, client):
        """Listed reviews have correct structure."""
        response = client.get("/reviews")

        assert response.status_code == 200
        review = response.json()[0]
        assert review["id"] == "rev-123"
        assert review["token"] == "[NAME_1]"
        assert review["type"] == "NAME"
        assert review["confidence"] == 0.72
        assert review["reason"] == "LOW_CONFIDENCE"
        assert "context_redacted" in review
        assert review["suggested"] == "review"

    def test_list_empty_when_no_pending(self, client, mock_scrubiq):
        """List returns empty when no pending reviews."""
        mock_scrubiq.get_pending_reviews.return_value = []

        response = client.get("/reviews")

        assert response.status_code == 200
        assert response.json() == []


# =============================================================================
# APPROVE REVIEW TESTS
# =============================================================================

class TestApproveReview:
    """Tests for POST /reviews/{item_id}/approve endpoint."""

    def test_approve_success(self, client, mock_scrubiq):
        """Approve review succeeds."""
        response = client.post("/reviews/rev-123/approve")

        assert response.status_code == 200
        assert response.json()["success"] is True
        mock_scrubiq.approve_review.assert_called_once_with("rev-123")

    def test_approve_not_found(self, client, mock_scrubiq):
        """Approve returns 404 for unknown item."""
        mock_scrubiq.approve_review.return_value = False

        response = client.post("/reviews/unknown-rev/approve")

        assert response.status_code == 404

    def test_approve_validates_item_id(self, client):
        """Approve validates item_id format."""
        # Invalid characters
        response = client.post("/reviews/rev<script>/approve")

        assert response.status_code == 422

    def test_approve_item_id_length_validation(self, client):
        """Approve validates item_id length."""
        # Too long
        long_id = "x" * 100
        response = client.post(f"/reviews/{long_id}/approve")

        assert response.status_code == 422


# =============================================================================
# REJECT REVIEW TESTS
# =============================================================================

class TestRejectReview:
    """Tests for POST /reviews/{item_id}/reject endpoint."""

    def test_reject_success(self, client, mock_scrubiq):
        """Reject review succeeds."""
        response = client.post("/reviews/rev-123/reject")

        assert response.status_code == 200
        assert response.json()["success"] is True
        mock_scrubiq.reject_review.assert_called_once_with("rev-123")

    def test_reject_not_found(self, client, mock_scrubiq):
        """Reject returns 404 for unknown item."""
        mock_scrubiq.reject_review.return_value = False

        response = client.post("/reviews/unknown-rev/reject")

        assert response.status_code == 404

    def test_reject_validates_item_id(self, client):
        """Reject validates item_id format."""
        response = client.post("/reviews/rev;drop/reject")

        assert response.status_code == 422


# =============================================================================
# LIST AUDITS TESTS
# =============================================================================

class TestListAudits:
    """Tests for GET /audits endpoint."""

    def test_list_success(self, client, mock_scrubiq):
        """List audits returns audit entries."""
        response = client.get("/audits")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2

    def test_list_audit_structure(self, client):
        """Listed audits have correct structure."""
        response = client.get("/audits")

        assert response.status_code == 200
        audit = response.json()[0]
        assert audit["sequence"] == 1
        assert audit["event"] == "REDACT"
        assert "timestamp" in audit
        assert "data" in audit

    def test_list_with_limit(self, client, mock_scrubiq):
        """List audits respects limit parameter."""
        client.get("/audits?limit=50")

        mock_scrubiq.get_audit_entries.assert_called_once()
        call_kwargs = mock_scrubiq.get_audit_entries.call_args[1]
        assert call_kwargs["limit"] == 50

    def test_list_limit_validation(self, client):
        """List validates limit parameter range."""
        response = client.get("/audits?limit=0")
        assert response.status_code == 422

    def test_list_audit_order(self, client):
        """Audits are returned in order."""
        response = client.get("/audits")

        data = response.json()
        assert data[0]["sequence"] == 1
        assert data[1]["sequence"] == 2


# =============================================================================
# VERIFY AUDITS TESTS
# =============================================================================

class TestVerifyAudits:
    """Tests for GET /audits/verify endpoint."""

    def test_verify_success(self, client, mock_scrubiq):
        """Verify returns chain validity."""
        response = client.get("/audits/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["error"] is None

    def test_verify_chain_broken(self, client, mock_scrubiq):
        """Verify reports broken chain."""
        mock_scrubiq.verify_audit_chain.return_value = (False, "Hash mismatch at entry 42")

        response = client.get("/audits/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "Hash mismatch" in data["error"]

    def test_verify_calls_method(self, client, mock_scrubiq):
        """Verify calls verify_audit_chain."""
        client.get("/audits/verify")

        mock_scrubiq.verify_audit_chain.assert_called_once()


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================

class TestReviewsRateLimiting:
    """Tests that rate limiting is applied to review endpoints."""

    def test_reviews_check_rate_limit(self, mock_scrubiq):
        """Reviews endpoint checks rate limit."""
        from scrubiq.api.routes.reviews import router
        from scrubiq.api.dependencies import require_unlocked

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

        with patch("scrubiq.api.routes.reviews.check_rate_limit") as mock_rate:
            test_client = TestClient(app)
            test_client.get("/reviews")

            mock_rate.assert_called_once()
            call_kwargs = mock_rate.call_args[1]
            assert call_kwargs["action"] == "review"

    def test_audits_check_rate_limit(self, mock_scrubiq):
        """Audits endpoint checks rate limit."""
        from scrubiq.api.routes.reviews import router
        from scrubiq.api.dependencies import require_unlocked

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

        with patch("scrubiq.api.routes.reviews.check_rate_limit") as mock_rate:
            test_client = TestClient(app)
            test_client.get("/audits")

            mock_rate.assert_called_once()
            call_kwargs = mock_rate.call_args[1]
            assert call_kwargs["action"] == "audit"
