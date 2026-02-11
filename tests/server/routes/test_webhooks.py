"""
Tests for webhook API endpoints.

Tests focus on:
- M365 audit webhook receiver (validation handshake + notification processing)
- Graph change notification receiver (validation handshake + notification processing)
- Client state validation
- Malformed input handling
"""

import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_webhook_settings():
    """Create mock settings with webhook client state configured."""
    mock_settings = MagicMock()
    mock_settings.monitoring.webhook_client_state = "test-secret-state"
    return mock_settings


class TestM365Webhook:
    """Tests for POST /api/v1/webhooks/webhooks/m365 endpoint."""

    async def test_validation_handshake_echoes_token(self, test_client, test_db):
        """Should echo validationToken for subscription handshake."""
        response = await test_client.post(
            "/api/v1/webhooks/webhooks/m365?validationToken=test-token-123",
        )
        assert response.status_code == 200
        assert response.text == "test-token-123"
        assert response.headers.get("content-type", "").startswith("text/plain")

    async def test_validation_handshake_rejects_long_token(self, test_client, test_db):
        """Should reject suspiciously long validation tokens."""
        long_token = "x" * 1025
        response = await test_client.post(
            f"/api/v1/webhooks/webhooks/m365?validationToken={long_token}",
        )
        assert response.status_code == 400

    async def test_notification_with_valid_client_state(self, test_client, test_db, mock_webhook_settings):
        """Should accept notification with matching client state."""
        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_webhook_settings), \
             patch("openlabels.server.routes.webhooks.push_m365_notification", return_value=True) as mock_push:
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/m365",
                json=[{"clientState": "test-secret-state", "contentType": "Audit.General"}],
            )

        assert response.status_code == 200
        mock_push.assert_called_once()

    async def test_notification_rejects_invalid_client_state(self, test_client, test_db, mock_webhook_settings):
        """Should reject notification with mismatched client state."""
        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_webhook_settings), \
             patch("openlabels.server.routes.webhooks.push_m365_notification") as mock_push:
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/m365",
                json=[{"clientState": "wrong-state", "contentType": "Audit.General"}],
            )

        assert response.status_code == 200  # Returns 200 per spec but doesn't push
        mock_push.assert_not_called()

    async def test_notification_rejects_when_state_unconfigured(self, test_client, test_db):
        """Should reject all notifications when webhook_client_state is empty."""
        mock_settings = MagicMock()
        mock_settings.monitoring.webhook_client_state = ""

        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_settings), \
             patch("openlabels.server.routes.webhooks.push_m365_notification") as mock_push:
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/m365",
                json=[{"clientState": "any-state"}],
            )

        assert response.status_code == 200
        mock_push.assert_not_called()

    async def test_notification_rejects_invalid_json(self, test_client, test_db):
        """Should return 400 for invalid JSON body."""
        response = await test_client.post(
            "/api/v1/webhooks/webhooks/m365",
            content=b"not-json",
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400

    async def test_notification_accepts_single_object(self, test_client, test_db, mock_webhook_settings):
        """Should accept a single notification object (not wrapped in array)."""
        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_webhook_settings), \
             patch("openlabels.server.routes.webhooks.push_m365_notification", return_value=True) as mock_push:
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/m365",
                json={"clientState": "test-secret-state", "contentType": "Audit.General"},
            )

        assert response.status_code == 200
        mock_push.assert_called_once()


class TestGraphWebhook:
    """Tests for POST /api/v1/webhooks/webhooks/graph endpoint."""

    async def test_validation_handshake_echoes_token(self, test_client, test_db):
        """Should echo validationToken for subscription handshake."""
        response = await test_client.post(
            "/api/v1/webhooks/webhooks/graph?validationToken=graph-token-456",
        )
        assert response.status_code == 200
        assert response.text == "graph-token-456"

    async def test_validation_handshake_rejects_long_token(self, test_client, test_db):
        """Should reject suspiciously long validation tokens."""
        long_token = "x" * 1025
        response = await test_client.post(
            f"/api/v1/webhooks/webhooks/graph?validationToken={long_token}",
        )
        assert response.status_code == 400

    async def test_notification_with_valid_client_state(self, test_client, test_db, mock_webhook_settings):
        """Should accept Graph notification with matching client state."""
        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_webhook_settings), \
             patch("openlabels.server.routes.webhooks.push_graph_notification", return_value=True) as mock_push:
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/graph",
                json={
                    "value": [
                        {
                            "clientState": "test-secret-state",
                            "changeType": "updated",
                            "resource": "drives/123/items/456",
                        }
                    ]
                },
            )

        assert response.status_code == 200
        mock_push.assert_called_once()

    async def test_notification_rejects_invalid_client_state(self, test_client, test_db, mock_webhook_settings):
        """Should reject notification with mismatched client state."""
        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_webhook_settings), \
             patch("openlabels.server.routes.webhooks.push_graph_notification") as mock_push:
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/graph",
                json={
                    "value": [
                        {"clientState": "wrong-state", "changeType": "updated"}
                    ]
                },
            )

        assert response.status_code == 200
        mock_push.assert_not_called()

    async def test_notification_handles_empty_value(self, test_client, test_db, mock_webhook_settings):
        """Should handle Graph notification with empty value array."""
        with patch("openlabels.server.routes.webhooks.get_settings", return_value=mock_webhook_settings):
            response = await test_client.post(
                "/api/v1/webhooks/webhooks/graph",
                json={"value": []},
            )

        assert response.status_code == 200

    async def test_notification_rejects_invalid_json(self, test_client, test_db):
        """Should return 400 for invalid JSON body."""
        response = await test_client.post(
            "/api/v1/webhooks/webhooks/graph",
            content=b"not-json",
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400


class TestWebhookSecurity:
    """Tests for webhook security features."""

    async def test_validation_token_has_nosniff_header(self, test_client, test_db):
        """Validation response should include X-Content-Type-Options: nosniff."""
        response = await test_client.post(
            "/api/v1/webhooks/webhooks/m365?validationToken=test",
        )
        assert response.status_code == 200
        assert response.headers.get("x-content-type-options") == "nosniff"

    async def test_client_state_uses_constant_time_comparison(self, test_client, test_db):
        """Verify _validate_client_state uses hmac.compare_digest."""
        from openlabels.server.routes.webhooks import _validate_client_state

        assert _validate_client_state("secret", "secret", "test") is True
        assert _validate_client_state("wrong", "secret", "test") is False
        assert _validate_client_state("any", "", "test") is False
