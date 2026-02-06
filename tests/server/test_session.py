"""
Unit tests for session module constants and configuration.

For integration tests of actual database behavior, see tests/test_session_store.py.
"""

import pytest


class TestSessionStoreConfiguration:
    """Tests for SessionStore configuration."""

    def test_session_store_requires_db(self):
        """SessionStore requires a database session."""
        from openlabels.server.session import SessionStore

        with pytest.raises(TypeError):
            SessionStore()  # No db argument


class TestPendingAuthStoreConfiguration:
    """Tests for PendingAuthStore configuration."""

    def test_pending_auth_store_requires_db(self):
        """PendingAuthStore requires a database session."""
        from openlabels.server.session import PendingAuthStore

        with pytest.raises(TypeError):
            PendingAuthStore()  # No db argument

    def test_auth_timeout_is_secure(self):
        """AUTH_TIMEOUT_MINUTES should be reasonable for security (5-15 min)."""
        from openlabels.server.session import PendingAuthStore

        timeout = PendingAuthStore.AUTH_TIMEOUT_MINUTES
        assert 5 <= timeout <= 15, \
            f"Auth timeout {timeout} should be 5-15 minutes for security"


