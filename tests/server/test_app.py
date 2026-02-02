"""Tests for FastAPI application components.

Tests config, session, and models without triggering pyo3 runtime issues.
Routes tests are skipped to avoid import conflicts.
"""

import pytest


class TestAppModule:
    """Tests for app module components."""

    def test_config_module_imports(self):
        """Test config module can be imported."""
        from openlabels.server.config import Settings

        assert Settings is not None

    def test_session_module_imports(self):
        """Test session module can be imported."""
        from openlabels.server.session import SessionStore

        assert SessionStore is not None

    def test_models_module_imports(self):
        """Test models module can be imported."""
        from openlabels.server.models import User, Tenant, ScanJob

        assert User is not None
        assert Tenant is not None
        assert ScanJob is not None

    def test_db_module_exists(self):
        """Test db module exists."""
        from openlabels.server import db

        assert db is not None
