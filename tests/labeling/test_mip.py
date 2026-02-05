"""Tests for MIP SDK integration.

Note: MIP SDK tests use limited assertions since the actual SDK requires Windows/.NET.
Tests focus on dataclasses, configuration, and availability checks.
"""

from unittest.mock import MagicMock, patch
from pathlib import Path

import pytest


# =============================================================================
# MIP AVAILABILITY TESTS
# =============================================================================


class TestMIPAvailability:
    """Tests for MIP SDK availability checks."""

    def test_pythonnet_available_is_boolean(self):
        """PYTHONNET_AVAILABLE should be a boolean."""
        from openlabels.labeling.mip import PYTHONNET_AVAILABLE

        assert isinstance(PYTHONNET_AVAILABLE, bool)

    def test_is_mip_available_returns_boolean(self):
        """is_mip_available() should return a boolean."""
        from openlabels.labeling.mip import is_mip_available

        result = is_mip_available()
        assert isinstance(result, bool)

    def test_is_mip_available_matches_constant(self):
        """is_mip_available() should match PYTHONNET_AVAILABLE constant."""
        from openlabels.labeling.mip import is_mip_available, PYTHONNET_AVAILABLE

        assert is_mip_available() == PYTHONNET_AVAILABLE

    def test_assemblies_loaded_starts_false(self):
        """_MIP_ASSEMBLIES_LOADED should start as False."""
        from openlabels.labeling import mip

        # The module-level flag should exist
        assert hasattr(mip, '_MIP_ASSEMBLIES_LOADED')
        # Note: Can't assert initial value since module state persists


# =============================================================================
# SENSITIVITY LABEL DATACLASS TESTS
# =============================================================================


class TestSensitivityLabel:
    """Tests for SensitivityLabel dataclass."""

    def test_creation_with_required_fields(self):
        """SensitivityLabel should require id, name, description, tooltip."""
        from openlabels.labeling.mip import SensitivityLabel

        label = SensitivityLabel(
            id="label-123",
            name="Confidential",
            description="For confidential data",
            tooltip="Apply to confidential information",
        )

        assert label.id == "label-123"
        assert label.name == "Confidential"
        assert label.description == "For confidential data"
        assert label.tooltip == "Apply to confidential information"

    def test_default_values(self):
        """SensitivityLabel should have sensible defaults."""
        from openlabels.labeling.mip import SensitivityLabel

        label = SensitivityLabel(
            id="label-123",
            name="Test",
            description="Test description",
            tooltip="Test tooltip",
        )

        assert label.color is None
        assert label.priority == 0
        assert label.parent_id is None
        assert label.is_active is True

    def test_optional_fields(self):
        """SensitivityLabel should accept optional fields."""
        from openlabels.labeling.mip import SensitivityLabel

        label = SensitivityLabel(
            id="label-789",
            name="Internal",
            description="Internal use",
            tooltip="For internal data",
            color="#FF0000",
            priority=5,
            parent_id="parent-label",
            is_active=False,
        )

        assert label.color == "#FF0000"
        assert label.priority == 5
        assert label.parent_id == "parent-label"
        assert label.is_active is False

    def test_to_dict_includes_all_fields(self):
        """to_dict should include all fields."""
        from openlabels.labeling.mip import SensitivityLabel

        label = SensitivityLabel(
            id="label-456",
            name="Public",
            description="Public info",
            tooltip="For public data",
            priority=10,
            color="#00FF00",
            parent_id="parent-123",
            is_active=True,
        )

        d = label.to_dict()

        assert d["id"] == "label-456"
        assert d["name"] == "Public"
        assert d["description"] == "Public info"
        assert d["tooltip"] == "For public data"
        assert d["priority"] == 10
        assert d["color"] == "#00FF00"
        assert d["parent_id"] == "parent-123"
        assert d["is_active"] is True

    def test_to_dict_includes_none_values(self):
        """to_dict should include None values explicitly."""
        from openlabels.labeling.mip import SensitivityLabel

        label = SensitivityLabel(
            id="label-123",
            name="Test",
            description="Test",
            tooltip="Test",
        )

        d = label.to_dict()

        assert "color" in d
        assert d["color"] is None
        assert "parent_id" in d
        assert d["parent_id"] is None


# =============================================================================
# LABELING RESULT DATACLASS TESTS
# =============================================================================


class TestLabelingResult:
    """Tests for LabelingResult dataclass."""

    def test_successful_result(self):
        """Successful result should have success=True."""
        from openlabels.labeling.mip import LabelingResult

        result = LabelingResult(
            success=True,
            file_path="/path/to/file.docx",
            label_id="label-123",
            label_name="Confidential",
        )

        assert result.success is True
        assert result.file_path == "/path/to/file.docx"
        assert result.label_id == "label-123"
        assert result.label_name == "Confidential"
        assert result.error is None

    def test_failed_result(self):
        """Failed result should have success=False and error."""
        from openlabels.labeling.mip import LabelingResult

        result = LabelingResult(
            success=False,
            file_path="/path/to/file.docx",
            error="File not found",
        )

        assert result.success is False
        assert result.error == "File not found"

    def test_default_values(self):
        """LabelingResult should have sensible defaults."""
        from openlabels.labeling.mip import LabelingResult

        result = LabelingResult(
            success=True,
            file_path="/test.txt",
        )

        assert result.label_id is None
        assert result.label_name is None
        assert result.error is None
        assert result.was_protected is False
        assert result.is_protected is False

    def test_protection_fields(self):
        """LabelingResult should track protection status."""
        from openlabels.labeling.mip import LabelingResult

        result = LabelingResult(
            success=True,
            file_path="/test.docx",
            label_id="label-123",
            was_protected=True,
            is_protected=False,
        )

        assert result.was_protected is True
        assert result.is_protected is False

    def test_to_dict_includes_all_fields(self):
        """to_dict should include all fields."""
        from openlabels.labeling.mip import LabelingResult

        result = LabelingResult(
            success=True,
            file_path="/test.docx",
            label_id="label-123",
            label_name="Confidential",
            error=None,
            was_protected=True,
            is_protected=True,
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["file_path"] == "/test.docx"
        assert d["label_id"] == "label-123"
        assert d["label_name"] == "Confidential"
        assert d["error"] is None
        assert d["was_protected"] is True
        assert d["is_protected"] is True


# =============================================================================
# AUTH DELEGATE TESTS
# =============================================================================


class TestAuthDelegateImpl:
    """Tests for AuthDelegateImpl class."""

    def test_stores_credentials(self):
        """AuthDelegateImpl should store credentials."""
        from openlabels.labeling.mip import AuthDelegateImpl

        delegate = AuthDelegateImpl(
            client_id="my-client-id",
            client_secret="my-secret",
            tenant_id="my-tenant-id",
        )

        assert delegate.client_id == "my-client-id"
        assert delegate.client_secret == "my-secret"
        assert delegate.tenant_id == "my-tenant-id"

    def test_app_initially_none(self):
        """MSAL app should not be created until needed."""
        from openlabels.labeling.mip import AuthDelegateImpl

        delegate = AuthDelegateImpl(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        assert delegate._app is None


# =============================================================================
# MIP CLIENT CONFIGURATION TESTS
# =============================================================================


class TestMIPClientConfiguration:
    """Tests for MIPClient configuration."""

    def test_stores_credentials(self):
        """MIPClient should store credentials."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="my-client-id",
            client_secret="my-secret",
            tenant_id="my-tenant-id",
        )

        assert client.client_id == "my-client-id"
        assert client.client_secret == "my-secret"
        assert client.tenant_id == "my-tenant-id"

    def test_accepts_custom_sdk_path(self):
        """MIPClient should accept custom SDK path."""
        from openlabels.labeling.mip import MIPClient

        custom_path = Path("/custom/mip/sdk")
        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
            mip_sdk_path=custom_path,
        )

        assert client.mip_sdk_path == custom_path

    def test_accepts_app_info(self):
        """MIPClient should accept app name and version."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
            app_name="TestApp",
            app_version="2.0.0",
        )

        assert client.app_name == "TestApp"
        assert client.app_version == "2.0.0"

    def test_default_app_info(self):
        """MIPClient should have default app info."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        assert client.app_name == "OpenLabels"
        assert client.app_version == "1.0.0"

    def test_starts_not_initialized(self):
        """MIPClient should start in uninitialized state."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        assert client.is_initialized is False

    def test_is_available_matches_pythonnet(self):
        """MIPClient.is_available should match PYTHONNET_AVAILABLE."""
        from openlabels.labeling.mip import MIPClient, PYTHONNET_AVAILABLE

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        assert client.is_available == PYTHONNET_AVAILABLE

    def test_internal_state_initialized_empty(self):
        """MIPClient internal state should be empty initially."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        assert client._mip_context is None
        assert client._file_profile is None
        assert client._file_engine is None
        assert client._auth_delegate is None
        assert client._labels == []


# =============================================================================
# MIP CLIENT METHODS TESTS (without initialization)
# =============================================================================


class TestMIPClientMethods:
    """Tests for MIPClient methods that don't require initialization."""

    async def test_get_labels_without_init_returns_empty(self):
        """get_labels should return empty list if not initialized."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        labels = await client.get_labels()

        assert labels == []

    async def test_apply_label_without_init_returns_error(self):
        """apply_label should return error if not initialized."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        result = await client.apply_label("/test.docx", "label-123")

        assert result.success is False
        assert "not initialized" in result.error.lower()

    async def test_remove_label_without_init_returns_error(self):
        """remove_label should return error if not initialized."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        result = await client.remove_label("/test.docx")

        assert result.success is False
        assert "not initialized" in result.error.lower()

    async def test_get_file_label_without_init_returns_none(self):
        """get_file_label should return None if not initialized."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        label = await client.get_file_label("/test.docx")

        assert label is None

    async def test_is_file_protected_without_init_returns_false(self):
        """is_file_protected should return False if not initialized."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )

        result = await client.is_file_protected("/test.docx")

        assert result is False


# =============================================================================
# MIP CLIENT FILE VALIDATION TESTS
# =============================================================================


class TestMIPClientFileValidation:
    """Tests for MIPClient file validation."""

    async def test_apply_label_nonexistent_file(self, tmp_path):
        """apply_label should fail for nonexistent file."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )
        # Manually set initialized to test file validation
        client._initialized = True

        result = await client.apply_label(str(tmp_path / "nonexistent.docx"), "label-123")

        assert result.success is False
        assert "not found" in result.error.lower()

    async def test_remove_label_nonexistent_file(self, tmp_path):
        """remove_label should fail for nonexistent file."""
        from openlabels.labeling.mip import MIPClient

        client = MIPClient(
            client_id="client",
            client_secret="secret",
            tenant_id="tenant",
        )
        client._initialized = True

        result = await client.remove_label(str(tmp_path / "nonexistent.docx"))

        assert result.success is False
        assert "not found" in result.error.lower()
