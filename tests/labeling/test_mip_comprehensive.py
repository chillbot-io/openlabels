"""
Comprehensive tests for MIP SDK integration.

Tests cover:
- Assembly loading checks
- Pythonnet availability handling
- MIPClient initialization and lifecycle
- Label operations (get, apply, remove)
- Authentication delegate
- Error handling paths
- Thread pool executor usage

Note: MIP SDK tests use mocks since the actual SDK requires Windows/.NET.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from openlabels.labeling.mip import (
    PYTHONNET_AVAILABLE,
    SensitivityLabel,
    LabelingResult,
    AuthDelegateImpl,
    MIPClient,
    is_mip_available,
    _load_mip_assemblies,
)


class TestPythonnetAvailability:
    """Tests for pythonnet availability checks."""

    def test_pythonnet_available_is_boolean(self):
        """PYTHONNET_AVAILABLE is a boolean."""
        assert isinstance(PYTHONNET_AVAILABLE, bool)

    def test_is_mip_available_returns_boolean(self):
        """is_mip_available returns boolean."""
        result = is_mip_available()
        assert isinstance(result, bool)
        assert result == PYTHONNET_AVAILABLE


class TestLoadMipAssemblies:
    """Tests for MIP assembly loading."""

    def test_load_assemblies_returns_true_if_already_loaded(self):
        """Returns True if assemblies already loaded."""
        import openlabels.labeling.mip as mip_module

        original = mip_module._MIP_ASSEMBLIES_LOADED

        try:
            mip_module._MIP_ASSEMBLIES_LOADED = True
            result = _load_mip_assemblies(Path("/fake/path"))
            assert result is True
        finally:
            mip_module._MIP_ASSEMBLIES_LOADED = original

    def test_load_assemblies_returns_false_without_pythonnet(self):
        """Returns False if pythonnet not available."""
        import openlabels.labeling.mip as mip_module

        original_loaded = mip_module._MIP_ASSEMBLIES_LOADED
        original_available = mip_module.PYTHONNET_AVAILABLE

        try:
            mip_module._MIP_ASSEMBLIES_LOADED = False
            mip_module.PYTHONNET_AVAILABLE = False

            result = _load_mip_assemblies(Path("/fake/path"))
            assert result is False
        finally:
            mip_module._MIP_ASSEMBLIES_LOADED = original_loaded
            mip_module.PYTHONNET_AVAILABLE = original_available

    def test_load_assemblies_returns_false_for_missing_path(self, tmp_path):
        """Returns False if SDK path doesn't exist."""
        import openlabels.labeling.mip as mip_module

        original_loaded = mip_module._MIP_ASSEMBLIES_LOADED
        original_available = mip_module.PYTHONNET_AVAILABLE

        try:
            mip_module._MIP_ASSEMBLIES_LOADED = False
            mip_module.PYTHONNET_AVAILABLE = True

            # Path that doesn't exist
            nonexistent = tmp_path / "nonexistent"
            result = _load_mip_assemblies(nonexistent)
            assert result is False
        finally:
            mip_module._MIP_ASSEMBLIES_LOADED = original_loaded
            mip_module.PYTHONNET_AVAILABLE = original_available

    def test_load_assemblies_returns_false_for_none_path(self):
        """Returns False if SDK path is None."""
        import openlabels.labeling.mip as mip_module

        original_loaded = mip_module._MIP_ASSEMBLIES_LOADED
        original_available = mip_module.PYTHONNET_AVAILABLE

        try:
            mip_module._MIP_ASSEMBLIES_LOADED = False
            mip_module.PYTHONNET_AVAILABLE = True

            result = _load_mip_assemblies(None)
            assert result is False
        finally:
            mip_module._MIP_ASSEMBLIES_LOADED = original_loaded
            mip_module.PYTHONNET_AVAILABLE = original_available


class TestSensitivityLabel:
    """Tests for SensitivityLabel dataclass."""

    def test_sensitivity_label_required_fields(self):
        """SensitivityLabel requires id, name, description, tooltip."""
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

    def test_sensitivity_label_optional_fields(self):
        """SensitivityLabel has optional fields with defaults."""
        label = SensitivityLabel(
            id="label-1",
            name="Test",
            description="Test desc",
            tooltip="Test tooltip",
        )

        assert label.color is None
        assert label.priority == 0
        assert label.parent_id is None
        assert label.is_active is True

    def test_sensitivity_label_with_all_fields(self):
        """SensitivityLabel accepts all fields."""
        label = SensitivityLabel(
            id="label-456",
            name="Highly Confidential",
            description="For highly confidential data",
            tooltip="Apply to HC data",
            color="#FF0000",
            priority=10,
            parent_id="parent-123",
            is_active=True,
        )

        assert label.color == "#FF0000"
        assert label.priority == 10
        assert label.parent_id == "parent-123"

    def test_sensitivity_label_to_dict(self):
        """to_dict returns all fields."""
        label = SensitivityLabel(
            id="label-789",
            name="Public",
            description="Public data",
            tooltip="For public info",
            color="#00FF00",
            priority=1,
            parent_id=None,
            is_active=True,
        )

        d = label.to_dict()

        assert d["id"] == "label-789"
        assert d["name"] == "Public"
        assert d["description"] == "Public data"
        assert d["tooltip"] == "For public info"
        assert d["color"] == "#00FF00"
        assert d["priority"] == 1
        assert d["parent_id"] is None
        assert d["is_active"] is True


class TestLabelingResult:
    """Tests for LabelingResult dataclass."""

    def test_labeling_result_success(self):
        """LabelingResult for successful operation."""
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

    def test_labeling_result_failure(self):
        """LabelingResult for failed operation."""
        result = LabelingResult(
            success=False,
            file_path="/path/to/file.docx",
            error="File not found",
        )

        assert result.success is False
        assert result.error == "File not found"

    def test_labeling_result_protection_flags(self):
        """LabelingResult has protection status flags."""
        result = LabelingResult(
            success=True,
            file_path="/path/file.docx",
            was_protected=True,
            is_protected=True,
        )

        assert result.was_protected is True
        assert result.is_protected is True

    def test_labeling_result_to_dict(self):
        """to_dict returns all fields."""
        result = LabelingResult(
            success=True,
            file_path="/path/file.docx",
            label_id="label-1",
            label_name="Test",
            error=None,
            was_protected=False,
            is_protected=True,
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["file_path"] == "/path/file.docx"
        assert d["label_id"] == "label-1"
        assert d["label_name"] == "Test"
        assert d["was_protected"] is False
        assert d["is_protected"] is True


class TestAuthDelegateImpl:
    """Tests for AuthDelegateImpl class."""

    def test_auth_delegate_init(self):
        """AuthDelegateImpl stores credentials."""
        delegate = AuthDelegateImpl(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
        )

        assert delegate.client_id == "client-123"
        assert delegate.client_secret == "secret-456"
        assert delegate.tenant_id == "tenant-789"
        assert delegate._app is None

    def test_auth_delegate_get_msal_app_creates_app(self):
        """_get_msal_app creates MSAL app on first call."""
        delegate = AuthDelegateImpl(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
        )

        with patch("msal.ConfidentialClientApplication") as mock_msal:
            mock_app = MagicMock()
            mock_msal.return_value = mock_app

            result = delegate._get_msal_app()

            assert result == mock_app
            mock_msal.assert_called_once()

    def test_auth_delegate_get_msal_app_caches_app(self):
        """_get_msal_app returns cached app on subsequent calls."""
        delegate = AuthDelegateImpl(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
        )

        mock_app = MagicMock()
        delegate._app = mock_app

        result = delegate._get_msal_app()

        assert result is mock_app

    def test_auth_delegate_acquire_token_success(self):
        """acquire_token returns token on success."""
        delegate = AuthDelegateImpl(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
        )

        mock_app = MagicMock()
        mock_app.acquire_token_for_client.return_value = {"access_token": "test-token"}

        with patch.object(delegate, "_get_msal_app", return_value=mock_app):
            result = delegate.acquire_token("identity", None)

        assert result == "test-token"

    def test_auth_delegate_acquire_token_failure(self):
        """acquire_token returns empty string on failure."""
        delegate = AuthDelegateImpl(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
        )

        mock_app = MagicMock()
        mock_app.acquire_token_for_client.return_value = {
            "error_description": "Invalid credentials"
        }

        with patch.object(delegate, "_get_msal_app", return_value=mock_app):
            result = delegate.acquire_token("identity", None)

        assert result == ""

    def test_auth_delegate_acquire_token_msal_not_installed(self):
        """acquire_token returns empty string if msal not installed."""
        delegate = AuthDelegateImpl(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
        )

        with patch.object(delegate, "_get_msal_app", side_effect=ImportError("msal not found")):
            result = delegate.acquire_token("identity", None)

        assert result == ""


class TestMIPClientInit:
    """Tests for MIPClient initialization."""

    def test_mip_client_init(self):
        """MIPClient stores credentials and settings."""
        client = MIPClient(
            client_id="client-123",
            client_secret="secret-456",
            tenant_id="tenant-789",
            app_name="TestApp",
            app_version="1.0.0",
        )

        assert client.client_id == "client-123"
        assert client.client_secret == "secret-456"
        assert client.tenant_id == "tenant-789"
        assert client.app_name == "TestApp"
        assert client.app_version == "1.0.0"
        assert client._initialized is False

    def test_mip_client_default_sdk_path(self):
        """MIPClient has default SDK path."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        assert client.mip_sdk_path is not None
        assert isinstance(client.mip_sdk_path, Path)

    def test_mip_client_custom_sdk_path(self, tmp_path):
        """MIPClient accepts custom SDK path."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
            mip_sdk_path=tmp_path,
        )

        assert client.mip_sdk_path == tmp_path

    def test_mip_client_is_available_property(self):
        """is_available reflects pythonnet availability."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        assert client.is_available == PYTHONNET_AVAILABLE

    def test_mip_client_is_initialized_initially_false(self):
        """is_initialized is False initially."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        assert client.is_initialized is False


class TestMIPClientInitialize:
    """Tests for MIPClient.initialize method."""

    @pytest.mark.asyncio
    async def test_initialize_returns_false_without_pythonnet(self):
        """initialize returns False if pythonnet not available."""
        import openlabels.labeling.mip as mip_module

        original = mip_module.PYTHONNET_AVAILABLE

        try:
            mip_module.PYTHONNET_AVAILABLE = False

            client = MIPClient(
                client_id="c",
                client_secret="s",
                tenant_id="t",
            )

            result = await client.initialize()

            assert result is False
        finally:
            mip_module.PYTHONNET_AVAILABLE = original

    @pytest.mark.asyncio
    async def test_initialize_returns_true_if_already_initialized(self):
        """initialize returns True if already initialized."""
        import openlabels.labeling.mip as mip_module

        original_available = mip_module.PYTHONNET_AVAILABLE

        try:
            # Need to mock PYTHONNET_AVAILABLE as True to get past the first check
            mip_module.PYTHONNET_AVAILABLE = True

            client = MIPClient(
                client_id="c",
                client_secret="s",
                tenant_id="t",
            )
            client._initialized = True

            result = await client.initialize()

            assert result is True
        finally:
            mip_module.PYTHONNET_AVAILABLE = original_available

    @pytest.mark.asyncio
    async def test_initialize_calls_load_assemblies(self):
        """initialize attempts to load assemblies."""
        import openlabels.labeling.mip as mip_module

        original = mip_module.PYTHONNET_AVAILABLE

        try:
            mip_module.PYTHONNET_AVAILABLE = True

            client = MIPClient(
                client_id="c",
                client_secret="s",
                tenant_id="t",
            )

            with patch("openlabels.labeling.mip._load_mip_assemblies", return_value=False) as mock_load:
                result = await client.initialize()

                mock_load.assert_called_once()
                assert result is False
        finally:
            mip_module.PYTHONNET_AVAILABLE = original


class TestMIPClientShutdown:
    """Tests for MIPClient.shutdown method."""

    @pytest.mark.asyncio
    async def test_shutdown_clears_state(self):
        """shutdown clears internal state."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True
        client._file_engine = MagicMock()
        client._file_profile = MagicMock()
        client._mip_context = MagicMock()

        # Mock the executor
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=None)

            await client.shutdown()

        assert client._initialized is False
        assert client._file_engine is None
        assert client._file_profile is None
        assert client._mip_context is None

    @pytest.mark.asyncio
    async def test_shutdown_handles_no_engine(self):
        """shutdown handles case where no engine exists."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        # Should not raise
        await client.shutdown()

        assert client._initialized is False


class TestMIPClientGetLabels:
    """Tests for MIPClient.get_labels method."""

    @pytest.mark.asyncio
    async def test_get_labels_returns_empty_if_not_initialized(self):
        """get_labels returns empty list if not initialized."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        labels = await client.get_labels()

        assert labels == []

    @pytest.mark.asyncio
    async def test_get_labels_returns_cached_if_available(self):
        """get_labels returns cached labels if available."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True
        client._labels = [
            SensitivityLabel(id="1", name="Label 1", description="", tooltip=""),
            SensitivityLabel(id="2", name="Label 2", description="", tooltip=""),
        ]

        labels = await client.get_labels(force_refresh=False)

        assert len(labels) == 2

    @pytest.mark.asyncio
    async def test_get_labels_force_refresh(self):
        """get_labels fetches fresh labels when force_refresh=True."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True
        client._labels = [SensitivityLabel(id="old", name="Old", description="", tooltip="")]

        new_labels = [SensitivityLabel(id="new", name="New", description="", tooltip="")]

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=new_labels)

            labels = await client.get_labels(force_refresh=True)

        assert len(labels) == 1
        assert labels[0].id == "new"


class TestMIPClientGetLabel:
    """Tests for MIPClient.get_label method."""

    @pytest.mark.asyncio
    async def test_get_label_finds_by_id(self):
        """get_label finds label by ID."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True
        client._labels = [
            SensitivityLabel(id="label-123", name="Target", description="", tooltip=""),
            SensitivityLabel(id="label-456", name="Other", description="", tooltip=""),
        ]

        label = await client.get_label("label-123")

        assert label is not None
        assert label.id == "label-123"

    @pytest.mark.asyncio
    async def test_get_label_returns_none_if_not_found(self):
        """get_label returns None if label not found."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True
        client._labels = []

        label = await client.get_label("nonexistent")

        assert label is None


class TestMIPClientApplyLabel:
    """Tests for MIPClient.apply_label method."""

    @pytest.mark.asyncio
    async def test_apply_label_returns_error_if_not_initialized(self):
        """apply_label returns error if not initialized."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        result = await client.apply_label("/path/file.docx", "label-123")

        assert result.success is False
        assert "not initialized" in result.error

    @pytest.mark.asyncio
    async def test_apply_label_returns_error_if_file_not_found(self, tmp_path):
        """apply_label returns error if file doesn't exist."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True

        nonexistent = tmp_path / "nonexistent.docx"

        result = await client.apply_label(str(nonexistent), "label-123")

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_apply_label_success(self, tmp_path):
        """apply_label succeeds with valid file."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True

        test_file = tmp_path / "test.docx"
        test_file.write_text("test content")

        mock_result = LabelingResult(
            success=True,
            file_path=str(test_file),
            label_id="label-123",
            label_name="Confidential",
        )

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=mock_result)

            result = await client.apply_label(str(test_file), "label-123")

        assert result.success is True

    @pytest.mark.asyncio
    async def test_apply_label_handles_permission_error(self, tmp_path):
        """apply_label handles permission errors."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True

        test_file = tmp_path / "test.docx"
        test_file.write_text("test content")

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(
                side_effect=PermissionError("Access denied")
            )

            result = await client.apply_label(str(test_file), "label-123")

        assert result.success is False
        assert "Permission denied" in result.error


class TestMIPClientRemoveLabel:
    """Tests for MIPClient.remove_label method."""

    @pytest.mark.asyncio
    async def test_remove_label_returns_error_if_not_initialized(self):
        """remove_label returns error if not initialized."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        result = await client.remove_label("/path/file.docx")

        assert result.success is False
        assert "not initialized" in result.error

    @pytest.mark.asyncio
    async def test_remove_label_returns_error_if_file_not_found(self, tmp_path):
        """remove_label returns error if file doesn't exist."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True

        nonexistent = tmp_path / "nonexistent.docx"

        result = await client.remove_label(str(nonexistent))

        assert result.success is False
        assert "not found" in result.error.lower()


class TestMIPClientGetFileLabel:
    """Tests for MIPClient.get_file_label method."""

    @pytest.mark.asyncio
    async def test_get_file_label_returns_none_if_not_initialized(self):
        """get_file_label returns None if not initialized."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        result = await client.get_file_label("/path/file.docx")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_file_label_returns_none_if_file_not_found(self, tmp_path):
        """get_file_label returns None if file doesn't exist."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True

        nonexistent = tmp_path / "nonexistent.docx"

        result = await client.get_file_label(str(nonexistent))

        assert result is None


class TestMIPClientIsFileProtected:
    """Tests for MIPClient.is_file_protected method."""

    @pytest.mark.asyncio
    async def test_is_file_protected_returns_false_if_not_initialized(self):
        """is_file_protected returns False if not initialized."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        result = await client.is_file_protected("/path/file.docx")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_file_protected_returns_false_if_file_not_found(self, tmp_path):
        """is_file_protected returns False if file doesn't exist."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )
        client._initialized = True

        nonexistent = tmp_path / "nonexistent.docx"

        result = await client.is_file_protected(str(nonexistent))

        assert result is False


class TestMIPClientDefaultSdkPath:
    """Tests for default SDK path determination."""

    def test_default_sdk_path_windows(self):
        """Default path on Windows uses LOCALAPPDATA."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        with patch("sys.platform", "win32"):
            with patch.dict("os.environ", {"LOCALAPPDATA": "C:\\Users\\Test\\AppData\\Local"}):
                path = client._default_sdk_path()

        # Path should end with MIP/SDK
        assert "MIP" in str(path) or "mip" in str(path).lower()

    def test_default_sdk_path_linux(self):
        """Default path on Linux uses home directory."""
        client = MIPClient(
            client_id="c",
            client_secret="s",
            tenant_id="t",
        )

        with patch("sys.platform", "linux"):
            path = client._default_sdk_path()

        # Path should be under home
        assert ".mip" in str(path) or "mip" in str(path).lower()
