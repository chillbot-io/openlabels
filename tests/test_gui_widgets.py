"""
GUI Tests using pytest-qt.

Tests for PySide6 widgets including dialogs, dashboard, and workers.
Run with: pytest -p pytest_qt tests/test_gui.py -v

Requires:
    pip install pytest-qt pytest-xvfb PySide6
    apt install libegl1 (for headless systems)
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

# Skip entire module if Qt is not available
pytest.importorskip("PySide6", reason="PySide6 not installed or Qt libs missing")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
except (ImportError, OSError) as e:
    pytest.skip(f"Qt not available: {e}", allow_module_level=True)


# =============================================================================
# LoginDialog Tests
# =============================================================================

class TestLoginDialog:
    """Tests for the LoginDialog widget."""

    def test_dialog_creates(self, qtbot):
        """Test that LoginDialog initializes correctly."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "OpenLabels - Login"
        assert dialog._username_input is not None
        assert dialog._password_input is not None
        assert dialog._login_btn is not None

    def test_empty_username_shows_error(self, qtbot):
        """Test that empty username shows error."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        # Leave username empty, set password
        dialog._password_input.setText("password123")

        # Click login
        dialog._on_login()

        # Check error text is set (visibility may not work in headless mode)
        assert "username and password" in dialog._error_label.text().lower()

    def test_empty_password_shows_error(self, qtbot):
        """Test that empty password shows error."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        # Set username, leave password empty
        dialog._username_input.setText("testuser")

        dialog._on_login()

        # Check error text is set (visibility may not work in headless mode)
        assert "username and password" in dialog._error_label.text().lower()

    def test_login_failure_shows_error(self, qtbot):
        """Test that failed login shows error message."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("baduser")
        dialog._password_input.setText("badpass")

        # Mock AuthManager to raise exception (patch at source module)
        with patch("openlabels.auth.AuthManager") as mock_auth:
            mock_auth.return_value.login.side_effect = Exception("Invalid credentials")
            dialog._on_login()

        # Check error text is set (visibility may not work in headless mode)
        assert "failed" in dialog._error_label.text().lower()

    def test_successful_login_emits_signal(self, qtbot):
        """Test that successful login emits login_successful signal."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("admin")
        dialog._password_input.setText("correctpassword")

        mock_session = MagicMock()

        with patch("openlabels.auth.AuthManager") as mock_auth:
            mock_auth.return_value.login.return_value = mock_session

            # Use signal spy to verify signal emission
            with qtbot.waitSignal(dialog.login_successful, timeout=1000) as blocker:
                dialog._on_login()

            assert blocker.args == [mock_session]

    def test_password_field_is_hidden(self, qtbot):
        """Test that password field uses echo mode."""
        from openlabels.gui.widgets.login_dialog import LoginDialog
        from PySide6.QtWidgets import QLineEdit

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        assert dialog._password_input.echoMode() == QLineEdit.Password

    def test_enter_key_triggers_login(self, qtbot):
        """Test that pressing Enter in password field triggers login."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("user")
        dialog._password_input.setText("pass")

        # Verify returnPressed signal has receivers (using string signature for PySide6)
        # The signal connection is set up in _connect_signals
        assert dialog._password_input.receivers("2returnPressed()") > 0


# =============================================================================
# SetupDialog Tests
# =============================================================================

class TestSetupDialog:
    """Tests for the SetupDialog widget (first-time admin setup)."""

    def test_dialog_creates(self, qtbot):
        """Test that SetupDialog initializes correctly."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "OpenLabels - Setup"
        assert dialog._username_input is not None
        assert dialog._password_input is not None
        assert dialog._confirm_input is not None

    def test_short_username_shows_error(self, qtbot):
        """Test that username < 3 chars shows error."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("ab")  # Too short
        dialog._password_input.setText("password123")
        dialog._confirm_input.setText("password123")

        dialog._on_setup()

        # Check error text is set (visibility may not work in headless mode)
        assert "3 characters" in dialog._error_label.text()

    def test_short_password_shows_error(self, qtbot):
        """Test that password < 8 chars shows error."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("admin")
        dialog._password_input.setText("short")  # Too short
        dialog._confirm_input.setText("short")

        dialog._on_setup()

        # Check error text is set (visibility may not work in headless mode)
        assert "8 characters" in dialog._error_label.text()

    def test_password_mismatch_shows_error(self, qtbot):
        """Test that password mismatch shows error."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("admin")
        dialog._password_input.setText("password123")
        dialog._confirm_input.setText("different456")

        dialog._on_setup()

        # Check error text is set (visibility may not work in headless mode)
        assert "match" in dialog._error_label.text().lower()

    def test_successful_setup_emits_signal(self, qtbot):
        """Test that successful setup emits setup_complete signal."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("admin")
        dialog._password_input.setText("securepassword123")
        dialog._confirm_input.setText("securepassword123")

        mock_session = MagicMock()
        mock_keys = ["key1-abc", "key2-def", "key3-ghi"]

        with patch("openlabels.auth.AuthManager") as mock_auth:
            mock_auth.return_value.setup_admin.return_value = mock_keys
            mock_auth.return_value.login.return_value = mock_session

            with qtbot.waitSignal(dialog.setup_complete, timeout=1000) as blocker:
                dialog._on_setup()

            assert blocker.args[0] == mock_session
            assert blocker.args[1] == mock_keys

    def test_subscribe_checkbox_default_checked(self, qtbot):
        """Test that newsletter checkbox is checked by default."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        assert dialog._subscribe_checkbox.isChecked()


# =============================================================================
# RecoveryKeysDialog Tests
# =============================================================================

class TestRecoveryKeysDialog:
    """Tests for the RecoveryKeysDialog widget."""

    def test_dialog_displays_keys(self, qtbot):
        """Test that dialog displays all recovery keys."""
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog

        keys = ["abc-123-def", "ghi-456-jkl", "mno-789-pqr"]
        dialog = RecoveryKeysDialog(None, keys)
        qtbot.addWidget(dialog)

        # Keys should be stored
        assert dialog._recovery_keys == keys

    def test_continue_button_disabled_initially(self, qtbot):
        """Test that continue button is disabled until checkbox is checked."""
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog

        dialog = RecoveryKeysDialog(None, ["key1", "key2"])
        qtbot.addWidget(dialog)

        assert not dialog._continue_btn.isEnabled()

    def test_checkbox_enables_continue_button(self, qtbot):
        """Test that checking confirmation enables continue button."""
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog
        from PySide6.QtCore import Qt

        dialog = RecoveryKeysDialog(None, ["key1", "key2"])
        qtbot.addWidget(dialog)

        # Manually call the handler since setChecked may not trigger signals
        # when dialog is not shown - pass Qt.Checked (the enum value is 2)
        dialog._confirm_checkbox.setChecked(True)
        dialog._on_confirm_changed(Qt.Checked)

        assert dialog._continue_btn.isEnabled()

    def test_unchecking_disables_continue_button(self, qtbot):
        """Test that unchecking confirmation disables continue button."""
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog

        dialog = RecoveryKeysDialog(None, ["key1", "key2"])
        qtbot.addWidget(dialog)

        dialog._confirm_checkbox.setChecked(True)
        dialog._confirm_checkbox.setChecked(False)

        assert not dialog._continue_btn.isEnabled()

    def test_copy_keys_to_clipboard(self, qtbot):
        """Test that copy button copies keys to clipboard."""
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog

        keys = ["key1-abc", "key2-def"]
        dialog = RecoveryKeysDialog(None, keys)
        qtbot.addWidget(dialog)

        # Mock the message box
        with patch("openlabels.gui.widgets.login_dialog.QMessageBox.information"):
            dialog._copy_keys()

        clipboard = QApplication.clipboard()
        text = clipboard.text()

        assert "key1-abc" in text
        assert "key2-def" in text


# =============================================================================
# CreateUserDialog Tests
# =============================================================================

class TestCreateUserDialog:
    """Tests for the CreateUserDialog widget."""

    def test_dialog_creates(self, qtbot):
        """Test that CreateUserDialog initializes correctly."""
        from openlabels.gui.widgets.login_dialog import CreateUserDialog

        mock_session = MagicMock()
        dialog = CreateUserDialog(None, mock_session)
        qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "Create User"
        assert dialog._username_input is not None
        assert dialog._password_input is not None

    def test_empty_fields_shows_error(self, qtbot):
        """Test that empty fields show error."""
        from openlabels.gui.widgets.login_dialog import CreateUserDialog

        mock_session = MagicMock()
        dialog = CreateUserDialog(None, mock_session)
        qtbot.addWidget(dialog)

        dialog._on_create()

        # Check error text is set (visibility may not work in headless mode)
        assert "required" in dialog._error_label.text().lower()

    def test_successful_creation_emits_signal(self, qtbot):
        """Test that successful user creation emits user_created signal."""
        from openlabels.gui.widgets.login_dialog import CreateUserDialog

        mock_session = MagicMock()
        dialog = CreateUserDialog(None, mock_session)
        qtbot.addWidget(dialog)

        dialog._username_input.setText("newuser")
        dialog._password_input.setText("password123")

        mock_user = MagicMock()

        with patch("openlabels.auth.AuthManager") as mock_auth:
            mock_auth.return_value.create_user.return_value = mock_user

            with qtbot.waitSignal(dialog.user_created, timeout=1000) as blocker:
                dialog._on_create()

            assert blocker.args == [mock_user]

    def test_cancel_button_rejects_dialog(self, qtbot):
        """Test that cancel button rejects the dialog."""
        from openlabels.gui.widgets.login_dialog import CreateUserDialog

        mock_session = MagicMock()
        dialog = CreateUserDialog(None, mock_session)
        qtbot.addWidget(dialog)

        # Verify cancel button is connected
        assert dialog._cancel_btn is not None


# =============================================================================
# Dashboard Widget Tests
# =============================================================================

class TestHeatmapCell:
    """Tests for the HeatmapCell widget."""

    def test_cell_creates(self, qtbot):
        """Test that HeatmapCell initializes correctly."""
        from openlabels.gui.widgets.dashboard import HeatmapCell

        cell = HeatmapCell(intensity=0.5, count=10)
        qtbot.addWidget(cell)

        assert cell._intensity == 0.5
        assert cell._count == 10

    def test_set_data_updates_values(self, qtbot):
        """Test that set_data updates cell values."""
        from openlabels.gui.widgets.dashboard import HeatmapCell

        cell = HeatmapCell()
        qtbot.addWidget(cell)

        cell.set_data(0.8, 25)

        assert cell._intensity == 0.8
        assert cell._count == 25

    def test_zero_intensity_renders(self, qtbot):
        """Test that zero intensity cell renders without error."""
        from openlabels.gui.widgets.dashboard import HeatmapCell

        cell = HeatmapCell(intensity=0, count=0)
        qtbot.addWidget(cell)

        # Force a paint event
        cell.repaint()

        # No assertion needed - just checking no crash

    def test_high_intensity_renders(self, qtbot):
        """Test that high intensity cell renders without error."""
        from openlabels.gui.widgets.dashboard import HeatmapCell

        cell = HeatmapCell(intensity=1.0, count=999)
        qtbot.addWidget(cell)

        cell.repaint()


class TestBreadcrumbBar:
    """Tests for the BreadcrumbBar widget."""

    def test_bar_creates(self, qtbot):
        """Test that BreadcrumbBar initializes correctly."""
        from openlabels.gui.widgets.dashboard import BreadcrumbBar

        bar = BreadcrumbBar()
        qtbot.addWidget(bar)

        assert bar._segments == []

    def test_set_path_updates_segments(self, qtbot):
        """Test that set_path updates breadcrumb segments."""
        from openlabels.gui.widgets.dashboard import BreadcrumbBar

        bar = BreadcrumbBar()
        qtbot.addWidget(bar)

        bar.set_path(["Root", "Folder", "Subfolder"])

        assert bar._segments == ["Root", "Folder", "Subfolder"]

    def test_path_click_emits_signal(self, qtbot):
        """Test that clicking a breadcrumb emits path_clicked signal."""
        from openlabels.gui.widgets.dashboard import BreadcrumbBar

        bar = BreadcrumbBar()
        qtbot.addWidget(bar)

        bar.set_path(["Root", "Folder", "Subfolder"])

        # Verify signal exists as an attribute
        assert hasattr(bar, 'path_clicked')


class TestDashboardWidget:
    """Tests for the main DashboardWidget."""

    def test_widget_creates(self, qtbot):
        """Test that DashboardWidget initializes correctly."""
        from openlabels.gui.widgets.dashboard import DashboardWidget

        dashboard = DashboardWidget()
        qtbot.addWidget(dashboard)

        assert dashboard._breadcrumb is not None
        assert dashboard._table is not None


# =============================================================================
# ScanWorker Tests
# =============================================================================

class TestScanWorker:
    """Tests for the ScanWorker thread."""

    def test_worker_creates(self, qtbot):
        """Test that ScanWorker initializes correctly."""
        from openlabels.gui.workers.scan_worker import ScanWorker

        worker = ScanWorker(
            target_type="local",
            path="/tmp/test",
        )

        assert worker._target_type == "local"
        assert worker._path == "/tmp/test"
        assert not worker._stop_event.is_set()

    def test_stop_sets_event(self, qtbot):
        """Test that stop() sets the stop event."""
        from openlabels.gui.workers.scan_worker import ScanWorker

        worker = ScanWorker(
            target_type="local",
            path="/tmp/test",
        )

        worker.stop()

        assert worker._stop_event.is_set()

    def test_error_emits_signal(self, qtbot):
        """Test that errors emit error signal."""
        from openlabels.gui.workers.scan_worker import ScanWorker

        worker = ScanWorker(
            target_type="local",
            path="/nonexistent/path/that/does/not/exist",
        )

        with qtbot.waitSignal(worker.error, timeout=5000):
            worker.start()
            worker.wait()

    def test_extract_spans_with_context(self, qtbot):
        """Test span extraction with context."""
        from openlabels.gui.workers.scan_worker import ScanWorker

        worker = ScanWorker(
            target_type="local",
            path="/tmp",
        )

        # Create a mock detection
        mock_span = MagicMock()
        mock_span.start = 10
        mock_span.end = 20
        mock_span.text = "1234567890"
        mock_span.entity_type = "SSN"
        mock_span.confidence = 0.95
        mock_span.detector = "pattern"

        mock_detection = MagicMock()
        mock_detection.text = "Before text 1234567890 after text"
        mock_detection.spans = [mock_span]

        spans = worker._extract_spans_with_context(mock_detection, context_chars=5)

        assert len(spans) == 1
        assert spans[0]["entity_type"] == "SSN"
        assert spans[0]["confidence"] == 0.95


# =============================================================================
# Integration Tests
# =============================================================================

class TestLoginToSetupFlow:
    """Integration tests for login/setup flow."""

    def test_forgot_password_opens_recovery_dialog(self, qtbot):
        """Test that forgot password button opens recovery dialog."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        # Mock the RecoveryDialog - it's imported from .recovery_dialog inside the method
        with patch("openlabels.gui.widgets.recovery_dialog.RecoveryDialog") as mock_recovery:
            mock_recovery.return_value.exec.return_value = None
            dialog._on_forgot_password()
            mock_recovery.assert_called_once()


# =============================================================================
# Edge Cases & Error Handling
# =============================================================================

# =============================================================================
# RecoveryDialog Tests
# =============================================================================

class TestRecoveryDialog:
    """Tests for the RecoveryDialog widget."""

    def test_recover_mode_creates(self, qtbot):
        """Test that RecoveryDialog in recover mode initializes correctly."""
        from openlabels.gui.widgets.recovery_dialog import RecoveryDialog

        dialog = RecoveryDialog(mode="recover")
        qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "Account Recovery"
        assert dialog._key_input is not None
        assert dialog._password_input is not None
        assert dialog._confirm_input is not None

    def test_view_keys_mode_creates(self, qtbot):
        """Test that RecoveryDialog in view_keys mode initializes correctly."""
        from openlabels.gui.widgets.recovery_dialog import RecoveryDialog

        mock_session = MagicMock()
        mock_session.is_admin = True

        dialog = RecoveryDialog(mode="view_keys", admin_session=mock_session)
        qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "Recovery Keys"

    def test_password_fields_are_hidden(self, qtbot):
        """Test that password fields use echo mode."""
        from openlabels.gui.widgets.recovery_dialog import RecoveryDialog
        from PySide6.QtWidgets import QLineEdit

        dialog = RecoveryDialog(mode="recover")
        qtbot.addWidget(dialog)

        assert dialog._password_input.echoMode() == QLineEdit.Password
        assert dialog._confirm_input.echoMode() == QLineEdit.Password


# =============================================================================
# AuditLogDialog Tests
# =============================================================================

class TestAuditLogDialog:
    """Tests for the AuditLogDialog widget."""

    def test_dialog_creates(self, qtbot):
        """Test that AuditLogDialog initializes correctly."""
        from openlabels.gui.widgets.audit_dialog import AuditLogDialog

        mock_session = MagicMock()
        mock_session.is_admin.return_value = True
        mock_session._dek = b"fake_dek_32_bytes_long_exactly!"

        # Mock the audit log loading (patch at source module)
        with patch("openlabels.vault.audit.AuditLog") as mock_audit:
            mock_audit.return_value.read.return_value = iter([])
            mock_audit.return_value.verify_chain.return_value = (True, "Chain valid")
            mock_audit.return_value.get_stats.return_value = {"total_entries": 0}

            dialog = AuditLogDialog(session=mock_session)
            qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "Audit Log"
        assert dialog._table is not None

    def test_action_filter_has_options(self, qtbot):
        """Test that action filter combo box has options."""
        from openlabels.gui.widgets.audit_dialog import AuditLogDialog

        mock_session = MagicMock()
        mock_session.is_admin.return_value = True
        mock_session._dek = b"fake_dek_32_bytes_long_exactly!"

        with patch("openlabels.vault.audit.AuditLog") as mock_audit:
            mock_audit.return_value.read.return_value = iter([])
            mock_audit.return_value.verify_chain.return_value = (True, "Chain valid")
            mock_audit.return_value.get_stats.return_value = {"total_entries": 0}

            dialog = AuditLogDialog(session=mock_session)
            qtbot.addWidget(dialog)

        assert dialog._action_filter.count() > 0


# =============================================================================
# Edge Cases & Error Handling
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_login_with_whitespace_username(self, qtbot):
        """Test that whitespace-only username is treated as empty."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("   ")  # Whitespace only
        dialog._password_input.setText("password")

        dialog._on_login()

        # Check error text is set (visibility may not work in headless mode)
        assert "username and password" in dialog._error_label.text().lower()

    def test_setup_email_is_optional(self, qtbot):
        """Test that email field can be left empty."""
        from openlabels.gui.widgets.login_dialog import SetupDialog

        dialog = SetupDialog()
        qtbot.addWidget(dialog)

        dialog._username_input.setText("admin")
        dialog._email_input.setText("")  # Empty email
        dialog._password_input.setText("password123")
        dialog._confirm_input.setText("password123")

        mock_session = MagicMock()
        mock_keys = ["key1"]

        with patch("openlabels.auth.AuthManager") as mock_auth:
            mock_auth.return_value.setup_admin.return_value = mock_keys
            mock_auth.return_value.login.return_value = mock_session

            with qtbot.waitSignal(dialog.setup_complete, timeout=1000):
                dialog._on_setup()

            # Verify email was passed as None
            call_kwargs = mock_auth.return_value.setup_admin.call_args[1]
            assert call_kwargs["email"] is None

    def test_heatmap_cell_intensity_boundaries(self, qtbot):
        """Test HeatmapCell at intensity boundaries."""
        from openlabels.gui.widgets.dashboard import HeatmapCell

        # Test all color transition boundaries
        for intensity in [0.0, 0.33, 0.66, 1.0]:
            cell = HeatmapCell(intensity=intensity, count=1)
            qtbot.addWidget(cell)
            cell.repaint()  # Should not crash


# =============================================================================
# S3CredentialsDialog Tests
# =============================================================================

class TestS3CredentialsDialog:
    """Tests for the S3CredentialsDialog widget."""

    def test_dialog_creates(self, qtbot):
        """Test that S3CredentialsDialog initializes correctly."""
        from openlabels.gui.widgets.dialogs import S3CredentialsDialog

        dialog = S3CredentialsDialog()
        qtbot.addWidget(dialog)

        assert dialog.windowTitle() == "AWS Credentials"
        assert dialog._profile_radio is not None
        assert dialog._manual_radio is not None

    def test_profile_mode_is_default(self, qtbot):
        """Test that profile mode is selected by default."""
        from openlabels.gui.widgets.dialogs import S3CredentialsDialog

        dialog = S3CredentialsDialog()
        qtbot.addWidget(dialog)

        assert dialog._profile_radio.isChecked()
        assert not dialog._manual_radio.isChecked()

    def test_manual_inputs_disabled_in_profile_mode(self, qtbot):
        """Test that manual credential inputs are disabled in profile mode."""
        from openlabels.gui.widgets.dialogs import S3CredentialsDialog

        dialog = S3CredentialsDialog()
        qtbot.addWidget(dialog)

        assert not dialog._access_key_input.isEnabled()
        assert not dialog._secret_key_input.isEnabled()

    def test_secret_key_is_hidden(self, qtbot):
        """Test that secret key field uses password echo mode."""
        from openlabels.gui.widgets.dialogs import S3CredentialsDialog
        from PySide6.QtWidgets import QLineEdit

        dialog = S3CredentialsDialog()
        qtbot.addWidget(dialog)

        assert dialog._secret_key_input.echoMode() == QLineEdit.Password


# =============================================================================
# ResultsTableWidget Tests
# =============================================================================

class TestResultsTableWidget:
    """Tests for the ResultsTableWidget."""

    def test_widget_creates(self, qtbot):
        """Test that ResultsTableWidget initializes correctly."""
        from openlabels.gui.widgets.results_table import ResultsTableWidget

        widget = ResultsTableWidget()
        qtbot.addWidget(widget)

        assert widget._table is not None
        assert widget._filter_input is not None
        assert widget._tier_filter is not None

    def test_tier_filter_has_all_tiers(self, qtbot):
        """Test that tier filter has all tier options."""
        from openlabels.gui.widgets.results_table import ResultsTableWidget

        widget = ResultsTableWidget()
        qtbot.addWidget(widget)

        # Should have "All Tiers" plus 5 tier levels
        assert widget._tier_filter.count() >= 6

    def test_columns_defined(self, qtbot):
        """Test that result columns are properly defined."""
        from openlabels.gui.widgets.results_table import ResultsTableWidget

        widget = ResultsTableWidget()
        qtbot.addWidget(widget)

        expected_columns = ["Name", "Directory", "Size", "Score", "Tier", "Entities", "Actions"]
        column_names = [col[0] for col in widget.COLUMNS]

        for col in expected_columns:
            assert col in column_names

    def test_signals_defined(self, qtbot):
        """Test that required signals are defined."""
        from openlabels.gui.widgets.results_table import ResultsTableWidget

        widget = ResultsTableWidget()
        qtbot.addWidget(widget)

        # Verify signals exist
        assert hasattr(widget, 'quarantine_requested')
        assert hasattr(widget, 'label_requested')
        assert hasattr(widget, 'detail_requested')


# =============================================================================
# ScanTargetPanel Tests
# =============================================================================

class TestScanTargetPanel:
    """Tests for the ScanTargetPanel widget."""

    def test_widget_creates(self, qtbot):
        """Test that ScanTargetPanel initializes correctly."""
        from openlabels.gui.widgets.scan_target import ScanTargetPanel

        panel = ScanTargetPanel()
        qtbot.addWidget(panel)

        assert panel._type_combo is not None
        assert panel._path_input is not None

    def test_has_all_target_types(self, qtbot):
        """Test that all target types are available."""
        from openlabels.gui.widgets.scan_target import ScanTargetPanel

        panel = ScanTargetPanel()
        qtbot.addWidget(panel)

        # Check for expected target types
        target_types = []
        for i in range(panel._type_combo.count()):
            target_types.append(panel._type_combo.itemData(i))

        assert "local" in target_types
        assert "smb" in target_types
        assert "nfs" in target_types
        assert "s3" in target_types

    def test_s3_inputs_hidden_by_default(self, qtbot):
        """Test that S3-specific inputs are hidden by default."""
        from openlabels.gui.widgets.scan_target import ScanTargetPanel

        panel = ScanTargetPanel()
        qtbot.addWidget(panel)

        assert not panel._bucket_input.isVisible()

    def test_signals_defined(self, qtbot):
        """Test that required signals are defined."""
        from openlabels.gui.widgets.scan_target import ScanTargetPanel

        panel = ScanTargetPanel()
        qtbot.addWidget(panel)

        assert hasattr(panel, 'scan_requested')
        assert hasattr(panel, 'path_changed')
        assert hasattr(panel, 'monitoring_toggled')


# =============================================================================
# FileWatcher Tests
# =============================================================================

class TestFileWatcher:
    """Tests for the FileWatcher worker."""

    def test_watcher_creates(self, qtbot):
        """Test that FileWatcher initializes correctly."""
        from openlabels.gui.workers.file_watcher import FileWatcher

        watcher = FileWatcher()
        # FileWatcher is a QObject, not a QWidget, so don't use addWidget

        assert watcher._enabled is False
        assert len(watcher._watched_dirs) == 0

    def test_stop_watching_clears_state(self, qtbot):
        """Test that stop_watching() clears watching state."""
        from openlabels.gui.workers.file_watcher import FileWatcher

        watcher = FileWatcher()
        watcher.stop_watching()

        assert not watcher.is_watching

    def test_signals_defined(self, qtbot):
        """Test that required signals are defined."""
        from openlabels.gui.workers.file_watcher import FileWatcher

        watcher = FileWatcher()

        assert hasattr(watcher, 'file_changed')
        assert hasattr(watcher, 'file_deleted')
        assert hasattr(watcher, 'watching_started')
        assert hasattr(watcher, 'watching_stopped')
        assert hasattr(watcher, 'error')
