"""
Recovery dialog for admin account recovery.

Allows admin to recover account using recovery key when password is forgotten.
"""

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from openlabels.auth.models import Session

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QFrame,
    QWidget,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont


class RecoveryDialog(QDialog):
    """
    Account recovery dialog.

    Two modes:
    - "recover": Enter recovery key and new password
    - "view_keys": Display existing recovery keys (admin only)
    """

    recovery_successful = Signal(object)  # Emits Session

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        mode: str = "recover",
        admin_session: Optional["Session"] = None,
    ):
        super().__init__(parent)
        self._mode = mode
        self._admin_session = admin_session

        if mode == "recover":
            self.setWindowTitle("Account Recovery")
            self._setup_recovery_ui()
        else:
            self.setWindowTitle("Recovery Keys")
            self._setup_view_keys_ui()

        self.setMinimumWidth(450)
        self.setModal(True)

    def _setup_recovery_ui(self):
        """Set up recovery form UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Header
        header = QLabel("Recover Your Account")
        header.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(header)

        instructions = QLabel(
            "Enter one of your recovery keys and choose a new password."
        )
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #666;")
        layout.addWidget(instructions)

        layout.addSpacing(10)

        # Form
        form = QFormLayout()
        form.setSpacing(12)

        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        self._key_input.setFont(QFont("Courier", 11))
        form.addRow("Recovery Key:", self._key_input)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("New password")
        self._password_input.setEchoMode(QLineEdit.Password)
        form.addRow("New Password:", self._password_input)

        self._confirm_input = QLineEdit()
        self._confirm_input.setPlaceholderText("Confirm new password")
        self._confirm_input.setEchoMode(QLineEdit.Password)
        form.addRow("Confirm:", self._confirm_input)

        layout.addLayout(form)

        # Error label
        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: red;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # Info box
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background-color: #fff0f0;
                border: 1px solid #ffcccc;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        info_layout = QVBoxLayout(info_frame)
        info_label = QLabel(
            "Note: After recovery, you should generate new recovery keys "
            "from Settings. The used recovery key will be marked as used."
        )
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        layout.addWidget(info_frame)

        layout.addSpacing(10)

        # Buttons
        btn_layout = QHBoxLayout()

        self._cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self._cancel_btn)

        btn_layout.addStretch()

        self._recover_btn = QPushButton("Recover Account")
        self._recover_btn.setDefault(True)
        btn_layout.addWidget(self._recover_btn)

        layout.addLayout(btn_layout)

        # Connect signals
        self._cancel_btn.clicked.connect(self.reject)
        self._recover_btn.clicked.connect(self._on_recover)

    def _setup_view_keys_ui(self):
        """Set up view keys UI (for admin viewing their recovery keys status)."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Header
        header = QLabel("Recovery Key Status")
        header.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(header)

        # Key status (will be populated)
        self._keys_frame = QFrame()
        self._keys_frame.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 12px;
            }
        """)
        self._keys_layout = QVBoxLayout(self._keys_frame)
        layout.addWidget(self._keys_frame)

        # Regenerate button
        regen_layout = QHBoxLayout()
        regen_layout.addStretch()

        self._regen_btn = QPushButton("Regenerate Recovery Keys")
        self._regen_btn.setStyleSheet("color: #cc6600;")
        regen_layout.addWidget(self._regen_btn)

        layout.addLayout(regen_layout)

        layout.addSpacing(10)

        # Close button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

        # Connect signals
        self._regen_btn.clicked.connect(self._on_regenerate)

        # Load key status
        self._load_key_status()

    def _load_key_status(self):
        """Load and display recovery key status."""
        if not self._admin_session:
            return

        try:
            from openlabels.auth import AuthManager
            auth = AuthManager()

            # Get key status (not the actual keys)
            key_status = auth._recovery.get_key_status(self._admin_session.user.id)

            # Clear existing
            while self._keys_layout.count():
                item = self._keys_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            if not key_status:
                label = QLabel("No recovery keys configured")
                label.setStyleSheet("color: red;")
                self._keys_layout.addWidget(label)
                return

            for key in key_status:
                status = "Used" if key["used"] else "Available"
                color = "#cc0000" if key["used"] else "#008800"

                label = QLabel(
                    f"Key {key['key_id']}: {status} "
                    f"(created {key['created_at'][:10]})"
                )
                label.setStyleSheet(f"color: {color};")
                self._keys_layout.addWidget(label)

        except Exception as e:
            error = QLabel(f"Error loading keys: {e}")
            error.setStyleSheet("color: red;")
            self._keys_layout.addWidget(error)

    def _on_recover(self):
        """Handle recovery attempt."""
        recovery_key = self._key_input.text().strip()
        password = self._password_input.text()
        confirm = self._confirm_input.text()

        # Validation
        if not recovery_key:
            self._show_error("Recovery key is required")
            return

        if not password:
            self._show_error("New password is required")
            return

        if len(password) < 8:
            self._show_error("Password must be at least 8 characters")
            return

        if password != confirm:
            self._show_error("Passwords do not match")
            return

        try:
            from openlabels.auth import AuthManager
            auth = AuthManager()

            success = auth.recover_with_key(recovery_key, password)

            if success:
                # Get admin user and login
                # Note: recover_with_key should have updated credentials
                # We need to find the admin user and login
                for user in auth._users.list_users():
                    if user.is_admin():
                        session = auth.login(user.username, password)
                        self.recovery_successful.emit(session)
                        self.accept()
                        return

                self._show_error("Recovery succeeded but login failed")
            else:
                self._show_error("Invalid recovery key")

        except Exception as e:
            self._show_error(f"Recovery failed: {str(e)}")

    def _on_regenerate(self):
        """Handle recovery key regeneration."""
        from PySide6.QtWidgets import QMessageBox

        reply = QMessageBox.warning(
            self,
            "Regenerate Recovery Keys",
            "This will invalidate your current recovery keys. "
            "You will receive new keys that must be saved securely.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply != QMessageBox.Yes:
            return

        try:
            from openlabels.auth import AuthManager
            auth = AuthManager()

            # Get the DEK from session
            dek = self._admin_session._dek
            if not dek:
                raise RuntimeError("Session has no decryption key")

            # Regenerate keys
            new_keys = auth._recovery.regenerate_keys(
                self._admin_session.user,
                dek,
            )

            # Show new keys dialog
            from .login_dialog import RecoveryKeysDialog
            dialog = RecoveryKeysDialog(self, new_keys)
            dialog.exec()

            # Refresh display
            self._load_key_status()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to regenerate keys: {str(e)}",
            )

    def _show_error(self, message: str):
        """Show error message."""
        self._error_label.setText(message)
        self._error_label.setVisible(True)
