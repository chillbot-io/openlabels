"""
Login and signup dialogs for OpenLabels.

Provides:
- LoginDialog: User authentication
- SetupDialog: First-time admin setup
- CreateUserDialog: Admin creating new users
"""

from typing import Optional
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QCheckBox,
    QMessageBox,
    QFrame,
    QTextEdit,
    QWidget,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont


class LoginDialog(QDialog):
    """
    Login dialog for existing users.

    Emits login_successful signal with session on success.
    """

    login_successful = Signal(object)  # Emits Session

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("OpenLabels - Login")
        self.setMinimumWidth(400)
        self.setModal(True)

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Set up the login form UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Header
        header = QLabel("OpenLabels")
        header.setFont(QFont("Arial", 24, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        subtitle = QLabel("Universal Data Risk Scoring")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: gray;")
        layout.addWidget(subtitle)

        layout.addSpacing(20)

        # Form
        form = QFormLayout()
        form.setSpacing(12)

        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("Enter username")
        form.addRow("Username:", self._username_input)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Enter password")
        self._password_input.setEchoMode(QLineEdit.Password)
        form.addRow("Password:", self._password_input)

        layout.addLayout(form)

        # Error label (hidden by default)
        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: red;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        layout.addSpacing(10)

        # Buttons
        btn_layout = QHBoxLayout()

        self._forgot_btn = QPushButton("Forgot Password?")
        self._forgot_btn.setFlat(True)
        self._forgot_btn.setStyleSheet("color: #0066cc;")
        btn_layout.addWidget(self._forgot_btn)

        btn_layout.addStretch()

        self._login_btn = QPushButton("Login")
        self._login_btn.setDefault(True)
        self._login_btn.setMinimumWidth(100)
        btn_layout.addWidget(self._login_btn)

        layout.addLayout(btn_layout)

    def _connect_signals(self):
        """Connect UI signals."""
        self._login_btn.clicked.connect(self._on_login)
        self._forgot_btn.clicked.connect(self._on_forgot_password)
        self._password_input.returnPressed.connect(self._on_login)

    def _on_login(self):
        """Handle login attempt."""
        username = self._username_input.text().strip()
        password = self._password_input.text()

        if not username or not password:
            self._show_error("Please enter username and password")
            return

        try:
            from openlabels.auth import AuthManager
            auth = AuthManager()
            session = auth.login(username, password)
            self.login_successful.emit(session)
            self.accept()

        except Exception as e:
            self._show_error(f"Login failed: {str(e)}")

    def _on_forgot_password(self):
        """Handle forgot password - show recovery dialog."""
        from .recovery_dialog import RecoveryDialog
        dialog = RecoveryDialog(self, mode="recover")
        dialog.exec()

    def _show_error(self, message: str):
        """Show error message."""
        self._error_label.setText(message)
        self._error_label.setVisible(True)


class SetupDialog(QDialog):
    """
    First-time setup dialog for creating admin account.

    Shown when no users exist in the system.
    """

    setup_complete = Signal(object, list)  # Emits (Session, recovery_keys)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("OpenLabels - Setup")
        self.setMinimumWidth(500)
        self.setModal(True)

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Set up the setup form UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Header
        header = QLabel("Welcome to OpenLabels")
        header.setFont(QFont("Arial", 20, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        subtitle = QLabel("Let's set up your admin account")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: gray;")
        layout.addWidget(subtitle)

        layout.addSpacing(20)

        # Form
        form = QFormLayout()
        form.setSpacing(12)

        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("Choose a username")
        form.addRow("Username:", self._username_input)

        self._email_input = QLineEdit()
        self._email_input.setPlaceholderText("your@email.com (optional)")
        form.addRow("Email:", self._email_input)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Choose a strong password")
        self._password_input.setEchoMode(QLineEdit.Password)
        form.addRow("Password:", self._password_input)

        self._confirm_input = QLineEdit()
        self._confirm_input.setPlaceholderText("Confirm password")
        self._confirm_input.setEchoMode(QLineEdit.Password)
        form.addRow("Confirm:", self._confirm_input)

        layout.addLayout(form)

        # Newsletter opt-in (checked by default)
        self._subscribe_checkbox = QCheckBox("Keep me updated on OpenLabels")
        self._subscribe_checkbox.setChecked(True)
        self._subscribe_checkbox.setStyleSheet("margin-top: 10px;")
        layout.addWidget(self._subscribe_checkbox)

        # Error label
        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: red;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        layout.addSpacing(10)

        # Info box
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f7ff;
                border: 1px solid #cce0ff;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        info_layout = QVBoxLayout(info_frame)
        info_label = QLabel(
            "After setup, you'll receive recovery keys. "
            "Save them securely - they're needed if you forget your password."
        )
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        layout.addWidget(info_frame)

        layout.addSpacing(10)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._setup_btn = QPushButton("Create Admin Account")
        self._setup_btn.setDefault(True)
        self._setup_btn.setMinimumWidth(150)
        btn_layout.addWidget(self._setup_btn)

        layout.addLayout(btn_layout)

    def _connect_signals(self):
        """Connect UI signals."""
        self._setup_btn.clicked.connect(self._on_setup)

    def _on_setup(self):
        """Handle admin setup."""
        username = self._username_input.text().strip()
        email = self._email_input.text().strip() or None
        password = self._password_input.text()
        confirm = self._confirm_input.text()
        subscribe = self._subscribe_checkbox.isChecked()

        # Validation
        if not username:
            self._show_error("Username is required")
            return

        if len(username) < 3:
            self._show_error("Username must be at least 3 characters")
            return

        if not password:
            self._show_error("Password is required")
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

            # Create admin and get recovery keys
            recovery_keys = auth.setup_admin(
                username=username,
                password=password,
                email=email,
                subscribe_updates=subscribe,
            )

            # If email provided and subscribed, send to webhook
            if email and subscribe:
                self._send_email_webhook(email)

            # Login to get session
            session = auth.login(username, password)

            self.setup_complete.emit(session, recovery_keys)
            self.accept()

        except Exception as e:
            self._show_error(f"Setup failed: {str(e)}")

    def _send_email_webhook(self, email: str):
        """Send email to collection webhook."""
        try:
            import urllib.request
            import json
            import os

            webhook_url = os.environ.get(
                "OPENLABELS_EMAIL_WEBHOOK",
                "https://api.openlabels.dev/subscribe"  # Placeholder
            )

            data = json.dumps({"email": email, "source": "desktop_setup"}).encode()
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )

            # Non-blocking, ignore failures
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass  # Silent failure - don't block setup

        except Exception:
            pass  # Silent failure

    def _show_error(self, message: str):
        """Show error message."""
        self._error_label.setText(message)
        self._error_label.setVisible(True)


class RecoveryKeysDialog(QDialog):
    """
    Dialog to display recovery keys after admin setup.

    User must acknowledge they've saved the keys before proceeding.
    """

    def __init__(
        self,
        parent: Optional[QWidget],
        recovery_keys: list[str],
    ):
        super().__init__(parent)
        self.setWindowTitle("Save Your Recovery Keys")
        self.setMinimumWidth(500)
        self.setModal(True)

        self._recovery_keys = recovery_keys
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Set up the UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Warning header
        header = QLabel("Save These Recovery Keys")
        header.setFont(QFont("Arial", 18, QFont.Bold))
        header.setStyleSheet("color: #cc6600;")
        layout.addWidget(header)

        warning = QLabel(
            "These keys are the ONLY way to recover your account if you forget "
            "your password. Save them in a secure location (password manager, "
            "printed copy in a safe, etc.)."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #666;")
        layout.addWidget(warning)

        layout.addSpacing(10)

        # Recovery keys display
        keys_frame = QFrame()
        keys_frame.setStyleSheet("""
            QFrame {
                background-color: #fffef0;
                border: 2px solid #e6d86e;
                border-radius: 4px;
                padding: 16px;
            }
        """)
        keys_layout = QVBoxLayout(keys_frame)

        for i, key in enumerate(self._recovery_keys, 1):
            key_label = QLabel(f"Key {i}: {key}")
            key_label.setFont(QFont("Courier", 12))
            key_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            keys_layout.addWidget(key_label)

        layout.addWidget(keys_frame)

        # Copy button
        copy_btn = QPushButton("Copy All Keys to Clipboard")
        copy_btn.clicked.connect(self._copy_keys)
        layout.addWidget(copy_btn)

        layout.addSpacing(10)

        # Confirmation checkbox
        self._confirm_checkbox = QCheckBox(
            "I have saved these recovery keys in a secure location"
        )
        layout.addWidget(self._confirm_checkbox)

        # Continue button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._continue_btn = QPushButton("Continue")
        self._continue_btn.setEnabled(False)
        self._continue_btn.setMinimumWidth(100)
        btn_layout.addWidget(self._continue_btn)

        layout.addLayout(btn_layout)

    def _connect_signals(self):
        """Connect signals."""
        self._confirm_checkbox.stateChanged.connect(self._on_confirm_changed)
        self._continue_btn.clicked.connect(self.accept)

    def _on_confirm_changed(self, state: int):
        """Enable continue button when confirmed."""
        self._continue_btn.setEnabled(state == Qt.Checked)

    def _copy_keys(self):
        """Copy recovery keys to clipboard."""
        from PySide6.QtWidgets import QApplication
        text = "\n".join(
            f"Key {i}: {key}"
            for i, key in enumerate(self._recovery_keys, 1)
        )
        QApplication.clipboard().setText(text)
        QMessageBox.information(
            self,
            "Copied",
            "Recovery keys copied to clipboard. Paste them somewhere secure!"
        )


class CreateUserDialog(QDialog):
    """
    Dialog for admin to create new users.
    """

    user_created = Signal(object)  # Emits User

    def __init__(
        self,
        parent: Optional[QWidget],
        admin_session: "Session",
    ):
        super().__init__(parent)
        self.setWindowTitle("Create User")
        self.setMinimumWidth(400)
        self.setModal(True)

        self._admin_session = admin_session
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Set up the UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Form
        form = QFormLayout()
        form.setSpacing(12)

        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("New user's username")
        form.addRow("Username:", self._username_input)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Initial password")
        self._password_input.setEchoMode(QLineEdit.Password)
        form.addRow("Password:", self._password_input)

        layout.addLayout(form)

        # Error label
        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: red;")
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # Buttons
        btn_layout = QHBoxLayout()

        self._cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self._cancel_btn)

        btn_layout.addStretch()

        self._create_btn = QPushButton("Create User")
        self._create_btn.setDefault(True)
        btn_layout.addWidget(self._create_btn)

        layout.addLayout(btn_layout)

    def _connect_signals(self):
        """Connect signals."""
        self._cancel_btn.clicked.connect(self.reject)
        self._create_btn.clicked.connect(self._on_create)

    def _on_create(self):
        """Handle user creation."""
        username = self._username_input.text().strip()
        password = self._password_input.text()

        if not username or not password:
            self._show_error("Username and password are required")
            return

        try:
            from openlabels.auth import AuthManager
            auth = AuthManager()
            user = auth.create_user(
                admin_session=self._admin_session,
                username=username,
                password=password,
            )
            self.user_created.emit(user)
            self.accept()

        except Exception as e:
            self._show_error(str(e))

    def _show_error(self, message: str):
        """Show error message."""
        self._error_label.setText(message)
        self._error_label.setVisible(True)
