"""
Dialog windows for OpenLabels GUI.

Includes:
- S3CredentialsDialog
- SettingsDialog
- LabelDialog
- QuarantineConfirmDialog
"""

from pathlib import Path
from typing import Optional, Dict, List

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGridLayout,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QSpinBox,
    QPushButton,
    QLabel,
    QGroupBox,
    QRadioButton,
    QButtonGroup,
    QFileDialog,
    QMessageBox,
    QDialogButtonBox,
    QTabWidget,
    QWidget,
)
from PySide6.QtCore import Qt, QSettings


class S3CredentialsDialog(QDialog):
    """Dialog for entering AWS S3 credentials."""

    def __init__(self, parent=None, current_credentials: Optional[Dict[str, str]] = None):
        super().__init__(parent)
        self.setWindowTitle("AWS Credentials")
        self.setMinimumWidth(450)
        self._credentials: Optional[Dict[str, str]] = current_credentials
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Mode selection
        mode_group = QGroupBox("Authentication Method")
        mode_layout = QVBoxLayout(mode_group)

        self._mode_group = QButtonGroup(self)

        self._profile_radio = QRadioButton("Use existing AWS profile")
        self._manual_radio = QRadioButton("Enter credentials manually")
        self._mode_group.addButton(self._profile_radio, 0)
        self._mode_group.addButton(self._manual_radio, 1)
        self._profile_radio.setChecked(True)

        mode_layout.addWidget(self._profile_radio)

        # Profile selector
        profile_layout = QHBoxLayout()
        profile_layout.addSpacing(20)
        profile_layout.addWidget(QLabel("Profile:"))
        self._profile_combo = QComboBox()
        self._profile_combo.setMinimumWidth(200)
        self._load_aws_profiles()
        profile_layout.addWidget(self._profile_combo)
        profile_layout.addStretch()
        mode_layout.addLayout(profile_layout)

        mode_layout.addWidget(self._manual_radio)

        # Manual credentials
        manual_form = QFormLayout()
        manual_form.setContentsMargins(20, 10, 0, 0)

        self._access_key_input = QLineEdit()
        self._access_key_input.setPlaceholderText("AKIA...")
        self._access_key_input.setEnabled(False)

        self._secret_key_input = QLineEdit()
        self._secret_key_input.setPlaceholderText("Secret key")
        self._secret_key_input.setEchoMode(QLineEdit.Password)
        self._secret_key_input.setEnabled(False)

        self._region_combo = QComboBox()
        self._region_combo.setEnabled(False)
        self._load_regions()

        self._session_token_input = QLineEdit()
        self._session_token_input.setPlaceholderText("Optional - for temporary credentials")
        self._session_token_input.setEnabled(False)

        manual_form.addRow("Access Key ID:", self._access_key_input)
        manual_form.addRow("Secret Access Key:", self._secret_key_input)
        manual_form.addRow("Region:", self._region_combo)
        manual_form.addRow("Session Token:", self._session_token_input)

        mode_layout.addLayout(manual_form)

        # Save to profile option
        save_layout = QHBoxLayout()
        self._save_check = QCheckBox("Save to AWS profile:")
        self._save_profile_input = QLineEdit()
        self._save_profile_input.setPlaceholderText("openlabels")
        self._save_profile_input.setMaximumWidth(150)
        self._save_check.setEnabled(False)
        self._save_profile_input.setEnabled(False)
        save_layout.addWidget(self._save_check)
        save_layout.addWidget(self._save_profile_input)
        save_layout.addStretch()
        mode_layout.addLayout(save_layout)

        layout.addWidget(mode_group)

        # Buttons
        button_layout = QHBoxLayout()

        self._test_btn = QPushButton("Test Connection")
        self._test_btn.clicked.connect(self._on_test)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        button_layout.addWidget(self._test_btn)
        button_layout.addStretch()
        button_layout.addWidget(button_box)

        layout.addLayout(button_layout)

        # Connect mode change
        self._mode_group.buttonClicked.connect(self._on_mode_changed)

    def _load_aws_profiles(self):
        """Load AWS profiles from credentials file."""
        self._profile_combo.clear()
        self._profile_combo.addItem("default")

        # Try to load from ~/.aws/credentials
        creds_file = Path.home() / ".aws" / "credentials"
        if creds_file.exists():
            try:
                with open(creds_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("[") and line.endswith("]"):
                            profile = line[1:-1]
                            if profile != "default":
                                self._profile_combo.addItem(profile)
            except Exception:
                pass

    def _load_regions(self):
        """Load AWS regions."""
        regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
            "ap-south-1", "sa-east-1", "ca-central-1",
        ]
        self._region_combo.addItems(regions)

    def _on_mode_changed(self, button):
        """Handle authentication mode change."""
        is_manual = self._manual_radio.isChecked()

        self._profile_combo.setEnabled(not is_manual)
        self._access_key_input.setEnabled(is_manual)
        self._secret_key_input.setEnabled(is_manual)
        self._region_combo.setEnabled(is_manual)
        self._session_token_input.setEnabled(is_manual)
        self._save_check.setEnabled(is_manual)
        self._save_profile_input.setEnabled(is_manual and self._save_check.isChecked())

    def _on_test(self):
        """Test the connection."""
        creds = self.get_credentials()
        if not creds:
            QMessageBox.warning(self, "No Credentials", "Please enter credentials first.")
            return

        try:
            import boto3

            if creds.get("profile"):
                session = boto3.Session(profile_name=creds["profile"])
            else:
                session = boto3.Session(
                    aws_access_key_id=creds.get("access_key"),
                    aws_secret_access_key=creds.get("secret_key"),
                    aws_session_token=creds.get("session_token"),
                    region_name=creds.get("region"),
                )

            # Try to list buckets to verify credentials
            s3 = session.client("s3")
            s3.list_buckets()

            QMessageBox.information(self, "Success", "Connection successful!")

        except ImportError:
            QMessageBox.warning(
                self, "Missing Dependency",
                "boto3 is required for S3 access.\nInstall it with: pip install boto3"
            )
        except Exception as e:
            QMessageBox.critical(self, "Connection Failed", str(e))

    def get_credentials(self) -> Optional[Dict[str, str]]:
        """Get the entered credentials."""
        if self._profile_radio.isChecked():
            return {"profile": self._profile_combo.currentText()}
        else:
            access_key = self._access_key_input.text().strip()
            secret_key = self._secret_key_input.text().strip()
            if not access_key or not secret_key:
                return None
            return {
                "access_key": access_key,
                "secret_key": secret_key,
                "region": self._region_combo.currentText(),
                "session_token": self._session_token_input.text().strip() or None,
            }


class SettingsDialog(QDialog):
    """Application settings dialog."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        tabs = QTabWidget()

        # Scanning tab
        scan_tab = QWidget()
        scan_layout = QFormLayout(scan_tab)

        self._max_file_size = QSpinBox()
        self._max_file_size.setRange(1, 10000)
        self._max_file_size.setValue(50)
        self._max_file_size.setSuffix(" MB")

        self._threads = QSpinBox()
        self._threads.setRange(1, 32)
        self._threads.setValue(4)

        self._include_archives = QCheckBox()

        self._excluded_patterns = QLineEdit()
        self._excluded_patterns.setPlaceholderText(".git,node_modules,__pycache__")

        scan_layout.addRow("Max file size:", self._max_file_size)
        scan_layout.addRow("Threads:", self._threads)
        scan_layout.addRow("Include archives:", self._include_archives)
        scan_layout.addRow("Excluded patterns:", self._excluded_patterns)

        tabs.addTab(scan_tab, "Scanning")

        # Storage tab
        storage_tab = QWidget()
        storage_layout = QFormLayout(storage_tab)

        quarantine_layout = QHBoxLayout()
        self._quarantine_path = QLineEdit()
        default_quarantine = str(Path.home() / ".openlabels" / "quarantine")
        self._quarantine_path.setText(default_quarantine)
        quarantine_browse = QPushButton("...")
        quarantine_browse.setMaximumWidth(40)
        quarantine_browse.clicked.connect(self._browse_quarantine)
        quarantine_layout.addWidget(self._quarantine_path)
        quarantine_layout.addWidget(quarantine_browse)

        storage_layout.addRow("Quarantine path:", quarantine_layout)

        tabs.addTab(storage_tab, "Storage")

        # Display tab
        display_tab = QWidget()
        display_layout = QFormLayout(display_tab)

        self._show_hidden = QCheckBox()

        display_layout.addRow("Show hidden files:", self._show_hidden)

        tabs.addTab(display_tab, "Display")

        layout.addWidget(tabs)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel | QDialogButtonBox.RestoreDefaults
        )
        button_box.accepted.connect(self._save_settings)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.RestoreDefaults).clicked.connect(self._restore_defaults)

        layout.addWidget(button_box)

    def _browse_quarantine(self):
        """Browse for quarantine folder."""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Quarantine Folder", self._quarantine_path.text()
        )
        if folder:
            self._quarantine_path.setText(folder)

    def _load_settings(self):
        """Load settings from QSettings."""
        from PySide6.QtCore import QSettings
        settings = QSettings("OpenLabels", "OpenLabels")

        self._max_file_size.setValue(settings.value("scanning/max_file_size_mb", 50, int))
        self._threads.setValue(settings.value("scanning/threads", 4, int))
        self._include_archives.setChecked(settings.value("scanning/include_archives", False, bool))
        self._excluded_patterns.setText(settings.value("scanning/excluded_patterns", ".git,node_modules,__pycache__"))
        self._quarantine_path.setText(settings.value("storage/quarantine_path", str(Path.home() / ".openlabels" / "quarantine")))
        self._show_hidden.setChecked(settings.value("display/show_hidden", False, bool))

    def _save_settings(self):
        """Save settings to QSettings."""
        from PySide6.QtCore import QSettings
        settings = QSettings("OpenLabels", "OpenLabels")

        settings.setValue("scanning/max_file_size_mb", self._max_file_size.value())
        settings.setValue("scanning/threads", self._threads.value())
        settings.setValue("scanning/include_archives", self._include_archives.isChecked())
        settings.setValue("scanning/excluded_patterns", self._excluded_patterns.text())
        settings.setValue("storage/quarantine_path", self._quarantine_path.text())
        settings.setValue("display/show_hidden", self._show_hidden.isChecked())

        self.accept()

    def _restore_defaults(self):
        """Restore default settings."""
        self._max_file_size.setValue(50)
        self._threads.setValue(4)
        self._include_archives.setChecked(False)
        self._excluded_patterns.setText(".git,node_modules,__pycache__")
        self._quarantine_path.setText(str(Path.home() / ".openlabels" / "quarantine"))
        self._show_hidden.setChecked(False)


class LabelDialog(QDialog):
    """Dialog for adding labels to a file."""

    def __init__(self, parent=None, file_path: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Labels")
        self.setMinimumWidth(400)
        self._file_path = file_path
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # File path
        file_label = QLabel(f"File: {Path(self._file_path).name}")
        file_label.setToolTip(self._file_path)
        layout.addWidget(file_label)

        # Labels input
        form = QFormLayout()

        self._labels_input = QLineEdit()
        self._labels_input.setPlaceholderText("PII, CONFIDENTIAL, HR-ONLY")
        form.addRow("Labels:", self._labels_input)

        layout.addLayout(form)

        # Common labels quick-add
        common_layout = QHBoxLayout()
        common_layout.addWidget(QLabel("Quick add:"))

        for label in ["PII", "CONFIDENTIAL", "INTERNAL", "PUBLIC"]:
            btn = QPushButton(label)
            btn.setMaximumWidth(100)
            btn.clicked.connect(lambda checked, l=label: self._add_label(l))
            common_layout.addWidget(btn)

        common_layout.addStretch()
        layout.addLayout(common_layout)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _add_label(self, label: str):
        """Add a label to the input."""
        current = self._labels_input.text().strip()
        if current:
            labels = [l.strip() for l in current.split(",")]
            if label not in labels:
                labels.append(label)
            self._labels_input.setText(", ".join(labels))
        else:
            self._labels_input.setText(label)

    def get_labels(self) -> List[str]:
        """Get the entered labels."""
        text = self._labels_input.text().strip()
        if not text:
            return []
        return [l.strip() for l in text.split(",") if l.strip()]


class QuarantineConfirmDialog(QDialog):
    """Confirmation dialog for quarantine action."""

    def __init__(self, parent=None, file_path: str = "", score: int = 0, tier: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Confirm Quarantine")
        self._setup_ui(file_path, score, tier)

    def _setup_ui(self, file_path: str, score: int, tier: str):
        layout = QVBoxLayout(self)

        # Warning message
        message = QLabel(
            f"Are you sure you want to quarantine this file?\n\n"
            f"File: {Path(file_path).name}\n"
            f"Score: {score}\n"
            f"Tier: {tier}\n\n"
            f"The file will be moved to the quarantine folder."
        )
        message.setWordWrap(True)
        layout.addWidget(message)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Yes | QDialogButtonBox.No)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
