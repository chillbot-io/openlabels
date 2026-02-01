"""Configuration for the OpenLabels Scanner."""

import os
import warnings
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Set, List
import logging

from .constants import MAX_FILE_SIZE_BYTES, MAX_PAGE_WORKERS, MAX_TEXT_LENGTH

logger = logging.getLogger(__name__)


# --- Schema Version ---
# Increment this when making breaking changes to Config fields.
# The migration system will help upgrade old configs to new format.

CURRENT_SCHEMA_VERSION = 1


class DeviceMode(str, Enum):
    """Device configuration options for ML inference."""
    AUTO = "auto"
    CUDA = "cuda"
    CPU = "cpu"


# Paths that should never be used as data directories
FORBIDDEN_PATHS = frozenset([
    "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/dev", "/proc", "/sys", "/tmp",
    "/System", "/Library", "/Applications",
    "C:\\Windows", "C:\\Program Files",
])


def validate_data_path(path: Path) -> bool:
    """Validate data directory path is safe."""
    testing_mode = os.environ.get("OPENLABELS_SCANNER_TESTING", "").lower() in ("1", "true", "yes")
    resolved = path.resolve()
    path_str = str(resolved)

    if path_str == "/" or path_str == "\\":
        logger.warning(f"Data path {path} is root directory - rejected")
        return False

    for forbidden in FORBIDDEN_PATHS:
        if testing_mode and forbidden == "/tmp":
            continue
        if path_str == forbidden:
            logger.warning(f"Data path {path} is forbidden system directory")
            return False
        if path_str.startswith(forbidden + os.sep):
            logger.warning(f"Data path {path} is inside forbidden directory {forbidden}")
            return False

    return True


def default_data_dir() -> Path:
    """
    Default data directory, checked in order:
    1. OPENLABELS_SCANNER_HOME env var (if set)
    2. .openlabels/ in current working directory (project-local)
    3. ~/.openlabels (user home fallback)
    """
    env_dir = os.environ.get("OPENLABELS_SCANNER_HOME")
    if env_dir:
        path = Path(env_dir).expanduser()
        if not validate_data_path(path):
            logger.warning(f"OPENLABELS_SCANNER_HOME={env_dir} failed validation, using default")
        else:
            return path

    local_dir = Path.cwd() / ".openlabels"
    if local_dir.exists() and local_dir.is_dir():
        if validate_data_path(local_dir):
            logger.debug(f"Using local data directory: {local_dir}")
            return local_dir

    return Path.home() / ".openlabels"


@dataclass
class Config:
    """OpenLabels Scanner configuration with schema versioning support."""

    schema_version: int = CURRENT_SCHEMA_VERSION  # For config migration

    # Paths
    data_dir: Path = field(default_factory=default_data_dir)
    _models_dir_override: Optional[Path] = field(default=None, repr=False)

    @property
    def models_dir(self) -> Path:
        """Directory for ML models (OCR, etc.)."""
        if self._models_dir_override is not None:
            return self._models_dir_override
        env_models = os.environ.get("OPENLABELS_SCANNER_MODELS_DIR")
        if env_models:
            return Path(env_models).expanduser()
        return self.data_dir / "models"

    @property
    def rapidocr_dir(self) -> Path:
        """Directory for RapidOCR models."""
        return self.models_dir / "rapidocr"

    @property
    def dictionaries_dir(self) -> Path:
        """Directory for dictionary files."""
        return self.data_dir / "dictionaries"

    # Detection Settings
    min_confidence: float = 0.50
    entity_types: Optional[List[str]] = None  # None = detect all types
    exclude_types: Optional[List[str]] = None  # Types to never detect

    # Device / GPU Configuration
    device: str = "auto"  # "auto", "cuda", "cpu"
    cuda_device_id: int = 0

    # OCR Settings
    enable_ocr: bool = True  # Enable OCR for images/scanned PDFs

    # Model Loading
    model_timeout_seconds: int = 45
    on_model_timeout: str = "degraded"  # "error" | "degraded" - continue without ML if timeout
    disabled_detectors: Set[str] = field(default_factory=set)

    # Parallel detection
    max_workers: int = MAX_PAGE_WORKERS  # Max threads for parallel detection

    # Size limits (prevent OOM from adversarial input)
    max_text_size: int = MAX_TEXT_LENGTH * 10  # Default 10MB, based on MAX_TEXT_LENGTH
    max_file_size: int = MAX_FILE_SIZE_BYTES  # From central constants

    def __post_init__(self):
        """Validate configuration values and migrate if needed."""
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            self._migrate_config()

        if not validate_data_path(self.data_dir):
            raise ValueError(
                f"Invalid data_dir '{self.data_dir}'. "
                f"Cannot use system directories like /etc, /var, /usr, etc."
            )

        valid_devices = {d.value for d in DeviceMode}
        if self.device not in valid_devices:
            raise ValueError(
                f"Invalid device '{self.device}'. "
                f"Must be one of: {', '.join(valid_devices)}"
            )

        if not 0 < self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")

        valid_timeout_modes = {"error", "degraded"}
        if self.on_model_timeout not in valid_timeout_modes:
            raise ValueError(
                f"Invalid on_model_timeout '{self.on_model_timeout}'. "
                f"Must be one of: {', '.join(valid_timeout_modes)}"
            )

        if self.model_timeout_seconds < 1:
            raise ValueError("model_timeout_seconds must be at least 1")

        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1")

        if self.max_text_size < 1:
            raise ValueError("max_text_size must be at least 1")

        if self.max_file_size < 1:
            raise ValueError("max_file_size must be at least 1")

    def _migrate_config(self) -> None:
        """
        Migrate config from older schema version to current.

        This method handles upgrades when loading configs from older versions.
        """
        original_version = self.schema_version

        if self.schema_version < CURRENT_SCHEMA_VERSION:
            # Config is from the future or unknown - warn but allow
            warnings.warn(
                f"Config schema_version {original_version} is older than current "
                f"version {CURRENT_SCHEMA_VERSION}. Config has been migrated. "
                "Please update your config file.",
                UserWarning,
                stacklevel=3,
            )
        elif self.schema_version > CURRENT_SCHEMA_VERSION:
            # Config is from a newer version of OpenLabels
            warnings.warn(
                f"Config schema_version {self.schema_version} is newer than "
                f"current version {CURRENT_SCHEMA_VERSION}. Some features may "
                "not work as expected. Consider upgrading OpenLabels.",
                UserWarning,
                stacklevel=3,
            )

        # Update to current version after migration
        self.schema_version = CURRENT_SCHEMA_VERSION

    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        config = cls()

        if env_conf := os.environ.get("OPENLABELS_SCANNER_MIN_CONFIDENCE"):
            try:
                config.min_confidence = float(env_conf)
            except ValueError:
                logger.warning(f"Invalid OPENLABELS_SCANNER_MIN_CONFIDENCE='{env_conf}', using default")

        if env_device := os.environ.get("OPENLABELS_SCANNER_DEVICE"):
            config.device = env_device.lower()

        if env_ocr := os.environ.get("OPENLABELS_SCANNER_ENABLE_OCR"):
            config.enable_ocr = env_ocr.lower() in ("1", "true", "yes")

        if env_workers := os.environ.get("OPENLABELS_SCANNER_MAX_WORKERS"):
            try:
                config.max_workers = int(env_workers)
            except ValueError:
                logger.warning(f"Invalid OPENLABELS_SCANNER_MAX_WORKERS='{env_workers}', using default")

        return config
