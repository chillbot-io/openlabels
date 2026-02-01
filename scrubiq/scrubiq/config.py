"""Configuration for ScrubIQ."""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Set, List
import logging

logger = logging.getLogger(__name__)


class FaceRedactionMethod(str, Enum):
    """Valid face redaction methods."""
    BLUR = "blur"
    PIXELATE = "pixelate"
    FILL = "fill"


class DeviceMode(str, Enum):
    """Device configuration options."""
    AUTO = "auto"
    CUDA = "cuda"
    CPU = "cpu"

# IV4: Paths that should never be used as data directories
FORBIDDEN_PATHS = frozenset([
    "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/dev", "/proc", "/sys", "/tmp",
    "/System", "/Library", "/Applications",  # macOS
    "C:\\Windows", "C:\\Program Files",  # Windows
])


def validate_data_path(path: Path) -> bool:
    """
    Validate data directory path is safe.

    Returns False if path is:
    - Root directory (/)
    - A forbidden system directory
    - A subdirectory of a forbidden path (e.g., /etc/scrubiq)

    Note: /root is allowed since it's a valid home directory.
    Note: Set SCRUBIQ_TESTING=1 to allow /tmp paths for tests.
    """
    # Allow test mode to bypass /tmp restriction
    testing_mode = os.environ.get("SCRUBIQ_TESTING", "").lower() in ("1", "true", "yes")

    resolved = path.resolve()
    path_str = str(resolved)

    # Reject root directory explicitly
    if path_str == "/" or path_str == "\\":
        logger.warning(f"Data path {path} is root directory - rejected")
        return False

    # Check forbidden paths - reject exact match or any subdirectory
    for forbidden in FORBIDDEN_PATHS:
        # Skip /tmp check in testing mode
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
    1. SCRUBIQ_HOME env var (if set)
    2. .scrubiq/ in current working directory (project-local)
    3. ~/.scrubiq (user home fallback)
    """
    # 1. Explicit env var takes priority
    env_dir = os.environ.get("SCRUBIQ_HOME")
    if env_dir:
        path = Path(env_dir).expanduser()
        if not validate_data_path(path):
            logger.warning(f"SCRUBIQ_HOME={env_dir} failed validation, using default")
        else:
            return path
    
    # 2. Check for local .scrubiq in current directory
    local_dir = Path.cwd() / ".scrubiq"
    if local_dir.exists() and local_dir.is_dir():
        if validate_data_path(local_dir):
            logger.debug(f"Using local data directory: {local_dir}")
            return local_dir
    
    # 3. Fall back to user home
    return Path.home() / ".scrubiq"


@dataclass
class Config:
    """ScrubIQ configuration."""

    # Paths
    data_dir: Path = field(default_factory=default_data_dir)
    _models_dir_override: Optional[Path] = field(default=None, repr=False)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "data.db"

    @property
    def models_dir(self) -> Path:
        # Priority: explicit override > env var > default (data_dir/models)
        if self._models_dir_override is not None:
            return self._models_dir_override
        
        # Check env var (useful for tests to share models while isolating data)
        env_models = os.environ.get("SCRUBIQ_MODELS_DIR")
        if env_models:
            return Path(env_models).expanduser()
        
        return self.data_dir / "models"

    @property
    def phi_bert_path(self) -> Path:
        return self.models_dir / "phi_bert"

    @property
    def pii_bert_path(self) -> Path:
        return self.models_dir / "pii_bert"

    @property
    def rapidocr_dir(self) -> Path:
        return self.models_dir / "rapidocr"

    @property
    def face_detection_dir(self) -> Path:
        """Directory for face detection models."""
        return self.models_dir / "face_detection"

    @property
    def dictionaries_dir(self) -> Path:
        return self.data_dir / "dictionaries"

    # Detection
    min_confidence: float = 0.50
    review_threshold: float = 0.95
    entity_types: Optional[List[str]] = None  # None = detect all types
    exclude_types: Optional[List[str]] = None  # Types to never detect

    # Alias for API compatibility (API uses confidence_threshold, core uses min_confidence)
    @property
    def confidence_threshold(self) -> float:
        """Alias for min_confidence (API compatibility)."""
        return self.min_confidence

    @confidence_threshold.setter
    def confidence_threshold(self, value: float):
        """Set min_confidence via confidence_threshold alias."""
        self.min_confidence = value

    # Coreference
    coref_enabled: bool = True
    coref_window_sentences: int = 2
    coref_max_expansions: int = 3
    coref_min_anchor_confidence: float = 0.85
    coref_confidence_decay: float = 0.90

    # Entity Resolution (Phase 2)
    # When enabled, uses entity_id (not entity_type) as the token lookup key.
    # This ensures the same person gets the same token regardless of semantic role.
    entity_resolution_enabled: bool = True

    # Safe Harbor
    safe_harbor_enabled: bool = True

    # Security
    # Note: encryption_enabled reserved for future optional unencrypted mode
    encryption_enabled: bool = True
    # Scrypt-specific parameters for key derivation
    scrypt_memory_mb: int = 16  # Memory cost for Scrypt KDF (16MB = ~1s unlock)
    # Session inactivity timeout
    session_timeout_minutes: int = 15

    # Gateway
    gateway_url: Optional[str] = None
    gateway_timeout_seconds: int = 30

    # Audit
    audit_retention_days: int = 2190  # 6 years per HIPAA

    # Upload
    max_upload_size_mb: int = 50
    max_upload_results: int = 10

    # Image Protection
    enable_face_detection: bool = True
    enable_metadata_stripping: bool = True
    face_redaction_method: str = "blur"  # blur, pixelate, fill

    # Device / GPU Configuration
    # Options: "auto" (detect), "cuda" (force GPU), "cpu" (force CPU)
    device: str = "auto"
    # For multi-GPU systems, specify which GPU (0, 1, etc.) when device="cuda"
    cuda_device_id: int = 0

    # LLM Verification (precision improvement)
    # Enable LLM-based verification to filter false positives
    # Requires Ollama running locally with a compatible model
    enable_llm_verification: bool = False
    # LLM model for verification (default: qwen2.5:3b - Apache 2.0, good multilingual)
    # Options: qwen2.5:3b, qwen2.5:7b, phi3:mini
    llm_verification_model: str = "qwen2.5:3b"
    # Ollama API endpoint
    llm_ollama_url: str = "http://localhost:11434"

    # API
    api_host: str = "127.0.0.1"
    api_port: int = 8741

    # Model Loading Behavior
    model_timeout_seconds: int = 45
    on_model_timeout: str = "error"  # "error" | "degraded"
    disabled_detectors: Set[str] = field(default_factory=set)

    def __post_init__(self):
        """Validate configuration values."""
        # Validate data_dir is not a forbidden system path
        if not validate_data_path(self.data_dir):
            raise ValueError(
                f"Invalid data_dir '{self.data_dir}'. "
                f"Cannot use system directories like /etc, /var, /usr, etc."
            )

        # Validate face_redaction_method
        valid_methods = {m.value for m in FaceRedactionMethod}
        if self.face_redaction_method not in valid_methods:
            raise ValueError(
                f"Invalid face_redaction_method '{self.face_redaction_method}'. "
                f"Must be one of: {', '.join(valid_methods)}"
            )
        
        # Validate device
        valid_devices = {d.value for d in DeviceMode}
        if self.device not in valid_devices:
            raise ValueError(
                f"Invalid device '{self.device}'. "
                f"Must be one of: {', '.join(valid_devices)}"
            )
        
        # Validate numeric ranges
        if not 0 < self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")
        
        if not 0 < self.review_threshold <= 1.0:
            raise ValueError("review_threshold must be between 0 and 1")
        
        if self.session_timeout_minutes < 1:
            raise ValueError("session_timeout_minutes must be at least 1")
        
        if self.api_port < 1 or self.api_port > 65535:
            raise ValueError("api_port must be between 1 and 65535")
        
        # Validate on_model_timeout
        valid_timeout_modes = {"error", "degraded"}
        if self.on_model_timeout not in valid_timeout_modes:
            raise ValueError(
                f"Invalid on_model_timeout '{self.on_model_timeout}'. "
                f"Must be one of: {', '.join(valid_timeout_modes)}"
            )
        
        # Validate model_timeout_seconds
        if self.model_timeout_seconds < 1:
            raise ValueError("model_timeout_seconds must be at least 1")

    def ensure_directories(self) -> None:
        """Create data directories with secure permissions (0700)."""
        import stat
        
        for dir_path in [self.data_dir, self.models_dir, self.dictionaries_dir, self.face_detection_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
            # Set permissions to owner-only (rwx------)
            dir_path.chmod(stat.S_IRWXU)
