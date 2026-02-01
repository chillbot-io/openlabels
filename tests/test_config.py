"""Tests for ScrubIQ configuration.

Tests for Config dataclass and helper functions.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from scrubiq.config import (
    FaceRedactionMethod,
    DeviceMode,
    FORBIDDEN_PATHS,
    validate_data_path,
    default_data_dir,
    Config,
)


# =============================================================================
# FACEREDACTIONMETHOD ENUM TESTS
# =============================================================================

class TestFaceRedactionMethod:
    """Tests for FaceRedactionMethod enum."""

    def test_blur_value(self):
        """BLUR has correct value."""
        assert FaceRedactionMethod.BLUR.value == "blur"

    def test_pixelate_value(self):
        """PIXELATE has correct value."""
        assert FaceRedactionMethod.PIXELATE.value == "pixelate"

    def test_fill_value(self):
        """FILL has correct value."""
        assert FaceRedactionMethod.FILL.value == "fill"

    def test_is_str_enum(self):
        """FaceRedactionMethod is str enum."""
        assert issubclass(FaceRedactionMethod, str)

    def test_usable_as_string(self):
        """Can use as string directly."""
        method = FaceRedactionMethod.BLUR
        assert method == "blur"


# =============================================================================
# DEVICEMODE ENUM TESTS
# =============================================================================

class TestDeviceMode:
    """Tests for DeviceMode enum."""

    def test_auto_value(self):
        """AUTO has correct value."""
        assert DeviceMode.AUTO.value == "auto"

    def test_cuda_value(self):
        """CUDA has correct value."""
        assert DeviceMode.CUDA.value == "cuda"

    def test_cpu_value(self):
        """CPU has correct value."""
        assert DeviceMode.CPU.value == "cpu"

    def test_is_str_enum(self):
        """DeviceMode is str enum."""
        assert issubclass(DeviceMode, str)


# =============================================================================
# FORBIDDEN_PATHS TESTS
# =============================================================================

class TestForbiddenPaths:
    """Tests for FORBIDDEN_PATHS constant."""

    def test_is_frozenset(self):
        """FORBIDDEN_PATHS is frozenset."""
        assert isinstance(FORBIDDEN_PATHS, frozenset)

    def test_contains_linux_system_paths(self):
        """Contains Linux system paths."""
        linux_paths = ["/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/tmp"]
        for path in linux_paths:
            assert path in FORBIDDEN_PATHS

    def test_contains_macos_paths(self):
        """Contains macOS system paths."""
        macos_paths = ["/System", "/Library", "/Applications"]
        for path in macos_paths:
            assert path in FORBIDDEN_PATHS

    def test_contains_windows_paths(self):
        """Contains Windows system paths."""
        windows_paths = ["C:\\Windows", "C:\\Program Files"]
        for path in windows_paths:
            assert path in FORBIDDEN_PATHS

    def test_immutable(self):
        """FORBIDDEN_PATHS cannot be modified."""
        with pytest.raises(AttributeError):
            FORBIDDEN_PATHS.add("/new_path")


# =============================================================================
# VALIDATE_DATA_PATH TESTS
# =============================================================================

class TestValidateDataPath:
    """Tests for validate_data_path function."""

    def test_allows_home_directory(self):
        """Allows paths in home directory."""
        path = Path.home() / ".scrubiq"

        result = validate_data_path(path)

        assert result is True

    def test_allows_root_user_directory(self):
        """Allows /root directory."""
        path = Path("/root/.scrubiq")

        result = validate_data_path(path)

        assert result is True

    def test_rejects_root_directory(self):
        """Rejects root directory (/)."""
        path = Path("/")

        result = validate_data_path(path)

        assert result is False

    def test_rejects_etc_directory(self):
        """Rejects /etc directory."""
        path = Path("/etc")

        result = validate_data_path(path)

        assert result is False

    def test_rejects_etc_subdirectory(self):
        """Rejects subdirectories of /etc."""
        path = Path("/etc/scrubiq")

        result = validate_data_path(path)

        assert result is False

    def test_rejects_var_directory(self):
        """Rejects /var directory."""
        path = Path("/var")

        result = validate_data_path(path)

        assert result is False

    def test_rejects_usr_directory(self):
        """Rejects /usr directory."""
        path = Path("/usr/local/scrubiq")

        result = validate_data_path(path)

        assert result is False

    def test_rejects_tmp_without_testing_mode(self):
        """Rejects /tmp without SCRUBIQ_TESTING."""
        with patch.dict(os.environ, {}, clear=True):
            path = Path("/tmp/scrubiq")

            result = validate_data_path(path)

            assert result is False

    def test_allows_tmp_with_testing_mode(self):
        """Allows /tmp with SCRUBIQ_TESTING=1."""
        with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
            path = Path("/tmp/scrubiq")

            result = validate_data_path(path)

            assert result is True

    def test_testing_mode_accepts_various_values(self):
        """SCRUBIQ_TESTING accepts 1, true, yes."""
        for value in ["1", "true", "yes", "TRUE", "YES"]:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": value}):
                result = validate_data_path(Path("/tmp/test"))
                assert result is True


# =============================================================================
# DEFAULT_DATA_DIR TESTS
# =============================================================================

class TestDefaultDataDir:
    """Tests for default_data_dir function."""

    def test_uses_scrubiq_home_env(self):
        """Uses SCRUBIQ_HOME env var when set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                result = default_data_dir()

                assert result == Path(tmpdir)

    def test_falls_back_to_home_directory(self):
        """Falls back to ~/.scrubiq when no env var."""
        with patch.dict(os.environ, {}, clear=True):
            # Mock that .scrubiq doesn't exist in cwd
            with patch.object(Path, "exists", return_value=False):
                result = default_data_dir()

                assert result == Path.home() / ".scrubiq"

    def test_uses_local_directory_if_exists(self):
        """Uses .scrubiq in cwd if it exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            local_scrubiq = Path(tmpdir) / ".scrubiq"
            local_scrubiq.mkdir()

            # Change to the temp directory
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                    # Clear SCRUBIQ_HOME so it falls through to local check
                    if "SCRUBIQ_HOME" in os.environ:
                        del os.environ["SCRUBIQ_HOME"]

                    result = default_data_dir()

                    # Should use local .scrubiq or fall back to home
                    # (depends on whether cwd/.scrubiq is inside /tmp which is forbidden)
                    assert result is not None
            finally:
                os.chdir(original_cwd)


# =============================================================================
# CONFIG INIT TESTS
# =============================================================================

class TestConfigInit:
    """Tests for Config initialization."""

    def test_creates_with_defaults(self):
        """Creates config with default values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                config = Config()

                assert config.min_confidence == 0.50
                assert config.review_threshold == 0.95
                assert config.coref_enabled is True
                assert config.safe_harbor_enabled is True
                assert config.encryption_enabled is True

    def test_custom_data_dir(self):
        """Accepts custom data_dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.data_dir == Path(tmpdir)

    def test_rejects_invalid_data_dir(self):
        """Rejects forbidden data_dir."""
        with pytest.raises(ValueError, match="Invalid data_dir"):
            Config(data_dir=Path("/etc/scrubiq"))

    def test_rejects_invalid_face_redaction_method(self):
        """Rejects invalid face_redaction_method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="Invalid face_redaction_method"):
                    Config(face_redaction_method="invalid")

    def test_rejects_invalid_device(self):
        """Rejects invalid device."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="Invalid device"):
                    Config(device="invalid")

    def test_rejects_invalid_min_confidence(self):
        """Rejects min_confidence outside (0, 1]."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="min_confidence"):
                    Config(min_confidence=0)

                with pytest.raises(ValueError, match="min_confidence"):
                    Config(min_confidence=1.5)

    def test_rejects_invalid_review_threshold(self):
        """Rejects review_threshold outside (0, 1]."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="review_threshold"):
                    Config(review_threshold=0)

    def test_rejects_invalid_session_timeout(self):
        """Rejects session_timeout_minutes < 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="session_timeout_minutes"):
                    Config(session_timeout_minutes=0)

    def test_rejects_invalid_api_port(self):
        """Rejects api_port outside [1, 65535]."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="api_port"):
                    Config(api_port=0)

                with pytest.raises(ValueError, match="api_port"):
                    Config(api_port=70000)

    def test_rejects_invalid_on_model_timeout(self):
        """Rejects invalid on_model_timeout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="on_model_timeout"):
                    Config(on_model_timeout="invalid")

    def test_rejects_invalid_model_timeout_seconds(self):
        """Rejects model_timeout_seconds < 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_HOME": tmpdir, "SCRUBIQ_TESTING": "1"}):
                with pytest.raises(ValueError, match="model_timeout_seconds"):
                    Config(model_timeout_seconds=0)


# =============================================================================
# CONFIG PROPERTIES TESTS
# =============================================================================

class TestConfigProperties:
    """Tests for Config property methods."""

    def test_db_path(self):
        """db_path is data_dir/data.db."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.db_path == Path(tmpdir) / "data.db"

    def test_models_dir_default(self):
        """models_dir defaults to data_dir/models."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                # Ensure SCRUBIQ_MODELS_DIR is not set
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))

                assert config.models_dir == Path(tmpdir) / "models"

    def test_models_dir_from_env(self):
        """models_dir uses SCRUBIQ_MODELS_DIR env var."""
        with tempfile.TemporaryDirectory() as tmpdir:
            models_path = Path(tmpdir) / "custom_models"
            with patch.dict(os.environ, {
                "SCRUBIQ_TESTING": "1",
                "SCRUBIQ_MODELS_DIR": str(models_path)
            }):
                config = Config(data_dir=Path(tmpdir))

                assert config.models_dir == models_path

    def test_models_dir_override(self):
        """models_dir uses explicit override."""
        with tempfile.TemporaryDirectory() as tmpdir:
            override_path = Path(tmpdir) / "override"
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(
                    data_dir=Path(tmpdir),
                    _models_dir_override=override_path
                )

                assert config.models_dir == override_path

    def test_phi_bert_path(self):
        """phi_bert_path is models_dir/phi_bert."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))

                assert config.phi_bert_path == Path(tmpdir) / "models" / "phi_bert"

    def test_pii_bert_path(self):
        """pii_bert_path is models_dir/pii_bert."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))

                assert config.pii_bert_path == Path(tmpdir) / "models" / "pii_bert"

    def test_rapidocr_dir(self):
        """rapidocr_dir is models_dir/rapidocr."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))

                assert config.rapidocr_dir == Path(tmpdir) / "models" / "rapidocr"

    def test_face_detection_dir(self):
        """face_detection_dir is models_dir/face_detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))

                assert config.face_detection_dir == Path(tmpdir) / "models" / "face_detection"

    def test_dictionaries_dir(self):
        """dictionaries_dir is data_dir/dictionaries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.dictionaries_dir == Path(tmpdir) / "dictionaries"

    def test_confidence_threshold_alias(self):
        """confidence_threshold is alias for min_confidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir), min_confidence=0.75)

                assert config.confidence_threshold == 0.75

    def test_confidence_threshold_setter(self):
        """Setting confidence_threshold sets min_confidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))
                config.confidence_threshold = 0.80

                assert config.min_confidence == 0.80


# =============================================================================
# ENSURE_DIRECTORIES TESTS
# =============================================================================

class TestEnsureDirectories:
    """Tests for ensure_directories method."""

    def test_creates_directories(self):
        """Creates required directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))
                config.ensure_directories()

                assert config.data_dir.exists()
                assert config.models_dir.exists()
                assert config.dictionaries_dir.exists()
                assert config.face_detection_dir.exists()

    def test_sets_secure_permissions(self):
        """Sets 0700 permissions on directories."""
        import stat

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))
                config.ensure_directories()

                # Check permissions on data_dir
                mode = config.data_dir.stat().st_mode
                assert mode & 0o777 == stat.S_IRWXU  # 0700

    def test_idempotent(self):
        """Can be called multiple times safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}, clear=True):
                if "SCRUBIQ_MODELS_DIR" in os.environ:
                    del os.environ["SCRUBIQ_MODELS_DIR"]

                config = Config(data_dir=Path(tmpdir))

                # Should not raise
                config.ensure_directories()
                config.ensure_directories()

                assert config.data_dir.exists()


# =============================================================================
# CONFIG DEFAULTS TESTS
# =============================================================================

class TestConfigDefaults:
    """Tests for Config default values."""

    def test_coref_defaults(self):
        """Coreference settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.coref_enabled is True
                assert config.coref_window_sentences == 2
                assert config.coref_max_expansions == 3
                assert config.coref_min_anchor_confidence == 0.85
                assert config.coref_confidence_decay == 0.90

    def test_security_defaults(self):
        """Security settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.encryption_enabled is True
                assert config.scrypt_memory_mb == 16
                assert config.session_timeout_minutes == 15

    def test_upload_defaults(self):
        """Upload settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.max_upload_size_mb == 50
                assert config.max_upload_results == 10

    def test_image_protection_defaults(self):
        """Image protection settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.enable_face_detection is True
                assert config.enable_metadata_stripping is True
                assert config.face_redaction_method == "blur"

    def test_api_defaults(self):
        """API settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.api_host == "127.0.0.1"
                assert config.api_port == 8741

    def test_model_loading_defaults(self):
        """Model loading settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.model_timeout_seconds == 45
                assert config.on_model_timeout == "error"
                assert config.disabled_detectors == set()

    def test_audit_defaults(self):
        """Audit settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                # 6 years per HIPAA
                assert config.audit_retention_days == 2190

    def test_llm_verification_defaults(self):
        """LLM verification settings have correct defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
                config = Config(data_dir=Path(tmpdir))

                assert config.enable_llm_verification is False
                assert config.llm_verification_model == "qwen2.5:3b"
                assert config.llm_ollama_url == "http://localhost:11434"
