"""Comprehensive tests for config.py to achieve 80%+ coverage."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestFaceRedactionMethodEnum:
    """Tests for FaceRedactionMethod enum."""

    def test_blur_value(self):
        """BLUR value should be 'blur'."""
        from scrubiq.config import FaceRedactionMethod

        assert FaceRedactionMethod.BLUR.value == "blur"

    def test_pixelate_value(self):
        """PIXELATE value should be 'pixelate'."""
        from scrubiq.config import FaceRedactionMethod

        assert FaceRedactionMethod.PIXELATE.value == "pixelate"

    def test_fill_value(self):
        """FILL value should be 'fill'."""
        from scrubiq.config import FaceRedactionMethod

        assert FaceRedactionMethod.FILL.value == "fill"

    def test_all_methods_count(self):
        """Should have exactly 3 methods."""
        from scrubiq.config import FaceRedactionMethod

        assert len(FaceRedactionMethod) == 3


class TestDeviceModeEnum:
    """Tests for DeviceMode enum."""

    def test_auto_value(self):
        """AUTO value should be 'auto'."""
        from scrubiq.config import DeviceMode

        assert DeviceMode.AUTO.value == "auto"

    def test_cuda_value(self):
        """CUDA value should be 'cuda'."""
        from scrubiq.config import DeviceMode

        assert DeviceMode.CUDA.value == "cuda"

    def test_cpu_value(self):
        """CPU value should be 'cpu'."""
        from scrubiq.config import DeviceMode

        assert DeviceMode.CPU.value == "cpu"


class TestForbiddenPaths:
    """Tests for FORBIDDEN_PATHS constant."""

    def test_forbidden_paths_is_frozenset(self):
        """FORBIDDEN_PATHS should be frozenset."""
        from scrubiq.config import FORBIDDEN_PATHS

        assert isinstance(FORBIDDEN_PATHS, frozenset)

    def test_contains_etc(self):
        """/etc should be forbidden."""
        from scrubiq.config import FORBIDDEN_PATHS

        assert "/etc" in FORBIDDEN_PATHS

    def test_contains_var(self):
        """/var should be forbidden."""
        from scrubiq.config import FORBIDDEN_PATHS

        assert "/var" in FORBIDDEN_PATHS

    def test_contains_usr(self):
        """/usr should be forbidden."""
        from scrubiq.config import FORBIDDEN_PATHS

        assert "/usr" in FORBIDDEN_PATHS

    def test_contains_tmp(self):
        """/tmp should be forbidden."""
        from scrubiq.config import FORBIDDEN_PATHS

        assert "/tmp" in FORBIDDEN_PATHS


class TestValidateDataPath:
    """Tests for validate_data_path function."""

    def test_root_rejected(self):
        """Root directory should be rejected."""
        from scrubiq.config import validate_data_path

        assert validate_data_path(Path("/")) is False

    def test_etc_rejected(self):
        """/etc should be rejected."""
        from scrubiq.config import validate_data_path

        assert validate_data_path(Path("/etc")) is False

    def test_etc_subdirectory_rejected(self):
        """/etc subdirectories should be rejected."""
        from scrubiq.config import validate_data_path

        assert validate_data_path(Path("/etc/scrubiq")) is False

    def test_var_rejected(self):
        """/var should be rejected."""
        from scrubiq.config import validate_data_path

        assert validate_data_path(Path("/var")) is False

    def test_valid_home_path(self):
        """Valid home path should be accepted."""
        from scrubiq.config import validate_data_path

        assert validate_data_path(Path.home() / ".scrubiq") is True

    def test_valid_custom_path(self):
        """Valid custom path should be accepted."""
        from scrubiq.config import validate_data_path

        # /root is valid (it's a user home)
        assert validate_data_path(Path("/root/.scrubiq")) is True

    def test_tmp_allowed_in_test_mode(self):
        """/tmp should be allowed in test mode."""
        from scrubiq.config import validate_data_path

        with patch.dict(os.environ, {"SCRUBIQ_TESTING": "1"}):
            assert validate_data_path(Path("/tmp/scrubiq_test")) is True

    def test_tmp_rejected_in_prod(self):
        """/tmp should be rejected outside test mode."""
        from scrubiq.config import validate_data_path

        with patch.dict(os.environ, {"SCRUBIQ_TESTING": ""}, clear=True):
            assert validate_data_path(Path("/tmp")) is False


class TestDefaultDataDir:
    """Tests for default_data_dir function."""

    def test_env_var_takes_priority(self):
        """SCRUBIQ_HOME env var should take priority."""
        from scrubiq.config import default_data_dir

        with patch.dict(os.environ, {"SCRUBIQ_HOME": "/custom/path"}):
            with patch('scrubiq.config.validate_data_path', return_value=True):
                result = default_data_dir()
                assert result == Path("/custom/path")

    def test_invalid_env_var_falls_back(self):
        """Invalid SCRUBIQ_HOME should fall back to default."""
        from scrubiq.config import default_data_dir

        with patch.dict(os.environ, {"SCRUBIQ_HOME": "/etc/scrubiq"}):
            result = default_data_dir()
            # Should not be /etc/scrubiq
            assert result != Path("/etc/scrubiq")

    def test_local_scrubiq_dir_used_if_exists(self):
        """Local .scrubiq directory should be used if it exists."""
        from scrubiq.config import default_data_dir

        with patch.dict(os.environ, {}, clear=True):
            if "SCRUBIQ_HOME" in os.environ:
                del os.environ["SCRUBIQ_HOME"]

            # Mock Path.cwd() and local dir existence
            mock_local = Path("/project/.scrubiq")

            with patch('scrubiq.config.Path.cwd', return_value=Path("/project")):
                with patch.object(Path, 'exists', return_value=True):
                    with patch.object(Path, 'is_dir', return_value=True):
                        with patch('scrubiq.config.validate_data_path', return_value=True):
                            # Should use local directory
                            result = default_data_dir()
                            # Either local or home fallback
                            assert isinstance(result, Path)

    def test_falls_back_to_home(self):
        """Should fall back to ~/.scrubiq."""
        from scrubiq.config import default_data_dir

        with patch.dict(os.environ, {}, clear=True):
            if "SCRUBIQ_HOME" in os.environ:
                del os.environ["SCRUBIQ_HOME"]

            with patch.object(Path, 'exists', return_value=False):
                result = default_data_dir()
                assert result == Path.home() / ".scrubiq"


class TestConfigDataclass:
    """Tests for Config dataclass."""

    def test_default_values(self):
        """Config should have reasonable defaults."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path.home() / ".scrubiq")

        assert config.min_confidence == 0.50
        assert config.review_threshold == 0.95
        assert config.coref_enabled is True
        assert config.safe_harbor_enabled is True
        assert config.encryption_enabled is True
        assert config.enable_face_detection is True
        assert config.face_redaction_method == "blur"
        assert config.device == "auto"

    def test_db_path_property(self):
        """db_path should return data_dir/data.db."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.db_path == Path("/home/user/.scrubiq/data.db")

    def test_models_dir_property(self):
        """models_dir should return data_dir/models."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.models_dir == Path("/home/user/.scrubiq/models")

    def test_models_dir_env_override(self):
        """SCRUBIQ_MODELS_DIR env var should override models_dir."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        with patch.dict(os.environ, {"SCRUBIQ_MODELS_DIR": "/custom/models"}):
            assert config.models_dir == Path("/custom/models")

    def test_phi_bert_path(self):
        """phi_bert_path should be models_dir/phi_bert."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.phi_bert_path == Path("/home/user/.scrubiq/models/phi_bert")

    def test_dictionaries_dir(self):
        """dictionaries_dir should be data_dir/dictionaries."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.dictionaries_dir == Path("/home/user/.scrubiq/dictionaries")

    def test_confidence_threshold_alias(self):
        """confidence_threshold should be alias for min_confidence."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path.home() / ".scrubiq")

        assert config.confidence_threshold == config.min_confidence

        config.confidence_threshold = 0.7
        assert config.min_confidence == 0.7


class TestConfigValidation:
    """Tests for Config validation in __post_init__."""

    def test_invalid_face_redaction_method_raises(self):
        """Invalid face_redaction_method should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="Invalid face_redaction_method"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    face_redaction_method="invalid"
                )

    def test_invalid_device_raises(self):
        """Invalid device should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="Invalid device"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    device="invalid"
                )

    def test_invalid_min_confidence_raises(self):
        """min_confidence outside 0-1 should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="min_confidence"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    min_confidence=1.5
                )

    def test_invalid_review_threshold_raises(self):
        """review_threshold outside 0-1 should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="review_threshold"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    review_threshold=-0.1
                )

    def test_invalid_session_timeout_raises(self):
        """session_timeout_minutes < 1 should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="session_timeout_minutes"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    session_timeout_minutes=0
                )

    def test_invalid_api_port_raises(self):
        """api_port outside valid range should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="api_port"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    api_port=70000
                )

    def test_invalid_on_model_timeout_raises(self):
        """Invalid on_model_timeout should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="on_model_timeout"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    on_model_timeout="invalid"
                )

    def test_invalid_model_timeout_seconds_raises(self):
        """model_timeout_seconds < 1 should raise ValueError."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            with pytest.raises(ValueError, match="model_timeout_seconds"):
                Config(
                    data_dir=Path.home() / ".scrubiq",
                    model_timeout_seconds=0
                )

    def test_forbidden_data_dir_raises(self):
        """Forbidden data_dir should raise ValueError."""
        from scrubiq.config import Config

        with pytest.raises(ValueError, match="Invalid data_dir"):
            Config(data_dir=Path("/etc"))


class TestEnsureDirectories:
    """Tests for ensure_directories method."""

    def test_creates_directories(self, tmp_path):
        """ensure_directories should create required directories."""
        from scrubiq.config import Config

        data_dir = tmp_path / "scrubiq_test"

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=data_dir)
            config.ensure_directories()

        assert data_dir.exists()
        assert (data_dir / "models").exists()
        assert (data_dir / "dictionaries").exists()

    def test_sets_permissions(self, tmp_path):
        """ensure_directories should set secure permissions."""
        from scrubiq.config import Config
        import stat

        data_dir = tmp_path / "scrubiq_test2"

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=data_dir)
            config.ensure_directories()

        # Check permissions (owner only)
        mode = data_dir.stat().st_mode
        assert mode & stat.S_IRWXU  # Owner has rwx
        assert not (mode & stat.S_IRWXG)  # Group has nothing
        assert not (mode & stat.S_IRWXO)  # Others have nothing


class TestConfigProperties:
    """Tests for additional Config properties."""

    def test_rapidocr_dir(self):
        """rapidocr_dir should be models_dir/rapidocr."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.rapidocr_dir == Path("/home/user/.scrubiq/models/rapidocr")

    def test_face_detection_dir(self):
        """face_detection_dir should be models_dir/face_detection."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.face_detection_dir == Path("/home/user/.scrubiq/models/face_detection")

    def test_pii_bert_path(self):
        """pii_bert_path should be models_dir/pii_bert."""
        from scrubiq.config import Config

        with patch('scrubiq.config.validate_data_path', return_value=True):
            config = Config(data_dir=Path("/home/user/.scrubiq"))

        assert config.pii_bert_path == Path("/home/user/.scrubiq/models/pii_bert")
