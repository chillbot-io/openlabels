"""Tests for Phase O: Model Bundling — model registry, CLI, and wiring.

Covers:
- Model registry (specs, aliases, resolution, install detection)
- CLI commands (list, check, download)
- Download logic (mocked HuggingFace)
- Orchestrator & OCR missing-model messages
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Model registry unit tests
# ---------------------------------------------------------------------------

class TestModelRegistry:
    """Tests for model_registry.py."""

    def test_registry_has_expected_models(self):
        from openlabels.core.detectors.model_registry import get_registry
        registry = get_registry()
        assert "phi" in registry
        assert "ocr" in registry

    def test_model_spec_fields(self):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi")
        assert spec.name == "phi"
        assert spec.repo_id  # Non-empty HuggingFace repo ID
        assert len(spec.files) > 0
        assert spec.description

    def test_ocr_spec_has_install_subdir(self):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("ocr")
        assert spec.install_subdir == "rapidocr"

    def test_resolve_names_concrete(self):
        from openlabels.core.detectors.model_registry import resolve_names
        assert resolve_names(["phi"]) == ["phi"]
        assert resolve_names(["phi", "ocr"]) == ["phi", "ocr"]

    def test_resolve_names_alias_all(self):
        from openlabels.core.detectors.model_registry import resolve_names
        resolved = resolve_names(["all"])
        assert "phi" in resolved
        assert "ocr" in resolved

    def test_resolve_names_alias_ml(self):
        from openlabels.core.detectors.model_registry import resolve_names
        resolved = resolve_names(["ml"])
        assert "phi" in resolved
        assert "ocr" not in resolved

    def test_resolve_names_deduplicates(self):
        from openlabels.core.detectors.model_registry import resolve_names
        resolved = resolve_names(["ml", "phi"])
        assert resolved.count("phi") == 1

    def test_resolve_names_unknown_raises(self):
        from openlabels.core.detectors.model_registry import resolve_names
        with pytest.raises(KeyError, match="Unknown model"):
            resolve_names(["nonexistent_model"])

    def test_is_installed_empty_dir(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi")
        assert not spec.is_installed(tmp_path)

    def test_is_installed_with_files(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi")
        # Create the stanford_phi/ subdirectory with required files
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "pytorch_model.bin").write_bytes(b"fake")
        (phi_dir / "config.json").write_text("{}")
        (phi_dir / "vocab.txt").write_text("vocab")
        (phi_dir / "special_tokens_map.json").write_text("{}")
        (phi_dir / "tokenizer_config.json").write_text("{}")
        assert spec.is_installed(tmp_path)

    def test_is_installed_missing_weights(self, tmp_path):
        """Missing weight files means not installed."""
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi")
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "config.json").write_text("{}")
        (phi_dir / "vocab.txt").write_text("vocab")
        # No pytorch_model.bin
        assert not spec.is_installed(tmp_path)

    def test_get_missing_files(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi")
        missing = spec.get_missing_files(tmp_path)
        assert len(missing) > 0
        # Should mention model weights and config
        filenames = " ".join(missing)
        assert "pytorch_model.bin" in filenames or "config.json" in filenames

    def test_ocr_install_dir(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("ocr")
        assert spec.get_install_dir(tmp_path) == tmp_path / "rapidocr"

    def test_ocr_is_installed(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("ocr")
        ocr_dir = tmp_path / "rapidocr"
        ocr_dir.mkdir()
        (ocr_dir / "det.onnx").write_bytes(b"fake")
        (ocr_dir / "rec.onnx").write_bytes(b"fake")
        (ocr_dir / "cls.onnx").write_bytes(b"fake")
        assert spec.is_installed(tmp_path)


class TestModelDownload:
    """Tests for download_model with mocked HuggingFace Hub."""

    def _make_fake_hf_module(self, tmp_path):
        """Create a mock huggingface_hub module with a fake hf_hub_download."""
        cached = tmp_path / "hf_cache"
        cached.mkdir(exist_ok=True)

        mock_hf = MagicMock()

        def fake_hf_download(repo_id, filename):
            fake = cached / filename
            fake.parent.mkdir(parents=True, exist_ok=True)
            fake.write_bytes(b"model-data")
            return str(fake)

        mock_hf.hf_hub_download = fake_hf_download
        return mock_hf

    def test_download_creates_files(self, tmp_path):
        import sys

        from openlabels.core.detectors.model_registry import download_model

        mock_hf = self._make_fake_hf_module(tmp_path)
        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            models_dir = tmp_path / "models"
            path = download_model("ocr", models_dir=models_dir, force=True)

            # OCR installs to models/rapidocr/
            assert path == models_dir / "rapidocr"
            assert (path / "det.onnx").exists()
            assert (path / "rec.onnx").exists()
            assert (path / "cls.onnx").exists()

    def test_download_skips_if_installed(self, tmp_path):
        import sys

        from openlabels.core.detectors.model_registry import download_model, get_model_spec

        # Pre-install OCR models
        spec = get_model_spec("ocr")
        ocr_dir = tmp_path / "rapidocr"
        ocr_dir.mkdir(parents=True)
        for mf in spec.files:
            (ocr_dir / mf.filename).write_bytes(b"existing")

        mock_hf = MagicMock()
        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            download_model("ocr", models_dir=tmp_path)
            mock_hf.hf_hub_download.assert_not_called()

    def test_download_raises_without_huggingface_hub(self, tmp_path):
        """download_model raises ImportError if huggingface_hub is not installed."""
        from openlabels.core.detectors import model_registry

        with patch.dict("sys.modules", {"huggingface_hub": None}):
            # Force re-import attempt inside the function
            with pytest.raises(ImportError, match="huggingface_hub"):
                # The function tries `from huggingface_hub import hf_hub_download`
                # which will fail because we patched the module to None
                model_registry.download_model("ocr", models_dir=tmp_path, force=True)

    def test_download_unknown_model_raises(self, tmp_path):
        from openlabels.core.detectors.model_registry import download_model
        with pytest.raises(KeyError):
            download_model("nonexistent", models_dir=tmp_path)

    def test_sha256_verification(self, tmp_path):
        from openlabels.core.detectors.model_registry import _verify_sha256
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"hello")

        import hashlib
        expected = hashlib.sha256(b"hello").hexdigest()
        assert _verify_sha256(test_file, expected)
        assert not _verify_sha256(test_file, "0" * 64)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestModelsCLI:
    """Tests for the openlabels models CLI commands."""

    def test_models_group_registered(self):
        """models command group is registered in the CLI."""
        src = Path("src/openlabels/__main__.py").read_text()
        assert "cli.add_command(models)" in src

    def test_models_has_subcommands(self):
        src = Path("src/openlabels/cli/commands/models.py").read_text()
        assert 'def list_models' in src
        assert 'def check' in src
        assert 'def download' in src

    @pytest.fixture
    def cli_runner(self):
        try:
            from click.testing import CliRunner
            return CliRunner()
        except ImportError:
            pytest.skip("click not installed")

    def _get_models_group(self):
        """Import models group, skipping if CLI deps are missing."""
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "openlabels.cli.commands.models",
                "src/openlabels/cli/commands/models.py",
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.models
        except (ImportError, ModuleNotFoundError) as e:
            pytest.skip(f"CLI dependencies not available: {e}")

    def test_list_command_runs(self, tmp_path, cli_runner):
        models = self._get_models_group()

        result = cli_runner.invoke(models, ["list", "--models-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "phi" in result.output
        assert "ocr" in result.output
        assert "MISSING" in result.output

    def test_list_shows_installed(self, tmp_path, cli_runner):
        models = self._get_models_group()

        # Create OCR model files
        ocr_dir = tmp_path / "rapidocr"
        ocr_dir.mkdir()
        for name in ["det.onnx", "rec.onnx", "cls.onnx"]:
            (ocr_dir / name).write_bytes(b"fake")

        result = cli_runner.invoke(models, ["list", "--models-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "INSTALLED" in result.output

    def test_check_command_runs(self, tmp_path, cli_runner):
        models = self._get_models_group()

        result = cli_runner.invoke(models, ["check", "--models-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "Models directory" in result.output

    def test_download_requires_names(self, cli_runner):
        models = self._get_models_group()

        result = cli_runner.invoke(models, ["download"])
        assert result.exit_code != 0  # Missing required NAMES argument


# ---------------------------------------------------------------------------
# Orchestrator wiring tests
# ---------------------------------------------------------------------------

class TestOrchestratorMLWiring:
    """Verify orchestrator loads ML detectors when models are present."""

    def test_init_ml_detectors_logs_warning_when_missing(self, tmp_path, caplog):
        """When models fail to load, orchestrator logs warnings."""
        from openlabels.core.detectors.config import DetectionConfig
        from openlabels.core.detectors.orchestrator import DetectorOrchestrator

        missing_dir = tmp_path / "nonexistent"
        config = DetectionConfig(
            enable_ml=True, enable_phi=False,
            enable_language_detection=False,
            ml_model_dir=missing_dir,
        )

        import logging
        with caplog.at_level(logging.WARNING):
            DetectorOrchestrator(config)

        assert "failed to load" in caplog.text.lower() or "not available" in caplog.text.lower()

    def test_ml_enabled_by_default(self):
        """Default DetectionConfig has enable_ml=True."""
        from openlabels.core.detectors.config import DetectionConfig
        config = DetectionConfig()
        assert config.enable_ml is True

    def test_full_config_enables_ml(self):
        """DetectionConfig.full() enables ML."""
        from openlabels.core.detectors.config import DetectionConfig
        config = DetectionConfig.full()
        assert config.enable_ml is True


class TestOCRWiring:
    """Verify OCR engine messages reference download command."""

    def test_ocr_unavailable_message_mentions_download(self):
        """OCR engine's ImportError message suggests openlabels models download."""
        from openlabels.core.ocr import OCREngine

        engine = OCREngine(models_dir=Path("/nonexistent"))

        # Mock is_available to return False
        with patch.object(type(engine), "is_available", new_callable=lambda: property(lambda self: False)):
            with pytest.raises(ImportError, match="openlabels models download"):
                engine._ensure_initialized()

    def test_onnx_detector_load_message_mentions_download(self, tmp_path):
        """ONNX detector load failure log message suggests download command."""
        src = Path("src/openlabels/core/detectors/ml_onnx.py").read_text()
        assert "openlabels models download" in src


# ---------------------------------------------------------------------------
# Source code verification (guard against regressions)
# ---------------------------------------------------------------------------

class TestPhaseOSourceChecks:
    """Source-level checks for Phase O implementation completeness."""

    def test_main_registers_models_command(self):
        """__main__.py imports and registers the models command group."""
        src = Path("src/openlabels/__main__.py").read_text()
        assert "models" in src
        assert "cli.add_command(models)" in src

    def test_commands_init_exports_models(self):
        """cli/commands/__init__.py exports models."""
        src = Path("src/openlabels/cli/commands/__init__.py").read_text()
        assert "from openlabels.cli.commands.models import models" in src
        assert '"models"' in src

    def test_model_registry_exists(self):
        """model_registry.py exists and defines expected functions."""
        src = Path("src/openlabels/core/detectors/model_registry.py").read_text()
        assert "def download_model" in src
        assert "def list_models" in src
        assert "def resolve_names" in src
        assert "def get_registry" in src
        assert "class ModelSpec" in src
        assert "huggingface_hub" in src

    def test_model_registry_has_all_models(self):
        """Registry includes phi and ocr."""
        src = Path("src/openlabels/core/detectors/model_registry.py").read_text()
        assert '"phi"' in src
        assert '"ocr"' in src
        assert "StanfordAIMI" in src or "stanford" in src.lower()  # HF repo
