"""Tests for Phase O: Model Bundling — model registry, CLI, and wiring.

Covers:
- Model registry (specs, aliases, resolution, install detection)
- CLI commands (list, check, download)
- Download logic (mocked HuggingFace)
- Orchestrator & OCR missing-model messages
"""

import json
import os
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Model registry unit tests
# ---------------------------------------------------------------------------

class TestModelRegistry:
    """Tests for model_registry.py."""

    def test_registry_has_expected_models(self):
        from openlabels.core.detectors.model_registry import get_registry
        registry = get_registry()
        assert "phi_bert" in registry
        assert "pii_bert" in registry
        assert "ocr" in registry

    def test_model_spec_fields(self):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi_bert")
        assert spec.name == "phi_bert"
        assert spec.repo_id  # Non-empty HuggingFace repo ID
        assert len(spec.files) > 0
        assert spec.description

    def test_ocr_spec_has_install_subdir(self):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("ocr")
        assert spec.install_subdir == "rapidocr"

    def test_resolve_names_concrete(self):
        from openlabels.core.detectors.model_registry import resolve_names
        assert resolve_names(["phi_bert"]) == ["phi_bert"]
        assert resolve_names(["phi_bert", "ocr"]) == ["phi_bert", "ocr"]

    def test_resolve_names_alias_all(self):
        from openlabels.core.detectors.model_registry import resolve_names
        resolved = resolve_names(["all"])
        assert "phi_bert" in resolved
        assert "pii_bert" in resolved
        assert "ocr" in resolved

    def test_resolve_names_alias_ner(self):
        from openlabels.core.detectors.model_registry import resolve_names
        resolved = resolve_names(["ner"])
        assert "phi_bert" in resolved
        assert "pii_bert" in resolved
        assert "ocr" not in resolved

    def test_resolve_names_deduplicates(self):
        from openlabels.core.detectors.model_registry import resolve_names
        resolved = resolve_names(["ner", "phi_bert"])
        assert resolved.count("phi_bert") == 1

    def test_resolve_names_unknown_raises(self):
        from openlabels.core.detectors.model_registry import resolve_names
        with pytest.raises(KeyError, match="Unknown model"):
            resolve_names(["nonexistent_model"])

    def test_is_installed_empty_dir(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi_bert")
        assert not spec.is_installed(tmp_path)

    def test_is_installed_with_files(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi_bert")
        # Create all required files (using alternatives — INT8 covers the ONNX group)
        (tmp_path / "phi_bert_int8.onnx").write_bytes(b"fake")
        (tmp_path / "phi_bert.tokenizer.json").write_text("{}")
        (tmp_path / "phi_bert.labels.json").write_text("{}")
        assert spec.is_installed(tmp_path)

    def test_is_installed_alternative_satisfied(self, tmp_path):
        """INT8 model satisfies the ONNX model alternative group."""
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi_bert")
        # Only INT8 present (not full-precision)
        (tmp_path / "phi_bert_int8.onnx").write_bytes(b"fake")
        (tmp_path / "phi_bert.tokenizer.json").write_text("{}")
        (tmp_path / "phi_bert.labels.json").write_text("{}")
        assert spec.is_installed(tmp_path)

    def test_get_missing_files(self, tmp_path):
        from openlabels.core.detectors.model_registry import get_model_spec
        spec = get_model_spec("phi_bert")
        missing = spec.get_missing_files(tmp_path)
        assert len(missing) > 0
        # Should mention at least the ONNX model and tokenizer
        filenames = " ".join(missing)
        assert "onnx" in filenames
        assert "tokenizer" in filenames

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
        import importlib
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
        assert "phi_bert" in result.output
        assert "pii_bert" in result.output
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

    def test_init_ml_detectors_logs_download_hint_when_missing(self, tmp_path, caplog):
        """When models dir doesn't exist, orchestrator suggests download command."""
        from openlabels.core.detectors.orchestrator import DetectorOrchestrator
        from openlabels.core.detectors.config import DetectionConfig

        missing_dir = tmp_path / "nonexistent"
        config = DetectionConfig(enable_ml=True, ml_model_dir=missing_dir)

        import logging
        with caplog.at_level(logging.WARNING):
            orch = DetectorOrchestrator(config)

        assert "openlabels models download" in caplog.text

    def test_ml_disabled_by_default(self):
        """Default DetectionConfig has enable_ml=False."""
        from openlabels.core.detectors.config import DetectionConfig
        config = DetectionConfig()
        assert config.enable_ml is False

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
        """Registry includes phi_bert, pii_bert, ocr."""
        src = Path("src/openlabels/core/detectors/model_registry.py").read_text()
        assert '"phi_bert"' in src
        assert '"pii_bert"' in src
        assert '"ocr"' in src
        assert "chillbot-io" in src  # HF org prefix
