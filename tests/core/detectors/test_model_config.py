"""Tests for ML model configuration and availability checking."""


from openlabels.core.detectors.model_config import (
    ModelsReport,
    ModelStatus,
    check_models_available,
)


class TestCheckModelsAvailable:
    """Tests for check_models_available()."""

    def test_directory_missing(self, tmp_path):
        missing_dir = tmp_path / "nonexistent"
        report = check_models_available(missing_dir)

        assert not report.models_dir_exists
        assert not report.any_available
        assert not report.all_available
        assert "phi" in report.models
        assert not report.models["phi"].available
        assert any("does not exist" in f for f in report.models["phi"].missing_files)

    def test_empty_directory(self, tmp_path):
        report = check_models_available(tmp_path)

        assert report.models_dir_exists
        assert not report.any_available
        assert "phi" in report.models
        assert not report.models["phi"].available

    def test_stanford_phi_all_present(self, tmp_path):
        """All required Stanford PHI model files present."""
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "config.json").write_text("{}")
        (phi_dir / "vocab.txt").write_text("vocab")
        (phi_dir / "pytorch_model.bin").write_bytes(b"weights")

        report = check_models_available(tmp_path)

        assert report.all_available
        assert report.any_available
        assert report.models["phi"].available
        assert report.models["phi"].backend == "hf"
        assert report.models["phi"].path == phi_dir

    def test_safetensors_accepted(self, tmp_path):
        """model.safetensors accepted as alternative to pytorch_model.bin."""
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "config.json").write_text("{}")
        (phi_dir / "vocab.txt").write_text("vocab")
        (phi_dir / "model.safetensors").write_bytes(b"weights")

        report = check_models_available(tmp_path)
        assert report.models["phi"].available

    def test_missing_weights_reported(self, tmp_path):
        """Model directory present but weights missing -> not available."""
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "config.json").write_text("{}")
        (phi_dir / "vocab.txt").write_text("vocab")
        # No weight files

        report = check_models_available(tmp_path)
        assert not report.models["phi"].available
        assert any("weights" in f for f in report.models["phi"].missing_files)

    def test_missing_config_reported(self, tmp_path):
        """Weights present but config.json missing -> not available."""
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "pytorch_model.bin").write_bytes(b"weights")
        (phi_dir / "vocab.txt").write_text("vocab")
        # No config.json

        report = check_models_available(tmp_path)
        assert not report.models["phi"].available
        assert any("config.json" in f for f in report.models["phi"].missing_files)

    def test_missing_vocab_reported(self, tmp_path):
        """Weights and config present but vocab.txt missing -> not available."""
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "pytorch_model.bin").write_bytes(b"weights")
        (phi_dir / "config.json").write_text("{}")
        # No vocab.txt

        report = check_models_available(tmp_path)
        assert not report.models["phi"].available
        assert any("vocab.txt" in f for f in report.models["phi"].missing_files)

    def test_missing_subdir_reported(self, tmp_path):
        """stanford_phi/ directory does not exist -> directory reported missing."""
        report = check_models_available(tmp_path)
        assert not report.models["phi"].available
        assert any("directory" in f for f in report.models["phi"].missing_files)

    def test_use_onnx_parameter_ignored(self, tmp_path):
        """use_onnx parameter is accepted but ignored (API compatibility)."""
        phi_dir = tmp_path / "stanford_phi"
        phi_dir.mkdir()
        (phi_dir / "config.json").write_text("{}")
        (phi_dir / "vocab.txt").write_text("vocab")
        (phi_dir / "pytorch_model.bin").write_bytes(b"weights")

        report_onnx = check_models_available(tmp_path, use_onnx=True)
        report_hf = check_models_available(tmp_path, use_onnx=False)

        assert report_onnx.models["phi"].available
        assert report_hf.models["phi"].available

    def test_only_phi_model_checked(self, tmp_path):
        """Only 'phi' model is checked (no phi_bert/pii_bert)."""
        report = check_models_available(tmp_path)
        assert "phi" in report.models
        assert "phi_bert" not in report.models
        assert "pii_bert" not in report.models


class TestModelsReport:
    """Tests for ModelsReport properties and summary."""

    def test_summary_format(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi": ModelStatus(
                    name="phi", available=True, path=tmp_path / "stanford_phi", backend="hf"
                ),
            },
        )

        summary = report.summary()
        assert "phi: AVAILABLE" in summary
        assert "hf" in summary

    def test_summary_missing_model(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi": ModelStatus(
                    name="phi",
                    available=False,
                    missing_files=["config.json"],
                    backend="hf",
                ),
            },
        )

        summary = report.summary()
        assert "phi: MISSING" in summary
        assert "config.json" in summary

    def test_any_available_true_when_one_available(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi": ModelStatus(name="phi", available=True, path=tmp_path, backend="hf"),
            },
        )
        assert report.any_available is True

    def test_any_available_false_when_none_available(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi": ModelStatus(name="phi", available=False, backend="hf"),
            },
        )
        assert report.any_available is False

    def test_all_available_true(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi": ModelStatus(name="phi", available=True, path=tmp_path, backend="hf"),
            },
        )
        assert report.all_available is True

    def test_all_available_false(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi": ModelStatus(name="phi", available=False, backend="hf"),
            },
        )
        assert report.all_available is False


class TestModelStatus:
    """Tests for ModelStatus dataclass."""

    def test_default_values(self):
        status = ModelStatus(name="phi", available=False)
        assert status.name == "phi"
        assert status.available is False
        assert status.path is None
        assert status.missing_files == []
        assert status.backend == "unknown"

    def test_with_all_fields(self, tmp_path):
        status = ModelStatus(
            name="phi",
            available=True,
            path=tmp_path / "stanford_phi",
            missing_files=[],
            backend="hf",
        )
        assert status.available is True
        assert status.backend == "hf"
        assert status.path == tmp_path / "stanford_phi"
