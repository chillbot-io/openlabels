"""Tests for ML model configuration and availability checking."""

import pytest
from pathlib import Path

from openlabels.core.detectors.model_config import (
    ModelStatus,
    ModelsReport,
    check_models_available,
    get_model_paths,
)


class TestGetModelPaths:
    """Tests for get_model_paths()."""

    def test_returns_dict_with_expected_keys(self, tmp_path):
        paths = get_model_paths(tmp_path)
        assert "phi_bert" in paths
        assert "pii_bert" in paths
        assert "phi_bert_hf" in paths
        assert "pii_bert_hf" in paths

    def test_onnx_paths_point_to_base_dir(self, tmp_path):
        paths = get_model_paths(tmp_path)
        assert paths["phi_bert"] == tmp_path
        assert paths["pii_bert"] == tmp_path

    def test_hf_paths_point_to_subdirs(self, tmp_path):
        paths = get_model_paths(tmp_path)
        assert paths["phi_bert_hf"] == tmp_path / "phi_bert"
        assert paths["pii_bert_hf"] == tmp_path / "pii_bert"


class TestCheckModelsAvailableOnnx:
    """Tests for check_models_available() with ONNX backend."""

    def test_directory_missing(self, tmp_path):
        missing_dir = tmp_path / "nonexistent"
        report = check_models_available(missing_dir, use_onnx=True)

        assert not report.models_dir_exists
        assert not report.any_available
        assert not report.all_available
        for model in report.models.values():
            assert not model.available
            assert len(model.missing_files) > 0

    def test_empty_directory(self, tmp_path):
        report = check_models_available(tmp_path, use_onnx=True)

        assert report.models_dir_exists
        assert not report.any_available
        for model in report.models.values():
            assert not model.available

    def test_all_onnx_models_present(self, tmp_path):
        # Create all required ONNX files
        (tmp_path / "phi_bert_int8.onnx").write_text("model")
        (tmp_path / "phi_bert.tokenizer.json").write_text("{}")
        (tmp_path / "pii_bert_int8.onnx").write_text("model")
        (tmp_path / "pii_bert.tokenizer.json").write_text("{}")

        report = check_models_available(tmp_path, use_onnx=True)

        assert report.all_available
        assert report.any_available
        for model in report.models.values():
            assert model.available
            assert model.backend == "onnx"
            assert model.path == tmp_path

    def test_fallback_onnx_variant(self, tmp_path):
        """Full precision ONNX is accepted when INT8 is missing."""
        (tmp_path / "phi_bert.onnx").write_text("model")
        (tmp_path / "phi_bert.tokenizer.json").write_text("{}")

        report = check_models_available(tmp_path, use_onnx=True)
        assert report.models["phi_bert"].available

    def test_fallback_tokenizer_dir(self, tmp_path):
        """HuggingFace tokenizer directory is accepted as fallback."""
        (tmp_path / "phi_bert_int8.onnx").write_text("model")
        tok_dir = tmp_path / "phi_bert_tokenizer"
        tok_dir.mkdir()
        (tok_dir / "tokenizer.json").write_text("{}")

        report = check_models_available(tmp_path, use_onnx=True)
        assert report.models["phi_bert"].available

    def test_partial_availability(self, tmp_path):
        """One model available, the other missing."""
        (tmp_path / "phi_bert_int8.onnx").write_text("model")
        (tmp_path / "phi_bert.tokenizer.json").write_text("{}")

        report = check_models_available(tmp_path, use_onnx=True)

        assert report.any_available
        assert not report.all_available
        assert report.models["phi_bert"].available
        assert not report.models["pii_bert"].available

    def test_missing_tokenizer_reported(self, tmp_path):
        """Model file present but tokenizer missing -> not available."""
        (tmp_path / "phi_bert_int8.onnx").write_text("model")

        report = check_models_available(tmp_path, use_onnx=True)
        assert not report.models["phi_bert"].available
        assert any("tokenizer" in f for f in report.models["phi_bert"].missing_files)


class TestCheckModelsAvailableHF:
    """Tests for check_models_available() with HuggingFace backend."""

    def test_hf_all_present(self, tmp_path):
        for name in ("phi_bert", "pii_bert"):
            subdir = tmp_path / name
            subdir.mkdir()
            (subdir / "config.json").write_text("{}")
            (subdir / "model.safetensors").write_text("weights")

        report = check_models_available(tmp_path, use_onnx=False)

        assert report.all_available
        for model in report.models.values():
            assert model.backend == "hf"

    def test_hf_missing_weights(self, tmp_path):
        subdir = tmp_path / "phi_bert"
        subdir.mkdir()
        (subdir / "config.json").write_text("{}")
        # No weight files

        report = check_models_available(tmp_path, use_onnx=False)
        assert not report.models["phi_bert"].available

    def test_hf_missing_subdir(self, tmp_path):
        report = check_models_available(tmp_path, use_onnx=False)
        assert not report.models["phi_bert"].available


class TestModelsReport:
    """Tests for ModelsReport properties and summary."""

    def test_summary_format(self, tmp_path):
        report = ModelsReport(
            models_dir=tmp_path,
            models_dir_exists=True,
            models={
                "phi_bert": ModelStatus(
                    name="phi_bert", available=True, path=tmp_path, backend="onnx"
                ),
                "pii_bert": ModelStatus(
                    name="pii_bert",
                    available=False,
                    missing_files=["pii_bert_int8.onnx"],
                    backend="onnx",
                ),
            },
        )

        summary = report.summary()
        assert "phi_bert: AVAILABLE" in summary
        assert "pii_bert: MISSING" in summary
        assert "pii_bert_int8.onnx" in summary
