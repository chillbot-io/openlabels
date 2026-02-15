"""Tests for the benchmark CLI command."""

import json
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from openlabels.cli.commands.benchmark import benchmark
from openlabels.core.benchmark.dataset import BenchmarkSample, GoldSpan
from openlabels.core.benchmark.harness import BenchmarkConfig, BenchmarkResult
from openlabels.core.benchmark.evaluate import EvalMetrics


# Synthetic samples for testing
MOCK_SAMPLES = [
    BenchmarkSample(
        sample_id=0,
        text="Contact john@example.com or 555-123-4567",
        gold_spans=[
            GoldSpan(8, 24, "john@example.com", "EMAIL", "EMAIL"),
            GoldSpan(28, 40, "555-123-4567", "PHONE", "PHONENUMBER"),
        ],
    ),
]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_load_dataset():
    """Mock dataset loading to avoid downloading."""
    with patch(
        "openlabels.core.benchmark.harness.load_dataset",
        return_value=MOCK_SAMPLES,
    ) as mock:
        yield mock


class TestBenchmarkCommand:
    """Test the main benchmark command."""

    def test_basic_invocation(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, ["--samples", "1"])
        assert result.exit_code == 0
        assert "Precision:" in result.output
        assert "Recall:" in result.output
        assert "F1 Score:" in result.output

    def test_verbose_flag(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, ["--samples", "1", "--verbose"])
        assert result.exit_code == 0
        assert "Per-category" in result.output

    def test_invalid_preset(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, ["--preset", "nonexistent"])
        assert result.exit_code == 0
        assert "Unknown preset" in result.output

    def test_output_to_file(self, runner, mock_load_dataset, tmp_path):
        output = tmp_path / "results.json"
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "--output", str(output),
        ])
        assert result.exit_code == 0
        assert output.exists()

        data = json.loads(output.read_text())
        assert "results" in data

    def test_threshold_override(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "--threshold", "0.5",
        ])
        assert result.exit_code == 0
        assert "0.5" in result.output  # threshold shown in header

    def test_enable_ml_flag(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "--enable-ml",
        ])
        assert result.exit_code == 0
        assert "ML: on" in result.output

    def test_tiered_flag(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "--tiered",
        ])
        assert result.exit_code == 0
        assert "tiered" in result.output


class TestSweepCommand:
    """Test the sweep subcommand."""

    def test_basic_sweep(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "sweep",
        ])
        assert result.exit_code == 0
        assert "patterns_relaxed" in result.output
        assert "patterns_only" in result.output
        assert "patterns_strict" in result.output

    def test_sweep_with_presets(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "sweep",
            "--presets", "patterns_only,patterns_strict",
        ])
        assert result.exit_code == 0
        assert "patterns_only" in result.output
        assert "patterns_strict" in result.output


class TestTuneCommand:
    """Test the tune subcommand."""

    def test_basic_tune(self, runner, mock_load_dataset):
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "tune",
            "--thresholds", "0.5,0.7",
        ])
        assert result.exit_code == 0
        assert "Optimal threshold" in result.output

    def test_tune_output(self, runner, mock_load_dataset, tmp_path):
        output = tmp_path / "tune.json"
        result = runner.invoke(benchmark, [
            "--samples", "1",
            "--output", str(output),
            "tune",
            "--thresholds", "0.5,0.7",
        ])
        assert result.exit_code == 0
        assert output.exists()
