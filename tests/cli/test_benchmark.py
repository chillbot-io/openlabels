"""
Functional tests for the benchmark CLI command.

Tests benchmark command invocation, argument parsing, output formatting,
adapter selection, and result display.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


def _make_mock_result(config_name="patterns_only"):
    """Create a mock BenchmarkResult with realistic fields."""
    mock_result = MagicMock()
    mock_result.detectors_loaded = ["checksum", "pattern"]
    mock_result.dataset_source = "ai4privacy (bundled)"
    mock_result.config.name = config_name
    mock_result.config.confidence_threshold = 0.5
    mock_result.config.enable_ml = False
    mock_result.config.enable_phi = False
    mock_result.config.use_tiered_pipeline = False
    mock_result.overall.f1 = 0.75
    mock_result.by_category = {}
    mock_result.sample_results = []
    mock_result.summary.return_value = {
        "config": config_name,
        "precision": 0.80,
        "recall": 0.70,
        "f1": 0.75,
        "true_positives": 100,
        "false_positives": 25,
        "false_negatives": 43,
        "exact_matches": 80,
        "partial_matches": 20,
        "type_mismatches": 5,
        "avg_time_ms": 12.5,
        "throughput_sps": 80.0,
        "total_time_s": 6.3,
    }
    return mock_result


class TestBenchmarkHelp:
    """Tests for benchmark command help text."""

    def test_benchmark_help_shows_usage(self, runner):
        """benchmark --help should show usage information."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "--samples" in result.output
        assert "--preset" in result.output
        assert "--dataset" in result.output
        assert "--ml" in result.output

    def test_benchmark_help_shows_subcommands(self, runner):
        """benchmark --help should list subcommands."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["--help"])

        assert result.exit_code == 0
        assert "sweep" in result.output
        assert "tune" in result.output
        assert "diagnose" in result.output
        assert "calibrate" in result.output

    def test_sweep_help(self, runner):
        """benchmark sweep --help should show sweep options."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["sweep", "--help"])

        assert result.exit_code == 0
        assert "--presets" in result.output
        assert "Compare" in result.output or "configurations" in result.output

    def test_tune_help(self, runner):
        """benchmark tune --help should show tuning options."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["tune", "--help"])

        assert result.exit_code == 0
        assert "--thresholds" in result.output
        assert "--ml" in result.output

    def test_diagnose_help(self, runner):
        """benchmark diagnose --help should show diagnose options."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["diagnose", "--help"])

        assert result.exit_code == 0
        assert "--top" in result.output


class TestBenchmarkArgumentParsing:
    """Tests for benchmark argument parsing and validation."""

    def test_invalid_dataset_rejected(self, runner):
        """benchmark with invalid --dataset should fail."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["--dataset", "nonexistent_dataset"])

        assert result.exit_code == 2
        assert "Invalid value" in result.output or "nonexistent_dataset" in result.output

    def test_samples_accepts_integer(self, runner):
        """benchmark --samples should accept integer values."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_result = _make_mock_result()
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.get_preset") as mock_get_preset, \
             patch("openlabels.core.benchmark.harness.run_benchmark", return_value=mock_result):
            mock_config = MagicMock()
            mock_config.name = "patterns_only"
            mock_config.confidence_threshold = 0.5
            mock_config.enable_ml = False
            mock_config.enable_phi = False
            mock_config.use_tiered_pipeline = False
            mock_get_preset.return_value = mock_config

            result = runner.invoke(benchmark, ["--samples", "100"])

        assert result.exit_code == 0

    def test_invalid_samples_rejected(self, runner):
        """benchmark --samples with non-integer should fail."""
        from openlabels.cli.commands.benchmark import benchmark

        result = runner.invoke(benchmark, ["--samples", "not_a_number"])

        assert result.exit_code == 2

    def test_dataset_choices_are_accepted(self, runner):
        """Valid dataset names should be accepted."""
        from openlabels.cli.commands.benchmark import DATASET_CHOICES

        assert "ai4privacy" in DATASET_CHOICES
        assert "nemotron_pii" in DATASET_CHOICES
        assert "gretel_pii" in DATASET_CHOICES
        assert "gretel_finance" in DATASET_CHOICES


class TestBenchmarkExecution:
    """Tests for benchmark execution and result formatting."""

    def test_benchmark_runs_and_prints_results(self, runner):
        """benchmark should run and print precision/recall/F1."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_result = _make_mock_result()
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.get_preset") as mock_get_preset, \
             patch("openlabels.core.benchmark.harness.run_benchmark", return_value=mock_result):
            mock_config = MagicMock()
            mock_config.name = "patterns_only"
            mock_config.confidence_threshold = 0.5
            mock_config.enable_ml = False
            mock_config.enable_phi = False
            mock_config.use_tiered_pipeline = False
            mock_get_preset.return_value = mock_config

            result = runner.invoke(benchmark, ["--samples", "10"])

        assert result.exit_code == 0
        assert "Precision" in result.output
        assert "Recall" in result.output
        assert "F1 Score" in result.output

    def test_benchmark_shows_config_name(self, runner):
        """benchmark should display configuration name."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_result = _make_mock_result()
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.get_preset") as mock_get_preset, \
             patch("openlabels.core.benchmark.harness.run_benchmark", return_value=mock_result):
            mock_config = MagicMock()
            mock_config.name = "patterns_only"
            mock_config.confidence_threshold = 0.5
            mock_config.enable_ml = False
            mock_config.enable_phi = False
            mock_config.use_tiered_pipeline = False
            mock_get_preset.return_value = mock_config

            result = runner.invoke(benchmark, [])

        assert result.exit_code == 0
        assert "Benchmark:" in result.output
        assert "patterns_only" in result.output

    def test_benchmark_invalid_preset_shows_error(self, runner):
        """benchmark with invalid preset should show error."""
        from openlabels.cli.commands.benchmark import benchmark

        with patch("openlabels.core.benchmark.harness.get_preset", side_effect=ValueError("Unknown preset: bad")):
            result = runner.invoke(benchmark, ["--preset", "bad"])

        assert result.exit_code == 0  # Error is echoed, not raised
        assert "Error" in result.output

    def test_benchmark_ml_flag_applied(self, runner):
        """benchmark --ml should enable ML in config."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_result = _make_mock_result("patterns_only+ml")
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.get_preset") as mock_get_preset, \
             patch("openlabels.core.benchmark.harness.run_benchmark", return_value=mock_result), \
             patch("openlabels.cli.commands.benchmark._show_model_status"):
            mock_config = MagicMock()
            mock_config.name = "patterns_only"
            mock_config.confidence_threshold = 0.5
            mock_config.enable_ml = False
            mock_config.enable_phi = False
            mock_config.use_tiered_pipeline = False
            mock_get_preset.return_value = mock_config

            result = runner.invoke(benchmark, ["--ml"])

        assert result.exit_code == 0
        # The config's enable_ml should have been set to True
        assert mock_config.enable_ml is True

    def test_benchmark_dataset_load_error(self, runner):
        """benchmark should handle DatasetLoadError gracefully."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.get_preset") as mock_get_preset, \
             patch("openlabels.core.benchmark.harness.run_benchmark") as mock_run:
            mock_config = MagicMock()
            mock_config.name = "patterns_only"
            mock_config.confidence_threshold = 0.5
            mock_config.enable_ml = False
            mock_config.enable_phi = False
            mock_config.use_tiered_pipeline = False
            mock_get_preset.return_value = mock_config

            # Simulate DatasetLoadError
            from openlabels.core.benchmark.dataset import DatasetLoadError
            mock_run.side_effect = DatasetLoadError("Dataset not available")

            result = runner.invoke(benchmark, [])

        assert result.exit_code == 1
        assert "Dataset error" in result.output


class TestBenchmarkOutputSave:
    """Tests for benchmark output saving."""

    def test_benchmark_save_output(self, runner, tmp_path):
        """benchmark --output should save results to file."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_result = _make_mock_result()
        mock_samples = [MagicMock()]
        output_file = str(tmp_path / "results.json")

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.get_preset") as mock_get_preset, \
             patch("openlabels.core.benchmark.harness.run_benchmark", return_value=mock_result), \
             patch("openlabels.core.benchmark.harness.save_results") as mock_save, \
             patch("openlabels.core.path_validation.validate_output_path", return_value=output_file):
            mock_config = MagicMock()
            mock_config.name = "patterns_only"
            mock_config.confidence_threshold = 0.5
            mock_config.enable_ml = False
            mock_config.enable_phi = False
            mock_config.use_tiered_pipeline = False
            mock_get_preset.return_value = mock_config

            result = runner.invoke(benchmark, ["--output", output_file])

        assert result.exit_code == 0
        assert "Results saved to" in result.output
        mock_save.assert_called_once()


class TestSweepCommand:
    """Tests for benchmark sweep subcommand."""

    def test_sweep_runs_comparison(self, runner):
        """benchmark sweep should compare multiple configurations."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_results = [
            _make_mock_result("patterns_relaxed"),
            _make_mock_result("patterns_only"),
            _make_mock_result("patterns_strict"),
        ]
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.run_sweep", return_value=mock_results):
            result = runner.invoke(benchmark, ["sweep"])

        assert result.exit_code == 0
        assert "Sweep:" in result.output

    def test_sweep_custom_presets(self, runner):
        """benchmark sweep --presets should use custom preset list."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_results = [
            _make_mock_result("patterns_only"),
            _make_mock_result("patterns_strict"),
        ]
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.run_sweep", return_value=mock_results) as mock_sweep:
            result = runner.invoke(
                benchmark, ["sweep", "--presets", "patterns_only,patterns_strict"]
            )

        assert result.exit_code == 0
        # Verify the preset names were passed correctly
        call_kwargs = mock_sweep.call_args
        assert "patterns_only" in call_kwargs.kwargs.get("preset_names", call_kwargs[1].get("preset_names", []))


class TestTuneCommand:
    """Tests for benchmark tune subcommand."""

    def test_tune_runs_threshold_sweep(self, runner):
        """benchmark tune should run threshold sweep."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_results = [_make_mock_result("threshold=0.5")]
        mock_results[0].config.confidence_threshold = 0.5
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.threshold_sweep", return_value=mock_results):
            result = runner.invoke(benchmark, ["tune"])

        assert result.exit_code == 0
        assert "Threshold tuning" in result.output

    def test_tune_custom_thresholds(self, runner):
        """benchmark tune --thresholds should use custom thresholds."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_results = [_make_mock_result("threshold=0.3")]
        mock_results[0].config.confidence_threshold = 0.3
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.threshold_sweep", return_value=mock_results) as mock_sweep:
            result = runner.invoke(
                benchmark, ["tune", "--thresholds", "0.3,0.5,0.7"]
            )

        assert result.exit_code == 0
        # Verify custom thresholds were passed
        call_kwargs = mock_sweep.call_args
        threshold_arg = call_kwargs.kwargs.get("thresholds", call_kwargs[1].get("thresholds"))
        assert threshold_arg == [0.3, 0.5, 0.7]

    def test_tune_shows_optimal_threshold(self, runner):
        """benchmark tune should show the optimal threshold."""
        from openlabels.cli.commands.benchmark import benchmark

        mock_results = [_make_mock_result("threshold=0.50")]
        mock_results[0].config.confidence_threshold = 0.50
        mock_results[0].overall.f1 = 0.85
        mock_samples = [MagicMock()]

        with patch("openlabels.cli.commands.benchmark._load_dataset_samples", return_value=mock_samples), \
             patch("openlabels.core.benchmark.harness.threshold_sweep", return_value=mock_results):
            result = runner.invoke(benchmark, ["tune"])

        assert result.exit_code == 0
        assert "Optimal threshold" in result.output
        assert "Best F1" in result.output


class TestLoadDatasetSamples:
    """Tests for _load_dataset_samples adapter selection."""

    def test_load_ai4privacy_default(self, runner):
        """Default dataset should load ai4privacy."""
        from openlabels.cli.commands.benchmark import _load_dataset_samples

        mock_samples = [MagicMock()]
        with patch("openlabels.core.benchmark.dataset.load_dataset", return_value=(mock_samples, "bundled")):
            samples = _load_dataset_samples("ai4privacy", 100, 42)

        assert len(samples) == 1

    def test_load_nemotron_pii(self, runner):
        """nemotron_pii dataset should use nemotron adapter."""
        from openlabels.cli.commands.benchmark import _load_dataset_samples

        mock_samples = [MagicMock()]
        with patch("openlabels.core.benchmark.adapters.load_nemotron_pii", return_value=(mock_samples, "cache")):
            samples = _load_dataset_samples("nemotron_pii", 100, 42)

        assert len(samples) == 1

    def test_load_unknown_dataset_raises(self):
        """Unknown dataset should raise BadParameter."""
        from openlabels.cli.commands.benchmark import _load_dataset_samples

        with pytest.raises(Exception) as exc_info:
            _load_dataset_samples("totally_unknown", 100, 42)

        assert "Unknown dataset" in str(exc_info.value)


class TestResultFormatting:
    """Tests for benchmark result formatting functions."""

    def test_print_result_outputs_metrics(self, runner, capsys):
        """_print_result should display all metrics."""
        from openlabels.cli.commands.benchmark import _print_result

        mock_result = _make_mock_result()
        _print_result(mock_result, verbose=False)

        captured = capsys.readouterr()
        assert "Precision" in captured.out
        assert "Recall" in captured.out
        assert "F1 Score" in captured.out
        assert "TP:" in captured.out
        assert "FP:" in captured.out
        assert "FN:" in captured.out

    def test_print_result_verbose_shows_categories(self, runner, capsys):
        """_print_result verbose=True should show per-category breakdown."""
        from openlabels.cli.commands.benchmark import _print_result

        mock_result = _make_mock_result()
        mock_metric = MagicMock()
        mock_metric.precision = 0.9
        mock_metric.recall = 0.85
        mock_metric.f1 = 0.87
        mock_metric.true_positives = 50
        mock_metric.false_positives = 5
        mock_metric.false_negatives = 8
        mock_result.by_category = {"SSN": mock_metric}

        _print_result(mock_result, verbose=True)

        captured = capsys.readouterr()
        assert "Per-category breakdown" in captured.out
        assert "SSN" in captured.out

    def test_cli_progress_callback(self, capsys):
        """_cli_progress should show progress bar."""
        from openlabels.cli.commands.benchmark import _cli_progress

        _cli_progress(50, 100)

        captured = capsys.readouterr()
        assert "50/100" in captured.out
        assert "50%" in captured.out

    def test_print_comparison_shows_table(self, capsys):
        """_print_comparison should show comparison table."""
        from openlabels.cli.commands.benchmark import _print_comparison

        mock_results = [
            _make_mock_result("config_a"),
            _make_mock_result("config_b"),
        ]

        _print_comparison(mock_results)

        captured = capsys.readouterr()
        assert "Config" in captured.out
        assert "Prec" in captured.out
        assert "Recall" in captured.out
        assert "F1" in captured.out
