"""Tests for the benchmark harness.

Uses synthetic BenchmarkSample data to test the harness without
downloading the full dataset or requiring ML models.
"""

import pytest

from openlabels.core.benchmark.dataset import BenchmarkSample, GoldSpan
from openlabels.core.benchmark.harness import (
    BenchmarkConfig,
    BenchmarkResult,
    PRESET_CONFIGS,
    get_preset,
    run_benchmark,
    run_sweep,
    threshold_sweep,
    save_results,
)


def _make_sample(sample_id, text, spans_data):
    """Helper to create a BenchmarkSample with gold spans."""
    gold_spans = []
    for start, end, entity_type, label in spans_data:
        gold_spans.append(GoldSpan(
            start=start,
            end=end,
            text=text[start:end],
            entity_type=entity_type,
            original_label=label,
        ))
    return BenchmarkSample(
        sample_id=sample_id,
        text=text,
        gold_spans=gold_spans,
    )


# Synthetic samples with entities that pattern detectors can find
SYNTHETIC_SAMPLES = [
    _make_sample(
        0,
        "Contact John at john.doe@example.com or 555-123-4567",
        [
            (15, 35, "EMAIL", "EMAIL"),
            (39, 51, "PHONE", "PHONENUMBER"),
        ],
    ),
    _make_sample(
        1,
        "SSN: 078-05-1120, Credit Card: 4532015112830366",
        [
            (5, 16, "SSN", "SSN"),
            (31, 47, "CREDIT_CARD", "CREDITCARDNUMBER"),
        ],
    ),
    _make_sample(
        2,
        "My IBAN is GB82WEST12345698765432 and email is test@test.com",
        [
            (11, 33, "IBAN", "IBAN"),
            (48, 61, "EMAIL", "EMAIL"),
        ],
    ),
]


class TestBenchmarkConfig:
    """Test benchmark configuration."""

    def test_default_config(self):
        cfg = BenchmarkConfig()
        assert cfg.name == "default"
        assert cfg.confidence_threshold == 0.70
        assert cfg.enable_ml is False
        assert cfg.enable_patterns is True

    def test_to_detection_config(self):
        cfg = BenchmarkConfig(enable_ml=True, confidence_threshold=0.5)
        dc = cfg.to_detection_config()
        assert dc.enable_ml is True
        assert dc.confidence_threshold == 0.5
        assert dc.enable_patterns is True

    def test_to_pipeline_config(self):
        cfg = BenchmarkConfig(
            use_tiered_pipeline=True,
            escalation_threshold=0.6,
        )
        pc = cfg.to_pipeline_config()
        assert pc.escalation_threshold == 0.6
        assert pc.enable_checksum is True


class TestPresets:
    """Test preset configurations."""

    def test_all_presets_exist(self):
        expected = [
            "patterns_only", "patterns_strict", "patterns_relaxed",
            "with_ml", "tiered", "tiered_with_ml",
        ]
        for name in expected:
            assert name in PRESET_CONFIGS

    def test_get_preset_valid(self):
        cfg = get_preset("patterns_only")
        assert cfg.name == "patterns_only"
        assert cfg.enable_ml is False

    def test_get_preset_invalid(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            get_preset("nonexistent")

    def test_patterns_strict_has_higher_threshold(self):
        strict = get_preset("patterns_strict")
        default = get_preset("patterns_only")
        assert strict.confidence_threshold > default.confidence_threshold

    def test_patterns_relaxed_has_lower_threshold(self):
        relaxed = get_preset("patterns_relaxed")
        default = get_preset("patterns_only")
        assert relaxed.confidence_threshold < default.confidence_threshold


class TestRunBenchmark:
    """Test the core benchmark runner."""

    def test_basic_run(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        assert isinstance(result, BenchmarkResult)
        assert result.samples_evaluated == 3
        assert result.total_time_s > 0
        assert result.overall.total_gold > 0
        assert result.overall.total_pred >= 0

    def test_result_has_category_breakdown(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        assert isinstance(result.by_category, dict)
        assert isinstance(result.by_entity_type, dict)

    def test_result_summary(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test_summary"),
        )

        summary = result.summary()
        assert summary["config"] == "test_summary"
        assert "precision" in summary
        assert "recall" in summary
        assert "f1" in summary
        assert "avg_time_ms" in summary

    def test_result_to_dict(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        d = result.to_dict()
        assert "summary" in d
        assert "by_category" in d
        assert "by_entity_type" in d

    def test_avg_time_per_sample(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        assert result.avg_time_per_sample_ms > 0

    def test_throughput(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        assert result.throughput_samples_per_sec > 0

    def test_sample_results(self):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        assert len(result.sample_results) == 3
        for sr in result.sample_results:
            assert sr.processing_time_ms > 0
            assert sr.gold_count > 0

    def test_progress_callback(self):
        calls = []

        def callback(current, total):
            calls.append((current, total))

        run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
            progress_callback=callback,
        )

        assert len(calls) == 3
        assert calls[-1] == (3, 3)

    def test_different_thresholds_produce_different_results(self):
        result_strict = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="strict", confidence_threshold=0.95),
        )
        result_relaxed = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="relaxed", confidence_threshold=0.30),
        )

        # Relaxed threshold should generally find more (or equal) predictions
        assert result_relaxed.overall.total_pred >= result_strict.overall.total_pred


class TestRunSweep:
    """Test multi-configuration sweep."""

    def test_sweep_with_presets(self):
        results = run_sweep(
            samples=SYNTHETIC_SAMPLES,
            preset_names=["patterns_only", "patterns_strict"],
        )

        assert len(results) == 2
        assert results[0].config.name == "patterns_only"
        assert results[1].config.name == "patterns_strict"

    def test_sweep_with_custom_configs(self):
        configs = [
            BenchmarkConfig(name="config_a", confidence_threshold=0.5),
            BenchmarkConfig(name="config_b", confidence_threshold=0.8),
        ]

        results = run_sweep(
            samples=SYNTHETIC_SAMPLES,
            configs=configs,
        )

        assert len(results) == 2

    def test_sweep_default_configs(self):
        results = run_sweep(samples=SYNTHETIC_SAMPLES)
        assert len(results) == 3  # Default: patterns_only, strict, relaxed


class TestThresholdSweep:
    """Test confidence threshold sweep."""

    def test_threshold_sweep(self):
        results = threshold_sweep(
            samples=SYNTHETIC_SAMPLES,
            thresholds=[0.5, 0.7, 0.9],
        )

        assert len(results) == 3
        # Results should be sorted by F1 (descending)
        for i in range(len(results) - 1):
            assert results[i].overall.f1 >= results[i + 1].overall.f1

    def test_threshold_sweep_default_thresholds(self):
        results = threshold_sweep(samples=SYNTHETIC_SAMPLES)
        assert len(results) == 7  # Default 7 thresholds

    def test_threshold_sweep_config_names(self):
        results = threshold_sweep(
            samples=SYNTHETIC_SAMPLES,
            thresholds=[0.3, 0.7],
        )
        names = {r.config.name for r in results}
        assert "threshold_0.30" in names
        assert "threshold_0.70" in names


class TestSaveResults:
    """Test result serialisation."""

    def test_save_single_result(self, tmp_path):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        output = tmp_path / "results.json"
        save_results(result, output)

        assert output.exists()
        import json
        data = json.loads(output.read_text())
        assert "results" in data
        assert len(data["results"]) == 1

    def test_save_multiple_results(self, tmp_path):
        results = run_sweep(
            samples=SYNTHETIC_SAMPLES,
            preset_names=["patterns_only", "patterns_strict"],
        )

        output = tmp_path / "sweep.json"
        save_results(results, output)

        import json
        data = json.loads(output.read_text())
        assert len(data["results"]) == 2
        assert data["comparison"] is not None
        assert len(data["comparison"]) == 2

    def test_save_creates_parent_dirs(self, tmp_path):
        result = run_benchmark(
            samples=SYNTHETIC_SAMPLES,
            config=BenchmarkConfig(name="test"),
        )

        output = tmp_path / "nested" / "dir" / "results.json"
        save_results(result, output)
        assert output.exists()
