"""Benchmark harness for the OpenLabels classification pipeline.

Orchestrates end-to-end evaluation: load dataset, run detection pipeline
across multiple configurations, collect metrics, and report results.

Supports parameter sweeps for tuning confidence thresholds, detector
combinations, and pipeline stages.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, replace
from pathlib import Path

from openlabels.core.benchmark.dataset import BenchmarkSample, load_dataset
from openlabels.core.benchmark.entity_mapping import UNMAPPED_PRED_TYPES
from openlabels.core.benchmark.evaluate import (
    EvalMetrics,
    SpanMatch,
    aggregate_metrics,
    confusion_matrix,
    evaluate_spans,
    non_identification_rate,
    per_category_metrics,
    per_entity_type_metrics,
)
from openlabels.core.types import normalize_entity_type

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkConfig:
    """Configuration for a single benchmark run."""

    name: str = "default"

    # Detection config
    enable_checksum: bool = True
    enable_secrets: bool = True
    enable_financial: bool = True
    enable_government: bool = True
    enable_patterns: bool = True
    enable_ml: bool = False
    enable_phi: bool = False
    enable_hyperscan: bool = False
    confidence_threshold: float = 0.70
    max_workers: int = 4
    ml_model_dir: str | None = None  # None = use DEFAULT_MODELS_DIR

    # ML tuning
    ml_confidence_threshold: float = 0.50
    gliner_model: str = "gretelai/gretel-gliner-bi-base-v1.0"
    gliner_threshold: float = 0.4
    use_onnx: bool = True
    enable_label_selection: bool = True

    # Stanford PHI detector
    phi_model: str = "StanfordAIMI/stanford-deidentifier-base"
    phi_threshold: float = 0.5

    # Language-gated detection
    enable_language_detection: bool = True

    # Per-entity-type confidence thresholds (None = use DetectionConfig defaults)
    entity_thresholds: tuple[tuple[str, float], ...] | None = None

    # Post-processing / relationship graph
    enable_coref: bool = False
    enable_context_enhancement: bool = True
    enable_context_keywords: bool = True
    enable_proximity_boost: bool = False
    proximity_window_chars: int = 500
    enable_allowlist: bool = True
    enable_policy: bool = True

    # Pipeline config
    use_tiered_pipeline: bool = False
    escalation_threshold: float = 0.70
    auto_detect_medical: bool = False
    medical_triggers_deep_analysis: bool = True

    # Evaluation config
    min_overlap_ratio: float = 0.5
    strict_type_match: bool = True

    def to_detection_config(self):
        """Convert to a DetectionConfig for the orchestrator."""
        from pathlib import Path

        from openlabels.core.detectors.config import DetectionConfig

        ml_dir = Path(self.ml_model_dir) if self.ml_model_dir else None
        kwargs: dict = {
            "enable_checksum": self.enable_checksum,
            "enable_secrets": self.enable_secrets,
            "enable_financial": self.enable_financial,
            "enable_government": self.enable_government,
            "enable_patterns": self.enable_patterns,
            "enable_dictionary_names": self.enable_patterns,  # follows patterns flag
            "enable_language_detection": self.enable_language_detection,
            "enable_ml": self.enable_ml,
            "enable_phi": self.enable_phi,
            "enable_hyperscan": self.enable_hyperscan,
            "confidence_threshold": self.confidence_threshold,
            "max_workers": self.max_workers,
            "ml_model_dir": ml_dir,
            # ML tuning
            "ml_confidence_threshold": self.ml_confidence_threshold,
            "gliner_model": self.gliner_model,
            "gliner_threshold": self.gliner_threshold,
            "use_onnx": self.use_onnx,
            "enable_label_selection": self.enable_label_selection,
            # Stanford PHI
            "phi_model": self.phi_model,
            "phi_threshold": self.phi_threshold,
            # Post-processing
            "enable_coref": self.enable_coref,
            "enable_context_enhancement": self.enable_context_enhancement,
            "enable_context_keywords": self.enable_context_keywords,
            "enable_proximity_boost": self.enable_proximity_boost,
            "proximity_window_chars": self.proximity_window_chars,
            "enable_allowlist": self.enable_allowlist,
            "enable_policy": self.enable_policy,
        }
        if self.entity_thresholds is not None:
            kwargs["entity_thresholds"] = self.entity_thresholds
        return DetectionConfig(**kwargs)

    def to_pipeline_config(self):
        """Convert to a PipelineConfig for the tiered pipeline."""
        from pathlib import Path

        from openlabels.core.pipeline.tiered import PipelineConfig

        ml_dir = Path(self.ml_model_dir) if self.ml_model_dir else None
        return PipelineConfig(
            enable_checksum=self.enable_checksum,
            enable_secrets=self.enable_secrets,
            enable_financial=self.enable_financial,
            enable_government=self.enable_government,
            enable_patterns=self.enable_patterns,
            enable_hyperscan=self.enable_hyperscan,
            confidence_threshold=self.confidence_threshold,
            escalation_threshold=self.escalation_threshold,
            auto_detect_medical=self.auto_detect_medical,
            max_workers=self.max_workers,
            ml_model_dir=ml_dir,
            use_onnx=self.use_onnx,
            medical_triggers_deep_analysis=self.medical_triggers_deep_analysis,
            # Eager-load ML for benchmarks so every sample gets ML detection,
            # not just those that trigger escalation.
            eager_load_ml=self.enable_ml,
            enable_coref=self.enable_coref,
            enable_context_enhancement=self.enable_context_enhancement,
        )


@dataclass
class SampleResult:
    """Result for a single sample."""

    sample_id: int
    metrics: EvalMetrics
    matches: list[SpanMatch]
    processing_time_ms: float
    text_length: int
    gold_count: int
    pred_count: int


@dataclass
class BenchmarkResult:
    """Complete result of a benchmark run."""

    config: BenchmarkConfig
    overall: EvalMetrics
    by_category: dict[str, EvalMetrics]
    by_entity_type: dict[str, EvalMetrics]
    sample_results: list[SampleResult]
    total_time_s: float
    samples_evaluated: int
    dataset_source: str = "unknown"
    # Confusion matrix: (gold_type, pred_type) -> count of misclassifications
    type_confusion: dict[tuple[str, str], int] | None = None
    # Non-identification rate per gold entity type (fraction of missed spans)
    miss_rates: dict[str, float] | None = None
    # Per-language metrics (language code -> EvalMetrics)
    by_language: dict[str, EvalMetrics] | None = None
    # Per-NER-difficulty-dimension metrics (Singh & Narayanan 2025)
    by_dimension: dict[str, EvalMetrics] | None = None
    # Detectors that were actually loaded and used
    detectors_loaded: list[str] | None = None

    @property
    def avg_time_per_sample_ms(self) -> float:
        if not self.sample_results:
            return 0.0
        return sum(r.processing_time_ms for r in self.sample_results) / len(
            self.sample_results
        )

    @property
    def throughput_samples_per_sec(self) -> float:
        if self.total_time_s <= 0:
            return 0.0
        return self.samples_evaluated / self.total_time_s

    def summary(self) -> dict[str, object]:
        """Return a compact summary dict."""
        return {
            "config": self.config.name,
            "samples": self.samples_evaluated,
            "precision": round(self.overall.precision, 4),
            "recall": round(self.overall.recall, 4),
            "f1": round(self.overall.f1, 4),
            "exact_matches": self.overall.exact_matches,
            "partial_matches": self.overall.partial_matches,
            "type_mismatches": self.overall.type_mismatches,
            "true_positives": self.overall.true_positives,
            "false_positives": self.overall.false_positives,
            "false_negatives": self.overall.false_negatives,
            "avg_time_ms": round(self.avg_time_per_sample_ms, 2),
            "throughput_sps": round(self.throughput_samples_per_sec, 2),
            "total_time_s": round(self.total_time_s, 2),
        }

    def to_dict(self) -> dict[str, object]:
        """Full serialisable result."""
        result: dict[str, object] = {
            "summary": self.summary(),
            "by_category": {
                cat: m.to_dict() for cat, m in sorted(self.by_category.items())
            },
            "by_entity_type": {
                et: m.to_dict() for et, m in sorted(self.by_entity_type.items())
            },
            "failures": self._collect_failures(),
        }
        if self.type_confusion:
            result["confusion_matrix"] = {
                f"{g}->{p}": cnt
                for (g, p), cnt in sorted(
                    self.type_confusion.items(), key=lambda x: -x[1]
                )
            }
        if self.miss_rates:
            result["non_identification_rates"] = {
                k: round(v, 4) for k, v in self.miss_rates.items()
            }
        if self.by_language:
            result["by_language"] = {
                lang: m.to_dict()
                for lang, m in sorted(self.by_language.items())
            }
        if self.by_dimension:
            result["by_dimension"] = {
                dim: m.to_dict()
                for dim, m in sorted(self.by_dimension.items())
            }
        return result

    def _collect_failures(self) -> list[dict[str, object]]:
        """Collect SPURIOUS / MISS / TYPE_MISMATCH matches for failure analysis."""
        from .evaluate import MatchType

        failures: list[dict[str, object]] = []
        error_types = {MatchType.SPURIOUS, MatchType.MISS, MatchType.TYPE_MISMATCH}
        for sr in self.sample_results:
            for m in sr.matches:
                if m.match_type not in error_types:
                    continue
                entry: dict[str, object] = {
                    "sample_id": sr.sample_id,
                    "match_type": m.match_type.value,
                }
                if m.gold:
                    entry["gold_type"] = m.gold.entity_type
                    entry["gold_text"] = m.gold.text
                if m.pred:
                    entry["pred_type"] = m.pred.entity_type
                    entry["pred_text"] = m.pred.text
                if m.overlap_ratio > 0:
                    entry["overlap"] = round(m.overlap_ratio, 3)
                failures.append(entry)
        return failures


# ── Preset configurations ────────────────────────────────────────────

PRESET_CONFIGS: dict[str, BenchmarkConfig] = {
    "patterns_only": BenchmarkConfig(
        name="patterns_only",
        enable_ml=False,
    ),
    "patterns_strict": BenchmarkConfig(
        name="patterns_strict",
        enable_ml=False,
        confidence_threshold=0.80,
    ),
    "patterns_relaxed": BenchmarkConfig(
        name="patterns_relaxed",
        enable_ml=False,
        confidence_threshold=0.50,
    ),
    "with_ml": BenchmarkConfig(
        name="with_ml",
        enable_ml=True,
        enable_phi=True,
    ),
    "tiered": BenchmarkConfig(
        name="tiered",
        use_tiered_pipeline=True,
        auto_detect_medical=True,
    ),
    "tiered_with_ml": BenchmarkConfig(
        name="tiered_with_ml",
        use_tiered_pipeline=True,
        enable_ml=True,
        enable_phi=True,
        auto_detect_medical=True,
    ),
    "with_context": BenchmarkConfig(
        name="with_context",
        enable_ml=False,
        enable_proximity_boost=True,
        enable_context_keywords=True,
    ),
    "full": BenchmarkConfig(
        name="full",
        enable_ml=True,
        enable_phi=True,
        enable_proximity_boost=True,
        enable_context_keywords=True,
        enable_coref=True,
        enable_context_enhancement=True,
    ),
}


def get_preset(name: str) -> BenchmarkConfig:
    """Get a preset benchmark configuration by name.

    Returns a *copy* so callers can mutate without affecting the preset.
    """
    if name not in PRESET_CONFIGS:
        available = ", ".join(sorted(PRESET_CONFIGS))
        raise ValueError(
            f"Unknown preset {name!r}. Available: {available}"
        )
    from dataclasses import asdict
    return BenchmarkConfig(**asdict(PRESET_CONFIGS[name]))


# ── Core benchmark runner ─────────────────────────────────────────────

def run_benchmark(
    *,
    samples: list[BenchmarkSample] | None = None,
    sample_size: int | None = 500,
    config: BenchmarkConfig | None = None,
    seed: int = 42,
    progress_callback: object | None = None,
) -> BenchmarkResult:
    """Run a single benchmark evaluation.

    Args:
        samples: Pre-loaded samples (skips dataset loading if provided).
        sample_size: Number of samples to evaluate (ignored if *samples*
            is provided).
        config: Detection/pipeline configuration.  Uses default if None.
        seed: Random seed for sample selection.
        progress_callback: Optional callable(current, total) for progress.

    Returns:
        ``BenchmarkResult`` with overall and per-category metrics.
    """
    config = config or BenchmarkConfig()
    dataset_source = "pre-loaded"

    # Load dataset
    if samples is None:
        samples, dataset_source = load_dataset(
            sample_size=sample_size, seed=seed
        )

    logger.info(
        "Running benchmark %r on %d samples (source: %s)",
        config.name,
        len(samples),
        dataset_source,
    )

    # Create detector
    _detector_names: list[str] = []
    if config.use_tiered_pipeline:
        from openlabels.core.pipeline.tiered import TieredPipeline

        pipeline = TieredPipeline(config.to_pipeline_config())

        def detect_fn(text: str):
            return pipeline.detect(text).result
    else:
        from openlabels.core.detectors.orchestrator import DetectorOrchestrator

        orchestrator = DetectorOrchestrator(config.to_detection_config())
        detect_fn = orchestrator.detect_sync
        _detector_names = orchestrator.detector_names

        # Warn loudly if ML/PHI was requested but didn't load
        if config.enable_ml and not orchestrator.ml_loaded:
            import warnings
            warnings.warn(
                "ML detectors were requested (--ml) but NONE loaded! "
                "Benchmark is running with pattern-only detection. "
                f"Active detectors: {orchestrator.detector_names}",
                stacklevel=1,
            )
        if config.enable_phi and not orchestrator.phi_loaded:
            import warnings
            warnings.warn(
                "PHI detector was requested but failed to load!",
                stacklevel=1,
            )

    # Run evaluation
    sample_results: list[SampleResult] = []
    all_matches: list[SpanMatch] = []
    per_sample_metrics: list[EvalMetrics] = []
    start_time = time.monotonic()

    # Build dataset-aware exclusion set: only exclude predicted types that
    # have ZERO gold counterparts in this dataset.  UNMAPPED_PRED_TYPES was
    # designed for ai4privacy (where e.g. JOBTITLE is excluded from gold),
    # but Nemotron maps "occupation" → JOB_TITLE as real gold spans.
    gold_entity_types: set[str] = set()
    for sample in samples:
        for g in sample.gold_spans:
            gold_entity_types.add(normalize_entity_type(g.entity_type))
    active_pred_exclusions = UNMAPPED_PRED_TYPES - gold_entity_types

    for i, sample in enumerate(samples):
        t0 = time.monotonic()
        detection_result = detect_fn(sample.text)
        elapsed_ms = (time.monotonic() - t0) * 1000

        # Exclude predicted types whose gold counterparts are unmapped
        # (e.g. JOB_TITLE when JOBTITLE is not scored as PII).
        pred_spans = [
            s for s in detection_result.spans
            if normalize_entity_type(s.entity_type) not in active_pred_exclusions
        ]

        metrics, matches = evaluate_spans(
            sample.gold_spans,
            pred_spans,
            min_overlap_ratio=config.min_overlap_ratio,
            strict_type_match=config.strict_type_match,
        )

        sample_results.append(SampleResult(
            sample_id=sample.sample_id,
            metrics=metrics,
            matches=matches,
            processing_time_ms=elapsed_ms,
            text_length=len(sample.text),
            gold_count=len(sample.gold_spans),
            pred_count=len(pred_spans),
        ))
        per_sample_metrics.append(metrics)
        all_matches.extend(matches)

        if progress_callback is not None:
            progress_callback(i + 1, len(samples))

    total_time = time.monotonic() - start_time

    # Aggregate
    overall = aggregate_metrics(per_sample_metrics)
    by_category = per_category_metrics(all_matches)
    by_entity_type = per_entity_type_metrics(all_matches)

    # Confusion matrix & non-identification rates (Singh & Narayanan 2025)
    type_confusion = confusion_matrix(all_matches)
    miss_rates = non_identification_rate(all_matches)

    # Per-dimension metrics (Singh & Narayanan 2025 NER difficulty dimensions)
    from openlabels.core.benchmark.dimensions import classify_samples
    dim_to_sample_ids = classify_samples(samples)
    sample_id_to_result: dict[int, SampleResult] = {
        sr.sample_id: sr for sr in sample_results
    }
    by_dimension: dict[str, EvalMetrics] = {}
    for dim, sample_ids in dim_to_sample_ids.items():
        if not sample_ids:
            continue
        dim_metrics_list = [
            sample_id_to_result[sid].metrics
            for sid in sample_ids
            if sid in sample_id_to_result
        ]
        if dim_metrics_list:
            by_dimension[dim.value] = aggregate_metrics(dim_metrics_list)

    # Per-language metrics — build a mapping from sample_id to language,
    # then bucket the per-sample matches by language.
    sample_lang: dict[int, str] = {s.sample_id: s.language for s in samples}
    lang_matches: dict[str, list[SpanMatch]] = {}
    for sr in sample_results:
        lang = sample_lang.get(sr.sample_id, "en")
        if lang not in lang_matches:
            lang_matches[lang] = []
        lang_matches[lang].extend(sr.matches)

    by_language: dict[str, EvalMetrics] | None = None
    if len(lang_matches) > 1:
        by_language = {}
        for lang, matches in sorted(lang_matches.items()):
            lm = EvalMetrics()
            for m in matches:
                from .evaluate import MatchType
                if m.match_type in (MatchType.EXACT, MatchType.PARTIAL):
                    lm.true_positives += 1
                    if m.match_type == MatchType.EXACT:
                        lm.exact_matches += 1
                    else:
                        lm.partial_matches += 1
                elif m.match_type == MatchType.TYPE_MISMATCH:
                    lm.type_mismatches += 1
                    lm.false_positives += 1
                    lm.false_negatives += 1
                elif m.match_type == MatchType.MISS:
                    lm.false_negatives += 1
                elif m.match_type == MatchType.SPURIOUS:
                    lm.false_positives += 1
            by_language[lang] = lm

    # Cleanup
    if not config.use_tiered_pipeline:
        orchestrator.shutdown()

    return BenchmarkResult(
        config=config,
        overall=overall,
        by_category=by_category,
        by_entity_type=by_entity_type,
        sample_results=sample_results,
        total_time_s=total_time,
        samples_evaluated=len(samples),
        dataset_source=dataset_source,
        type_confusion=type_confusion or None,
        miss_rates=miss_rates or None,
        by_language=by_language,
        by_dimension=by_dimension or None,
        detectors_loaded=_detector_names or None,
    )


def run_sweep(
    *,
    samples: list[BenchmarkSample] | None = None,
    sample_size: int | None = 500,
    configs: list[BenchmarkConfig] | None = None,
    preset_names: list[str] | None = None,
    seed: int = 42,
) -> list[BenchmarkResult]:
    """Run benchmarks across multiple configurations.

    Args:
        samples: Pre-loaded samples (loaded once, reused across configs).
        sample_size: Number of samples to evaluate.
        configs: List of ``BenchmarkConfig`` instances to compare.
        preset_names: List of preset names (alternative to *configs*).
        seed: Random seed.

    Returns:
        List of ``BenchmarkResult``, one per configuration.
    """
    if configs is None and preset_names is not None:
        configs = [get_preset(name) for name in preset_names]
    elif configs is None:
        configs = [
            PRESET_CONFIGS["patterns_only"],
            PRESET_CONFIGS["patterns_strict"],
            PRESET_CONFIGS["patterns_relaxed"],
        ]

    # Load dataset once
    if samples is None:
        samples, _source = load_dataset(sample_size=sample_size, seed=seed)

    results: list[BenchmarkResult] = []
    for cfg in configs:
        logger.info("=== Sweep: %s ===", cfg.name)
        result = run_benchmark(
            samples=samples,
            config=cfg,
            seed=seed,
        )
        results.append(result)
        logger.info(
            "  P=%.3f  R=%.3f  F1=%.3f  (%.1fs)",
            result.overall.precision,
            result.overall.recall,
            result.overall.f1,
            result.total_time_s,
        )

    return results


def threshold_sweep(
    *,
    samples: list[BenchmarkSample] | None = None,
    sample_size: int | None = 500,
    thresholds: list[float] | None = None,
    base_config: BenchmarkConfig | None = None,
    seed: int = 42,
) -> list[BenchmarkResult]:
    """Sweep confidence thresholds to find the optimal operating point.

    Args:
        samples: Pre-loaded samples.
        sample_size: Number of samples.
        thresholds: List of confidence thresholds to try.
            Defaults to ``[0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]``.
        base_config: Base config (threshold will be overridden).
        seed: Random seed.

    Returns:
        List of ``BenchmarkResult``, one per threshold, sorted by F1.
    """
    if thresholds is None:
        thresholds = [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]

    base = base_config or BenchmarkConfig()

    configs = []
    for t in thresholds:
        cfg = replace(base, name=f"threshold_{t:.2f}", confidence_threshold=t)
        configs.append(cfg)

    results = run_sweep(
        samples=samples,
        sample_size=sample_size,
        configs=configs,
        seed=seed,
    )

    # Sort by F1 descending
    results.sort(key=lambda r: r.overall.f1, reverse=True)
    return results


def save_results(
    results: list[BenchmarkResult] | BenchmarkResult,
    output_path: str | Path,
) -> None:
    """Save benchmark results to a JSON file."""
    if isinstance(results, BenchmarkResult):
        results = [results]

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "results": [r.to_dict() for r in results],
        "comparison": _comparison_table(results) if len(results) > 1 else None,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info("Results saved to %s", output_path)


def _comparison_table(results: list[BenchmarkResult]) -> list[dict]:
    """Build a comparison table across configurations."""
    return [r.summary() for r in results]
