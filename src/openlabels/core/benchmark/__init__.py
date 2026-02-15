"""Benchmark and tuning tools for the OpenLabels classification pipeline.

Evaluates detection accuracy against the ai4privacy pii-masking-400k dataset
using span-level precision, recall, and F1 metrics.

Usage:
    from openlabels.core.benchmark import run_benchmark

    results = run_benchmark(sample_size=500, configs=["patterns_only", "full"])
"""

from openlabels.core.benchmark.evaluate import (
    EvalMetrics,
    SpanMatch,
    aggregate_metrics,
    evaluate_spans,
)
from openlabels.core.benchmark.harness import (
    BenchmarkConfig,
    BenchmarkResult,
    run_benchmark,
)

__all__ = [
    "SpanMatch",
    "EvalMetrics",
    "evaluate_spans",
    "aggregate_metrics",
    "BenchmarkConfig",
    "BenchmarkResult",
    "run_benchmark",
]
