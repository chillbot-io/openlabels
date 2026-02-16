"""Benchmark and tuning tools for the OpenLabels classification pipeline.

Evaluates detection accuracy against PII datasets using span-level
precision, recall, and F1 metrics.

Supported datasets:
- ai4privacy/pii-masking-400k (bundled)
- gretelai/gretel-pii-masking-en-v1
- gretelai/synthetic_pii_finance_multilingual
- Any JSONL with {text, entities} format

Usage:
    from openlabels.core.benchmark import run_benchmark
    from openlabels.core.benchmark.adapters import load_gretel_pii

    samples = load_gretel_pii("path/to/gretel_pii_test.jsonl", sample_size=1000)
    results = run_benchmark(samples=samples, config=config)
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
