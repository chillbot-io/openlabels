#!/usr/bin/env python3
"""Analyze type mismatches from Gretel PII benchmark with ML enabled.

Runs the benchmark and produces a detailed confusion matrix showing
which gold entity types are being misclassified as which predicted types.
"""

import json
import sys
import time
from collections import Counter
from pathlib import Path

# Ensure package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from openlabels.core.benchmark.adapters import load_gretel_pii
from openlabels.core.benchmark.evaluate import MatchType
from openlabels.core.benchmark.harness import BenchmarkConfig, run_benchmark


def main():
    dataset_path = Path(__file__).resolve().parent.parent / "src/openlabels/core/benchmark/gretel_pii_test.jsonl.gz"

    print(f"Loading Gretel PII dataset from {dataset_path}...")
    samples = load_gretel_pii(dataset_path, sample_size=1000, seed=42)
    print(f"Loaded {len(samples)} samples")

    # Count gold entity types
    gold_type_counts: Counter = Counter()
    for s in samples:
        for g in s.gold_spans:
            gold_type_counts[g.entity_type] += 1
    print(f"Total gold entities: {sum(gold_type_counts.values())}")
    print(f"Unique gold types: {len(gold_type_counts)}")

    # ML model requires HuggingFace download - use patterns_only if ML unavailable
    use_ml = "--ml" in sys.argv
    config = BenchmarkConfig(
        name="gretel_pii_1k_ml" if use_ml else "gretel_pii_1k_patterns",
        enable_ml=use_ml,
        confidence_threshold=0.70,
    )

    print(f"\nRunning benchmark (ML enabled, threshold={config.confidence_threshold})...")
    t0 = time.time()

    def progress(current, total):
        if current % 50 == 0 or current == total:
            pct = current * 100 // total
            elapsed = time.time() - t0
            print(f"  [{current}/{total}] {pct}% ({elapsed:.0f}s)")

    result = run_benchmark(samples=samples, config=config, progress_callback=progress)
    elapsed = time.time() - t0
    print(f"\nBenchmark complete in {elapsed:.1f}s")

    # Print summary
    s = result.summary()
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  P={s['precision']:.4f}  R={s['recall']:.4f}  F1={s['f1']:.4f}")
    print(f"  Exact: {s['exact_matches']}  Partial: {s['partial_matches']}  "
          f"Type mismatch: {s['type_mismatches']}")
    print(f"  TP: {s['true_positives']}  FP: {s['false_positives']}  FN: {s['false_negatives']}")

    # Collect all type mismatches
    mismatch_pairs: Counter = Counter()  # (gold_type, pred_type) -> count
    mismatch_examples: dict = {}  # (gold_type, pred_type) -> [(gold_text, pred_text)]

    for sr in result.sample_results:
        for m in sr.matches:
            if m.match_type != MatchType.TYPE_MISMATCH:
                continue
            if m.gold is None or m.pred is None:
                continue

            from openlabels.core.types import normalize_entity_type
            gold_type = normalize_entity_type(m.gold.entity_type)
            pred_type = normalize_entity_type(m.pred.entity_type)
            pair = (gold_type, pred_type)
            mismatch_pairs[pair] += 1

            if pair not in mismatch_examples:
                mismatch_examples[pair] = []
            if len(mismatch_examples[pair]) < 3:
                mismatch_examples[pair].append({
                    "gold_text": m.gold.text[:60],
                    "pred_text": m.pred.text[:60],
                    "sample_id": sr.sample_id,
                })

    total_mismatches = sum(mismatch_pairs.values())
    print(f"\n{'='*70}")
    print(f"TYPE MISMATCH ANALYSIS ({total_mismatches} total)")
    print(f"{'='*70}")

    # Top misclassification pairs
    print(f"\n{'Gold Type':<25} {'Pred Type':<25} {'Count':>6}  {'%':>6}")
    print("-" * 70)
    for (gold, pred), count in mismatch_pairs.most_common(40):
        pct = 100 * count / total_mismatches
        print(f"  {gold:<23} -> {pred:<23} {count:>5}  {pct:>5.1f}%")

    # Group by gold type: what is each gold type being misclassified as?
    print(f"\n{'='*70}")
    print(f"MISCLASSIFICATIONS BY GOLD TYPE")
    print(f"{'='*70}")

    gold_mismatch_totals: Counter = Counter()
    for (gold, _), count in mismatch_pairs.items():
        gold_mismatch_totals[gold] += count

    for gold_type, total in gold_mismatch_totals.most_common():
        gold_total = gold_type_counts.get(gold_type, 0)
        mismatch_rate = 100 * total / gold_total if gold_total else 0
        print(f"\n  {gold_type} ({total} mismatches / {gold_total} gold = {mismatch_rate:.1f}% mismatch rate)")
        for (g, p), count in mismatch_pairs.most_common():
            if g != gold_type:
                continue
            print(f"    -> {p:<25} {count:>4}x")
            examples = mismatch_examples.get((g, p), [])
            for ex in examples[:2]:
                print(f"       gold='{ex['gold_text']}'  pred='{ex['pred_text']}'  (sample {ex['sample_id']})")

    # Group by pred type: what is each pred type actually supposed to be?
    print(f"\n{'='*70}")
    print(f"MISCLASSIFICATIONS BY PRED TYPE (what our detections are actually)")
    print(f"{'='*70}")

    pred_mismatch_totals: Counter = Counter()
    for (_, pred), count in mismatch_pairs.items():
        pred_mismatch_totals[pred] += count

    for pred_type, total in pred_mismatch_totals.most_common():
        print(f"\n  {pred_type} (predicted {total} times incorrectly)")
        for (g, p), count in mismatch_pairs.most_common():
            if p != pred_type:
                continue
            print(f"    <- {g:<25} {count:>4}x (should have been {g})")

    # Category-level analysis
    print(f"\n{'='*70}")
    print(f"PER-CATEGORY BREAKDOWN")
    print(f"{'='*70}")
    print(f"\n{'Category':<20} {'Prec':>6} {'Recall':>6} {'F1':>6} "
          f"{'TP':>5} {'FP':>5} {'FN':>5} {'TM':>5}")
    print("-" * 70)
    for cat, m in sorted(result.by_category.items(), key=lambda x: -x[1].f1):
        print(f"  {cat:<18} {m.precision:>6.3f} {m.recall:>6.3f} {m.f1:>6.3f} "
              f"{m.true_positives:>5} {m.false_positives:>5} {m.false_negatives:>5} "
              f"{m.type_mismatches:>5}")

    # Save full results
    output_path = Path(__file__).resolve().parent / "type_mismatch_report.json"
    report = {
        "summary": s,
        "type_mismatches": {
            "total": total_mismatches,
            "pairs": [
                {"gold": g, "pred": p, "count": c, "examples": mismatch_examples.get((g, p), [])}
                for (g, p), c in mismatch_pairs.most_common()
            ],
        },
        "by_category": {cat: m.to_dict() for cat, m in result.by_category.items()},
        "by_entity_type": {et: m.to_dict() for et, m in result.by_entity_type.items()},
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved to: {output_path}")


if __name__ == "__main__":
    main()
