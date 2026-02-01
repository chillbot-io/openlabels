#!/usr/bin/env python3
"""
Benchmark the OpenLabels detector against annotated data.

This script evaluates detection precision/recall using annotated samples
like AI4Privacy English dataset or similar ground-truth data.

Usage:
    python scripts/benchmark_detector.py --data path/to/annotations.json
    python scripts/benchmark_detector.py --data path/to/ai4privacy/ --format ai4privacy

Output:
    - Overall precision, recall, F1
    - Per-entity-type breakdown
    - False positive / false negative examples
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set


def load_annotations_json(path: Path) -> List[Dict[str, Any]]:
    """Load annotations from a JSON file.

    Expected format:
    [
        {
            "text": "My SSN is 123-45-6789 and email john@example.com",
            "entities": [
                {"start": 10, "end": 21, "type": "SSN", "text": "123-45-6789"},
                {"start": 32, "end": 48, "type": "EMAIL", "text": "john@example.com"}
            ]
        },
        ...
    ]
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_ai4privacy_format(path: Path) -> List[Dict[str, Any]]:
    """Load AI4Privacy format data.

    AI4Privacy typically provides data in various formats.
    This handles the common JSON/JSONL format.
    """
    samples = []

    # Check if it's a directory or file
    if path.is_dir():
        files = list(path.glob("*.json")) + list(path.glob("*.jsonl"))
    else:
        files = [path]

    for file_path in files:
        with open(file_path, "r", encoding="utf-8") as f:
            if file_path.suffix == ".jsonl":
                for line in f:
                    if line.strip():
                        samples.append(json.loads(line))
            else:
                data = json.load(f)
                if isinstance(data, list):
                    samples.extend(data)
                else:
                    samples.append(data)

    # Normalize to our format
    normalized = []
    for sample in samples:
        text = sample.get("source_text") or sample.get("text") or sample.get("content", "")

        # AI4Privacy uses various entity annotation formats
        entities = []

        # Format 1: "privacy_mask" with annotations
        if "privacy_mask" in sample:
            annotations = sample.get("span_labels", []) or sample.get("annotations", [])
            for ann in annotations:
                entities.append({
                    "start": ann.get("start", 0),
                    "end": ann.get("end", 0),
                    "type": ann.get("label", ann.get("type", "UNKNOWN")),
                    "text": ann.get("text", text[ann.get("start", 0):ann.get("end", 0)]),
                })

        # Format 2: Direct entities list
        elif "entities" in sample:
            for ent in sample["entities"]:
                entities.append({
                    "start": ent.get("start", ent.get("start_offset", 0)),
                    "end": ent.get("end", ent.get("end_offset", 0)),
                    "type": ent.get("type", ent.get("label", "UNKNOWN")),
                    "text": ent.get("text", ent.get("value", "")),
                })

        # Format 3: Labels with positions
        elif "labels" in sample:
            for label in sample["labels"]:
                entities.append({
                    "start": label.get("start", 0),
                    "end": label.get("end", 0),
                    "type": label.get("label", "UNKNOWN"),
                    "text": text[label.get("start", 0):label.get("end", 0)] if text else "",
                })

        if text:
            normalized.append({
                "text": text,
                "entities": entities,
                "id": sample.get("id", len(normalized)),
            })

    return normalized


def run_detector(text: str) -> List[Dict[str, Any]]:
    """Run OpenLabels detector on text and return detected entities."""
    from openlabels.adapters.scanner import detect

    try:
        result = detect(text)
        detected = []
        for span in result.spans:
            detected.append({
                "start": span.start,
                "end": span.end,
                "type": span.entity_type,
                "text": span.text,
                "confidence": span.confidence,
            })
        return detected
    except Exception as e:
        print(f"Warning: Detection failed: {e}", file=sys.stderr)
        return []


def normalize_entity_type(entity_type: str) -> str:
    """Normalize entity type names for comparison."""
    # Map common variations to standard names
    type_map = {
        # SSN variations
        "SSN": "SSN",
        "SOCIAL_SECURITY": "SSN",
        "SOCIAL_SECURITY_NUMBER": "SSN",
        "US_SSN": "SSN",
        "SOCIALSECURITYNUMBER": "SSN",

        # Email variations
        "EMAIL": "EMAIL",
        "EMAIL_ADDRESS": "EMAIL",
        "EMAILADDRESS": "EMAIL",

        # Phone variations
        "PHONE": "PHONE",
        "PHONE_NUMBER": "PHONE",
        "PHONENUMBER": "PHONE",
        "TELEPHONE": "PHONE",
        "TEL": "PHONE",
        "MOBILE": "PHONE",
        "MOBILE_NUMBER": "PHONE",

        # Credit card variations
        "CREDIT_CARD": "CREDIT_CARD",
        "CREDITCARD": "CREDIT_CARD",
        "CC": "CREDIT_CARD",
        "CARD_NUMBER": "CREDIT_CARD",
        "CREDITCARDNUMBER": "CREDIT_CARD",

        # IP variations
        "IP": "IP_ADDRESS",
        "IP_ADDRESS": "IP_ADDRESS",
        "IPADDRESS": "IP_ADDRESS",
        "IPV4": "IP_ADDRESS",
        "IPV6": "IP_ADDRESS",

        # Name variations (AI4Privacy uses many)
        "NAME": "NAME",
        "PERSON": "NAME",
        "PERSON_NAME": "NAME",
        "FIRSTNAME": "NAME",
        "LASTNAME": "NAME",
        "FIRST_NAME": "NAME",
        "LAST_NAME": "NAME",
        "GIVENNAME": "NAME",
        "SURNAME": "NAME",
        "FULLNAME": "NAME",
        "FULL_NAME": "NAME",
        "USERNAME": "NAME",
        "USER_NAME": "NAME",
        "NAME_PATIENT": "NAME",
        "PATIENT_NAME": "NAME",
        "DOCTOR_NAME": "NAME",
        "NAME_DOCTOR": "NAME",

        # Address variations
        "ADDRESS": "ADDRESS",
        "STREET_ADDRESS": "ADDRESS",
        "LOCATION": "ADDRESS",
        "STREET": "ADDRESS",
        "CITY": "ADDRESS",
        "STATE": "ADDRESS",
        "ZIPCODE": "ADDRESS",
        "ZIP_CODE": "ADDRESS",
        "ZIP": "ADDRESS",
        "POSTCODE": "ADDRESS",
        "POSTAL_CODE": "ADDRESS",

        # Date variations
        "DATE": "DATE",
        "DOB": "DATE",
        "DATE_OF_BIRTH": "DATE",
        "DATEOFBIRTH": "DATE",
        "BIRTHDATE": "DATE",
        "BIRTH_DATE": "DATE",

        # Account/ID variations
        "ACCOUNT": "ACCOUNT",
        "ACCOUNT_NUMBER": "ACCOUNT",
        "ACCOUNTNUMBER": "ACCOUNT",
        "BANK_ACCOUNT": "ACCOUNT",
        "IBAN": "IBAN",

        # URL variations
        "URL": "URL",
        "WEBSITE": "URL",
        "WEB_ADDRESS": "URL",

        # Password variations
        "PASSWORD": "PASSWORD",
        "PASS": "PASSWORD",
        "SECRET": "PASSWORD",

        # Medical variations
        "MEDICAL_RECORD": "MEDICAL_ID",
        "MRN": "MEDICAL_ID",
        "MEDICAL_RECORD_NUMBER": "MEDICAL_ID",
    }

    upper = entity_type.upper().replace("-", "_").replace(" ", "_")
    return type_map.get(upper, upper)


def entities_overlap(e1: Dict, e2: Dict, threshold: float = 0.5) -> bool:
    """Check if two entity spans overlap significantly."""
    start1, end1 = e1["start"], e1["end"]
    start2, end2 = e2["start"], e2["end"]

    # Calculate overlap
    overlap_start = max(start1, start2)
    overlap_end = min(end1, end2)
    overlap = max(0, overlap_end - overlap_start)

    # Calculate union
    union = max(end1, end2) - min(start1, start2)

    if union == 0:
        return False

    # IoU (Intersection over Union)
    iou = overlap / union
    return iou >= threshold


def evaluate_sample(
    ground_truth: List[Dict],
    detected: List[Dict],
    strict_type_match: bool = True,
) -> Dict[str, Any]:
    """Evaluate detection results against ground truth for a single sample."""

    # Normalize types
    for gt in ground_truth:
        gt["norm_type"] = normalize_entity_type(gt["type"])
    for det in detected:
        det["norm_type"] = normalize_entity_type(det["type"])

    matched_gt = set()
    matched_det = set()

    true_positives = []
    false_positives = []
    false_negatives = []

    # Match detected to ground truth
    for i, det in enumerate(detected):
        best_match = None
        best_iou = 0

        for j, gt in enumerate(ground_truth):
            if j in matched_gt:
                continue

            # Check type match if strict
            if strict_type_match and det["norm_type"] != gt["norm_type"]:
                continue

            if entities_overlap(det, gt):
                # Calculate IoU for ranking
                overlap_start = max(det["start"], gt["start"])
                overlap_end = min(det["end"], gt["end"])
                overlap = max(0, overlap_end - overlap_start)
                union = max(det["end"], gt["end"]) - min(det["start"], gt["start"])
                iou = overlap / union if union > 0 else 0

                if iou > best_iou:
                    best_iou = iou
                    best_match = j

        if best_match is not None:
            matched_gt.add(best_match)
            matched_det.add(i)
            true_positives.append({
                "detected": det,
                "ground_truth": ground_truth[best_match],
                "iou": best_iou,
            })
        else:
            false_positives.append(det)

    # Remaining ground truth are false negatives
    for j, gt in enumerate(ground_truth):
        if j not in matched_gt:
            false_negatives.append(gt)

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "tp_count": len(true_positives),
        "fp_count": len(false_positives),
        "fn_count": len(false_negatives),
    }


def calculate_metrics(results: List[Dict]) -> Dict[str, float]:
    """Calculate overall precision, recall, F1 from results."""
    total_tp = sum(r["tp_count"] for r in results)
    total_fp = sum(r["fp_count"] for r in results)
    total_fn = sum(r["fn_count"] for r in results)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
    }


def calculate_per_type_metrics(results: List[Dict]) -> Dict[str, Dict[str, float]]:
    """Calculate metrics broken down by entity type."""
    type_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for r in results:
        for tp in r["true_positives"]:
            entity_type = tp["ground_truth"]["norm_type"]
            type_stats[entity_type]["tp"] += 1

        for fp in r["false_positives"]:
            entity_type = fp["norm_type"]
            type_stats[entity_type]["fp"] += 1

        for fn in r["false_negatives"]:
            entity_type = fn["norm_type"]
            type_stats[entity_type]["fn"] += 1

    metrics = {}
    for entity_type, stats in type_stats.items():
        tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics[entity_type] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }

    return metrics


def print_report(
    overall: Dict[str, float],
    per_type: Dict[str, Dict[str, float]],
    fp_examples: List[Dict],
    fn_examples: List[Dict],
    verbose: bool = False,
):
    """Print benchmark report."""
    print("\n" + "=" * 60)
    print("OPENLABELS DETECTOR BENCHMARK REPORT")
    print("=" * 60)

    print("\n📊 OVERALL METRICS")
    print("-" * 40)
    print(f"  Precision: {overall['precision']:.2%}")
    print(f"  Recall:    {overall['recall']:.2%}")
    print(f"  F1 Score:  {overall['f1']:.2%}")
    print(f"  TP: {overall['true_positives']}  FP: {overall['false_positives']}  FN: {overall['false_negatives']}")

    print("\n📋 PER-TYPE BREAKDOWN")
    print("-" * 40)
    print(f"{'Type':<20} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TP':>5} {'FP':>5} {'FN':>5}")
    print("-" * 60)

    for entity_type in sorted(per_type.keys()):
        m = per_type[entity_type]
        print(f"{entity_type:<20} {m['precision']:>7.1%} {m['recall']:>7.1%} {m['f1']:>7.1%} {m['tp']:>5} {m['fp']:>5} {m['fn']:>5}")

    if verbose and fp_examples:
        print("\n⚠️  FALSE POSITIVE EXAMPLES (showing up to 10)")
        print("-" * 40)
        for i, fp in enumerate(fp_examples[:10]):
            print(f"  [{fp['norm_type']}] \"{fp['text']}\"")

    if verbose and fn_examples:
        print("\n❌ FALSE NEGATIVE EXAMPLES (showing up to 10)")
        print("-" * 40)
        for i, fn in enumerate(fn_examples[:10]):
            print(f"  [{fn['norm_type']}] \"{fn['text']}\"")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark OpenLabels detector against annotated data"
    )
    parser.add_argument(
        "--data", "-d",
        required=True,
        help="Path to annotation file or directory"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "ai4privacy"],
        default="json",
        help="Data format (default: json)"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=None,
        help="Limit number of samples to process"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show FP/FN examples"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output results to JSON file"
    )
    parser.add_argument(
        "--relaxed",
        action="store_true",
        help="Use relaxed type matching (any overlap counts)"
    )

    args = parser.parse_args()

    # Load data
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"Error: Data path not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading data from {data_path}...")

    if args.format == "ai4privacy":
        samples = load_ai4privacy_format(data_path)
    else:
        samples = load_annotations_json(data_path)

    if args.limit:
        samples = samples[:args.limit]

    print(f"Loaded {len(samples)} samples")

    # Run evaluation
    print("Running detector evaluation...")
    results = []
    all_fps = []
    all_fns = []

    for i, sample in enumerate(samples):
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(samples)}...")

        detected = run_detector(sample["text"])
        result = evaluate_sample(
            sample["entities"],
            detected,
            strict_type_match=not args.relaxed,
        )
        results.append(result)
        all_fps.extend(result["false_positives"])
        all_fns.extend(result["false_negatives"])

    # Calculate metrics
    overall = calculate_metrics(results)
    per_type = calculate_per_type_metrics(results)

    # Print report
    print_report(overall, per_type, all_fps, all_fns, verbose=args.verbose)

    # Save to JSON if requested
    if args.output:
        output_data = {
            "overall": overall,
            "per_type": per_type,
            "false_positives": all_fps[:100],  # Limit for file size
            "false_negatives": all_fns[:100],
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
