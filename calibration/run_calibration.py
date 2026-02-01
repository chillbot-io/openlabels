#!/usr/bin/env python3
"""
OpenLabels Calibration Runner

Processes the calibration dataset and generates scoring results for analysis.
"""

import json
import csv
import sys
import yaml
# SECURITY NOTE (MED-011): Using `random` module here is intentional and acceptable.
# This is calibration/test code for sampling test data - cryptographic randomness
# is not required. DO NOT copy this pattern to production security-sensitive code
# (e.g., token generation, sampling for security decisions). Use `secrets` module instead.
import random
from pathlib import Path
from collections import Counter
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Ensure local imports work regardless of working directory
sys.path.insert(0, str(Path(__file__).parent))
from scorer import score_entities, RiskTier, ENTITY_WEIGHTS


# --- Configuration ---

DATA_DIR = Path('../data')
OUTPUT_DIR = Path('.')

# Files to process
DATA_FILES = [
    'ai4privacy.jsonl',
    'claude.jsonl',
    'corpus.jsonl',
    'negative.jsonl',
    'template.jsonl',
]


# --- Entity Mapping ---

def load_entity_mapping() -> Dict[str, Optional[str]]:
    """Load the entity label -> OpenLabels type mapping."""
    with open('entity_mapping.yaml') as f:
        return yaml.safe_load(f)


def map_entities(sample: dict, mapping: Dict[str, Optional[str]]) -> Dict[str, int]:
    """Convert sample entities to OpenLabels entity counts."""
    counts = Counter()
    for entity in sample.get('entities', []):
        label = entity['label']
        openlabels_type = mapping.get(label)
        if openlabels_type:
            counts[openlabels_type] += 1
    return dict(counts)


# --- Dataset Processing ---

@dataclass
class ProcessedSample:
    id: str
    source: str
    text_preview: str
    raw_entities: List[dict]
    mapped_entities: Dict[str, int]
    content_score: float
    risk_score: float
    tier: str
    is_adversarial: bool
    adversarial_type: Optional[str]


def process_dataset(mapping: Dict[str, Optional[str]]) -> List[ProcessedSample]:
    """Process all data files and return scored samples."""
    results = []

    for filename in DATA_FILES:
        filepath = DATA_DIR / filename
        if not filepath.exists():
            print(f"Warning: {filepath} not found, skipping")
            continue

        print(f"Processing {filename}...", end=' ')
        count = 0

        with open(filepath) as f:
            for line in f:
                sample = json.loads(line)
                mapped = map_entities(sample, mapping)
                scoring = score_entities(mapped)

                results.append(ProcessedSample(
                    id=sample['id'],
                    source=sample.get('source', filename.replace('.jsonl', '')),
                    text_preview=sample['text'][:100],
                    raw_entities=sample.get('entities', []),
                    mapped_entities=mapped,
                    content_score=scoring.content_score,
                    risk_score=scoring.risk_score,
                    tier=scoring.tier.value,
                    is_adversarial=sample.get('is_adversarial', False),
                    adversarial_type=sample.get('adversarial_type'),
                ))
                count += 1

        print(f"{count:,} samples")

    return results


# --- Analysis ---

def analyze_distribution(results: List[ProcessedSample]) -> dict:
    """Analyze score and tier distribution."""
    tier_counts = Counter(r.tier for r in results)
    source_counts = Counter(r.source for r in results)

    # Score distribution by decile
    score_deciles = Counter()
    for r in results:
        decile = int(r.content_score // 10) * 10
        score_deciles[f"{decile}-{decile+9}"] += 1

    # Entity type frequency
    entity_freq = Counter()
    for r in results:
        for entity_type, count in r.mapped_entities.items():
            entity_freq[entity_type] += count

    # Samples by entity count
    entity_count_dist = Counter()
    for r in results:
        count = sum(r.mapped_entities.values())
        bucket = '0' if count == 0 else '1-2' if count <= 2 else '3-5' if count <= 5 else '6+'
        entity_count_dist[bucket] += 1

    return {
        'total_samples': len(results),
        'tier_distribution': dict(tier_counts),
        'source_distribution': dict(source_counts),
        'score_deciles': dict(sorted(score_deciles.items())),
        'entity_type_frequency': dict(entity_freq.most_common(20)),
        'entity_count_distribution': dict(entity_count_dist),
    }


def find_calibration_issues(results: List[ProcessedSample]) -> List[dict]:
    """Find samples that might indicate calibration issues."""
    issues = []

    for r in results:
        # SSN alone should be at least Medium
        if 'ssn' in r.mapped_entities and r.tier == 'Minimal':
            issues.append({
                'id': r.id,
                'issue': 'SSN scored as Minimal',
                'entities': r.mapped_entities,
                'score': r.content_score,
                'tier': r.tier,
            })

        # HIPAA combo should be High
        has_direct_id = any(e in r.mapped_entities for e in ['ssn', 'passport', 'drivers_license'])
        has_health = any(e in r.mapped_entities for e in ['mrn', 'diagnosis', 'medication'])
        if has_direct_id and has_health and r.tier in ['Minimal', 'Low']:
            issues.append({
                'id': r.id,
                'issue': 'HIPAA combo scored too low',
                'entities': r.mapped_entities,
                'score': r.content_score,
                'tier': r.tier,
            })

        # Credit card should be at least Low
        if 'credit_card' in r.mapped_entities and r.tier == 'Minimal':
            issues.append({
                'id': r.id,
                'issue': 'Credit card scored as Minimal',
                'entities': r.mapped_entities,
                'score': r.content_score,
                'tier': r.tier,
            })

    return issues[:50]  # Return first 50 issues


# --- Sampling for Expert Labeling ---

def select_labeling_samples(results: List[ProcessedSample], n: int = 250) -> List[ProcessedSample]:
    """Select stratified sample for expert labeling."""
    # Stratify by tier
    by_tier = {tier: [] for tier in ['Minimal', 'Low', 'Medium', 'High', 'Critical']}
    for r in results:
        by_tier[r.tier].append(r)

    selected = []
    # Target distribution: 50 Minimal, 60 Low, 60 Medium, 50 High, 30 Critical
    targets = {'Minimal': 50, 'Low': 60, 'Medium': 60, 'High': 50, 'Critical': 30}

    for tier, target in targets.items():
        available = by_tier[tier]
        n_select = min(target, len(available))
        if available:
            selected.extend(random.sample(available, n_select))

    random.shuffle(selected)
    return selected


def export_for_labeling(samples: List[ProcessedSample], filepath: str):
    """Export samples to CSV for expert labeling."""
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'id', 'source', 'text_preview', 'entities',
            'predicted_score', 'predicted_tier', 'expected_tier'
        ])

        for s in samples:
            writer.writerow([
                s.id,
                s.source,
                s.text_preview[:80],
                json.dumps(s.mapped_entities),
                s.content_score,
                s.tier,
                '',  # Expert fills this in
            ])


# --- Reporting ---

def print_report(analysis: dict, issues: List[dict]):
    """Print calibration analysis report."""
    print("\n" + "=" * 70)
    print("CALIBRATION ANALYSIS REPORT")
    print("=" * 70)

    print(f"\nTotal Samples: {analysis['total_samples']:,}")

    print("\n--- Tier Distribution ---")
    for tier in ['Minimal', 'Low', 'Medium', 'High', 'Critical']:
        count = analysis['tier_distribution'].get(tier, 0)
        pct = count / analysis['total_samples'] * 100
        bar = '#' * int(pct / 2)
        print(f"  {tier:10} {count:6,} ({pct:5.1f}%) {bar}")

    print("\n--- Score Distribution (deciles) ---")
    for decile, count in sorted(analysis['score_deciles'].items()):
        pct = count / analysis['total_samples'] * 100
        bar = '#' * int(pct / 2)
        print(f"  {decile:8} {count:6,} ({pct:5.1f}%) {bar}")

    print("\n--- Entity Count Distribution ---")
    for bucket in ['0', '1-2', '3-5', '6+']:
        count = analysis['entity_count_distribution'].get(bucket, 0)
        pct = count / analysis['total_samples'] * 100
        print(f"  {bucket:5} entities: {count:6,} ({pct:5.1f}%)")

    print("\n--- Top Entity Types (by occurrence) ---")
    for entity_type, count in list(analysis['entity_type_frequency'].items())[:15]:
        weight = ENTITY_WEIGHTS.get(entity_type, 3)
        print(f"  {entity_type:20} {count:6,} (weight={weight})")

    print("\n--- Source Distribution ---")
    for source, count in sorted(analysis['source_distribution'].items(), key=lambda x: -x[1]):
        pct = count / analysis['total_samples'] * 100
        print(f"  {source:20} {count:6,} ({pct:5.1f}%)")

    if issues:
        print(f"\n--- Potential Calibration Issues ({len(issues)} found) ---")
        for issue in issues[:10]:
            print(f"  [{issue['id']}] {issue['issue']}")
            print(f"    Entities: {issue['entities']}, Score: {issue['score']}, Tier: {issue['tier']}")


def main():
    print("OpenLabels Calibration Runner")
    print("=" * 70)

    # Load entity mapping
    print("\nLoading entity mapping...")
    mapping = load_entity_mapping()
    print(f"  Loaded {len(mapping)} label mappings")

    # Process dataset
    print("\nProcessing calibration dataset...")
    results = process_dataset(mapping)

    # Analyze
    print("\nAnalyzing results...")
    analysis = analyze_distribution(results)
    issues = find_calibration_issues(results)

    # Report
    print_report(analysis, issues)

    # Export for labeling
    print("\n" + "=" * 70)
    print("EXPORTS")
    print("=" * 70)

    # Full results
    print("\nExporting full results to scoring_results.jsonl...")
    with open(OUTPUT_DIR / 'scoring_results.jsonl', 'w') as f:
        for r in results:
            f.write(json.dumps(asdict(r)) + '\n')
    print(f"  Wrote {len(results):,} samples")

    # Labeling samples
    print("\nSelecting samples for expert labeling...")
    labeling_samples = select_labeling_samples(results)
    export_for_labeling(labeling_samples, OUTPUT_DIR / 'labeling_sheet.csv')
    print(f"  Wrote {len(labeling_samples)} samples to labeling_sheet.csv")

    # Analysis summary
    print("\nExporting analysis summary...")
    with open(OUTPUT_DIR / 'analysis_summary.json', 'w') as f:
        json.dump(analysis, f, indent=2)
    print("  Wrote analysis_summary.json")

    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("""
1. Review the tier distribution above
2. Check the calibration issues - these indicate parameter problems
3. Open labeling_sheet.csv and fill in 'expected_tier' column
4. Run validate_calibration.py after labeling to compare
5. Adjust scorer.py parameters based on mismatches
6. Re-run this script and iterate until accuracy > 85%
""")


if __name__ == '__main__':
    main()
