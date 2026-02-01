# OpenLabels Calibration Plan

**Step-by-Step Instructions for Score Calibration**

**Date:** January 2026

---

## Overview

This document provides explicit instructions for calibrating the OpenLabels scoring algorithm using your annotated dataset. You will:

1. Prepare the calibration dataset
2. Label a subset with expected risk tiers
3. Run scoring simulations
4. Analyze distribution and adjust parameters
5. Validate against edge cases

**Time estimate:** 4-6 hours of focused work

---

## Prerequisites

You need:
- [ ] Python 3.9+ environment
- [ ] The dataset files (already in repo):
  - `ai4privacy.jsonl` (2,723 records)
  - `claude.jsonl` (42,340 records)
  - `corpus.jsonl` (1,000 records)
  - `negative.jsonl` (7,543 records)
  - `template.jsonl` (4,215 records)
- [ ] Spreadsheet software (Excel, Google Sheets) for tier labeling
- [ ] Text editor for parameter adjustments

---

## Phase 1: Dataset Preparation

### Step 1.1: Understand the Data Format

Your data is in JSONL format with this structure:

```json
{
  "id": "synthetic_00001",
  "text": "Patient: Olivia Moore, SSN: 160-28-5515, Diagnosis: Type 2 Diabetes",
  "entities": [
    {"text": "Olivia Moore", "label": "NAME_PATIENT", "start": 9, "end": 21},
    {"text": "160-28-5515", "label": "SSN", "start": 27, "end": 38},
    {"text": "Type 2 Diabetes", "label": "DIAGNOSIS", "start": 51, "end": 66}
  ],
  "source": "corpus",
  "is_adversarial": false
}
```

### Step 1.2: Create Entity Mapping

Your dataset uses labels that need mapping to OpenLabels entity types. Create a file `entity_mapping.yaml`:

```yaml
# Dataset label → OpenLabels entity type
NAME: null              # Ignore generic names
NAME_PATIENT: full_name
NAME_PROVIDER: null     # Ignore provider names
SSN: ssn
DOB: date_of_birth
DATE_DOB: date_of_birth
DATE: null              # Ignore generic dates
MRN: mrn
PHONE: phone
EMAIL: email
ADDRESS: physical_address
CREDIT_CARD: credit_card
IP: ip_address
IBAN: bank_account
ACCOUNT: bank_account
URL: null               # Ignore URLs
FACILITY: null          # Ignore facility names
DIAGNOSIS: diagnosis    # Add this mapping
```

**Your task:**
1. Open each JSONL file
2. Extract all unique labels: `cat *.jsonl | jq -r '.entities[].label' | sort | uniq`
3. Map each label to an OpenLabels entity type (or null to ignore)
4. Save as `entity_mapping.yaml`

### Step 1.3: Convert Dataset to Scoring Input

Write a script `prepare_calibration.py`:

```python
import json
import yaml
from collections import Counter

# Load your mapping
with open('entity_mapping.yaml') as f:
    ENTITY_MAP = yaml.safe_load(f)

def process_sample(sample):
    """Convert a sample to OpenLabels scoring input."""
    entity_counts = Counter()

    for entity in sample.get('entities', []):
        label = entity['label']
        openlabels_type = ENTITY_MAP.get(label)
        if openlabels_type:
            entity_counts[openlabels_type] += 1

    return {
        'id': sample['id'],
        'text': sample['text'][:100] + '...',  # Truncated preview
        'source': sample.get('source', 'unknown'),
        'is_adversarial': sample.get('is_adversarial', False),
        'entities': dict(entity_counts),
    }

# Process all files
results = []
for filename in ['ai4privacy.jsonl', 'claude.jsonl', 'corpus.jsonl',
                  'negative.jsonl', 'template.jsonl']:
    with open(filename) as f:
        for line in f:
            sample = json.loads(line)
            results.append(process_sample(sample))

# Save processed data
with open('calibration_input.jsonl', 'w') as f:
    for r in results:
        f.write(json.dumps(r) + '\n')

print(f"Processed {len(results)} samples")
```

**Run:** `python prepare_calibration.py`

---

## Phase 2: Expert Tier Labeling

### Step 2.1: Sample Selection

You need to manually label ~200-300 samples with expected risk tiers. Select a stratified sample:

```python
import json
import random

with open('calibration_input.jsonl') as f:
    samples = [json.loads(line) for line in f]

# Stratify by entity presence
no_entities = [s for s in samples if not s['entities']]
low_entities = [s for s in samples if 0 < len(s['entities']) <= 2]
high_entities = [s for s in samples if len(s['entities']) > 2]

# Sample from each stratum
selected = (
    random.sample(no_entities, min(50, len(no_entities))) +
    random.sample(low_entities, min(100, len(low_entities))) +
    random.sample(high_entities, min(100, len(high_entities)))
)

# Export for labeling
with open('samples_for_labeling.jsonl', 'w') as f:
    for s in selected:
        f.write(json.dumps(s) + '\n')

print(f"Selected {len(selected)} samples for labeling")
```

### Step 2.2: Create Labeling Spreadsheet

Convert to CSV for easier labeling:

```python
import json
import csv

with open('samples_for_labeling.jsonl') as f:
    samples = [json.loads(line) for line in f]

with open('labeling_sheet.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['id', 'text_preview', 'entities', 'source', 'expected_tier'])

    for s in samples:
        writer.writerow([
            s['id'],
            s['text'][:80],
            json.dumps(s['entities']),
            s['source'],
            ''  # You fill this in
        ])
```

### Step 2.3: Label Each Sample

Open `labeling_sheet.csv` in your spreadsheet software.

For each row, read the text preview and entities, then assign an `expected_tier`:

| Tier | When to Use |
|------|-------------|
| **Minimal** | No PII, or only generic terms (name only, URL only) |
| **Low** | Single low-sensitivity entity (email, phone) |
| **Medium** | Multiple PII types, OR single medium-sensitivity (DOB, address) |
| **High** | Direct identifier present (SSN, credit card), OR health + PII |
| **Critical** | Bulk sensitive data, credentials, SSN + health, SSN + financial |

**Labeling guidelines:**

```
Sample: "Contact me at john@email.com"
Entities: {"email": 1}
→ expected_tier: Low

Sample: "SSN: 123-45-6789"
Entities: {"ssn": 1}
→ expected_tier: Medium

Sample: "Patient John Smith, SSN 123-45-6789, Diagnosis: Diabetes"
Entities: {"full_name": 1, "ssn": 1, "diagnosis": 1}
→ expected_tier: High (SSN + health = HIPAA)

Sample: "Invoice #12345"
Entities: {}
→ expected_tier: Minimal
```

**Your task:** Label all ~250 samples. Save as `labeled_samples.csv`.

---

## Phase 3: Scoring Simulation

### Step 3.1: Implement the Scorer

Create `openlabels_scorer.py`:

```python
import math

# Entity weights from OpenLabels spec
ENTITY_WEIGHTS = {
    'ssn': 9,
    'aadhaar': 9,
    'passport': 9,
    'drivers_license': 7,
    'tax_id': 8,
    'credit_card': 9,
    'bank_account': 7,
    'mrn': 7,
    'diagnosis': 8,
    'medication': 7,
    'procedure': 7,
    'lab_result': 7,
    'health_plan_id': 6,
    'full_name': 5,
    'physical_address': 5,
    'email': 5,
    'phone': 4,
    'ip_address': 4,
    'date_of_birth': 6,
    'age': 2,
    'gender': 2,
    'postal_code': 2,
}

# Co-occurrence rules
CO_OCCURRENCE_RULES = [
    ({'direct_id', 'health'}, 2.0),       # HIPAA
    ({'direct_id', 'financial'}, 1.8),    # Fraud
    ({'credentials', 'any'}, 2.0),        # Access
]

# Category mappings for co-occurrence
ENTITY_CATEGORIES = {
    'ssn': 'direct_id',
    'credit_card': 'direct_id',
    'passport': 'direct_id',
    'drivers_license': 'direct_id',
    'diagnosis': 'health',
    'medication': 'health',
    'mrn': 'health',
    'bank_account': 'financial',
}

def get_categories(entities):
    """Get set of categories present in entities."""
    categories = set()
    for entity_type in entities:
        cat = ENTITY_CATEGORIES.get(entity_type)
        if cat:
            categories.add(cat)
    if entities:
        categories.add('any')
    return categories

def get_multiplier(entities):
    """Get co-occurrence multiplier."""
    categories = get_categories(entities)
    max_mult = 1.0

    for required_cats, mult in CO_OCCURRENCE_RULES:
        if required_cats.issubset(categories):
            max_mult = max(max_mult, mult)

    return max_mult

def calculate_score(entities, confidence=0.90):
    """
    Calculate OpenLabels score.

    entities: dict of {entity_type: count}
    confidence: assumed confidence (since ground truth has no confidence)
    """
    if not entities:
        return 0

    # Stage 1 & 2: Entity scoring
    base_score = 0
    for entity_type, count in entities.items():
        weight = ENTITY_WEIGHTS.get(entity_type, 3)  # default weight 3
        aggregation = 1 + math.log(count)
        entity_score = weight * aggregation * confidence
        base_score += entity_score

    # Stage 3: Co-occurrence
    multiplier = get_multiplier(entities)
    adjusted_score = base_score * multiplier

    # Stage 4: Normalize
    final_score = min(100, adjusted_score)

    return round(final_score, 1)

def score_to_tier(score):
    """Map score to tier."""
    if score >= 86:
        return 'Critical'
    elif score >= 61:
        return 'High'
    elif score >= 31:
        return 'Medium'
    elif score >= 11:
        return 'Low'
    else:
        return 'Minimal'
```

### Step 3.2: Score All Labeled Samples

```python
import csv
import json
from openlabels_scorer import calculate_score, score_to_tier

# Load labeled samples
results = []
with open('labeled_samples.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        entities = json.loads(row['entities']) if row['entities'] else {}
        score = calculate_score(entities)
        predicted_tier = score_to_tier(score)

        results.append({
            'id': row['id'],
            'entities': entities,
            'score': score,
            'predicted_tier': predicted_tier,
            'expected_tier': row['expected_tier'],
            'match': predicted_tier == row['expected_tier'],
        })

# Save results
with open('scoring_results.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

# Calculate accuracy
matches = sum(1 for r in results if r['match'])
print(f"Tier accuracy: {matches}/{len(results)} = {matches/len(results)*100:.1f}%")
```

---

## Phase 4: Analysis & Adjustment

### Step 4.1: Analyze Mismatches

Look at where predicted ≠ expected:

```python
import csv

mismatches = []
with open('scoring_results.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['match'] == 'False':
            mismatches.append(row)

print(f"\n{len(mismatches)} mismatches:\n")
for m in mismatches[:20]:  # Show first 20
    print(f"ID: {m['id']}")
    print(f"  Entities: {m['entities']}")
    print(f"  Score: {m['score']}")
    print(f"  Predicted: {m['predicted_tier']}, Expected: {m['expected_tier']}")
    print()
```

### Step 4.2: Common Mismatch Patterns

Look for patterns:

**Over-scoring (predicted > expected):**
- Are weights too high for certain entities?
- Is the aggregation factor too aggressive?

**Under-scoring (predicted < expected):**
- Are weights too low?
- Is a co-occurrence rule missing?

### Step 4.3: Adjust Parameters

Based on your analysis, adjust in `openlabels_scorer.py`:

**If emails/phones score too high:**
```python
'email': 3,  # Try lowering to 2
'phone': 3,  # Try lowering to 2
```

**If SSN alone scores too low for "High":**
```python
'ssn': 9,  # Try raising to 10
```

**If HIPAA combinations score too low:**
```python
({'direct_id', 'health'}, 2.0),  # Try raising to 2.5
```

**If tier boundaries are wrong:**
```python
def score_to_tier(score):
    if score >= 80:      # Was 86, adjust down
        return 'Critical'
    elif score >= 55:    # Was 61, adjust down
        return 'High'
    # ...
```

### Step 4.4: Iterate

1. Adjust parameters
2. Re-run scoring simulation (Step 3.2)
3. Check accuracy
4. Repeat until accuracy > 85%

---

## Phase 5: Validation

### Step 5.1: Test Negative Samples

All samples from `negative.jsonl` should score Minimal:

```python
import json
from openlabels_scorer import calculate_score, score_to_tier

failures = []
with open('negative.jsonl') as f:
    for line in f:
        sample = json.loads(line)
        # Negatives have no entities
        score = calculate_score({})
        if score > 10:
            failures.append(sample)

print(f"Negative sample failures: {len(failures)}")
# Should be 0
```

### Step 5.2: Test Known Critical Cases

Create explicit test cases:

```python
from openlabels_scorer import calculate_score, score_to_tier

test_cases = [
    # (entities, expected_tier, description)
    ({}, 'Minimal', 'Empty file'),
    ({'email': 1}, 'Low', 'Single email'),
    ({'ssn': 1}, 'Medium', 'Single SSN'),
    ({'ssn': 10}, 'High', 'Bulk SSN'),
    ({'ssn': 1, 'diagnosis': 1}, 'High', 'HIPAA: SSN + diagnosis'),
    ({'ssn': 100, 'diagnosis': 50}, 'Critical', 'Bulk PHI'),
    ({'credit_card': 1, 'ssn': 1}, 'High', 'Identity theft risk'),
]

for entities, expected, desc in test_cases:
    score = calculate_score(entities)
    tier = score_to_tier(score)
    status = '✓' if tier == expected else '✗'
    print(f"{status} {desc}: score={score}, tier={tier}, expected={expected}")
```

### Step 5.3: Test Adversarial Samples

Your dataset includes adversarial examples (unicode, homoglyph). Verify they score correctly:

```python
import json

adversarial_results = []
for filename in ['ai4privacy.jsonl', 'claude.jsonl', 'template.jsonl']:
    with open(filename) as f:
        for line in f:
            sample = json.loads(line)
            if sample.get('is_adversarial'):
                # Process and score
                entities = process_sample(sample)['entities']
                score = calculate_score(entities)
                adversarial_results.append({
                    'type': sample.get('adversarial_type'),
                    'score': score,
                    'entities': entities,
                })

# Analyze by adversarial type
from collections import defaultdict
by_type = defaultdict(list)
for r in adversarial_results:
    by_type[r['type']].append(r['score'])

for adv_type, scores in by_type.items():
    avg = sum(scores) / len(scores)
    print(f"{adv_type}: {len(scores)} samples, avg score = {avg:.1f}")
```

---

## Phase 6: Documentation

### Step 6.1: Record Final Parameters

Create `calibration_results.md`:

```markdown
# OpenLabels Calibration Results

## Final Parameters

### Entity Weights
| Entity | Weight | Notes |
|--------|--------|-------|
| ssn | 9 | |
| credit_card | 7 | |
| ... | ... | |

### Tier Thresholds
| Tier | Score Range |
|------|-------------|
| Critical | 86-100 |
| High | 61-85 |
| Medium | 31-60 |
| Low | 11-30 |
| Minimal | 0-10 |

### Co-occurrence Multipliers
| Rule | Multiplier |
|------|------------|
| direct_id + health | 2.0 |
| ... | ... |

## Validation Results

- Tier accuracy on labeled samples: X%
- Negative sample false positive rate: X%
- Adversarial sample handling: [notes]

## Calibration Date
January 2026

## Calibration Dataset
- 57,821 total samples
- 250 expert-labeled samples
- Sources: ai4privacy, claude, corpus, negative, template
```

### Step 6.2: Commit Calibrated Parameters

Once validated, update the official OpenLabels specification with your calibrated values.

---

## Checklist

- [ ] **Phase 1:** Dataset preparation complete
- [ ] **Phase 2:** 200+ samples labeled with expected tiers
- [ ] **Phase 3:** Scorer implemented and tested
- [ ] **Phase 4:** Tier accuracy > 85%
- [ ] **Phase 5:** Negative samples pass (0 false positives)
- [ ] **Phase 5:** Critical test cases pass
- [ ] **Phase 5:** Adversarial samples handled correctly
- [ ] **Phase 6:** Final parameters documented

---

## Troubleshooting

### "Accuracy is stuck at 60%"

- Check your entity mapping - are important labels being dropped?
- Review tier labeling criteria - be consistent
- Consider adjusting tier thresholds, not just weights

### "All scores cluster at 0 or 100"

- Your weights may be too extreme
- Check the aggregation factor calculation
- Consider sigmoid normalization instead of linear cap

### "Co-occurrence rules never trigger"

- Check your ENTITY_CATEGORIES mapping
- Verify category detection in `get_categories()`
- Add debug logging to see what's being detected

### "Adversarial samples score wrong"

- This is a detection issue, not scoring
- Document which adversarial types cause problems
- These become requirements for the scanner component

---

## Next Steps After Calibration

1. **Integrate into SDK:** Port calibrated parameters to production code
2. **Add unit tests:** Encode test cases as automated tests
3. **Monitor in production:** Track score distributions on real data
4. **Periodic recalibration:** Re-run calibration quarterly with new samples

---

*Good luck! Reach out if you hit blockers.*
