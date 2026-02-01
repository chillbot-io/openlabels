# OpenLabels Calibration Results

**Calibration Date:** January 2026
**Dataset Size:** 57,821 samples

---

## Final Parameters

### Entity Weights

| Entity Type | Weight | Rationale |
|-------------|--------|-----------|
| **Direct Identifiers** | | |
| ssn | 40 | Single instance = Medium |
| passport | 38 | Near-SSN risk |
| drivers_license | 32 | Can be used for ID theft |
| tax_id | 36 | High fraud risk |
| **Financial** | | |
| credit_card | 40 | Direct fraud risk |
| bank_account | 25 | Lower than CC (needs routing) |
| routing_number | 15 | Needs account to be useful |
| **Medical/Health** | | |
| mrn | 28 | HIPAA identifier |
| diagnosis | 25 | PHI, triggers HIPAA with ID |
| medication | 20 | PHI |
| procedure | 20 | PHI |
| lab_result | 22 | PHI |
| health_plan_id | 18 | PHI |
| **Personal** | | |
| full_name | 12 | Common, needs context |
| physical_address | 15 | Location risk |
| email | 10 | Very common |
| phone | 10 | Very common |
| ip_address | 8 | Pseudonymous |
| date_of_birth | 18 | Quasi-identifier |
| **Quasi-identifiers** | | |
| age | 5 | Low risk alone |
| gender | 4 | Very low risk |
| postal_code | 6 | Aggregatable |
| ethnicity | 8 | Sensitive but not identifying |
| **Credentials** | | |
| api_key | 70 | Access risk |
| password | 70 | Access risk |
| private_key | 80 | Highest access risk |
| access_token | 65 | Temporary access |
| aws_key | 75 | Cloud access |

### Tier Thresholds

| Tier | Score Range | Description |
|------|-------------|-------------|
| Critical | 80-100 | HIPAA violations, bulk sensitive data, credentials |
| High | 55-79 | Direct ID + context, multiple high-risk entities |
| Medium | 31-54 | Single direct identifier |
| Low | 11-30 | Personal info without direct ID |
| Minimal | 0-10 | Generic data, single low-risk entity |

### Co-occurrence Multipliers

| Rule | Multiplier | Rationale |
|------|------------|-----------|
| direct_id + health | 2.0x | HIPAA violation |
| direct_id + financial | 1.8x | Identity theft |
| credentials (any) | 1.5x | Access risk |
| personal + health | 1.5x | PHI without direct ID |
| direct_id + personal + financial | 2.2x | Full identity package |

### Exposure Multipliers

| Exposure Level | Multiplier |
|----------------|------------|
| Private | 1.0x |
| Internal | 1.2x |
| Over-exposed | 1.8x |
| Public | 2.5x |

---

## Validation Results

### Test Case Accuracy: 84%

| Test Case | Score | Tier | Expected | Status |
|-----------|-------|------|----------|--------|
| Single SSN | 36.0 | Medium | Medium | ✓ |
| Single CC | 36.0 | Medium | Medium | ✓ |
| Single email | 9.0 | Minimal | Minimal | ✓ |
| Bank account | 22.5 | Low | Low | ✓ |
| SSN + MRN (HIPAA) | 100.0 | Critical | Critical | ✓ |
| SSN + diagnosis | 100.0 | Critical | Critical | ✓ |
| CC + name | 46.8 | Medium | Medium | ✓ |
| Contact info | 28.8 | Low | Low | ✓ |
| Bulk SSN (50) | 100.0 | Critical | Critical | ✓ |
| API key | 94.5 | Critical | Critical | ✓ |

### Distribution on Calibration Dataset

| Tier | Count | Percentage |
|------|-------|------------|
| Minimal | 20,162 | 34.9% |
| Low | 12,616 | 21.8% |
| Medium | 12,788 | 22.1% |
| High | 11,564 | 20.0% |
| Critical | 691 | 1.2% |

---

## Calibration Dataset

| Source | Samples | Description |
|--------|---------|-------------|
| claude | 29,940 | Claude-generated PII samples |
| claude_adversarial | 12,400 | Adversarial Claude samples |
| template | 3,000 | Template-based samples |
| negative_near_miss | 2,900 | Near-miss negatives |
| ai4privacy | 2,000 | AI4Privacy dataset |
| negative_format_matching | 1,474 | Format-matching negatives |
| negative_brand_names | 1,361 | Brand name negatives |
| template_adversarial | 1,215 | Adversarial templates |
| negative_numbers_context | 1,208 | Numbers in context |
| corpus | 1,000 | Medical corpus |
| ai4privacy_adversarial | 723 | Adversarial AI4Privacy |
| negative_instructional | 368 | Instructional negatives |
| negative_clean_text | 232 | Clean text negatives |

---

## Next Steps

1. Port `scorer.py` to `openlabels/core/scorer.py`
2. Add unit tests for edge cases
3. Monitor distribution on production data
4. Recalibrate quarterly with new samples

---

*Calibration performed using OpenLabels calibration framework v1.0*
