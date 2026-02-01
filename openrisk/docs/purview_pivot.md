# OpenLabels Purview Pivot

## The Realization

We set out to build portable data labels. Along the way, we tried to solve data classification at scale, competing with Macie, Google DLP, and Purview itself. That was scope creep.

**Original intent:** An open-source autolabeler for Purview.

**The pivot:** Stop trying to save the world. Ship the thing we started.

---

## The Gap We Fill

### E3 vs E5 Licensing Gap

| Feature | E3 | E5 |
|---------|----|----|
| Manual sensitivity labeling | ✓ | ✓ |
| Basic DLP with SIT detection | ✓ | ✓ |
| Sensitive Information Types | ✓ | ✓ |
| **Automatic sensitivity labeling** | ✗ | ✓ |
| Endpoint DLP | ✗ | ✓ |
| ML-based classification | ✗ | ✓ |

**E3 customers can detect sensitive data but can't auto-label.** That's a $20-38/user/month gap.

### On-Prem Gap

Purview's cloud-based scanning doesn't reach on-prem file shares effectively. Customers need local classification that applies Purview-compatible labels.

---

## The Varonis Model (What We're Copying)

Varonis nailed this architecture:

```
┌─────────────────────────────────────────────────────────┐
│  Varonis DCE (Data Classification Engine)              │
│  - Scans M365 + on-prem with same engine               │
│  - Scales massively via incremental scanning           │
└─────────────────┬───────────────────────────────────────┘
                  │ classification results
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Mapping Layer (UI)                                     │
│  "DCE finds SSN" → "Apply Purview label: Confidential" │
│  Customer defines their own mappings                    │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Purview Labels (customer's own scheme)                │
│  - Read via Graph API / Purview API                    │
│  - Customer sets up labels however they want           │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Labeling SDK (MIP SDK)                                │
│  - Applies Purview-compatible labels to files          │
│  - Labels recognized by Purview, DLP policies work     │
└─────────────────────────────────────────────────────────┘
```

### The Genius of This Model

- **Classifier doesn't need to match Purview SITs exactly**
- **Customer brings their own label taxonomy**
- **Mapping layer decouples classification from labeling**
- **Varonis controls both ends**

---

## OpenLabels Architecture

### What We DON'T Own
- Label taxonomy (customer's Purview setup)
- Label format (Microsoft's MIP format)
- What "Confidential" means (customer decides)

### What We DO Own
- Classification engine (DCE equivalent)
- Mapping UI ("SSN findings → apply label X")
- Labeling pipeline (on-prem + cloud, at scale)
- The glue that makes it work without E5

### Customer Workflow
1. Set up labels in Purview however they want (they already have this)
2. Connect OpenLabels → pull their label definitions via API
3. Run classification on their files (on-prem, SharePoint, wherever)
4. Map: "When you find [X], apply [their label Y]"
5. OpenLabels applies labels via MIP SDK
6. Purview sees the labels, DLP policies work, compliance happy

---

## Classification Engine Decision

### Previous Attempts
- Built ML pipeline with BERT + fastcoref → high accuracy, too slow to scale
- Built pattern-based detector → faster, but accuracy gaps (55% precision, 40% recall)

### Presidio Consideration

**Pros:**
- Microsoft's own open-source PII framework
- "We use Microsoft Presidio" is defensible
- Well-maintained, handles edge cases

**Cons:**
- Not exact Purview SIT match (but doesn't need to be with mapping layer)
- spaCy NER adds latency
- Reported: 7MB file = 7-10 minutes (not great)
- No built-in scaling infrastructure

### Varonis DCE Scaling Secrets

Varonis scales because of **architecture**, not just the classifier:

| Secret Sauce | What It Does |
|--------------|--------------|
| Incremental scanning | Only scans new/changed files |
| Distributed nodes | Parallelized workers near the data |
| Metadata pre-filtering | Narrows scope before classifying |
| Pattern + AI hybrid | Heavy patterns, selective AI |

**Key insight:** The classifier is the smallest part of the scaling story. The infrastructure around it is what matters.

### Recommendation

```
OpenLabels DCE = Classifier + Incremental Tracker + Distributed Workers + Pre-filter
                     │
                     └── Can be current patterns, Presidio, or hybrid
                         (optimize this last, not first)
```

Build the scaling infrastructure first:
1. **Incremental scanning** — track file changes, only scan new/modified
2. **Parallel workers** — distribute classification workload
3. **Pre-filtering** — use metadata to narrow scope
4. **Classifier** — tune for accuracy once infrastructure is solid

---

## Benchmark Results (Current Classifier)

Ran against AI4Privacy dataset (500 samples):

**Overall:** 55% precision, 40% recall, 46% F1

### Strong Performers
| Entity Type | F1 Score |
|-------------|----------|
| URL | 100% |
| EMAIL | 99.2% |
| IBAN | 90% |
| SSN | 80% |
| PHONE | 70.8% |

### Needs Improvement
| Entity Type | F1 Score | Issue |
|-------------|----------|-------|
| NAME | 14.3% | Needs context/dictionary |
| ADDRESS | 13.7% | Pattern-based too limited |
| CREDIT_CARD | 44.4% | Missing formats |

**Note:** With mapping layer, exact accuracy matters less. Customer maps what *we* detect to *their* labels. We don't need to match Purview SITs 1:1.

---

## Components to Build

### 1. Purview Connector
- Authenticate via Azure AD / Graph API
- Pull customer's sensitivity label definitions
- Cache label schema locally

### 2. Mapping UI
- Display available labels from Purview
- Display classifier entity types
- Let customer create rules: "Entity X → Label Y"
- Support confidence thresholds: "SSN with >80% confidence → Highly Confidential"

### 3. Classification Engine (DCE)
- Current pattern-based detector as baseline
- Add incremental scanning (file change tracking)
- Add parallel processing
- Optional: Presidio recognizers for specific types

### 4. Labeling Engine
- Microsoft Information Protection (MIP) SDK integration
- Apply sensitivity labels to files
- Support: Office docs, PDFs, images (as metadata)
- Register in central registry

### 5. Central Registry
- Track all labeled files
- Detect drift (embedded label ≠ registry)
- Audit trail / label history
- Sync state back to Purview (optional)

---

## Value Proposition

> "You have E3. You have Purview labels. You have on-prem files. Microsoft wants E5 for autolabeling. We do it for free."

- Open source
- Works on-prem where Purview can't reach
- Uses YOUR label taxonomy
- No new format to learn
- Purview-compatible labels

---

## Next Steps

1. **Prototype Purview connector** — can we pull label definitions via API?
2. **Prototype MIP SDK integration** — can we apply labels programmatically?
3. **Design mapping UI** — simple rules editor
4. **Add incremental scanning** — track file changes
5. **Tune classifier as needed** — accuracy matters less with mapping layer

---

## References

- [Microsoft Purview Licensing: E3 vs E5](https://www.syskit.com/blog/microsoft-purview-licensing-e3-e5-comparison/)
- [Varonis: How to Do Data Classification at Scale](https://www.varonis.com/blog/how-to-do-data-classification-at-scale)
- [Varonis: Scaling Accurate Classification](https://www.varonis.com/blog/scaling-accurate-classification)
- [Microsoft Presidio GitHub](https://github.com/microsoft/presidio)
- [MIP SDK Documentation](https://learn.microsoft.com/en-us/information-protection/develop/)
