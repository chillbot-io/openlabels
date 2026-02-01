# < OpenLabels >

Scan files for sensitive data. Score risk.

OpenLabels detects PII/PHI in your files (SSNs, credit cards, health records, API keys) and computes a risk score 0-100.

## Install

### Windows

**[Download OpenLabels-0.1.0-Setup.exe](https://github.com/openlabels/openlabels/releases/latest)**

Double-click to install. Launches a desktop GUI for scanning files.

### Linux / macOS

```bash
pip install openlabels

# With document support (PDF, Word, Excel, images)
pip install openlabels[pdf,office,images,ocr]
```

## Quick Start

```bash
openlabels scan ./data           # Scan a directory
openlabels scan ./data -r        # Scan recursively
openlabels report ./data         # Generate HTML report
openlabels gui                   # Launch desktop GUI
```

Output:
```
./data/patients.csv:  85 (CRITICAL) [SSN(12), DIAGNOSIS(3)]
./data/contacts.xlsx: 28 (LOW)      [EMAIL(45), PHONE(23)]
./data/notes.pdf:      0 (MINIMAL)  []
```

### Python API

```python
from openlabels import Client

client = Client()

# Score a file
result = client.score_file("patients.csv")
print(f"Risk: {result.score}/100 ({result.tier})")
# Risk: 85/100 (CRITICAL)
```

## Features

- **Multi-format detection**: CSV, PDF, DOCX, XLSX, images (with OCR), and more
- **Entity types**: SSN, credit cards, phone numbers, emails, healthcare IDs, API keys, crypto addresses, and 50+ others
- **Checksum validation**: Validates SSNs, credit cards, IBANs, CUSIPs with Luhn/mod-97 algorithms
- **Context-aware scoring**: Co-occurrence multipliers (HIPAA, identity theft) and exposure levels
- **Cloud adapters**: AWS Macie, Google Cloud DLP, Azure Purview (normalize to common format)
- **Portable labels**: Labels travel with data via embedded metadata or virtual pointers

## Terminology: Labeler vs Scanner

OpenLabels provides two distinct modes of operation:

| Mode | Purpose | When to Use |
|------|---------|-------------|
| **Labeler** | Reads metadata and existing labels from external sources (Macie, DLP, Purview, NTFS ACLs, etc.) | You already have a DLP tool classifying your data |
| **Scanner** | Analyzes file content to detect sensitive data (patterns, checksums, ML) | You don't have DLP capabilities, or want defense-in-depth |

**Labeler** consumes findings from your existing tools and normalizes them into a portable risk score. It does NOT scan file contents—it trusts the external classification.

**Scanner** is a built-in classification engine that actually reads and analyzes file contents to detect sensitive entities. Use this if you don't have Macie/DLP/Purview, or as a second layer of verification.

You can run both together for defense-in-depth: the Labeler pulls existing classifications while the Scanner verifies with content analysis.

## Risk Scoring

Scores range 0-100 with five tiers:

| Tier | Score | Example |
|------|-------|---------|
| CRITICAL | 80+ | SSN + health diagnosis + public exposure |
| HIGH | 55-79 | Multiple direct identifiers |
| MEDIUM | 31-54 | Quasi-identifiers (name, DOB) |
| LOW | 11-30 | Contact info only |
| MINIMAL | 0-10 | No sensitive data detected |

## Architecture

```
CLI / Python API
     |
Components (Scanner, Scorer, FileOps, Reporter)
     |
Core Engine (Scoring, Labels, Entity Registry)
     |
Adapters (Cloud DLP, Filesystem, Built-in Scanner)
```

## Configuration

Entity weights are defined in `openlabels/core/registry/weights.yaml`:

```yaml
direct_identifiers:
  SSN: 10
  PASSPORT: 10
  DRIVERS_LICENSE: 9

healthcare:
  MRN: 8
  DIAGNOSIS: 7
```

## Documentation

- [OpenLabels Specification](docs/openlabels-spec-v1.md)
- [Architecture Overview](docs/openlabels-architecture-v2.md)
- [Entity Registry](docs/openlabels-entity-registry-v1.md)
- [Security Policy](SECURITY.md)

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy openlabels

# Linting
ruff check openlabels
```

## License

Apache-2.0
