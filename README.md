# OpenLabels

Unified platform for PII/PHI detection, redaction, and risk scoring.

## Packages

| Package | Purpose | History |
|---------|---------|---------|
| [**openrisk/**](./openrisk/) | Risk scanning & scoring (0-100) for files. Detects 50+ entity types, validates with checksums, integrates with AWS Macie / Google DLP / Azure Purview. | [Original repo](https://github.com/chillbot-io/OpenRisk) |
| [**scrubiq/**](./scrubiq/) | Real-time redaction with conversation awareness. Entity tracking across turns, coreference resolution, fuzzy name matching. | [Original repo](https://github.com/chillbot-io/scrubiq) |

## Quick Start

```python
# Risk scoring
from openlabels import Client
result = Client().score_file("patients.csv")
print(f"Risk: {result.score}/100 ({result.tier})")

# Redaction
from scrubiq import redact
print(redact("Call John Smith at 555-123-4567"))
# Call [NAME_1] at [PHONE_1]
```

## Installation

```bash
# OpenRisk
pip install openlabels

# ScrubIQ
pip install scrubiq
```

## Documentation

- [OpenRisk README](./openrisk/README.md)
- [ScrubIQ README](./scrubiq/README.md)
- [OpenLabels Specification](./openrisk/docs/openlabels-spec-v1.md)
- [Architecture Overview](./openrisk/docs/openlabels-architecture-v2.md)

## License

Apache-2.0 (OpenRisk) | MIT (ScrubIQ)
