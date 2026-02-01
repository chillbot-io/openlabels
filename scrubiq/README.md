# ScrubIQ

**Enterprise-grade PHI/PII redaction with conversation awareness**

```python
>>> from scrubiq import redact
>>> redact("Call John Smith at 555-123-4567")
'Call [NAME_1] at [PHONE_1]'
```

## Features

- **One-line redaction** for AI applications
- **Entity tracking** across conversation turns
- **Coreference resolution** ("he" → "John Smith")
- **Fuzzy name matching** ("J. Smith" = "John Smith")
- **Checksum validation** (Luhn for CC, mod-97 for IBAN, etc.)
- **ML-optional** - works without ML for lightweight deployments
- **Extensible** - add custom patterns, checksums, deny/allow lists

## Installation

```bash
# Basic installation (pattern + checksum detection)
pip install scrubiq

# With ML support
pip install scrubiq[ml]

# With server support (FastAPI)
pip install scrubiq[server]

# Everything
pip install scrubiq[all]
```

## Quick Start

### Single-shot redaction

```python
from scrubiq import redact

text = "Patient John Smith, DOB 01/15/1980, SSN 123-45-6789"
print(redact(text))
# Patient [NAME_1], DOB [DATE_1], SSN [SSN_1]
```

### Multi-turn conversations

```python
from scrubiq import Session

session = Session()

# First message
print(session.redact("Patient John Smith arrived").redacted)
# Patient [NAME_1] arrived

# Second message - "He" resolves to John Smith
print(session.redact("He reported chest pain").redacted)
# [NAME_1] reported chest pain

# Third message - "John" matches "John Smith"
print(session.redact("John's labs are normal").redacted)
# [NAME_1]'s labs are normal
```

### Restore original values

```python
session = Session()
result = session.redact("Call Dr. Wilson at 555-123-4567")

print(result.redacted)
# Call [NAME_1] at [PHONE_1]

print(session.restore(result.redacted))
# Call Dr. Wilson at 555-123-4567
```

## Configuration

```python
from scrubiq import Session, RedactionStyle

session = Session(
    style=RedactionStyle.TOKEN,      # [NAME_1], [SSN_1]
    confidence_threshold=0.7,         # Minimum confidence to redact
    enable_ml=False,                  # Disable ML for lightweight mode
    enable_coref=True,                # Resolve pronouns
    enable_fuzzy_match=True,          # Match partial names
    entity_types={"NAME", "SSN"},     # Only detect these types
    deny_list={"John Doe"},           # Always redact these values
    allow_list={"Dr. Smith"},         # Never redact these values
)
```

### Redaction Styles

| Style | Example Output |
|-------|----------------|
| `TOKEN` | `[NAME_1]`, `[SSN_1]` |
| `TYPE_ONLY` | `[NAME]`, `[SSN]` |
| `MASK` | `████████` |
| `REMOVE` | (empty string) |
| `HASH` | `[a1b2c3d4]` |

## Command Line

```bash
# Redact from stdin
echo "Call John at 555-123-4567" | scrubiq

# Redact a file
scrubiq --input patient_notes.txt --output redacted.txt

# Interactive mode
scrubiq --interactive
```

## Entity Types

ScrubIQ detects 50+ entity types including:

- **Names**: `NAME`, `NAME_PATIENT`, `NAME_PROVIDER`, `NAME_RELATIVE`
- **Dates**: `DATE`, `DATE_DOB`, `AGE`
- **IDs**: `SSN`, `MRN`, `NPI`, `DEA`, `DRIVER_LICENSE`, `PASSPORT`
- **Contact**: `PHONE`, `EMAIL`, `FAX`, `ADDRESS`
- **Financial**: `CREDIT_CARD`, `IBAN`, `ACCOUNT_NUMBER`
- **Network**: `IP_ADDRESS`, `MAC_ADDRESS`
- **Secrets**: `API_KEY`, `AWS_ACCESS_KEY`, `GITHUB_TOKEN`

## How It Works

1. **Detection**: Pattern matchers and checksum validators identify potential PHI
2. **Merge**: Overlapping detections resolved using authority hierarchy (CHECKSUM > PATTERN > ML)
3. **Entity Resolution**: Mentions grouped using multi-sieve algorithm (exact match, partial name, coreference)
4. **Tokenization**: Each entity assigned a unique token (same person = same token)

## License

MIT
