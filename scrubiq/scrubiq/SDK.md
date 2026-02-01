# ScrubIQ SDK

> Privacy Infrastructure That Just Works

## Installation

```bash
pip install scrubiq

# With ML models (recommended)
pip install scrubiq[ml]

# Everything
pip install scrubiq[all]
```

## Quick Start

```python
from scrubiq import redact

result = redact("Patient John Smith, SSN 123-45-6789")
print(result)  # "Patient [NAME_1], SSN [SSN_1]"
```

That's it. Zero config. It just works.

The result behaves like a string but has superpowers:
```python
result.restore()      # Get original back
result.entities       # What was found  
result.has_phi        # Quick check
result.mapping        # Token → value dict
```

## Core Verbs

| Verb | What it does | Returns |
|------|--------------|---------|
| `redact(text)` | Detect PHI, replace with tokens | `RedactionResult` |
| `restore(text, mapping)` | Replace tokens with originals | `str` |
| `scan(text)` | Detect only, no tokenization | `ScanResult` |
| `chat(message)` | Redact → LLM → Restore | `ChatResult` |

## Progressive Disclosure

### Level 0: Just works
```python
from scrubiq import redact

safe_text = redact("Patient John Smith")
```

### Level 1: I want control
```python
from scrubiq import Redactor

r = Redactor(confidence_threshold=0.9)
result = r.redact(text)
```

### Level 2: I want everything
```python
from scrubiq import Redactor

r = Redactor(
    confidence_threshold=0.85,
    thresholds={"NAME": 0.7, "SSN": 0.99},
    entity_types=["NAME", "SSN", "DOB"],
    exclude_types=["EMAIL"],
    allowlist=["Mayo Clinic", "Tylenol"],
    allowlist_file="./allowlist.txt",
    patterns={"MRN": r"MRN-\d{8}"},
    safe_harbor=True,
    coreference=True,
    device="cuda",
    workers=4,
)
```

## Working with Results

```python
result = redact("Patient John Smith, SSN 123-45-6789")

# String-like behavior
print(result)            # Just print it
"[NAME_1]" in result     # Check contents
len(result)              # Get length

# Rich properties
result.text              # "[NAME_1] has SSN [SSN_1]"
result.entities          # [Entity(type="NAME", ...), Entity(type="SSN", ...)]
result.tokens            # ["[NAME_1]", "[SSN_1]"]
result.mapping           # {"[NAME_1]": "John Smith", "[SSN_1]": "123-45-6789"}
result.has_phi           # True
result.stats             # {"time_ms": 12.5, "entities_found": 2}

# Restore original values
original = result.restore()
# "Patient John Smith, SSN 123-45-6789"

# Or use the standalone function
from scrubiq import restore
original = restore(result.text, result.mapping)

# JSON serialization
result.to_dict()
result.to_json()
```

## Entity Objects

Each detected entity has rich metadata:

```python
for entity in result.entities:
    print(f"Type: {entity.type}")           # NAME, SSN, DOB, etc.
    print(f"Text: {entity.text}")           # Original text
    print(f"Confidence: {entity.confidence}") # 0.0 to 1.0
    print(f"Token: {entity.token}")         # [NAME_1], etc.
    print(f"Position: {entity.start}-{entity.end}")
    print(f"Detector: {entity.detector}")   # Which detector found it
```

## Scanning Without Tokenization

```python
from scrubiq import scan

result = scan("Patient John Smith")

if result.has_phi:
    print(f"Found: {result.entity_types}")  # {"NAME"}
    for entity in result.entities:
        print(f"  {entity.type}: {entity.text}")
```

## Chat with LLM

```python
from scrubiq import chat

# Automatically: redact → send to LLM → restore
result = chat("Summarize John Smith's condition")
print(result.response)  # Response with "John Smith" restored

# With options
result = chat(
    "What medications does the patient take?",
    model="claude-sonnet-4-20250514",
)
```

## Configuration

### Via Environment Variables

```bash
export SCRUBIQ_THRESHOLD=0.9
export SCRUBIQ_DEVICE=cuda
export SCRUBIQ_WORKERS=4
export SCRUBIQ_SAFE_HARBOR=true
export SCRUBIQ_COREFERENCE=true
export SCRUBIQ_ALLOWLIST="Mayo Clinic,Tylenol"
export SCRUBIQ_ENTITY_TYPES="NAME,SSN,DOB"
export SCRUBIQ_EXCLUDE_TYPES="EMAIL"
```

### Via Constructor

```python
r = Redactor(
    # Thresholds
    confidence_threshold=0.85,
    thresholds={"NAME": 0.7, "SSN": 0.99},
    
    # What to detect
    entity_types=["NAME", "SSN", "DOB"],
    exclude_types=["EMAIL"],
    
    # Allowlist
    allowlist=["Tylenol", "Aspirin"],
    allowlist_file="./allowlist.txt",
    
    # Custom patterns (highest priority)
    patterns={"CASE_ID": r"CASE-\d{6}"},
    
    # Behavior
    safe_harbor=True,
    coreference=True,
    
    # Performance
    device="cuda",
    workers=4,
    
    # Review queue
    review_threshold=0.7,
)
```

### Per-Call Override

```python
# Override just for this call
result = r.redact(
    text,
    confidence_threshold=0.95,
    allowlist=["Dr. House"],
    entity_types=["NAME", "SSN"],
)
```

## Sub-Interfaces

The Redactor provides organized interfaces for different concerns:

### Conversations
```python
r = Redactor()

# Manage conversations
conv = r.conversations.create("Patient Intake")
convs = r.conversations.list(limit=50)
conv = r.conversations.get("conv_id")
r.conversations.delete("conv_id")
results = r.conversations.search("patient name")
```

### Human Review Queue
```python
# Items flagged for human review
pending = r.review.pending
count = r.review.count

# Approve or reject
r.review.approve("item_id")
r.review.reject("item_id")
```

### Memory System
```python
# Claude-like memory
results = r.memory.search("patient allergies")  # FTS across messages
memories = r.memory.get_for_entity("[NAME_1]")   # Memories for specific entity
all_mems = r.memory.get_all(limit=50)            # All memories
r.memory.add("Patient is allergic to penicillin", entity_token="[NAME_1]")
r.memory.delete("memory_id")
count = r.memory.count
stats = r.memory.stats
```

### Audit Log
```python
# Compliance audit trail
entries = r.audit.recent(limit=100)
is_valid = r.audit.verify()  # Verify hash chain integrity
csv_data = r.audit.export("2024-01-01", "2024-12-31", format="csv")
```

## File Processing

```python
# Process files (PDF, images, etc.)
result = r.redact_file("document.pdf")
result = r.redact_file(file_bytes, filename="scan.jpg")

print(result.text)      # Extracted and redacted text
print(result.entities)  # PHI found
print(result.pages)     # Number of pages
```

## Async Support

```python
# Same API, just add 'a' prefix
result = await r.aredact(text)
result = await r.ascan(text)
result = await r.achat(message)
restored = await r.arestore(text, mapping)
```

## Preloading

For faster first requests in server environments:

```python
from scrubiq import preload

# At startup
preload()  # Blocks until models loaded

# With progress callback
preload(on_progress=lambda pct, msg: print(f"{pct}% - {msg}"))

# Async version
await preload_async()
```

## Server Mode

```bash
# Start headless server
scrubiq-server

# With options
scrubiq-server --host 0.0.0.0 --port 8080 --workers 4

# Via environment
SCRUBIQ_WORKERS=4 scrubiq-server
```

## API Reference

### RedactionResult

| Field | Type | Description |
|-------|------|-------------|
| `text` | `str` | Redacted text with tokens |
| `entities` | `list[Entity]` | Detected PHI entities |
| `tokens` | `list[str]` | Tokens created |
| `mapping` | `dict` | Token → original value |
| `has_phi` | `bool` | True if PHI detected |
| `needs_review` | `list[ReviewItem]` | Items needing human review |
| `stats` | `dict` | Processing statistics |
| `error` | `str?` | Error message if failed |
| `warning` | `str?` | Warning message |

### ScanResult

| Field | Type | Description |
|-------|------|-------------|
| `entities` | `list[Entity]` | Detected PHI entities |
| `has_phi` | `bool` | True if any PHI detected |
| `entity_types` | `set[str]` | Entity types found |
| `stats` | `dict` | Processing statistics |

### Entity

| Field | Type | Description |
|-------|------|-------------|
| `text` | `str` | Original text |
| `type` | `str` | Type (NAME, SSN, etc.) |
| `confidence` | `float` | Detection confidence 0-1 |
| `token` | `str?` | Assigned token |
| `start` | `int` | Start position in text |
| `end` | `int` | End position in text |
| `detector` | `str` | Which detector found it |

### ChatResult

| Field | Type | Description |
|-------|------|-------------|
| `response` | `str` | Restored LLM response |
| `redacted_prompt` | `str` | What was sent to LLM |
| `redacted_response` | `str` | Raw LLM response |
| `model` | `str` | Model used |
| `provider` | `str` | LLM provider |
| `tokens_used` | `int` | Token count |
| `latency_ms` | `float` | Processing time |
| `entities` | `list[Entity]` | PHI in user message |
| `conversation_id` | `str?` | Conversation ID |
| `error` | `str?` | Error message |

## Error Handling

The SDK never crashes on bad input:

```python
# Empty input → returns empty result with warning
result = redact(None)
# RedactionResult(text="", warning="Empty input")

# Detection fails → returns original with error
result = redact(weird_input)
# RedactionResult(text=weird_input, error="...")

# Check for errors
if result.error:
    logger.error(f"Redaction failed: {result.error}")
```

## Context Manager

```python
with Redactor() as r:
    result = r.redact(text)
    # Resources automatically cleaned up
```

## For Persistent Storage

The SDK uses `ScrubIQ` internally for token persistence and audit logging. For direct access:

```python
from scrubiq import ScrubIQ

with ScrubIQ(key_material="your-secret-key") as cr:
    result = cr.redact(text)
    # Tokens persist across sessions
    # Audit log maintained
```

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SCRUBIQ_THRESHOLD` | `0.85` | Confidence threshold |
| `SCRUBIQ_DEVICE` | `auto` | `auto`, `cuda`, `cpu` |
| `SCRUBIQ_WORKERS` | `1` | Parallel workers |
| `SCRUBIQ_SAFE_HARBOR` | `true` | HIPAA Safe Harbor |
| `SCRUBIQ_COREFERENCE` | `true` | Resolve pronouns |
| `SCRUBIQ_ALLOWLIST` | | Comma-separated values |
| `SCRUBIQ_ENTITY_TYPES` | | Types to detect |
| `SCRUBIQ_EXCLUDE_TYPES` | | Types to skip |
| `SCRUBIQ_REVIEW_THRESHOLD` | `0.7` | Flag uncertain detections |
| `SCRUBIQ_DATA_DIR` | | Storage directory |
| `ANTHROPIC_API_KEY` | | For chat() function |
