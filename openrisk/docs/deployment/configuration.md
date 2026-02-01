# Configuration Reference

Complete reference for OpenLabels configuration options.

## Environment Variables

### Logging

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `OPENLABELS_LOG_LEVEL` | Logging verbosity | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `OPENLABELS_LOG_FILE` | Log file path | None (stdout) | File path |
| `OPENLABELS_LOG_FORMAT` | Log output format | `text` | `text`, `json` |
| `OPENLABELS_LOG_MAX_SIZE` | Max log file size before rotation | `100MB` | Size string |
| `OPENLABELS_LOG_BACKUP_COUNT` | Number of rotated logs to keep | `5` | Integer |

### Storage

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `OPENLABELS_INDEX_PATH` | SQLite index database path | `~/.openlabels/index.db` | File path |
| `OPENLABELS_QUARANTINE_DIR` | Default quarantine directory | `~/.openlabels/quarantine` | Directory path |
| `OPENLABELS_TEMP_DIR` | Temporary file directory | System temp | Directory path |
| `OPENLABELS_CACHE_DIR` | Cache directory | `~/.openlabels/cache` | Directory path |

### Scanning

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `OPENLABELS_DEFAULT_EXPOSURE` | Default exposure level for scoring | `PRIVATE` | `PUBLIC`, `ORG_WIDE`, `INTERNAL`, `PRIVATE` |
| `OPENLABELS_MIN_CONFIDENCE` | Minimum confidence threshold | `0.7` | `0.0` - `1.0` |
| `OPENLABELS_ENABLE_OCR` | Enable OCR for images/PDFs | `true` | `true`, `false` |
| `OPENLABELS_MAX_FILE_SIZE` | Maximum file size to scan | `100MB` | Size string |
| `OPENLABELS_WORKER_COUNT` | Number of parallel workers | CPU count | Integer |
| `OPENLABELS_SCAN_TIMEOUT` | Per-file scan timeout | `300` | Seconds |

### Detection

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `OPENLABELS_DETECTOR_TIMEOUT` | Detector timeout | `30` | Seconds |
| `OPENLABELS_STRICT_MODE` | Fail on any detector error | `false` | `true`, `false` |

### Database

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `OPENLABELS_DATABASE_URL` | Database connection string | `~/.openlabels/index.db` | SQLite path or PostgreSQL URL |
| `OPENLABELS_TENANT_ID` | Tenant identifier for multi-tenant mode | `default` | String |

**SQLite (default - single node):**
```bash
export OPENLABELS_DATABASE_URL="~/.openlabels/index.db"
```

**PostgreSQL (server mode - multi-tenant):**
```bash
export OPENLABELS_DATABASE_URL="postgresql://user:password@localhost:5432/openlabels"
```

### Performance

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `OPENLABELS_BATCH_SIZE` | Database batch size | `1000` | Integer |
| `OPENLABELS_MEMORY_LIMIT` | Memory limit for processing | None | Size string |
| `OPENLABELS_CONNECTION_POOL_SIZE` | Connection pool size | `5` | Integer |

## CLI Flags

### Global Flags

```bash
openlabels [global-flags] <command> [command-flags]
```

| Flag | Description | Environment Variable |
|------|-------------|---------------------|
| `--log-level` | Set log level | `OPENLABELS_LOG_LEVEL` |
| `--log-file` | Log to file | `OPENLABELS_LOG_FILE` |
| `--log-format` | Log format (text/json) | `OPENLABELS_LOG_FORMAT` |
| `--no-color` | Disable colored output | - |
| `--quiet`, `-q` | Suppress non-essential output | - |
| `--verbose`, `-v` | Enable verbose output | - |

### scan Command

```bash
openlabels scan <path> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--recursive`, `-r` | Scan directories recursively | `false` |
| `--exposure`, `-e` | Exposure level for scoring | `PRIVATE` |
| `--format`, `-f` | Output format (text/json/jsonl/csv) | `text` |
| `--output`, `-o` | Output file path | stdout |
| `--min-confidence` | Minimum confidence threshold | `0.7` |
| `--include` | Include file patterns (glob) | `*` |
| `--exclude` | Exclude file patterns (glob) | None |
| `--max-files` | Maximum files to scan | None |
| `--no-ocr` | Disable OCR | `false` |
| `--workers` | Number of parallel workers | CPU count |
| `--no-progress` | Disable progress bar | `false` |

### find Command

```bash
openlabels find <path> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--filter`, `-f` | Filter expression | None |
| `--min-score` | Minimum risk score | None |
| `--max-score` | Maximum risk score | None |
| `--tier` | Filter by tier | None |
| `--entity` | Filter by entity type | None |
| `--limit`, `-n` | Maximum results | None |
| `--format` | Output format | `table` |
| `--count` | Only show count | `false` |

### quarantine Command

```bash
openlabels quarantine <path> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--destination`, `-d` | Quarantine directory | `~/.openlabels/quarantine` |
| `--min-score` | Minimum score to quarantine | `80` |
| `--tier` | Tier to quarantine | None |
| `--dry-run` | Preview without moving | `false` |
| `--force`, `-y` | Skip confirmation | `false` |
| `--recursive`, `-r` | Process recursively | `false` |

### report Command

```bash
openlabels report <path> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format`, `-f` | Output format (text/json/html/csv/md) | `text` |
| `--output`, `-o` | Output file path | stdout |
| `--title` | Report title | Auto-generated |
| `--include-files` | Include file list in report | `true` |
| `--limit` | Max files to include | `100` |

### health Command

```bash
openlabels health [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output as JSON | `false` |
| `--check` | Run specific check | All |
| `--verbose`, `-v` | Show detailed info | `false` |

## Configuration File

Create `~/.openlabels/config.yaml` for persistent configuration:

```yaml
# ~/.openlabels/config.yaml

# Logging
logging:
  level: INFO
  format: json
  file: /var/log/openlabels/openlabels.log

# Storage
storage:
  index_path: ~/.openlabels/index.db
  quarantine_dir: ~/.openlabels/quarantine
  temp_dir: /tmp/openlabels

# Scanning defaults
scanning:
  default_exposure: PRIVATE
  min_confidence: 0.7
  enable_ocr: true
  max_file_size: 100MB
  worker_count: 4
  timeout: 300

# Detection
detection:
  detector_timeout: 30
  strict_mode: false

# Patterns to always exclude
exclude_patterns:
  - "*.pyc"
  - "__pycache__"
  - ".git"
  - "node_modules"
  - ".DS_Store"

# Entity types to ignore
ignore_entities:
  - EMAIL  # Too many false positives
```

## Precedence

Configuration is applied in the following order (later overrides earlier):

1. Built-in defaults
2. Configuration file (`~/.openlabels/config.yaml`)
3. Environment variables
4. CLI flags

## Size Strings

Size values can be specified with units:

| Unit | Example | Bytes |
|------|---------|-------|
| B | `100B` | 100 |
| KB | `10KB` | 10,240 |
| MB | `100MB` | 104,857,600 |
| GB | `1GB` | 1,073,741,824 |

## Exposure Levels

| Level | Description | Risk Multiplier |
|-------|-------------|-----------------|
| `PUBLIC` | Publicly accessible | 2.0x |
| `ORG_WIDE` | Accessible to entire organization | 1.5x |
| `INTERNAL` | Internal team access | 1.2x |
| `PRIVATE` | Private/restricted access | 1.0x |

## Risk Tiers

| Tier | Score Range | Description |
|------|-------------|-------------|
| `CRITICAL` | 90-100 | Immediate action required |
| `HIGH` | 70-89 | High priority remediation |
| `MEDIUM` | 40-69 | Standard remediation |
| `LOW` | 20-39 | Low priority |
| `MINIMAL` | 0-19 | Acceptable risk |
