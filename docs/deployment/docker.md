# Docker Deployment Guide

Deploy OpenLabels using Docker for consistent, reproducible environments.

## Quick Start

```bash
# Build the image
docker build -t openlabels:latest .

# Run a scan
docker run --rm -v /path/to/data:/data openlabels scan /data

# Run interactively
docker run -it --rm -v /path/to/data:/data openlabels shell
```

## Dockerfile

Create a `Dockerfile` in your project root:

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash openlabels
WORKDIR /home/openlabels

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install openlabels
COPY . /opt/openlabels
RUN pip install --no-cache-dir /opt/openlabels

# Switch to non-root user
USER openlabels

# Default command
ENTRYPOINT ["openlabels"]
CMD ["--help"]
```

## Docker Compose

For persistent storage and configuration:

```yaml
# docker-compose.yml
version: '3.8'

services:
  openlabels:
    build: .
    image: openlabels:latest
    volumes:
      # Data to scan
      - ./data:/data:ro
      # Persistent index database
      - openlabels-index:/home/openlabels/.openlabels
      # Quarantine directory
      - ./quarantine:/quarantine
      # Logs
      - ./logs:/var/log/openlabels
    environment:
      - OPENLABELS_LOG_LEVEL=INFO
      - OPENLABELS_LOG_FILE=/var/log/openlabels/openlabels.log
      - OPENLABELS_DEFAULT_EXPOSURE=PRIVATE

volumes:
  openlabels-index:
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENLABELS_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | INFO |
| `OPENLABELS_LOG_FILE` | Log file path | None (stdout) |
| `OPENLABELS_LOG_FORMAT` | Log format (json, text) | text |
| `OPENLABELS_DEFAULT_EXPOSURE` | Default exposure level | PRIVATE |
| `OPENLABELS_INDEX_PATH` | SQLite index database path | ~/.openlabels/index.db |
| `OPENLABELS_QUARANTINE_DIR` | Default quarantine directory | ~/.openlabels/quarantine |

## Volume Mounts

| Mount Point | Purpose | Mode |
|-------------|---------|------|
| `/data` | Data to scan | Read-only (`:ro`) |
| `/home/openlabels/.openlabels` | Index database | Read-write |
| `/quarantine` | Quarantined files | Read-write |
| `/var/log/openlabels` | Log files | Read-write |

## Security Considerations

1. **Run as non-root**: The container runs as the `openlabels` user
2. **Read-only data**: Mount data volumes as read-only when possible
3. **No network**: Add `--network=none` for offline scanning
4. **Resource limits**: Set memory/CPU limits to prevent runaway processes

```bash
docker run --rm \
  --network=none \
  --memory=2g \
  --cpus=2 \
  -v /data:/data:ro \
  openlabels scan /data
```

## CI/CD Integration

### GitHub Actions

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build OpenLabels image
        run: docker build -t openlabels:latest .

      - name: Scan repository
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/data:ro \
            openlabels scan /data --format json > scan-results.json

      - name: Check for critical findings
        run: |
          if jq -e '.summary.critical_count > 0' scan-results.json; then
            echo "Critical findings detected!"
            exit 1
          fi
```

### GitLab CI

```yaml
scan:
  image: openlabels:latest
  script:
    - openlabels scan . --format json > scan-results.json
    - openlabels report . --format markdown > SECURITY_REPORT.md
  artifacts:
    reports:
      security: scan-results.json
```

## Troubleshooting

### Permission denied errors

Ensure the container user can read the mounted volumes:

```bash
# Check file permissions
ls -la /path/to/data

# Run with specific user ID if needed
docker run --user $(id -u):$(id -g) -v /data:/data openlabels scan /data
```

### Out of memory

Large files or directories may require more memory:

```bash
docker run --memory=4g openlabels scan /large-dataset
```

### Slow scans

Enable parallel processing and disable OCR for faster scans:

```bash
docker run openlabels scan /data --no-ocr --workers 4
```
