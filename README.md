# OpenLabels

Enterprise sensitivity labeling and PII detection for Microsoft 365 environments.

## Overview

OpenLabels scans SharePoint, OneDrive, and file shares to detect sensitive data and automatically apply Microsoft Information Protection (MIP) sensitivity labels.

**Key Features:**
- Detect 50+ PII/PHI entity types (SSN, credit cards, health records, secrets, etc.)
- Integrate with Microsoft Purview sensitivity labels
- Scan SharePoint Online, OneDrive for Business, and Windows file shares
- Risk scoring (0-100) with tier-based label recommendations
- Real-time WebSocket progress updates
- OCR for scanned documents and images

## Architecture

```
┌───────────────────────────────────────────────────┐
│  Docker                                           │
│  - FastAPI server (REST API + WebSocket)          │
│  - PostgreSQL database                            │
│  - Detection engine                               │
│  - React frontend (Vite)                          │
└───────────────────────────────────────────────────┘
```

## Quick Start

### Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Start server (development)
uvicorn openlabels.server.app:app --reload
```

### Production (Docker)

```bash
docker-compose up -d
```

## Configuration

Set environment variables or create `config.yaml`:

```yaml
auth:
  provider: azure_ad
  tenant_id: "your-tenant-id"
  client_id: "your-client-id"
  client_secret: "your-secret"

database:
  url: "postgresql+asyncpg://localhost/openlabels"

adapters:
  sharepoint:
    enabled: true
  onedrive:
    enabled: true
  filesystem:
    enabled: true
```

## Azure AD Setup

Required API permissions (Application type):
- `Sites.Read.All` - Read SharePoint sites
- `Files.Read.All` - Read files
- `User.Read.All` - Read user profiles
- `InformationProtectionPolicy.Read.All` - Read sensitivity labels

For labeling:
- `Sites.ReadWrite.All` - Write to SharePoint
- `Files.ReadWrite.All` - Write files

## Documentation

- [Production Readiness Plan](./docs/PRODUCTION_PLAN.md)
- [Server Architecture](./docs/openlabels-server-architecture-v1.md)
- [Audit Report](./docs/AUDIT_REPORT.md)

## License

MIT — see [LICENSE](./LICENSE) for details.
