# OpenRisk Remediation Phases

Quick reference for working through fixes with Claude.

---

## Phase 1: CRITICAL (Production Blockers)

**Goal:** Make the application deployable to production.

**Work Items:**
1. Replace all 301 `print()` statements with structured logging
2. Add centralized logging configuration with log levels and file output
3. Create health check endpoint for Kubernetes/load balancer probes
4. Implement graceful shutdown with SIGTERM/SIGINT handling
5. Fix remaining database pagination issues in export paths

**Key Files:**
- `openlabels/cli/commands/*.py` (12 files with prints)
- `openlabels/cli/main.py`
- `openlabels/context.py`
- `openlabels/output/index.py`
- NEW: `openlabels/health.py`, `openlabels/logging.py`

**To start:** Tell Claude: *"Work on Phase 1 from REMEDIATION_PHASES.md"*

---

## Phase 2: HIGH (GA Release Blockers)

**Goal:** Production-quality error handling, testing, and documentation.

**Work Items:**
1. Replace boolean returns with structured Result objects
2. Propagate detector failures to callers (don't silently degrade)
3. Implement database connection pooling
4. Add scanner detector unit tests
5. Add CLI command integration tests
6. Create deployment documentation (Docker, K8s, systemd, env vars)

**Key Files:**
- `openlabels/components/fileops.py`
- `openlabels/components/scanner.py`
- `openlabels/adapters/scanner/detectors/orchestrator.py`
- `openlabels/output/index.py`
- NEW: `tests/test_scanner/*.py`, `tests/test_cli/*.py`
- NEW: `docs/deployment/*.md`

**To start:** Tell Claude: *"Work on Phase 2 from REMEDIATION_PHASES.md"*

---

## Phase 3: MEDIUM (Code Quality)

**Goal:** Clean up AI slop, reduce technical debt.

**Work Items:**
1. Split `registry.py` (1,054 lines) into entities, weights, vendors modules
2. Split `orchestrator.py` (1,064 lines) into threading and detection modules
3. Split `definitions.py` (1,067 lines) by pattern domain
4. Extract duplicate `_add()`/`detect()` code from 3 detector files into base class
5. Define confidence tier constants (replace magic numbers 0.85, 0.90, 0.98)
6. Split `embed.py` (459 lines) by format (PDF, Office, Image)

**Key Files:**
- `openlabels/core/registry.py`
- `openlabels/adapters/scanner/detectors/orchestrator.py`
- `openlabels/adapters/scanner/detectors/patterns/definitions.py`
- `openlabels/adapters/scanner/detectors/government.py`
- `openlabels/adapters/scanner/detectors/secrets.py`
- `openlabels/adapters/scanner/detectors/additional_patterns.py`
- `openlabels/output/embed.py`

**To start:** Tell Claude: *"Work on Phase 3 from REMEDIATION_PHASES.md"*

---

## Quick Commands

| Command | What it does |
|---------|--------------|
| *"Work on Phase 1"* | Tackle all critical production blockers |
| *"Work on Phase 2"* | Tackle GA release blockers |
| *"Work on Phase 3"* | Clean up code quality issues |
| *"Work on Chunk 1.3"* | Tackle one specific item (see REMEDIATION_CHUNKS.md) |

---

## Status Tracking

Update this section as you complete phases:

- [ ] Phase 1: CRITICAL
- [ ] Phase 2: HIGH
- [ ] Phase 3: MEDIUM

---

## Reference Documents

| Document | Purpose |
|----------|---------|
| `COMPREHENSIVE_AUDIT_REPORT.md` | Full audit findings with details |
| `REMEDIATION_CHUNKS.md` | Granular 18-chunk breakdown |
| `REMEDIATION_PHASES.md` | This file - phase-level overview |
