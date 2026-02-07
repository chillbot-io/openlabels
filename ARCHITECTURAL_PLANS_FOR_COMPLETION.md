# Architectural Plans for Completion

**Goal:** Get every module to **Best (3/3)** quality rating.
**Reference:** See `MODULE_QUALITY_REVIEW.md` for current ratings and findings.

Each section below is a self-contained implementation plan with exact files, code examples, and complexity estimates. These are designed to be picked up by a Claude agent and executed module-by-module. **All changes should be clean refactors — no backwards-compatibility shims, no deprecated fallbacks, no "keep old imports working" hacks. Do it the right way.**

---

## Table of Contents

1. [Core Detection Engine](#1-core-detection-engine) (2→3)
2. [Server](#2-server) (2→3)
3. [Adapters](#3-adapters) (2→3)
4. [Auth](#4-auth) (2→3)
5. [CLI](#5-cli) (1→3)
6. [GUI](#6-gui) (1→3)
7. [Jobs](#7-jobs) (maintain 3)
8. [Labeling](#8-labeling) (2→3)
9. [Remediation](#9-remediation) (2→3)
10. [Monitoring](#10-monitoring) (2→3)
11. [Web](#11-web) (0→3, deferred)
12. [Windows](#12-windows) (1→3)
13. [Client](#13-client) (1→3)
14. [Cross-Cutting Concerns](#14-cross-cutting-concerns)

---

## 1. Core Detection Engine

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/core/`

### 1.1 Configuration-Driven Detector Setup

**Complexity:** M
**Files to modify:** `core/detectors/orchestrator.py`

**Current state:** The orchestrator already uses boolean flags (`enable_checksum`, `enable_secrets`, `enable_hyperscan`, `enable_ml`, etc.) to conditionally construct detectors. This is explicit and functional, but the flags are spread across 15+ constructor parameters which is unwieldy.

**Plan:**

Replace the long parameter list with a single typed `DetectionConfig` dataclass. Keep the selective enable/disable capability — it's valuable for CLI vs. server vs. test scenarios — but consolidate the knobs into one config object:

```python
# core/detectors/config.py
"""Detection configuration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class DetectionConfig:
    """Configuration for the detection pipeline.

    Use class methods for common presets:
        config = DetectionConfig.full()       # Everything enabled
        config = DetectionConfig.patterns()   # Patterns only, no ML
        config = DetectionConfig.quick()      # Fast detectors only
    """
    # Pattern detectors
    enable_checksum: bool = True
    enable_secrets: bool = True
    enable_financial: bool = True
    enable_government: bool = True
    enable_patterns: bool = True

    # Accelerated detection
    enable_hyperscan: bool = False

    # ML detectors
    enable_ml: bool = False
    ml_model_dir: Optional[Path] = None
    use_onnx: bool = True

    # Post-processing
    enable_coref: bool = False
    enable_context_enhancement: bool = False
    enable_policy: bool = False

    # Tuning
    confidence_threshold: float = 0.70
    max_workers: int = 4

    @classmethod
    def full(cls) -> "DetectionConfig":
        return cls(enable_hyperscan=True, enable_ml=True,
                   enable_coref=True, enable_context_enhancement=True)

    @classmethod
    def patterns_only(cls) -> "DetectionConfig":
        return cls()

    @classmethod
    def quick(cls) -> "DetectionConfig":
        return cls(enable_ml=False, enable_coref=False,
                   enable_context_enhancement=False)
```

Update orchestrator:
```python
class DetectorOrchestrator:
    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self.detectors: list[BaseDetector] = []
        # ... same conditional init logic, reading from self.config
```

**Refactor scope:** Extract the 15+ constructor params into `DetectionConfig`. Update all callers (server startup, CLI, tests) to pass a config object. The orchestrator constructor becomes a single parameter.

### 1.2 Immutable Pattern Definitions

**Complexity:** M
**Files to modify:** `core/detectors/government.py`, `core/detectors/secrets.py`, `core/detectors/additional_patterns.py`
**Files to create:** `core/detectors/pattern_registry.py`

**Current state:** Patterns are defined via module-level `_add()` calls that mutate a global list at import time. This is fragile — creating two instances doubles entries, test isolation is impossible, and the mutation order is implicit.

**Plan:**

Replace mutable global lists with frozen dataclasses. No YAML files, no runtime file I/O, no new dependencies. Patterns stay in Python where they're testable, debuggable, and have zero overhead.

Create `core/detectors/pattern_registry.py`:
```python
"""Immutable pattern definitions for all detectors."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternDefinition:
    """Immutable, hashable pattern definition."""
    pattern: re.Pattern
    entity_type: str
    confidence: float
    group: int = 0


def _p(regex: str, entity_type: str, confidence: float,
       group: int = 0, flags: int = re.IGNORECASE) -> PatternDefinition:
    """Shorthand for defining a pattern."""
    return PatternDefinition(
        pattern=re.compile(regex, flags),
        entity_type=entity_type,
        confidence=confidence,
        group=group,
    )


# --- Government patterns ---
GOVERNMENT_PATTERNS: tuple[PatternDefinition, ...] = (
    _p(r'\b(TOP\s*SECRET)\b', 'CLASSIFICATION_LEVEL', 0.98, group=1),
    _p(r'\b(SECRET)\b(?!\s*(?:santa|garden|service|recipe|ingredient|weapon|sauce))',
       'CLASSIFICATION_LEVEL', 0.85, group=1),
    # ... all government patterns
)

# --- Secrets patterns ---
SECRETS_PATTERNS: tuple[PatternDefinition, ...] = (
    # ... all secrets patterns
)

# --- Financial patterns ---
FINANCIAL_PATTERNS: tuple[PatternDefinition, ...] = (
    # ... all financial patterns
)
```

Modify detectors to use the registry:
```python
class GovernmentDetector(BaseDetector):
    name = "government"
    tier = Tier.PATTERN

    def __init__(self):
        self._patterns = GOVERNMENT_PATTERNS  # Immutable tuple, shared across instances

    def detect(self, text: str) -> List[Span]:
        spans = []
        for pdef in self._patterns:
            for match in pdef.pattern.finditer(text):
                # ... same logic but using pdef.entity_type, pdef.confidence, etc.
```

**Why not YAML:** Patterns rarely change independently of code. When you modify a regex, you need to test it, which means a code change anyway. YAML adds runtime file I/O, a PyYAML dependency, a new failure mode (missing/malformed files), and makes patterns harder to debug (no breakpoints in YAML). Frozen dataclasses in Python give you immutability, zero I/O overhead, and full IDE support.

**Refactor scope:** Extract all `_add()` calls and mutable global lists into `pattern_registry.py` as frozen tuples. Delete the module-level mutation helpers. Each detector reads from a shared immutable tuple.

### 1.3 Async Detection Support

**Complexity:** M
**Files to modify:** `core/detectors/base.py`, `core/detectors/orchestrator.py`, `core/detectors/ml_onnx.py`

**Current state:** `BaseDetector.detect()` is synchronous. ML/ONNX detectors block the event loop when called from async server code.

**Plan:**

All detectors implement `detect()` synchronously — that's fine, the detection logic itself is CPU-bound. The orchestrator's job is to run them without blocking the event loop. Simple approach: orchestrator runs all detectors in a thread pool executor.

```python
# core/detectors/base.py
from abc import ABC, abstractmethod
from typing import List

class BaseDetector(ABC):
    name: str = "base"
    tier: Tier = Tier.PATTERN

    @abstractmethod
    def detect(self, text: str) -> List[Span]:
        """Detect entities in text. Always synchronous."""
        pass

    def is_available(self) -> bool:
        return True
```

No `adetect()`, no `is_async` flag. Detectors stay simple. The orchestrator handles async:

```python
# core/detectors/orchestrator.py
import asyncio
from concurrent.futures import ThreadPoolExecutor

class DetectorOrchestrator:
    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.max_workers, thread_name_prefix="detector"
        )

    async def detect(self, text: str) -> DetectionResult:
        """Run all detectors concurrently in thread pool."""
        loop = asyncio.get_running_loop()

        tasks = [
            loop.run_in_executor(self._executor, detector.detect, text)
            for detector in self.detectors
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_spans = []
        for detector, result in zip(self.detectors, results):
            if isinstance(result, Exception):
                logger.warning(f"Detector {detector.name} failed: {result}")
                continue
            all_spans.extend(result)

        return DetectionResult(spans=all_spans)

    def detect_sync(self, text: str) -> DetectionResult:
        """Synchronous detection for CLI/non-async contexts."""
        all_spans = []
        for detector in self.detectors:
            try:
                all_spans.extend(detector.detect(text))
            except Exception as e:
                logger.warning(f"Detector {detector.name} failed: {e}")
        return DetectionResult(spans=all_spans)
```

**Refactor scope:** The orchestrator gets two methods: `detect()` (async, for server/jobs) and `detect_sync()` (for CLI). All server and job code uses `detect()`. All CLI code uses `detect_sync()`. Remove the module-level `detect()` convenience function if it bypasses the orchestrator — everything should go through the orchestrator.

### 1.4 Confidence Calibration

**Complexity:** S
**Files to create:** `core/pipeline/confidence.py`
**Files to modify:** `core/pipeline/__init__.py`

**Plan:**

```python
# core/pipeline/confidence.py
"""Post-processing confidence calibration across detectors."""

from dataclasses import dataclass
from typing import Dict, List
from ..types import Span, Tier


# Calibration weights by tier - higher tiers get a confidence boost
TIER_CALIBRATION: Dict[Tier, float] = {
    Tier.CHECKSUM: 1.0,     # Already highest confidence
    Tier.STRUCTURED: 0.95,  # Very reliable
    Tier.PATTERN: 0.85,     # Good but can have false positives
    Tier.ML: 0.80,          # Depends on model quality
}

# Per-detector calibration offsets (learned from validation data)
DETECTOR_CALIBRATION: Dict[str, float] = {
    # Positive = detector tends to under-report confidence
    # Negative = detector tends to over-report confidence
    # Default: 0.0 (no adjustment)
}


@dataclass
class CalibrationConfig:
    """Configuration for confidence calibration."""
    apply_tier_weight: bool = True
    apply_detector_offset: bool = True
    min_confidence: float = 0.0
    max_confidence: float = 1.0


def calibrate_confidence(
    spans: List[Span],
    config: CalibrationConfig | None = None,
) -> List[Span]:
    """
    Normalize confidence scores across detectors to be comparable.

    Steps:
    1. Apply tier-based weighting (checksum > structured > pattern > ml)
    2. Apply per-detector calibration offsets (if configured)
    3. Clamp to [min_confidence, max_confidence]

    Returns new Span objects with calibrated confidence (original spans unchanged).
    """
    config = config or CalibrationConfig()
    calibrated = []

    for span in spans:
        confidence = span.confidence

        if config.apply_tier_weight:
            tier_weight = TIER_CALIBRATION.get(span.tier, 0.85)
            confidence = confidence * tier_weight

        if config.apply_detector_offset:
            offset = DETECTOR_CALIBRATION.get(span.detector, 0.0)
            confidence = confidence + offset

        # Clamp
        confidence = max(config.min_confidence, min(config.max_confidence, confidence))

        calibrated.append(Span(
            start=span.start,
            end=span.end,
            text=span.text,
            entity_type=span.entity_type,
            confidence=round(confidence, 4),
            detector=span.detector,
            tier=span.tier,
            context=span.context,  # Preserve SpanContext from Section 1.6
        ))

    return calibrated
```

### 1.5 Explicit Span Overlap Resolution

**Complexity:** M
**Files to create:** `core/pipeline/span_resolver.py`
**Files to modify:** `core/pipeline/__init__.py`

**Plan:**

```python
# core/pipeline/span_resolver.py
"""Resolve overlapping spans from multiple detectors."""

from enum import Enum
from typing import List
from ..types import Span, Tier


class ResolutionStrategy(str, Enum):
    PREFER_HIGHER_TIER = "prefer_higher_tier"
    PREFER_HIGHER_CONFIDENCE = "prefer_higher_confidence"
    PREFER_LONGER = "prefer_longer"
    MERGE = "merge"


# Tier ordering for comparison
_TIER_RANK = {
    Tier.CHECKSUM: 4,
    Tier.STRUCTURED: 3,
    Tier.PATTERN: 2,
    Tier.ML: 1,
}


def _spans_overlap(a: Span, b: Span) -> bool:
    """Check if two spans overlap."""
    return a.start < b.end and b.start < a.end


def _pick_winner(a: Span, b: Span, strategy: ResolutionStrategy) -> Span:
    """Pick the winning span from two overlapping spans."""
    if strategy == ResolutionStrategy.PREFER_HIGHER_TIER:
        rank_a = _TIER_RANK.get(a.tier, 0)
        rank_b = _TIER_RANK.get(b.tier, 0)
        if rank_a != rank_b:
            return a if rank_a > rank_b else b
        # Tie-break: higher confidence
        return a if a.confidence >= b.confidence else b

    elif strategy == ResolutionStrategy.PREFER_HIGHER_CONFIDENCE:
        if a.confidence != b.confidence:
            return a if a.confidence > b.confidence else b
        # Tie-break: higher tier
        return a if _TIER_RANK.get(a.tier, 0) >= _TIER_RANK.get(b.tier, 0) else b

    elif strategy == ResolutionStrategy.PREFER_LONGER:
        len_a = a.end - a.start
        len_b = b.end - b.start
        return a if len_a >= len_b else b

    return a  # Default


def resolve_overlaps(
    spans: List[Span],
    strategy: ResolutionStrategy = ResolutionStrategy.PREFER_HIGHER_TIER,
) -> List[Span]:
    """
    Resolve overlapping spans using the specified strategy.

    Algorithm:
    1. Sort spans by start position
    2. For each span, check if it overlaps with the current winner
    3. If overlap, pick the winner based on strategy
    4. If no overlap, emit the current winner and start a new group

    Args:
        spans: List of potentially overlapping spans
        strategy: Resolution strategy to use

    Returns:
        List of non-overlapping spans
    """
    if not spans:
        return []

    if strategy == ResolutionStrategy.MERGE:
        return _merge_overlaps(spans)

    # Sort by start position, then by tier rank descending
    sorted_spans = sorted(spans, key=lambda s: (s.start, -_TIER_RANK.get(s.tier, 0)))

    resolved = []
    current = sorted_spans[0]

    for span in sorted_spans[1:]:
        if _spans_overlap(current, span):
            current = _pick_winner(current, span, strategy)
        else:
            resolved.append(current)
            current = span

    resolved.append(current)
    return resolved


def _merge_overlaps(spans: List[Span]) -> List[Span]:
    """Merge overlapping spans into combined spans."""
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda s: s.start)
    merged = [sorted_spans[0]]

    for span in sorted_spans[1:]:
        prev = merged[-1]
        if _spans_overlap(prev, span):
            # Merge: extend the span, keep higher confidence/tier
            best = _pick_winner(prev, span, ResolutionStrategy.PREFER_HIGHER_TIER)
            merged[-1] = Span(
                start=min(prev.start, span.start),
                end=max(prev.end, span.end),
                text=best.text,  # Keep the winning text
                entity_type=best.entity_type,
                confidence=max(prev.confidence, span.confidence),
                detector=best.detector,
                tier=best.tier,
                context=best.context,  # Preserve SpanContext from Section 1.6
            )
        else:
            merged.append(span)

    return merged
```

### 1.6 Structured Result Metadata

**Complexity:** S
**Files to modify:** `core/types.py`

**Plan:**

Extend the `Span` dataclass:
```python
# Add to core/types.py

@dataclass
class SpanContext:
    """Contextual metadata about where a span was detected."""
    source_page: int | None = None          # PDF/DOCX page number
    source_sheet: str | None = None         # Excel sheet name
    source_section: str | None = None       # Document section heading
    source_cell: str | None = None          # Excel cell reference (e.g., "B12")
    surrounding_text: str | None = None     # ~50 chars before/after for context
    extraction_method: str | None = None    # "text", "ocr", "metadata", "embedded"


# Modify Span to include optional context
@dataclass
class Span:
    start: int
    end: int
    text: str
    entity_type: str
    confidence: float
    detector: str = ""
    tier: Tier = Tier.PATTERN
    context: SpanContext | None = None  # NEW: extraction context
```

**Refactor scope:** Add `context: SpanContext | None = None` to `Span`. Update all extractors to populate `SpanContext` with whatever context they have available (page number, sheet name, etc.). Detectors that don't have context info can leave it as `None` — but extractors should always fill it in.

---

## 2. Server

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/server/`

### 2.1 Service Layer Dependency Injection

**Complexity:** M
**Files to create:** `server/dependencies/services.py`
**Files to modify:** `server/dependencies.py`, all route files in `server/routes/`

**Plan:**

Create service provider dependencies:
```python
# server/dependencies/services.py
"""FastAPI dependency providers for service layer."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.config import get_settings, Settings
from openlabels.server.services import (
    BaseService, TenantContext, ScanService, LabelService,
    JobService, ResultService,
)
from openlabels.auth.dependencies import get_current_user, CurrentUser


async def get_tenant_context(
    user: CurrentUser = Depends(get_current_user),
) -> TenantContext:
    """Extract tenant context from authenticated user."""
    return TenantContext.from_current_user(user)


async def get_scan_service(
    session: AsyncSession = Depends(get_session),
    tenant: TenantContext = Depends(get_tenant_context),
    settings: Settings = Depends(get_settings),
) -> ScanService:
    return ScanService(session, tenant, settings)


async def get_label_service(
    session: AsyncSession = Depends(get_session),
    tenant: TenantContext = Depends(get_tenant_context),
    settings: Settings = Depends(get_settings),
) -> LabelService:
    return LabelService(session, tenant, settings)


async def get_job_service(
    session: AsyncSession = Depends(get_session),
    tenant: TenantContext = Depends(get_tenant_context),
    settings: Settings = Depends(get_settings),
) -> JobService:
    return JobService(session, tenant, settings)


async def get_result_service(
    session: AsyncSession = Depends(get_session),
    tenant: TenantContext = Depends(get_tenant_context),
    settings: Settings = Depends(get_settings),
) -> ResultService:
    return ResultService(session, tenant, settings)
```

Update route handlers (example):
```python
# server/routes/scans.py - BEFORE
@router.post("/")
async def create_scan(
    body: CreateScanRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
):
    tenant = TenantContext.from_current_user(user)
    service = ScanService(session, tenant, get_settings())
    return await service.create_scan(body.target_id, body.name)

# server/routes/scans.py - AFTER
@router.post("/")
async def create_scan(
    body: CreateScanRequest,
    service: ScanService = Depends(get_scan_service),
):
    return await service.create_scan(body.target_id, body.name)
```

### 2.2 Response Schema Declarations

**Complexity:** M
**Files to create:** `server/schemas/scans.py`, `server/schemas/results.py`, `server/schemas/targets.py`, `server/schemas/labels.py`, `server/schemas/jobs.py`, `server/schemas/dashboard.py`, `server/schemas/health.py`, `server/schemas/users.py`
**Files to modify:** All route files in `server/routes/`

**Plan:**

Create response schemas per domain (example for scans):
```python
# server/schemas/scans.py
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field


class ScanJobResponse(BaseModel):
    id: UUID
    name: str
    status: str
    target_id: UUID
    target_name: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    files_scanned: int = 0
    files_matched: int = 0
    error: Optional[str] = None

    class Config:
        from_attributes = True


class ScanJobListResponse(BaseModel):
    """Cursor-paginated list of scans. Consistent with Section 2.4."""
    items: list[ScanJobResponse]
    next_cursor: Optional[str] = None
    has_more: bool = False


class CreateScanRequest(BaseModel):
    target_id: UUID
    name: Optional[str] = Field(None, max_length=255)
```

Add `response_model` to every endpoint:
```python
@router.get("/", response_model=ScanJobListResponse)
async def list_scans(...): ...

@router.post("/", response_model=ScanJobResponse, status_code=201)
async def create_scan(...): ...

@router.get("/{scan_id}", response_model=ScanJobResponse)
async def get_scan(...): ...
```

### 2.3 Split app.py

**Complexity:** M
**Files to create:** `server/factory.py`, `server/error_handlers.py`, `server/lifespan.py`
**Files to modify:** `server/app.py`, `server/middleware/__init__.py`

**Plan:**

Split into four focused files:

```python
# server/lifespan.py
"""Application startup and shutdown lifecycle."""
from contextlib import asynccontextmanager
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_database()
    await start_scheduler()
    await populate_monitoring_cache()
    yield
    # Shutdown
    await stop_scheduler()
    await close_database()
```

```python
# server/error_handlers.py
"""Global exception handlers."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from .schemas.error import ErrorResponse
from openlabels.exceptions import NotFoundError, ConflictError, AuthError

def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotFoundError)
    async def not_found_handler(request: Request, exc: NotFoundError):
        return JSONResponse(status_code=404, content=ErrorResponse(...).model_dump())

    @app.exception_handler(ConflictError)
    async def conflict_handler(request: Request, exc: ConflictError):
        return JSONResponse(status_code=409, content=ErrorResponse(...).model_dump())
    # ... etc
```

```python
# server/middleware/__init__.py - register_middleware function
def register_middleware(app: FastAPI, settings: Settings) -> None:
    """Register all middleware in correct order."""
    app.add_middleware(CORSMiddleware, ...)
    app.add_middleware(CSRFMiddleware, ...)
    app.add_middleware(RateLimitMiddleware, ...)
    # ... security headers, request tracing, etc.
```

```python
# server/app.py - becomes thin factory
"""FastAPI application factory."""
from fastapi import FastAPI
from .lifespan import lifespan
from .middleware import register_middleware
from .error_handlers import register_error_handlers
from .routes.v1 import router as v1_router
from .config import get_settings

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="OpenLabels",
        version=settings.version,
        lifespan=lifespan,
    )
    register_middleware(app, settings)
    register_error_handlers(app)
    app.include_router(v1_router, prefix="/api/v1")
    return app

app = create_app()
```

### 2.4 Cursor-Based Pagination

**Complexity:** M
**Files to modify:** `server/schemas/pagination.py`, `server/pagination.py`
**Files to modify:** Route files that use pagination

**Plan:** Replace offset-based pagination with cursor-based. Offset pagination breaks on large datasets with concurrent writes and gets slower as offset increases. Remove the old offset approach entirely.

**Existing code:** `server/pagination.py` already has `CursorPaginationParams`, `CursorData`, `PaginatedResponse`, `CursorPaginatedResponse`, `encode_cursor()`, and `decode_cursor()`. The existing implementation uses composite `(id, timestamp)` cursors encoded as base64 JSON. Build on this — do not introduce a second cursor format.

What's missing from the existing module: a reusable query helper. Add `apply_cursor_pagination`:

```python
# server/pagination.py — add this function to the existing module
from sqlalchemy.ext.asyncio import AsyncSession

async def apply_cursor_pagination(
    session: AsyncSession,
    query,
    model_class,
    params: CursorPaginationParams,
    timestamp_column=None,
) -> CursorPaginatedResponse:
    """Apply cursor-based pagination to a SQLAlchemy query.

    Uses the existing (id, timestamp) composite cursor format.
    Fetches limit+1 rows to detect has_more.
    """
    ts_col = timestamp_column or model_class.created_at
    id_col = model_class.id

    # Decode cursor and apply WHERE clause
    cursor_data = params.decode()
    if cursor_data:
        # Keyset pagination: WHERE (ts, id) < (cursor_ts, cursor_id)
        query = query.where(
            (ts_col < cursor_data.timestamp) |
            ((ts_col == cursor_data.timestamp) & (id_col < cursor_data.id))
        )

    # Order by timestamp desc, then id desc (most recent first)
    query = query.order_by(ts_col.desc(), id_col.desc())
    query = query.limit(params.limit + 1)

    result = await session.execute(query)
    items = list(result.scalars().all())

    has_more = len(items) > params.limit
    if has_more:
        items = items[:params.limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.id, getattr(last, ts_col.key))

    return CursorPaginatedResponse(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )
```

**Refactor scope:** Add `apply_cursor_pagination` to the existing `server/pagination.py`. Migrate all API list endpoints from offset to cursor pagination in one pass. The web results list already uses cursor pagination — extend that pattern to all list endpoints (scans, targets, labels, schedules, audit logs). Remove offset pagination (`PaginationParams` with `page`/`limit`) entirely.

### 2.5 Per-Tenant Rate Limiting

**Complexity:** S
**Files to modify:** `server/middleware/rate_limit.py` (or wherever rate limiting is configured)

**Plan:**

```python
# server/middleware/rate_limit.py
"""Per-tenant rate limiting middleware."""

import time
from collections import defaultdict
from fastapi import Request, HTTPException


class TenantRateLimiter:
    """Rate limiter that tracks per-tenant request counts."""

    def __init__(
        self,
        requests_per_minute: int = 300,
        requests_per_hour: int = 10000,
    ):
        self.rpm_limit = requests_per_minute
        self.rph_limit = requests_per_hour
        self._minute_counts: dict[str, list[float]] = defaultdict(list)
        self._hour_counts: dict[str, list[float]] = defaultdict(list)

    def check_rate_limit(self, tenant_id: str) -> None:
        """Check if tenant has exceeded rate limits."""
        now = time.monotonic()

        # Clean old entries and check per-minute
        minute_ago = now - 60
        self._minute_counts[tenant_id] = [
            t for t in self._minute_counts[tenant_id] if t > minute_ago
        ]
        if len(self._minute_counts[tenant_id]) >= self.rpm_limit:
            raise HTTPException(
                429,
                detail=f"Rate limit exceeded: {self.rpm_limit} requests/minute",
                headers={"Retry-After": "60"},
            )

        # Check per-hour
        hour_ago = now - 3600
        self._hour_counts[tenant_id] = [
            t for t in self._hour_counts[tenant_id] if t > hour_ago
        ]
        if len(self._hour_counts[tenant_id]) >= self.rph_limit:
            raise HTTPException(
                429,
                detail=f"Rate limit exceeded: {self.rph_limit} requests/hour",
                headers={"Retry-After": "3600"},
            )

        # Record this request
        self._minute_counts[tenant_id].append(now)
        self._hour_counts[tenant_id].append(now)
```

The app already has optional Redis support (`server/cache.py`). Use a backend interface:

```python
from abc import ABC, abstractmethod

class RateLimitBackend(ABC):
    @abstractmethod
    async def check_and_increment(self, key: str, limit: int, window_seconds: int) -> bool:
        """Return True if under limit (and increment counter), False if exceeded."""
        ...

class InMemoryRateLimitBackend(RateLimitBackend):
    """For single-instance deployments. Uses the TenantRateLimiter above."""
    ...

class RedisRateLimitBackend(RateLimitBackend):
    """For multi-instance deployments. Uses INCR + EXPIRE sliding window."""
    async def check_and_increment(self, key: str, limit: int, window_seconds: int) -> bool:
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        count, _ = await pipe.execute()
        return count <= limit
```

The middleware instantiates the correct backend based on settings — never two code paths at runtime.

### 2.6 OpenTelemetry Tracing

**Complexity:** L
**Files to create:** `server/tracing.py`
**Files to modify:** `server/app.py`, `server/middleware/__init__.py`, `pyproject.toml`

**Plan:**

```python
# server/tracing.py
"""OpenTelemetry distributed tracing setup."""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor


def setup_tracing(app, settings):
    """Initialize OpenTelemetry tracing."""
    if not settings.tracing.enabled:
        return

    provider = TracerProvider(resource=Resource.create({
        "service.name": "openlabels-api",
        "service.version": settings.version,
    }))

    exporter = OTLPSpanExporter(endpoint=settings.tracing.otlp_endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Auto-instrument
    FastAPIInstrumentor.instrument_app(app)
    SQLAlchemyInstrumentor().instrument()
    HTTPXClientInstrumentor().instrument()
```

Add to `pyproject.toml`:
```toml
[project.optional-dependencies]
tracing = [
    "opentelemetry-api",
    "opentelemetry-sdk",
    "opentelemetry-exporter-otlp",
    "opentelemetry-instrumentation-fastapi",
    "opentelemetry-instrumentation-sqlalchemy",
    "opentelemetry-instrumentation-httpx",
]
```

---

## 3. Adapters

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/adapters/`

### 3.1 Fix FilterConfig Mutation Bug

**Complexity:** S (but critical correctness fix)
**Files to modify:** `adapters/base.py`

**Current bug:** `__post_init__` calls `self.exclude_extensions.extend(...)` which mutates the list that was passed in (or the default). Creating two `FilterConfig()` instances doubles the preset entries.

**Fix:**

```python
# adapters/base.py - FilterConfig.__post_init__
def __post_init__(self):
    """Apply presets after initialization."""
    # Build new lists instead of mutating in place
    extensions = list(self.exclude_extensions)  # Copy
    patterns = list(self.exclude_patterns)      # Copy

    if self.exclude_temp_files:
        extensions.extend([
            "tmp", "temp", "bak", "swp", "swo", "pyc", "pyo",
            "class", "o", "obj", "cache",
        ])

    if self.exclude_system_dirs:
        patterns.extend([
            ".git/*", ".svn/*", ".hg/*",
            "node_modules/*", "__pycache__/*",
            ".venv/*", "venv/*", ".env/*",
            "*.egg-info/*", "dist/*", "build/*",
            ".tox/*", ".pytest_cache/*",
        ])

    # Normalize and reassign (don't mutate originals)
    self.exclude_extensions = [ext.lower().lstrip(".") for ext in extensions]
    self.exclude_patterns = patterns

    # Compile Rust filter if available
    self._rust_filter = None
    if _USE_RUST_FILTER and _RustFileFilter is not None:
        self._rust_filter = _RustFileFilter(
            self.exclude_extensions,
            self.exclude_patterns,
            self.exclude_accounts,
            self.min_size_bytes,
            self.max_size_bytes,
        )
```

### 3.2 Adapter Lifecycle Management

**Complexity:** M
**Files to modify:** `adapters/base.py`, `adapters/graph_base.py`, `adapters/filesystem.py`, `adapters/sharepoint.py`, `adapters/onedrive.py`

**Plan:**

Add async context manager to the protocol. **Note:** Section 3.4 renames `Adapter` to `ReadAdapter` — implement these together or do 3.4 first. The lifecycle methods go on `ReadAdapter`:
```python
# adapters/base.py
class ReadAdapter(Protocol):
    async def __aenter__(self) -> "ReadAdapter":
        """Initialize adapter resources (connections, sessions)."""
        ...

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean up adapter resources."""
        ...

    # ... existing methods (list_files, read_file, etc.) ...
```

Implement in `graph_base.py`:
```python
class BaseGraphAdapter:
    _client: GraphClient | None = None

    async def __aenter__(self):
        self._client = GraphClient(...)
        await self._client.connect()
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.close()
            self._client = None
```

Usage:
```python
async with SharePointAdapter(credentials) as adapter:
    async for file_info in adapter.list_files(site_id):
        content = await adapter.read_file(file_info)
```

### 3.3 Adapter-Level Circuit Breaker

**Complexity:** M
**Files to modify:** `adapters/graph_base.py`, `adapters/graph_client.py`
**Files to reference:** `core/circuit_breaker.py`

**Plan:**

Integrate existing circuit breaker into GraphClient:
```python
# adapters/graph_client.py
from openlabels.core.circuit_breaker import CircuitBreaker

class GraphClient:
    def __init__(self, ...):
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=5,    # 5 consecutive failures
            recovery_timeout=60,    # Wait 60s before retry
            half_open_max_calls=1,  # Allow 1 test call
        )

    async def get(self, endpoint: str) -> dict:
        if not self._circuit_breaker.can_execute():
            raise AdapterUnavailableError(
                f"Circuit breaker open for Graph API (failures: {self._circuit_breaker.failure_count})"
            )
        try:
            result = await self._do_request("GET", endpoint)
            self._circuit_breaker.record_success()
            return result
        except Exception as e:
            self._circuit_breaker.record_failure()
            raise
```

### 3.4 Split Fat Protocol Interface

**Complexity:** M
**Files to modify:** `adapters/base.py`, `adapters/filesystem.py`, `adapters/sharepoint.py`, `adapters/onedrive.py`

**Plan:**

```python
# adapters/base.py

class ReadAdapter(Protocol):
    """Core read operations. All adapters must implement this."""

    @property
    def adapter_type(self) -> str: ...

    async def list_files(self, target: str, recursive: bool = True,
                         filter_config: FilterConfig | None = None) -> AsyncIterator[FileInfo]: ...

    async def read_file(self, file_info: FileInfo) -> bytes: ...

    async def get_metadata(self, file_info: FileInfo) -> FileInfo: ...

    async def test_connection(self, config: dict) -> bool: ...

    def supports_delta(self) -> bool: ...


class RemediationAdapter(Protocol):
    """Remediation operations. Optional — not all adapters support this."""

    async def move_file(self, file_info: FileInfo, dest_path: str) -> bool: ...

    async def get_acl(self, file_info: FileInfo) -> dict | None: ...

    async def set_acl(self, file_info: FileInfo, acl: dict) -> bool: ...


def supports_remediation(adapter: ReadAdapter) -> bool:
    """Check if an adapter supports remediation operations."""
    return isinstance(adapter, RemediationAdapter)
```

### 3.5 Adapter Health Checks

**Complexity:** S
**Files to create:** `adapters/health.py`
**Files to modify:** `adapters/base.py`

**Plan:**

```python
# adapters/health.py
"""Periodic adapter health checking."""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class AdapterHealth:
    adapter_type: str
    healthy: bool
    last_check: datetime
    latency_ms: float | None = None
    error: str | None = None


class AdapterHealthChecker:
    """Periodically checks adapter connectivity."""

    def __init__(self, check_interval: int = 60):
        self._adapters: Dict[str, "ReadAdapter"] = {}
        self._health: Dict[str, AdapterHealth] = {}
        self._interval = check_interval
        self._running = False

    def register(self, adapter: "ReadAdapter") -> None:
        self._adapters[adapter.adapter_type] = adapter

    async def check_all(self) -> Dict[str, AdapterHealth]:
        for name, adapter in self._adapters.items():
            loop = asyncio.get_running_loop()
            start = loop.time()
            try:
                healthy = await adapter.test_connection({})
                latency = (loop.time() - start) * 1000
                self._health[name] = AdapterHealth(
                    adapter_type=name, healthy=healthy,
                    last_check=datetime.now(timezone.utc), latency_ms=latency,
                )
            except Exception as e:
                self._health[name] = AdapterHealth(
                    adapter_type=name, healthy=False,
                    last_check=datetime.now(timezone.utc), error=str(e),
                )
        return dict(self._health)

    def get_health(self) -> Dict[str, AdapterHealth]:
        return dict(self._health)
```

---

## 4. Auth

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/auth/`

### 4.1 Thread-Safe JWKS Cache

**Complexity:** S
**Files to modify:** `auth/oauth.py`

```python
# auth/oauth.py - replace global dict with locked cache

import asyncio
import time
from typing import Optional

_jwks_cache: dict[str, tuple[dict, float]] = {}
_jwks_lock = asyncio.Lock()


async def get_jwks(tenant_id: str) -> dict:
    """Fetch JWKS with thread-safe TTL caching."""
    now = time.monotonic()

    # Check cache without lock (fast path)
    if tenant_id in _jwks_cache:
        cached_data, fetched_at = _jwks_cache[tenant_id]
        if now - fetched_at < _JWKS_CACHE_TTL_SECONDS:
            return cached_data

    # Acquire lock for cache update
    async with _jwks_lock:
        # Re-check time after acquiring lock (may have waited)
        now = time.monotonic()
        if tenant_id in _jwks_cache:
            cached_data, fetched_at = _jwks_cache[tenant_id]
            if now - fetched_at < _JWKS_CACHE_TTL_SECONDS:
                return cached_data

        # Fetch fresh JWKS
        jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        async with httpx.AsyncClient(timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            jwks_data = response.json()
            _jwks_cache[tenant_id] = (jwks_data, time.monotonic())
            return jwks_data
```

### 4.2 JWKS Refresh on Key-Not-Found

**Complexity:** S
**Files to modify:** `auth/oauth.py`

```python
# auth/oauth.py - in validate_token()

async def _find_signing_key(kid: str, tenant_id: str) -> dict:
    """Find signing key, refreshing JWKS cache if needed."""
    jwks = await get_jwks(tenant_id)
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k

    # Key not found — force refresh (Azure AD may have rotated keys)
    _jwks_cache.pop(tenant_id, None)
    jwks = await get_jwks(tenant_id)
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k

    raise TokenInvalidError("Unable to find signing key after cache refresh")
```

### 4.3 Granular Token Error Types

**Complexity:** S
**Files to modify:** `auth/oauth.py`

**Note:** The exception classes (`AuthError`, `TokenExpiredError`, `TokenInvalidError`) are defined in the unified hierarchy (Section 14.1, `openlabels/exceptions.py`). Do NOT create a separate `auth/exceptions.py` — import from `openlabels.exceptions` instead.

Update `validate_token()`:
```python
except JWTError as e:
    error_str = str(e).lower()
    if "expired" in error_str:
        raise TokenExpiredError(f"Token expired: {e}")
    elif "signature" in error_str:
        raise TokenInvalidError(f"Invalid signature: {e}")
    else:
        raise TokenInvalidError(f"Invalid token: {e}")
```

### 4.4 RBAC Dependencies

**Complexity:** M
**Files to modify:** `auth/dependencies.py`

```python
# auth/dependencies.py - add to existing file (get_current_user and CurrentUser are already defined here)

def require_role(*allowed_roles: str):
    """FastAPI dependency that enforces role-based access.

    Note: CurrentUser.role is a single string (e.g., "admin", "operator", "viewer").
    The existing `require_admin` dependency checks `user.role != "admin"`.
    This generalizes it to accept multiple allowed roles.

    Usage:
        @router.delete("/{id}", dependencies=[Depends(require_role("admin"))])
        async def delete_item(id: UUID): ...
    """
    async def _check_role(user: CurrentUser = Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {allowed_roles}. User has: {user.role}",
            )
        return user
    return _check_role


# Pre-built dependencies for common roles (replaces existing require_admin)
require_admin = require_role("admin")
require_operator = require_role("admin", "operator")
require_viewer = require_role("admin", "operator", "viewer")
```

---

## 5. CLI

**Current Rating:** 1 (Good) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/cli/`

### 5.1 Shared Base Command + Common Options

**Complexity:** M
**Files to create:** `cli/base.py`, `cli/output.py`
**Files to modify:** All 16 command files in `cli/commands/`

**Plan:**

```python
# cli/base.py
"""Shared CLI utilities and common option groups."""

import click
import functools


def common_options(f):
    """Decorator adding common options to all commands."""
    @click.option("--format", "-f", "output_format",
                  type=click.Choice(["table", "json", "csv"]),
                  default="table", help="Output format")
    @click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
    @click.option("--server", "-s", envvar="OPENLABELS_SERVER_URL",
                  default="http://localhost:8000", help="Server URL")
    @click.option("--token", envvar="OPENLABELS_TOKEN",
                  default=None, help="Authentication token")
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper


def api_client_options(f):
    """Decorator that injects a configured API client.

    Note: OpenLabelsClient is async (Section 13.1). CLI commands are sync (click).
    This decorator bridges the gap with asyncio.run() and proper cleanup.
    """
    @common_options
    @functools.wraps(f)
    def wrapper(*args, server, token, **kwargs):
        import asyncio
        from openlabels.client import OpenLabelsClient

        async def _run():
            async with OpenLabelsClient(base_url=server, token=token) as client:
                kwargs["client"] = client
                # If the wrapped function is async, await it
                result = f(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    return await result
                return result

        return asyncio.run(_run())
    return wrapper
```

### 5.2 Structured Output Formatter

**Complexity:** M
**Files to create:** `cli/output.py`

```python
# cli/output.py
"""Structured output formatting for CLI commands."""

import csv
import io
import json
import sys
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class OutputFormatter:
    """Format command output as table, JSON, or CSV."""

    def __init__(self, format: str = "table", quiet: bool = False):
        self.format = format
        self.quiet = quiet
        self.console = Console() if RICH_AVAILABLE else None

    def print_table(self, data: list[dict], columns: list[str] | None = None):
        """Print data as a formatted table."""
        if not data:
            if not self.quiet:
                print("No results found.")
            return

        if self.format == "json":
            print(json.dumps(data, indent=2, default=str))
            return

        if self.format == "csv":
            cols = columns or list(data[0].keys())
            writer = csv.DictWriter(sys.stdout, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
            return

        # Table format
        cols = columns or list(data[0].keys())
        if RICH_AVAILABLE and self.console:
            table = Table()
            for col in cols:
                table.add_column(col.replace("_", " ").title())
            for row in data:
                table.add_row(*[str(row.get(c, "")) for c in cols])
            self.console.print(table)
        else:
            # Fallback plain text table
            header = " | ".join(c.ljust(20) for c in cols)
            print(header)
            print("-" * len(header))
            for row in data:
                print(" | ".join(str(row.get(c, "")).ljust(20) for c in cols))

    def print_single(self, data: dict):
        """Print a single record."""
        if self.format == "json":
            print(json.dumps(data, indent=2, default=str))
        else:
            for key, value in data.items():
                print(f"  {key}: {value}")

    def print_success(self, message: str):
        if not self.quiet:
            if RICH_AVAILABLE and self.console:
                self.console.print(f"[green]✓[/green] {message}")
            else:
                print(f"OK: {message}")

    def print_error(self, message: str):
        if RICH_AVAILABLE and self.console:
            self.console.print(f"[red]✗[/red] {message}", style="red")
        else:
            print(f"ERROR: {message}", file=sys.stderr)
```

### 5.3 `openlabels doctor` Command

**Complexity:** M
**Files to create:** `cli/commands/doctor.py`

```python
# cli/commands/doctor.py
"""System diagnostic checks."""

import click
from openlabels.cli.base import common_options
from openlabels.cli.output import OutputFormatter


@click.command("doctor")
@common_options
def doctor(output_format, quiet, server, token):
    """Run diagnostic checks on the OpenLabels installation."""
    fmt = OutputFormatter(output_format, quiet)
    checks = []

    # 1. Server connectivity
    checks.append(_check_server(server, token))

    # 2. Database
    checks.append(_check_database(server, token))

    # 3. ML / ONNX
    checks.append(_check_ml())

    # 4. OCR
    checks.append(_check_ocr())

    # 5. Rust extensions
    checks.append(_check_rust())

    # 6. MIP SDK
    checks.append(_check_mip())

    # 7. Python version
    checks.append(_check_python())

    # Print results
    fmt.print_table(checks, columns=["check", "status", "detail"])

    failed = [c for c in checks if c["status"] == "FAIL"]
    if failed:
        fmt.print_error(f"{len(failed)} check(s) failed")
        raise SystemExit(1)
    else:
        fmt.print_success("All checks passed")


def _check_server(server, token):
    try:
        import httpx
        r = httpx.get(f"{server}/health", timeout=5)
        if r.status_code == 200:
            return {"check": "API Server", "status": "OK", "detail": f"Connected to {server}"}
        return {"check": "API Server", "status": "FAIL", "detail": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"check": "API Server", "status": "FAIL", "detail": str(e)}


def _check_ml():
    try:
        import onnxruntime
        providers = onnxruntime.get_available_providers()
        return {"check": "ONNX Runtime", "status": "OK", "detail": f"Providers: {providers}"}
    except ImportError:
        return {"check": "ONNX Runtime", "status": "WARN", "detail": "Not installed (ML detection disabled)"}


def _check_ocr():
    import shutil
    if shutil.which("tesseract"):
        return {"check": "OCR (Tesseract)", "status": "OK", "detail": "tesseract found in PATH"}
    try:
        from rapidocr_onnxruntime import RapidOCR
        return {"check": "OCR (RapidOCR)", "status": "OK", "detail": "RapidOCR available"}
    except ImportError:
        return {"check": "OCR", "status": "WARN", "detail": "No OCR engine available"}


def _check_rust():
    try:
        from openlabels_matcher import FileFilter
        return {"check": "Rust Extensions", "status": "OK", "detail": "openlabels_matcher loaded"}
    except ImportError:
        return {"check": "Rust Extensions", "status": "WARN", "detail": "Using Python fallback"}


def _check_mip():
    try:
        import clr
        return {"check": "MIP SDK", "status": "OK", "detail": "pythonnet available"}
    except ImportError:
        return {"check": "MIP SDK", "status": "WARN", "detail": "pythonnet not installed (labeling disabled)"}


def _check_python():
    import sys
    v = sys.version_info
    status = "OK" if v >= (3, 10) else "FAIL"
    return {"check": "Python", "status": status, "detail": f"{v.major}.{v.minor}.{v.micro}"}


def _check_database(server, token):
    try:
        import httpx
        r = httpx.get(f"{server}/api/v1/health/status", timeout=5,
                      headers={"Authorization": f"Bearer {token}"} if token else {})
        if r.status_code == 200:
            data = r.json()
            db_status = data.get("db", "unknown")
            return {"check": "Database", "status": "OK" if db_status == "healthy" else "FAIL",
                    "detail": data.get("db_text", db_status)}
        return {"check": "Database", "status": "WARN", "detail": f"Health endpoint returned {r.status_code}"}
    except Exception as e:
        return {"check": "Database", "status": "FAIL", "detail": str(e)}
```

### 5.4 Progress Indicators

**Complexity:** S
**Files to modify:** `cli/commands/scan.py`, `cli/commands/export.py`

Use `rich.progress` for long-running operations:
```python
# Example for scan command
from rich.progress import Progress, SpinnerColumn, TextColumn

with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
    task = progress.add_task("Scanning files...", total=None)
    # ... poll scan status ...
    progress.update(task, description=f"Scanned {count} files ({matched} matched)")
```

---

## 6. GUI

**Current Rating:** 1 (Good) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/gui/`

### 6.1 Fix Blocking HTTP Calls (CRITICAL)

**Complexity:** L
**Files to modify:** `gui/main_window.py`
**Files to create:** `gui/workers/api_client.py`

This is the single most impactful change. Every `httpx.get()` in `MainWindow` freezes the UI.

**Plan:**

Create a dedicated API worker:
```python
# gui/workers/api_client.py
"""Non-blocking API client for GUI using QThread."""

import httpx
from PySide6.QtCore import QObject, QThread, Signal
from typing import Callable, Any
from dataclasses import dataclass
from uuid import uuid4


@dataclass
class APIRequest:
    id: str
    method: str
    url: str
    json: dict | None = None
    params: dict | None = None


class APIWorkerThread(QThread):
    """Background thread for HTTP requests."""

    response_ready = Signal(str, int, object)  # request_id, status_code, data
    request_failed = Signal(str, str)          # request_id, error_message

    def __init__(self, base_url: str, token: str | None = None):
        super().__init__()
        self._base_url = base_url
        self._token = token
        # Thread-safe queue — accessed from GUI thread (enqueue) and worker thread (get)
        from queue import Queue, Empty
        self._queue: Queue[APIRequest] = Queue()
        self._running = True

    def enqueue(self, request: APIRequest):
        self._queue.put(request)

    def run(self):
        """Process queued requests in background thread."""
        from queue import Empty
        with httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._token}"} if self._token else {},
            timeout=10.0,
        ) as client:
            while self._running:
                try:
                    request = self._queue.get(timeout=0.1)
                except Empty:
                    continue

                try:
                    response = client.request(
                        request.method,
                        request.url,
                        json=request.json,
                        params=request.params,
                    )
                    self.response_ready.emit(
                        request.id,
                        response.status_code,
                        response.json() if response.status_code == 200 else None,
                    )
                except Exception as e:
                    self.request_failed.emit(request.id, str(e))

    def stop(self):
        self._running = False


class APIClient(QObject):
    """High-level async API client for GUI widgets."""

    connected = Signal(bool)
    stats_loaded = Signal(dict)
    targets_loaded = Signal(list)
    results_loaded = Signal(list)
    schedules_loaded = Signal(list)
    labels_loaded = Signal(list)
    health_loaded = Signal(dict)
    error_occurred = Signal(str, str)  # operation, error_message

    def __init__(self, base_url: str, token: str | None = None):
        super().__init__()
        self._worker = APIWorkerThread(base_url, token)
        self._worker.response_ready.connect(self._on_response)
        self._worker.request_failed.connect(self._on_error)
        self._callbacks: dict[str, tuple[str, Callable]] = {}  # id -> (operation, callback)
        self._worker.start()

    def check_health(self):
        self._enqueue("health", "GET", "/health", callback=self._handle_health)

    def load_stats(self):
        self._enqueue("stats", "GET", "/api/dashboard/stats", callback=self._handle_stats)

    def load_targets(self):
        self._enqueue("targets", "GET", "/api/targets", callback=self._handle_targets)

    def load_results(self):
        self._enqueue("results", "GET", "/api/results", callback=self._handle_results)

    # ... etc for each API call ...

    def _enqueue(self, operation: str, method: str, url: str,
                 callback: Callable | None = None, **kwargs):
        req_id = str(uuid4())
        if callback:
            self._callbacks[req_id] = (operation, callback)
        self._worker.enqueue(APIRequest(id=req_id, method=method, url=url, **kwargs))

    def _on_response(self, req_id: str, status_code: int, data: Any):
        if req_id in self._callbacks:
            operation, callback = self._callbacks.pop(req_id)
            callback(status_code, data)

    def _on_error(self, req_id: str, error: str):
        if req_id in self._callbacks:
            operation, _ = self._callbacks.pop(req_id)
            self.error_occurred.emit(operation, error)

    def _handle_health(self, status_code, data):
        self.connected.emit(status_code == 200)

    def _handle_stats(self, status_code, data):
        if data:
            self.stats_loaded.emit(data)

    def _handle_targets(self, status_code, data):
        if data:
            self.targets_loaded.emit(data)

    def close(self):
        self._worker.stop()
        self._worker.wait()
```

Refactor `MainWindow` to use signals:
```python
# gui/main_window.py
class MainWindow(QMainWindow):
    def __init__(self, server_url: str = "http://localhost:8000"):
        super().__init__()
        self.server_url = server_url

        # Create API client (non-blocking)
        self._api = APIClient(server_url)
        self._api.connected.connect(self._on_connected)
        self._api.stats_loaded.connect(self.dashboard_widget.update_stats)
        self._api.targets_loaded.connect(self._on_targets_loaded)
        self._api.results_loaded.connect(self.results_widget.load_results)
        self._api.error_occurred.connect(self._on_api_error)
        # ... setup UI ...

    def _load_initial_data(self):
        """Non-blocking initial data load."""
        self._api.check_health()
        self._api.load_stats()
        self._api.load_targets()

    def _on_connected(self, connected: bool):
        if connected:
            self.connection_label.setText(f"Connected to {self.server_url}")
            self.connection_label.setStyleSheet("color: green;")
        else:
            self.connection_label.setText("Not connected")
            self.connection_label.setStyleSheet("color: red;")
```

### 6.2 Fix Hardcoded Tab Indices

**Complexity:** S
**Files to modify:** `gui/main_window.py`

```python
# Replace all hardcoded indices:
# BEFORE:
self.tabs.setCurrentIndex(1)  # Scans tab
self.tabs.setCurrentIndex(8)  # Settings tab

# AFTER:
self.tabs.setCurrentWidget(self.scan_widget)
self.tabs.setCurrentWidget(self.settings_widget)
```

### 6.3 Loading States

**Complexity:** M
**Files to create:** `gui/widgets/loading_overlay.py`

```python
# gui/widgets/loading_overlay.py
from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout
from PySide6.QtCore import Qt


class LoadingOverlay(QWidget):
    """Semi-transparent loading overlay for widgets."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.setStyleSheet("background-color: rgba(255, 255, 255, 180);")

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        self._label = QLabel("Loading...")
        self._label.setStyleSheet("font-size: 14px; color: #666;")
        layout.addWidget(self._label)
        self.hide()

    def show_loading(self, message: str = "Loading..."):
        self._label.setText(message)
        self.resize(self.parent().size())
        self.show()
        self.raise_()

    def hide_loading(self):
        self.hide()
```

---

## 7. Jobs

**Current Rating:** 3 (Best) — Maintain

Minor enhancements only:

### 7.1 Max Concurrent Jobs Per Tenant

**Complexity:** S
**Files to modify:** `jobs/queue.py`

```python
async def dequeue(self, worker_id: str, max_concurrent: int | None = None) -> JobQueueModel | None:
    if max_concurrent:
        running = await self.get_running_count()
        if running >= max_concurrent:
            return None
    # ... existing dequeue logic
```

### 7.2 Job Completion Callbacks

**Complexity:** S
**Files to modify:** `jobs/queue.py`

Add a simple callback mechanism to the job queue. No webhook infrastructure needed — just let callers register post-completion hooks:

```python
# jobs/queue.py
from typing import Callable, Awaitable

JobCallback = Callable[["JobQueueModel"], Awaitable[None]]

class JobQueue:
    def __init__(self, session, tenant_id, on_complete: JobCallback | None = None):
        self._on_complete = on_complete
        # ...

    async def mark_completed(self, job_id, result=None):
        # ... existing completion logic ...
        if self._on_complete:
            await self._on_complete(job)
```

This keeps it simple and extensible. When a webhook API is needed later, the webhook sender just becomes one implementation of `JobCallback`.

### 7.3 Horizontal Scaling Path (future)

**Complexity:** N/A (informational — no code changes now)

The current `SELECT FOR UPDATE SKIP LOCKED` job queue already supports multiple consumers by design. If the single-server deployment ever becomes a bottleneck, the scaling path is straightforward:

1. **Run a second worker process** pointing at the same PostgreSQL database. The `SKIP LOCKED` pattern means both workers will dequeue different jobs without conflicts. No code changes needed.
2. **Split API and worker processes.** Run the FastAPI server and the job worker as separate processes (or containers). They share the same database. The API enqueues jobs; workers dequeue and execute. This is a deployment change, not a code change.
3. **Only if PostgreSQL becomes the bottleneck** (unlikely below millions of jobs/day): consider Celery or Dramatiq with Redis/RabbitMQ as the broker. This is a significant rewrite and should not be done preemptively.

The key insight: the current architecture already supports step 1 and 2 with zero code changes. Don't add distributed task queue infrastructure until you've measured that PostgreSQL job throughput is the actual bottleneck.

---

## 8. Labeling

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/labeling/`

### 8.1 Extract Common File Operation Wrapper

**Complexity:** M
**Files to modify:** `labeling/mip.py`

```python
# labeling/mip.py - add generic wrapper

async def _run_file_operation(
    self,
    file_path: str | Path,
    sync_fn: Callable,
    operation_name: str,
    **kwargs,
) -> Any:
    """
    Common wrapper for all MIP file operations.

    Handles: initialization check, file existence, executor dispatch,
    and unified exception handling.
    """
    if not self._initialized:
        raise RuntimeError(f"MIP engine not initialized. Call initialize() first.")

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(
            self._executor,
            partial(sync_fn, str(path), **kwargs),
        )
    except PermissionError as e:
        logger.error(f"{operation_name} permission denied: {path}: {e}")
        raise
    except OSError as e:
        logger.error(f"{operation_name} OS error: {path}: {e}")
        raise
    except RuntimeError as e:
        logger.error(f"{operation_name} runtime error: {path}: {e}")
        raise


# Usage - dramatically simplifies each method:
async def apply_label(self, file_path, label_id, justification=None):
    return await self._run_file_operation(
        file_path, self._apply_label_sync, "apply_label",
        label_id=label_id, justification=justification,
    )

async def remove_label(self, file_path):
    return await self._run_file_operation(
        file_path, self._remove_label_sync, "remove_label",
    )

async def get_file_label(self, file_path):
    return await self._run_file_operation(
        file_path, self._get_file_label_sync, "get_file_label",
    )
```

### 8.2 Fix Deprecated asyncio.get_event_loop()

**Complexity:** S
**Files to modify:** `labeling/mip.py`

Global find-and-replace:
```python
# BEFORE (6 occurrences):
loop = asyncio.get_event_loop()

# AFTER:
loop = asyncio.get_running_loop()
```

### 8.3 Batch Labeling

**Complexity:** M
**Files to modify:** `labeling/mip.py` or `labeling/engine.py`

```python
async def apply_labels_batch(
    self,
    items: list[tuple[str, str]],  # [(file_path, label_id), ...]
    max_concurrent: int = 4,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    """Apply labels to multiple files concurrently.

    Args:
        items: List of (file_path, label_id) tuples
        max_concurrent: Max parallel operations
        on_progress: Optional callback(completed, total)

    Returns:
        List of result dicts with success/error per file
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []
    completed = 0

    async def _process(file_path: str, label_id: str) -> dict:
        nonlocal completed
        async with semaphore:
            try:
                result = await self.apply_label(file_path, label_id)
                entry = {"file": file_path, "success": True, "result": result}
            except Exception as e:
                entry = {"file": file_path, "success": False, "error": str(e)}
            completed += 1
            if on_progress:
                on_progress(completed, len(items))
            return entry

    tasks = [_process(fp, lid) for fp, lid in items]
    results = await asyncio.gather(*tasks)
    return list(results)
```

---

## 9. Remediation

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/remediation/`

### 9.1 Quarantine Manifest

**Complexity:** M
**Files to create:** `remediation/manifest.py`
**Files to modify:** `remediation/quarantine.py`

```python
# remediation/manifest.py
"""Quarantine manifest for tracking quarantined files."""

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    quarantine_path: str
    quarantined_at: str  # ISO format
    reason: str
    risk_tier: str
    triggered_by: str
    scan_job_id: Optional[str] = None
    file_hash: Optional[str] = None  # SHA-256 before move
    restored: bool = False
    restored_at: Optional[str] = None


class QuarantineManifest:
    """JSON-file backed quarantine manifest."""

    def __init__(self, manifest_path: Path):
        self._path = manifest_path
        self._entries: dict[str, QuarantineEntry] = {}
        self._load()

    def _load(self):
        if self._path.exists():
            with open(self._path) as f:
                data = json.load(f)
                for entry_data in data.get("entries", []):
                    entry = QuarantineEntry(**entry_data)
                    self._entries[entry.id] = entry

    def _save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump({
                "entries": [asdict(e) for e in self._entries.values()],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2)

    def add(self, original_path: Path, quarantine_path: Path,
            reason: str, risk_tier: str, triggered_by: str,
            file_hash: str | None = None) -> QuarantineEntry:
        entry = QuarantineEntry(
            id=str(uuid4()),
            original_path=str(original_path),
            quarantine_path=str(quarantine_path),
            quarantined_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            risk_tier=risk_tier,
            triggered_by=triggered_by,
            file_hash=file_hash,
        )
        self._entries[entry.id] = entry
        self._save()
        return entry

    def get(self, entry_id: str) -> QuarantineEntry | None:
        return self._entries.get(entry_id)

    def find_by_original_path(self, path: str) -> list[QuarantineEntry]:
        return [e for e in self._entries.values() if e.original_path == path]

    def mark_restored(self, entry_id: str):
        if entry_id in self._entries:
            self._entries[entry_id].restored = True
            self._entries[entry_id].restored_at = datetime.now(timezone.utc).isoformat()
            self._save()

    def list_active(self) -> list[QuarantineEntry]:
        return [e for e in self._entries.values() if not e.restored]
```

### 9.2 Restore from Quarantine

**Complexity:** M
**Files to modify:** `remediation/quarantine.py`

```python
def restore_from_quarantine(
    entry_id: str,
    manifest: QuarantineManifest,
    verify_hash: bool = True,
    dry_run: bool = False,
) -> RemediationResult:
    """Restore a quarantined file to its original location."""
    entry = manifest.get(entry_id)
    if not entry:
        return RemediationResult.failure(
            action=RemediationAction.RESTORE,
            source=Path(entry_id),
            error="Quarantine entry not found",
        )

    quarantine_path = Path(entry.quarantine_path)
    original_path = Path(entry.original_path)

    if not quarantine_path.exists():
        return RemediationResult.failure(
            action=RemediationAction.RESTORE,
            source=quarantine_path,
            error="Quarantined file no longer exists",
        )

    # Verify integrity
    if verify_hash and entry.file_hash:
        import hashlib
        actual_hash = hashlib.sha256(quarantine_path.read_bytes()).hexdigest()
        if actual_hash != entry.file_hash:
            return RemediationResult.failure(
                action=RemediationAction.RESTORE,
                source=quarantine_path,
                error=f"Hash mismatch: expected {entry.file_hash}, got {actual_hash}",
            )

    if dry_run:
        return RemediationResult(
            success=True, action=RemediationAction.RESTORE,
            source_path=quarantine_path, dest_path=original_path,
        )

    # Move file back
    original_path.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.move(str(quarantine_path), str(original_path))
    manifest.mark_restored(entry_id)

    return RemediationResult(
        success=True, action=RemediationAction.RESTORE,
        source_path=quarantine_path, dest_path=original_path,
        performed_by=get_current_user(),
    )
```

### 9.3 File Integrity Verification

**Complexity:** S
**Files to modify:** `remediation/quarantine.py`

Add hash computation before and after move:
```python
import hashlib

def _compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# In quarantine() function, before moving:
pre_hash = _compute_file_hash(source)

# After moving:
post_hash = _compute_file_hash(dest_file)
if pre_hash != post_hash:
    logger.error(f"Hash mismatch after quarantine! {pre_hash} != {post_hash}")
    # Attempt to restore original
```

---

## 10. Monitoring

**Current Rating:** 2 (Better) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/monitoring/`

### 10.1 Thread-Safe _watched_files

**Complexity:** S
**Files to modify:** `monitoring/registry.py`

```python
# monitoring/registry.py
import threading

_watched_files: Dict[str, WatchedFile] = {}
_watched_lock = threading.Lock()


def enable_monitoring(path: Path, ...) -> MonitoringResult:
    path = Path(path).resolve()
    path_str = str(path)

    with _watched_lock:
        if path_str in _watched_files:
            return MonitoringResult(success=True, ...)

    # Platform-specific setup (outside lock — may be slow)
    result = _enable_platform(path, ...)

    if result.success:
        with _watched_lock:
            _watched_files[path_str] = WatchedFile(...)

    return result
```

### 10.2 Automatic Cache-DB Sync

**Complexity:** M
**Files to modify:** `monitoring/registry.py`

Make `enable_monitoring` and `disable_monitoring` async with automatic DB persistence:
```python
async def enable_monitoring_async(
    path: Path,
    session,  # AsyncSession
    tenant_id: UUID,
    risk_tier: str = "HIGH",
    **kwargs,
) -> MonitoringResult:
    """Enable monitoring with automatic DB persistence."""
    result = enable_monitoring(path, risk_tier=risk_tier, **kwargs)

    if result.success:
        from openlabels.monitoring import db as monitoring_db
        await monitoring_db.upsert_monitored_file(
            session, tenant_id, str(path),
            risk_tier=risk_tier,
            sacl_enabled=result.sacl_enabled,
            audit_rule_enabled=result.audit_rule_enabled,
        )

    return result
```

### 10.3 Bulk Operations

**Complexity:** M
**Files to modify:** `monitoring/registry.py`

```python
def enable_monitoring_batch(
    paths: list[Path],
    risk_tier: str = "HIGH",
) -> list[MonitoringResult]:
    """Enable monitoring on multiple files efficiently.

    On Windows: generates a single PowerShell script.
    On Linux: generates a single auditctl script.
    """
    if platform.system() == "Windows":
        return _enable_batch_windows(paths, risk_tier)
    else:
        return _enable_batch_linux(paths, risk_tier)


def _enable_batch_windows(paths: list[Path], risk_tier: str) -> list[MonitoringResult]:
    """Single PowerShell invocation for all files."""
    # Validate all paths before building script (same rules as _enable_monitoring_windows)
    _INJECTION_CHARS = set('"\'`$\n\r;&|')
    validated_paths = []
    results = []
    for p in paths:
        resolved = str(p.resolve())
        if any(c in resolved for c in _INJECTION_CHARS):
            results.append(MonitoringResult(success=False, path=p, error="Path contains invalid characters"))
        else:
            validated_paths.append(resolved)

    # Build one script with a loop (only validated paths)
    path_list = "\n".join(f'    "{p}"' for p in validated_paths)
    ps_script = f'''
$paths = @(
{path_list}
)
foreach ($p in $paths) {{
    $acl = Get-Acl -Path $p -Audit
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "Read, Write", "None", "None", "Success, Failure"
    )
    $acl.AddAuditRule($rule)
    Set-Acl -Path $p -AclObject $acl
    Write-Output "OK:$p"
}}
'''
    # Execute single script, parse per-file results
    # ...
```

### 10.4 Event Collection

**Complexity:** L
**Files to create:** `monitoring/collector.py`

```python
# monitoring/collector.py
"""Collect access events from OS audit systems."""

import platform
import subprocess
import re
from datetime import datetime
from typing import Iterator

from .base import AccessEvent


class EventCollector:
    """Collect file access events from the OS audit subsystem."""

    def collect_events(
        self,
        since: datetime | None = None,
        paths: list[str] | None = None,
    ) -> Iterator[AccessEvent]:
        if platform.system() == "Windows":
            yield from self._collect_windows(since, paths)
        else:
            yield from self._collect_linux(since, paths)

    def _collect_windows(self, since, paths) -> Iterator[AccessEvent]:
        """Query Windows Security Event Log for file access events.

        Event IDs:
        - 4663: Object access attempt
        - 4656: Handle requested
        """
        # Use wevtutil or PowerShell Get-WinEvent
        # Filter by Event ID 4663 + openlabels SACL entries
        # Parse XML output into AccessEvent objects
        ...

    def _collect_linux(self, since, paths) -> Iterator[AccessEvent]:
        """Query auditd logs via ausearch."""
        cmd = ["ausearch", "-k", "openlabels", "--format", "csv"]
        if since:
            cmd.extend(["--start", since.strftime("%m/%d/%Y %H:%M:%S")])
        # Parse ausearch CSV output into AccessEvent objects
        ...
```

---

## 11. Web

**Current Rating:** 0 (OK) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/web/`

**Status:** Skip for now. The existing `web/routes.py` has significant code (1400+ lines with HTMX partials, form handlers, etc.) but the architecture needs a from-scratch rebuild to reach Best. The current implementation bypasses the service layer by querying the database directly, lacks proper auth flow and CSRF protection, and has duplicated business logic.

**When ready to implement:** Build from scratch with:
- HTMX + Tailwind + Alpine.js stack
- Proper base template architecture (`base.html`, `components/`, `pages/`, `partials/`)
- Web routes that call through the service layer (Section 2.1), not raw DB queries
- Session-based auth flow with login redirect
- CSRF token validation on all form submissions
- Structured error states for partials (not silent empty data)
- Static asset pipeline with Tailwind build step

This is a large standalone effort. Prioritize the core platform improvements (Phases 0-3) first.

---

## 12. Windows

**Current Rating:** 1 (Good) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/windows/`

### 12.1 - 12.6 Combined Plan

**Complexity:** M overall
**Files to modify:** `windows/tray.py`
**Files to create:** `windows/log_viewer.py`

Key changes:
```python
# tray.py fixes

# 12.1: Use OS default editor
def _open_config(self):
    for path in config_paths:
        if path.exists():
            os.startfile(str(path))  # Opens with default editor
            return

# 12.4: Add tray notifications
def _on_scan_completed(self, job_name: str, files_found: int):
    self.tray_icon.showMessage(
        "Scan Complete",
        f"{job_name}: {files_found} sensitive files found",
        QSystemTrayIcon.Information,
        5000,  # 5 seconds
    )

# 12.5: Auto-start
def _toggle_auto_start(self, enabled: bool):
    import winreg
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0, winreg.KEY_SET_VALUE,
    )
    if enabled:
        winreg.SetValueEx(key, "OpenLabels", 0, winreg.REG_SZ, sys.executable)
    else:
        try:
            winreg.DeleteValue(key, "OpenLabels")
        except FileNotFoundError:
            pass
    winreg.CloseKey(key)

# 12.6: Background service operations
def _start_service(self):
    self.status_action.setText("Status: Starting...")
    worker = QThread()
    # ... run docker compose up -d in thread ...
```

---

## 13. Client

**Current Rating:** 1 (Good) → **Target:** 3 (Best)
**Module Path:** `src/openlabels/client/`

### 13.1 Persistent Client + Context Manager

**Complexity:** M
**Files to modify:** `client/client.py`

```python
class OpenLabelsClient:
    def __init__(self, base_url="http://localhost:8000", token=None, api_version="v1"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.api_version = api_version
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.api_base,
                headers=self._headers(),
                timeout=30.0,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # All methods now use persistent client:
    async def health(self) -> dict:
        client = await self._get_client()
        response = await client.get("/health")
        response.raise_for_status()
        return response.json()
```

### 13.2 Retry Logic

```python
# client/client.py
import asyncio
from httpx import HTTPStatusError, TransportError

async def _request(self, method: str, url: str, max_retries: int = 3, **kwargs):
    """Make a request with automatic retry on transient failures."""
    client = await self._get_client()
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            response = await client.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except TransportError as e:
            last_error = e
            if attempt < max_retries:
                delay = 2 ** attempt  # 1s, 2s, 4s
                await asyncio.sleep(delay)
        except HTTPStatusError as e:
            if e.response.status_code in (502, 503, 504) and attempt < max_retries:
                last_error = e
                await asyncio.sleep(2 ** attempt)
            else:
                raise

    raise last_error
```

### 13.3 Auto-Pagination (Cursor-Based)

Must be consistent with Section 2.4 and the existing `server/pagination.py` cursor format (base64-encoded `(id, timestamp)` composite cursor).

```python
from typing import AsyncIterator

async def list_all_scans(self, **filters) -> AsyncIterator[dict]:
    """Auto-paginating scan iterator using cursor-based pagination.

    The server returns:
      {"items": [...], "next_cursor": "<base64>", "has_more": true/false}
    """
    cursor = None
    while True:
        params = {**filters, "limit": 100}
        if cursor:
            params["cursor"] = cursor
        data = await self._request("GET", "/scans", params=params)
        body = data.json()
        for item in body.get("items", []):
            yield item
        if not body.get("has_more", False):
            break
        cursor = body.get("next_cursor")
        if not cursor:
            break
```

### 13.4 Complete API Coverage

Add methods for all missing endpoints:
```python
# Labels
async def list_labels(self) -> list[dict]: ...
async def sync_labels(self) -> dict: ...
async def list_label_rules(self) -> list[dict]: ...
async def create_label_rule(self, ...) -> dict: ...
async def apply_label(self, result_id, label_id) -> dict: ...

# Schedules
async def list_schedules(self) -> list[dict]: ...
async def create_schedule(self, ...) -> dict: ...
async def update_schedule(self, schedule_id, ...) -> dict: ...
async def delete_schedule(self, schedule_id) -> None: ...

# Users
async def list_users(self) -> list[dict]: ...
async def create_user(self, ...) -> dict: ...

# Settings
async def get_settings(self) -> dict: ...
async def update_settings(self, settings: dict) -> dict: ...

# Monitoring
async def get_monitoring_status(self) -> dict: ...
async def enable_monitoring(self, path: str, ...) -> dict: ...

# Audit
async def list_audit_logs(self, ...) -> dict: ...
```

---

## 14. Cross-Cutting Concerns

These span all modules and should be implemented as a foundation before module-specific work.

### 14.1 Unified Exception Hierarchy

**Complexity:** M
**Files to create:** `src/openlabels/exceptions.py`
**Files to modify:** Every module's exception classes
**Existing files to consolidate:**
- `core/exceptions.py` — already has `OpenLabelsError`, `DetectionError`, `ExtractionError`, `AdapterError`, `GraphAPIError`, `FilesystemError`, `ConfigurationError`, `ModelLoadError`, `JobError`, `SecurityError`
- `server/exceptions.py` — has `APIError`, `NotFoundError`, `ValidationError`, `RateLimitError`, `ConflictError`, `BadRequestError`, `InternalError`
- `remediation/base.py` — has `RemediationError`, `QuarantineError`, `PermissionError`
- `monitoring/base.py` — has `MonitoringError`, `SACLError`, `AuditRuleError`

**The task is to consolidate these into one file**, not create from scratch. Move the best definitions into `src/openlabels/exceptions.py`, merge overlaps, and update every import across the codebase.

```python
# src/openlabels/exceptions.py
"""Unified exception hierarchy for OpenLabels."""


class OpenLabelsError(Exception):
    """Root exception for all OpenLabels errors."""
    pass


class ConfigError(OpenLabelsError):
    """Configuration or settings error."""
    pass


class DetectionError(OpenLabelsError):
    """Error during entity detection."""
    pass


class AdapterError(OpenLabelsError):
    """Error communicating with a storage adapter."""
    pass


class AdapterUnavailableError(AdapterError):
    """Adapter is temporarily unavailable (circuit breaker open)."""
    pass


class AuthError(OpenLabelsError):
    """Authentication or authorization error."""
    pass


class TokenExpiredError(AuthError):
    """JWT token has expired."""
    pass


class TokenInvalidError(AuthError):
    """JWT token is malformed or has invalid signature."""
    pass


class LabelingError(OpenLabelsError):
    """Error during label application."""
    pass


class RemediationError(OpenLabelsError):
    """Error during file remediation."""
    pass


class QuarantineError(RemediationError):
    """Error during file quarantine."""
    pass


class MonitoringError(OpenLabelsError):
    """Error setting up or reading monitoring."""
    pass


class NotFoundError(OpenLabelsError):
    """Requested resource not found."""
    def __init__(self, message: str, resource_type: str = "", resource_id: str = ""):
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(message)


class ConflictError(OpenLabelsError):
    """Resource conflict (duplicate, version mismatch)."""
    pass


class ValidationError(OpenLabelsError):
    """Input validation error."""
    pass


class ExtractionError(OpenLabelsError):
    """Error during text/content extraction from files."""
    pass


class GraphAPIError(AdapterError):
    """Microsoft Graph API error with response details."""
    def __init__(self, message: str, status_code: int | None = None,
                 error_code: str | None = None):
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(message)


class FilesystemError(AdapterError):
    """Local filesystem adapter error."""
    pass


class ModelLoadError(OpenLabelsError):
    """ML model loading failure."""
    pass


class JobError(OpenLabelsError):
    """Background job processing failure."""
    pass


class SACLError(MonitoringError):
    """Windows SACL audit rule error."""
    pass


class AuditRuleError(MonitoringError):
    """Linux auditd rule error."""
    pass


# --- API-layer exceptions (used by server error handlers) ---

class APIError(OpenLabelsError):
    """Base for API-specific errors with HTTP status code."""
    status_code: int = 500
    def __init__(self, message: str, status_code: int = 500):
        self.status_code = status_code
        super().__init__(message)


class BadRequestError(APIError):
    """400 Bad Request."""
    def __init__(self, message: str = "Bad request"):
        super().__init__(message, status_code=400)


class ForbiddenError(AuthError):
    """403 Forbidden — authenticated but insufficient permissions."""
    pass


class RateLimitError(APIError):
    """429 Too Many Requests."""
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, status_code=429)


class InternalError(APIError):
    """500 Internal Server Error."""
    def __init__(self, message: str = "Internal server error"):
        super().__init__(message, status_code=500)


class SecurityError(OpenLabelsError):
    """Security check failure (path traversal, injection, etc.)."""
    pass


class ConfigurationError(ConfigError):
    """Alias for ConfigError — matches existing core/exceptions.py naming."""
    pass
```

**Refactor scope:** Do this all at once, not phased:
1. Create `exceptions.py` by consolidating from `core/exceptions.py`, `server/exceptions.py`, `remediation/base.py`, and `monitoring/base.py`
2. Delete all per-module exception definitions after moving them
3. Replace every import and catch block across the entire codebase to use the unified hierarchy
4. No old exception classes should remain — the unified hierarchy is the single source of truth

### 14.2 Strict Type Safety (mypy)

**Complexity:** L
**Files to modify:** `pyproject.toml`, every module

Enable strict mypy across the entire project. Fix all type errors in one pass.

Add to `pyproject.toml`:
```toml
[tool.mypy]
python_version = "3.10"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
check_untyped_defs = true
no_implicit_reexport = true

# PySide6 stubs are incomplete, need explicit overrides
[[tool.mypy.overrides]]
module = "PySide6.*"
ignore_missing_imports = true
```

Create `src/openlabels/py.typed` marker file (empty).

**Refactor scope:** Run `mypy --strict src/openlabels/` and fix every error. Replace all bare `dict`, `list`, `tuple` with proper generics. Add return types to every function. No `# type: ignore` unless there's a genuine stubs issue (e.g., PySide6). This is a single effort, not a phased rollout.

### 14.3 Structured Logging Convention

**Complexity:** M
**Files to create:** `src/openlabels/log.py` (thin wrapper)

```python
# src/openlabels/log.py
"""Structured logging convention for OpenLabels.

Convention:
    logger.info("scan_started", extra={"scan_id": str(scan.id), "target": target.name})

NOT:
    logger.info(f"Scan {scan.id} started for target {target.name}")
"""

import logging
import json


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured log output."""

    # Standard LogRecord attributes to exclude from extra fields
    _BUILTIN_ATTRS = frozenset({
        "name", "msg", "args", "created", "relativeCreated", "exc_info",
        "exc_text", "stack_info", "lineno", "funcName", "pathname", "filename",
        "module", "thread", "threadName", "process", "processName", "getMessage",
        "levelname", "levelno", "msecs", "taskName", "message",
    })

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Automatically capture ALL extra fields (no hardcoded list)
        for key, value in record.__dict__.items():
            if key not in self._BUILTIN_ATTRS and not key.startswith("_"):
                log_entry[key] = value

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)
```

### 14.4 Testing Strategy

**Complexity:** L
**Files to create:** `tests/conftest.py` improvements, `tests/core/test_detectors_property.py`

Property-based testing for detectors:
```python
# tests/core/test_detectors_property.py
from hypothesis import given, strategies as st
from openlabels.core import detect

@given(st.text(min_size=0, max_size=10000))
def test_detect_never_crashes(text):
    """Detection should never crash on any input."""
    result = detect(text)
    assert isinstance(result.spans, list)
    for span in result.spans:
        assert 0 <= span.start <= span.end <= len(text)
        assert span.confidence >= 0
        assert span.confidence <= 1.0
        assert span.entity_type != ""

@given(st.from_regex(r'\d{3}-\d{2}-\d{4}', fullmatch=True))
def test_ssn_pattern_always_matches(ssn):
    """SSN-shaped strings should always be detected."""
    result = detect(f"My SSN is {ssn}")
    ssn_spans = [s for s in result.spans if s.entity_type in ("SSN", "US_SSN")]
    assert len(ssn_spans) >= 1
```

### 14.5 Database Connection Pool Configuration

**Complexity:** S
**Files to modify:** `server/db.py`, `server/config.py`

**Current state:** SQLAlchemy async engine is created with default pool settings. Under load (concurrent API requests + async detection threads + job workers), the defaults will cause "too many connections" errors or connection starvation.

**Plan:**

```python
# server/db.py
from sqlalchemy.ext.asyncio import create_async_engine

def create_engine(settings):
    return create_async_engine(
        settings.database_url,
        # Pool sizing — these numbers assume a single-server deployment.
        # Rule of thumb: pool_size = expected_concurrent_requests
        # max_overflow = burst headroom (temporary connections beyond pool_size)
        pool_size=20,          # Persistent connections in the pool
        max_overflow=10,       # Burst capacity (pool_size + max_overflow = 30 max)
        pool_timeout=30,       # Seconds to wait for a connection before erroring
        pool_recycle=1800,     # Recycle connections after 30min (prevents stale connections)
        pool_pre_ping=True,    # Verify connection is alive before using it
        echo=settings.debug,   # SQL logging in debug mode only
    )
```

Add to `server/config.py`:
```python
class DatabaseSettings(BaseSettings):
    url: str
    pool_size: int = 20
    max_overflow: int = 10
    pool_recycle: int = 1800
```

**Sizing rationale:**
- Detection thread pool uses 4 threads (Section 1.3), each may hold a connection
- Job worker(s) hold 1-2 connections for dequeue + status updates
- API request concurrency depends on uvicorn workers (default: 1 process, many async tasks)
- 20 pool + 10 overflow = 30 max connections, well within PostgreSQL's default 100 limit
- `pool_pre_ping=True` adds a tiny overhead per checkout but prevents "connection already closed" errors

### 14.6 Alembic Migration Discipline

**Complexity:** S
**Files to modify:** `alembic/env.py` (if not already configured)

Any schema changes (new columns for SpanContext, cursor pagination bookmarks, etc.) must go through Alembic migrations. Each section that modifies database models should include migration steps.

**Convention:**
```bash
# Generate migration after model changes
alembic revision --autogenerate -m "add span_context to scan_results"

# Review the generated migration before applying
alembic upgrade head
```

No raw `CREATE TABLE` or `ALTER TABLE` statements. Alembic is the single source of truth for schema evolution.

---

## Implementation Priority Order

Recommended order for maximum impact with minimum risk:

### Phase 0: Foundation (do first — blocks everything else)
1. **14.1** Unified Exception Hierarchy — M effort, consolidate 4 exception files into one
2. **14.2** mypy strict — L effort, catches bugs before they're written
3. **14.5** Database Connection Pool Configuration — S effort, prevents production issues
4. **3.1** Fix FilterConfig Mutation Bug — S effort, critical correctness fix
5. **8.2** Fix deprecated `asyncio.get_event_loop()` in labeling — S effort

### Phase 1: Critical Fixes
6. **6.1** Fix GUI Blocking HTTP Calls — L effort, highest user-visible impact
7. **6.2** Fix Hardcoded Tab Indices — S effort, do with 6.1
8. **6.3** Loading States — M effort, do with 6.1
9. **13.1** Client Persistent Connection — M effort, major perf improvement
10. **4.1** Thread-Safe JWKS Cache — S effort, concurrency fix
11. **4.2** JWKS Refresh on Key-Not-Found — S effort, do with 4.1
12. **10.1** Thread-Safe _watched_files — S effort, concurrency fix

### Phase 2: Architecture Upgrades
13. **2.3** Split app.py — M effort, improves maintainability
14. **2.1** Service Dependency Injection — M effort, cleaner route handlers
15. **1.1** Configuration-Driven Detector Setup — M effort, clean config
16. **1.2** Immutable Pattern Definitions — M effort, can parallel with 1.1
17. **3.4** Split Fat Protocol Interface — M effort, cleaner adapter contracts
18. **3.2** Adapter Lifecycle Management — M effort, do with 3.4
19. **2.4** Cursor Pagination — M effort, extend existing implementation
20. **2.5** Per-Tenant Rate Limiting — S effort, do with 2.4
21. **14.3** Structured Logging Convention — M effort

### Phase 3: Feature Additions
22. **5.3** `openlabels doctor` — M effort, huge DX improvement
23. **1.3** Async Detection — M effort, biggest server performance unlock
24. **8.1** Labeling Code Deduplication — M effort, maintainability
25. **8.3** Batch Labeling — M effort, do with 8.1
26. **9.1-9.3** Quarantine Manifest + Restore + Integrity — M effort combined
27. **4.3-4.4** Granular Token Errors + RBAC — S+M effort, security
28. **3.3** Adapter-Level Circuit Breaker — M effort
29. **3.5** Adapter Health Checks — S effort, do with 3.3
30. **7.1-7.2** Job max concurrency + callbacks — S effort combined
31. **13.2** Client Retry Logic — S effort

### Phase 4: Polish
32. **2.2** Response Schema Declarations — M effort, API documentation (requires 2.1)
33. **5.1-5.2** CLI Base + Output Formatter — M effort, CLI DX
34. **5.4** Progress Indicators — S effort, do with 5.1-5.2
35. **1.4-1.5** Confidence Calibration + Span Resolution — M effort, detection quality
36. **1.6** Structured Result Metadata — S effort, do with 1.4-1.5
37. **10.2-10.4** Monitoring improvements — M+L effort combined
38. **12.1-12.6** Windows tray improvements — M effort combined
39. **13.3-13.4** Client auto-pagination + API coverage — M effort
40. **2.6** OpenTelemetry Tracing — L effort, observability
41. **14.4** Testing Strategy (property-based tests) — L effort
42. **14.6** Alembic Migration Discipline — S effort (conventions, not code)

### Phase 5: New Capabilities
43. **11.x** Web UI rebuild — L effort, deferred (skip for now per project decision)

---

## Estimated Total Effort (excluding Web rebuild)

| Size | Count | Typical Effort |
|------|-------|----------------|
| S (Small) | 11 | 1-2 hours each |
| M (Medium) | 24 | 3-6 hours each |
| L (Large) | 4 | 8-16 hours each |

**Total estimated: ~140-220 hours of implementation work** (not counting Web rebuild)

This document is designed so each section can be handed to a Claude agent as a self-contained task. The priority order minimizes dependency conflicts and maximizes value delivered at each phase.

---

## Execution Guidelines

Rules for implementing this plan, whether by hand or by agent.

### Agent Execution Model

Each numbered section (e.g., "1.1 Configuration-Driven Detector Setup") is a self-contained task. When handing a section to a Claude agent:

1. **Give it the section text** plus the relevant source files it references
2. **One section per agent** — don't combine sections into a single prompt
3. **Agent must read actual source files before writing code** — the plans contain code *examples*, not copy-paste solutions. The agent must adapt to the real codebase
4. **Run tests after each section completes** — `pytest` should pass before moving to the next section

### Ordering Constraints

- **Phase 0 must complete before anything else starts.** The unified exception hierarchy (14.1) changes imports across every module. mypy strict (14.2) changes type annotations everywhere. These are global changes.
- **Within Phases 1-4, sections are independent** and can run in parallel — with one exception: Section 2.1 (Service DI) should complete before 2.2 (Response Schemas), since the schemas depend on the service layer structure.
- **Section 1.2 (Pattern Registry) and 1.3 (Async Detection) can run in parallel** — one changes pattern storage, the other changes the orchestrator's execution model. They touch different parts of the orchestrator.
- **Section 3.2 (Adapter Lifecycle) and 3.4 (Split Protocol) must be done together** — both modify `adapters/base.py` and the Protocol definition. 3.4 renames `Adapter` to `ReadAdapter`, and 3.2 adds lifecycle methods to it.
- **Sections 1.4/1.5 (Calibration/Spans) should be done after 1.6 (SpanContext)** — 1.4 and 1.5 construct new Span objects and must include the `context` field added by 1.6.
- **Section 5.1 (CLI Base) depends on 13.1 (Client Persistent Connection)** — the CLI decorator uses `async with OpenLabelsClient(...)` which requires the context manager from 13.1.

### Quality Standards

Every implementation must:
- Pass `mypy --strict` (after Phase 0 enables it)
- Have unit tests for new code (not necessarily 100% coverage, but all happy paths and key error paths)
- Use `datetime.now(timezone.utc)` not `datetime.utcnow()`
- Use `asyncio.get_running_loop()` not `asyncio.get_event_loop()`
- Import exceptions from `openlabels.exceptions` (after Phase 0)
- Not introduce any `# type: ignore` unless there's a genuine stubs issue (e.g., PySide6)

### What Not to Do

- **Don't add features not in this document.** If you think something is missing, flag it — don't implement it.
- **Don't introduce new dependencies without discussion.** The PyYAML decision (Section 1.2) was specifically rejected in favor of keeping patterns in Python.
- **Don't create backwards-compatibility shims.** Old code paths get deleted, not wrapped.
- **Don't phase rollouts.** Each section is a complete refactor — no "migrate gradually" or "support both old and new for now."
