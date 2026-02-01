"""
Pydantic models for the Scanner API.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Status of a scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTargetType(str, Enum):
    """Type of scan target."""
    LOCAL = "local"
    SMB = "smb"
    NFS = "nfs"
    S3 = "s3"


class S3Credentials(BaseModel):
    """AWS S3 credentials for scanning S3 buckets."""
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    region: Optional[str] = None
    profile: Optional[str] = None


class ScanRequest(BaseModel):
    """Request to start a new scan."""
    path: str = Field(..., description="Path or S3 URI to scan")
    target_type: ScanTargetType = Field(default=ScanTargetType.LOCAL)
    s3_credentials: Optional[S3Credentials] = None
    max_workers: int = Field(default=8, ge=1, le=32)


class ScanResult(BaseModel):
    """Result for a single scanned file."""
    path: str
    size: int = 0
    label_id: Optional[str] = None
    content_hash: Optional[str] = None
    label_embedded: bool = False
    score: float = 0
    tier: str = "UNKNOWN"
    entities: Dict[str, int] = Field(default_factory=dict)
    spans: List[Dict[str, Any]] = Field(default_factory=list)
    exposure: str = "PRIVATE"
    error: Optional[str] = None


class ScanProgress(BaseModel):
    """Progress update for a scan."""
    current: int
    total: int
    percent: float = 0.0


class ScanJob(BaseModel):
    """Information about a scan job."""
    job_id: str
    status: ScanStatus
    path: str
    target_type: ScanTargetType
    progress: ScanProgress
    results_count: int = 0
    error: Optional[str] = None
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None


class ScanEvent(BaseModel):
    """Server-sent event for scan updates."""
    event: str  # "progress", "result", "batch", "complete", "error"
    data: Dict[str, Any]
