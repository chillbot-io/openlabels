"""
Async job management for file processing.

Tracks file upload jobs through their lifecycle:
uploading → queued → extracting → ocr → detecting → complete/failed
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..types import Span

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """File processing job status."""
    UPLOADING = "uploading"      # File being received
    QUEUED = "queued"            # Waiting to process
    LOADING_MODELS = "loading_models"  # Waiting for models to initialize
    PROCESSING = "processing"    # Metadata stripping, face detection
    EXTRACTING = "extracting"    # Text extraction in progress
    OCR = "ocr"                  # OCR in progress (if needed)
    DETECTING = "detecting"      # PHI detection running
    COMPLETE = "complete"        # Ready for use
    FAILED = "failed"            # Error occurred


@dataclass
class FileJob:
    """
    Tracks async file processing.
    
    Created when upload starts, updated as processing progresses.
    Results populated on completion.
    """
    # Identity
    id: str
    filename: str
    content_type: str
    size_bytes: int
    
    # Status
    status: JobStatus = JobStatus.QUEUED
    progress: float = 0.0  # 0.0 - 1.0
    status_message: Optional[str] = None  # Human-readable status
    
    # Page tracking (for multi-page docs)
    pages_total: Optional[int] = None
    pages_processed: Optional[int] = None
    
    # Error info
    error: Optional[str] = None
    
    # Results (populated on completion)
    extracted_text: Optional[str] = None
    redacted_text: Optional[str] = None
    spans: Optional[List["Span"]] = None
    phi_count: Optional[int] = None
    
    # Image redaction
    has_redacted_image: bool = False  # True if redacted image available for download
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    conversation_id: Optional[str] = None
    
    # Processing metadata
    processing_time_ms: Optional[float] = None
    ocr_confidence: Optional[float] = None
    metadata: Dict = field(default_factory=dict)  # Image protection results
    
    def update_status(self, status: JobStatus, progress: float = None) -> None:
        """Update job status and timestamp."""
        self.status = status
        if progress is not None:
            self.progress = progress
        self.updated_at = datetime.now(timezone.utc)
    
    def set_error(self, error: str) -> None:
        """Mark job as failed with error message."""
        self.status = JobStatus.FAILED
        self.error = error
        self.updated_at = datetime.now(timezone.utc)
    
    def set_complete(
        self,
        extracted_text: str,
        redacted_text: str,
        spans: List["Span"],
        processing_time_ms: float,
        ocr_confidence: float = None,
        has_redacted_image: bool = False,
    ) -> None:
        """Mark job as complete with results."""
        self.status = JobStatus.COMPLETE
        self.progress = 1.0
        self.extracted_text = extracted_text
        self.redacted_text = redacted_text
        self.spans = spans
        self.phi_count = len(spans)
        self.processing_time_ms = processing_time_ms
        self.ocr_confidence = ocr_confidence
        self.has_redacted_image = has_redacted_image
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "job_id": self.id,
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "status": self.status.value,
            "progress": self.progress,
            "pages_total": self.pages_total,
            "pages_processed": self.pages_processed,
            "error": self.error,
            "phi_count": self.phi_count,
            "processing_time_ms": self.processing_time_ms,
            "has_redacted_image": self.has_redacted_image,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "conversation_id": self.conversation_id,
        }
    
    def to_result_dict(self) -> Optional[dict]:
        """Convert to result dictionary (only if complete)."""
        if self.status != JobStatus.COMPLETE:
            return None
        
        return {
            "job_id": self.id,
            "filename": self.filename,
            "extracted_text": self.extracted_text,  # Raw OCR text for pipeline
            "redacted_text": self.redacted_text,    # Tokenized (for display only)
            "spans": [
                {
                    "start": s.start,
                    "end": s.end,
                    "text": s.text,
                    "entity_type": s.entity_type,
                    "confidence": s.confidence,
                    "detector": s.detector,
                    "token": s.token,
                }
                for s in (self.spans or [])
            ],
            "pages": self.pages_total or 1,
            "processing_time_ms": self.processing_time_ms,
            "ocr_confidence": self.ocr_confidence,
            "has_redacted_image": self.has_redacted_image,
        }


class JobManager:
    """
    Manages file processing jobs.
    
    Thread-safe job tracking with in-memory storage.
    Jobs are persisted to database on completion.
    """
    
    def __init__(self, max_jobs: int = 100):
        """
        Initialize job manager.
        
        Args:
            max_jobs: Maximum number of jobs to keep in memory
        """
        self._jobs: Dict[str, FileJob] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs
    
    def create_job(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        conversation_id: Optional[str] = None,
    ) -> FileJob:
        """
        Create a new file processing job.
        
        Args:
            filename: Original filename
            content_type: MIME type
            size_bytes: File size
            conversation_id: Optional conversation to link to
            
        Returns:
            New FileJob instance
        """
        job_id = str(uuid.uuid4())
        
        job = FileJob(
            id=job_id,
            filename=filename,
            content_type=content_type,
            size_bytes=size_bytes,
            conversation_id=conversation_id,
        )
        
        with self._lock:
            # Evict old completed jobs if at capacity
            if len(self._jobs) >= self._max_jobs:
                self._evict_old_jobs()
            
            self._jobs[job_id] = job
        
        logger.info(f"Created job {job_id} for {filename}")
        return job
    
    def get_job(self, job_id: str) -> Optional[FileJob]:
        """Get job by ID."""
        with self._lock:
            return self._jobs.get(job_id)

    def get_jobs_batch(self, job_ids: List[str]) -> Dict[str, FileJob]:
        """
        Get multiple jobs by ID in a single operation.

        Args:
            job_ids: List of job IDs to fetch

        Returns:
            Dict mapping job_id to FileJob (missing jobs not included)
        """
        with self._lock:
            return {
                job_id: self._jobs[job_id]
                for job_id in job_ids
                if job_id in self._jobs
            }
    
    def update_job(
        self,
        job_id: str,
        status: Optional[JobStatus] = None,
        progress: Optional[float] = None,
        pages_total: Optional[int] = None,
        pages_processed: Optional[int] = None,
        status_message: Optional[str] = None,
    ) -> Optional[FileJob]:
        """
        Update job status.
        
        Args:
            job_id: Job ID
            status: New status
            progress: Progress (0.0 - 1.0)
            pages_total: Total pages (for multi-page docs)
            pages_processed: Pages processed so far
            status_message: Human-readable status message
            
        Returns:
            Updated job, or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            
            if status is not None:
                job.status = status
            if progress is not None:
                job.progress = progress
            if pages_total is not None:
                job.pages_total = pages_total
            if pages_processed is not None:
                job.pages_processed = pages_processed
            if status_message is not None:
                job.status_message = status_message
            
            job.updated_at = datetime.now(timezone.utc)
            return job
    
    def complete_job(
        self,
        job_id: str,
        extracted_text: str,
        redacted_text: str,
        spans: List["Span"],
        processing_time_ms: float,
        ocr_confidence: float = None,
        has_redacted_image: bool = False,
    ) -> Optional[FileJob]:
        """
        Mark job as complete with results.
        
        Args:
            job_id: Job ID
            extracted_text: Raw extracted text
            redacted_text: Text with PHI tokenized
            spans: Detected PHI spans
            processing_time_ms: Processing time
            ocr_confidence: Average OCR confidence (if OCR was used)
            has_redacted_image: Whether a redacted image is available for download
            
        Returns:
            Completed job, or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            
            job.set_complete(
                extracted_text=extracted_text,
                redacted_text=redacted_text,
                spans=spans,
                processing_time_ms=processing_time_ms,
                ocr_confidence=ocr_confidence,
                has_redacted_image=has_redacted_image,
            )
            
            logger.info(
                f"Job {job_id} complete: {job.phi_count} PHI entities, "
                f"{processing_time_ms:.0f}ms"
                f"{', has redacted image' if has_redacted_image else ''}"
            )
            return job
    
    def fail_job(self, job_id: str, error: str) -> Optional[FileJob]:
        """
        Mark job as failed.
        
        Args:
            job_id: Job ID
            error: Error message
            
        Returns:
            Failed job, or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            
            job.set_error(error)
            logger.error(f"Job {job_id} failed: {error}")
            return job
    
    def list_jobs(
        self,
        conversation_id: Optional[str] = None,
        status: Optional[JobStatus] = None,
        limit: int = 50,
    ) -> List[FileJob]:
        """
        List jobs with optional filters.
        
        Args:
            conversation_id: Filter by conversation
            status: Filter by status
            limit: Maximum jobs to return
            
        Returns:
            List of matching jobs, newest first
        """
        with self._lock:
            jobs = list(self._jobs.values())
        
        # Apply filters
        if conversation_id:
            jobs = [j for j in jobs if j.conversation_id == conversation_id]
        if status:
            jobs = [j for j in jobs if j.status == status]
        
        # Sort by created_at descending
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        
        return jobs[:limit]
    
    def delete_job(self, job_id: str) -> bool:
        """
        Delete a job.
        
        Args:
            job_id: Job ID
            
        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                return True
            return False
    
    def _evict_old_jobs(self) -> None:
        """Evict oldest completed jobs to make room."""
        # Get completed jobs sorted by updated_at
        completed = [
            j for j in self._jobs.values() 
            if j.status in (JobStatus.COMPLETE, JobStatus.FAILED)
        ]
        completed.sort(key=lambda j: j.updated_at)
        
        # Evict oldest quarter
        to_evict = len(completed) // 4
        if to_evict < 1:
            to_evict = 1
        
        for job in completed[:to_evict]:
            del self._jobs[job.id]
            logger.debug(f"Evicted old job {job.id}")
