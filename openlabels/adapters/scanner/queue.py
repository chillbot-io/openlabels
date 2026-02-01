"""
OCR Priority Queue.

Prioritizes OCR jobs based on metadata risk indicators.

Priority is calculated based on:
- Exposure level (PUBLIC = highest priority)
- Scan triggers (no encryption, low confidence high risk, stale data)
- File size (smaller files processed faster)

Priority Scale (0-100, higher = more urgent):
┌───────────────────────────────────────┬────────────┐
│ Factor                                │ Points     │
├───────────────────────────────────────┼────────────┤
│ Exposure: PRIVATE                     │ 0          │
│ Exposure: INTERNAL                    │ 10         │
│ Exposure: ORG_WIDE                    │ 30         │
│ Exposure: PUBLIC                      │ 50         │
├───────────────────────────────────────┼────────────┤
│ Trigger: NO_ENCRYPTION                │ +20        │
│ Trigger: LOW_CONFIDENCE_HIGH_RISK     │ +25        │
│ Trigger: STALE_DATA                   │ +5         │
│ Trigger: NO_LABELS                    │ +15        │
│ Trigger: PUBLIC_ACCESS                │ +10        │
├───────────────────────────────────────┼────────────┤
│ Small file (<1MB)                     │ +5         │
│ Large file (>100MB)                   │ -10        │
└───────────────────────────────────────┴────────────┘

Example:
    >>> from openlabels.adapters.scanner.queue import OCRPriorityQueue, OCRJob
    >>>
    >>> queue = OCRPriorityQueue()
    >>> queue.enqueue(OCRJob(
    ...     path="/data/scan.pdf",
    ...     exposure="PUBLIC",
    ...     triggers=["NO_ENCRYPTION"],
    ... ))
    >>> job = queue.dequeue()
    >>> # Process job...
"""

import heapq
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Callable, Any, Dict

from ...core.triggers import ScanTrigger
from .constants import MAX_QUEUE_SIZE, DEFAULT_MAX_RETRIES, MAX_FILE_SIZE_BYTES

logger = logging.getLogger(__name__)


@dataclass(order=True)
class OCRJob:
    """
    An OCR job in the priority queue.

    Jobs are ordered by priority (higher = more urgent).
    """
    # Sort key (negated priority for max-heap behavior with heapq)
    _sort_key: int = field(init=False, repr=False)

    # Job identification
    path: str = field(compare=False)
    job_id: str = field(default="", compare=False)

    # Priority inputs
    exposure: str = field(default="PRIVATE", compare=False)
    triggers: List[str] = field(default_factory=list, compare=False)
    size_bytes: int = field(default=0, compare=False)

    # Calculated priority (0-100)
    priority: int = field(default=0, compare=False)

    # Metadata
    created_at: str = field(default="", compare=False)
    attempts: int = field(default=0, compare=False)
    last_error: Optional[str] = field(default=None, compare=False)

    # User data
    metadata: Dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self):
        if not self.job_id:
            self.job_id = f"{int(time.time() * 1000)}-{hash(self.path) & 0xFFFF:04x}"
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if self.priority == 0:
            self.priority = calculate_priority(
                self.exposure,
                self.triggers,
                self.size_bytes,
            )
        # Negate for max-heap behavior (heapq is min-heap)
        self._sort_key = -self.priority

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "path": self.path,
            "exposure": self.exposure,
            "triggers": self.triggers,
            "size_bytes": self.size_bytes,
            "priority": self.priority,
            "created_at": self.created_at,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "metadata": self.metadata,
        }


class QueueStatus(Enum):
    """Queue status."""
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"


class OCRPriorityQueue:
    """
    Thread-safe priority queue for OCR jobs.

    Jobs are prioritized based on exposure level and risk triggers.
    Higher priority jobs are processed first.
    """

    def __init__(
        self,
        max_size: int = MAX_QUEUE_SIZE,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        """
        Initialize the priority queue.

        Args:
            max_size: Maximum queue size
            max_retries: Maximum retry attempts for failed jobs
        """
        self.max_size = max_size
        self.max_retries = max_retries

        self._heap: List[OCRJob] = []
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)

        # Track jobs by ID for deduplication
        self._job_ids: set = set()

        # Statistics
        self._stats = {
            "enqueued": 0,
            "dequeued": 0,
            "retried": 0,
            "failed": 0,
            "dropped": 0,
        }

        self._status = QueueStatus.RUNNING

    def enqueue(
        self,
        job: OCRJob,
        block: bool = True,
        timeout: Optional[float] = None,
    ) -> bool:
        """
        Add a job to the queue.

        Args:
            job: Job to enqueue
            block: Block if queue is full
            timeout: Timeout for blocking

        Returns:
            True if enqueued, False if dropped

        Raises:
            Full: If queue is full and block=False
        """
        with self._not_full:
            # Check for duplicate
            if job.job_id in self._job_ids:
                logger.debug(f"Duplicate job ignored: {job.job_id}")
                return False

            # Wait for space if blocking
            if len(self._heap) >= self.max_size:
                if not block:
                    self._stats["dropped"] += 1
                    return False

                if not self._not_full.wait(timeout):
                    self._stats["dropped"] += 1
                    return False

            # Check again after wait
            if len(self._heap) >= self.max_size:
                self._stats["dropped"] += 1
                return False

            heapq.heappush(self._heap, job)
            self._job_ids.add(job.job_id)
            self._stats["enqueued"] += 1

            self._not_empty.notify()
            return True

    def dequeue(
        self,
        block: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[OCRJob]:
        """
        Get the highest priority job from the queue.

        Args:
            block: Block if queue is empty
            timeout: Timeout for blocking

        Returns:
            Highest priority job, or None if timeout/empty
        """
        with self._not_empty:
            while self._status == QueueStatus.PAUSED:
                if not block:
                    return None
                self._not_empty.wait(timeout=1.0)

            if not self._heap:
                if not block:
                    return None

                if not self._not_empty.wait(timeout):
                    return None

            if not self._heap:
                return None

            job = heapq.heappop(self._heap)
            self._job_ids.discard(job.job_id)
            self._stats["dequeued"] += 1

            self._not_full.notify()
            return job

    def requeue(self, job: OCRJob, error: Optional[str] = None) -> bool:
        """
        Requeue a failed job for retry.

        Args:
            job: Job to retry
            error: Error message from last attempt

        Returns:
            True if requeued, False if max retries exceeded
        """
        job.attempts += 1
        job.last_error = error

        if job.attempts >= self.max_retries:
            self._stats["failed"] += 1
            logger.warning(f"Job {job.job_id} failed after {job.attempts} attempts")
            return False

        # Reduce priority slightly on retry
        job.priority = max(0, job.priority - 5)
        job._sort_key = -job.priority

        self._stats["retried"] += 1

        # Remove from job_ids before re-enqueueing
        with self._lock:
            self._job_ids.discard(job.job_id)

        return self.enqueue(job)

    def peek(self) -> Optional[OCRJob]:
        """Peek at highest priority job without removing it."""
        with self._lock:
            if self._heap:
                return self._heap[0]
            return None

    def clear(self) -> int:
        """Clear all jobs from the queue."""
        with self._lock:
            count = len(self._heap)
            self._heap.clear()
            self._job_ids.clear()
            self._not_full.notify_all()
            return count

    def pause(self) -> None:
        """Pause queue processing."""
        with self._lock:
            self._status = QueueStatus.PAUSED
            logger.info("OCR queue paused")

    def resume(self) -> None:
        """Resume queue processing."""
        with self._not_empty:
            self._status = QueueStatus.RUNNING
            self._not_empty.notify_all()
            logger.info("OCR queue resumed")

    def stop(self) -> None:
        """Stop the queue."""
        with self._lock:
            self._status = QueueStatus.STOPPED

    @property
    def size(self) -> int:
        """Current queue size."""
        with self._lock:
            return len(self._heap)

    @property
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        with self._lock:
            return len(self._heap) == 0

    @property
    def is_full(self) -> bool:
        """Check if queue is full."""
        with self._lock:
            return len(self._heap) >= self.max_size

    @property
    def status(self) -> QueueStatus:
        """Current queue status. MED-009: accessed under lock."""
        with self._lock:
            return self._status

    @property
    def stats(self) -> dict:
        """Queue statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_size": len(self._heap),
                "max_size": self.max_size,
                "status": self._status.value,
            }



# --- Priority Calculation ---


def calculate_priority(
    exposure: str,
    triggers: List[str],
    size_bytes: int = 0,
) -> int:
    """
    Calculate job priority based on risk factors.

    Args:
        exposure: Exposure level string (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)
        triggers: List of trigger names
        size_bytes: File size in bytes

    Returns:
        Priority score 0-100 (higher = more urgent)
    """
    priority = 0

    # Exposure-based priority
    exposure_upper = exposure.upper() if isinstance(exposure, str) else "PRIVATE"
    exposure_priorities = {
        "PRIVATE": 0,
        "INTERNAL": 10,
        "ORG_WIDE": 30,
        "PUBLIC": 50,
    }
    priority += exposure_priorities.get(exposure_upper, 0)

    # Trigger-based boosts
    trigger_boosts = {
        "NO_ENCRYPTION": 20,
        "no_encryption": 20,
        "LOW_CONFIDENCE_HIGH_RISK": 25,
        "low_conf_high_risk": 25,
        "STALE_DATA": 5,
        "stale_data": 5,
        "NO_LABELS": 15,
        "no_labels": 15,
        "PUBLIC_ACCESS": 10,
        "public_access": 10,
        "ORG_WIDE": 5,
        "org_wide": 5,
    }

    for trigger in triggers:
        if isinstance(trigger, ScanTrigger):
            trigger = trigger.value
        priority += trigger_boosts.get(trigger, 0)

    # Size adjustments
    if size_bytes > 0:
        if size_bytes < 1024 * 1024:  # < 1MB - boost small files
            priority += 5
        elif size_bytes > MAX_FILE_SIZE_BYTES:  # Deprioritize large files
            priority -= 10

    # Cap at 100
    return min(100, max(0, priority))


def calculate_priority_from_context(
    context: Any,  # NormalizedContext
    triggers: Optional[List[ScanTrigger]] = None,
) -> int:
    """
    Calculate priority from a NormalizedContext.

    Args:
        context: NormalizedContext object
        triggers: Optional list of ScanTriggers

    Returns:
        Priority score 0-100
    """
    exposure = context.exposure
    if hasattr(exposure, 'name'):
        exposure = exposure.name

    trigger_names = []
    if triggers:
        trigger_names = [t.value if isinstance(t, ScanTrigger) else t for t in triggers]

    # Add implicit triggers based on context
    if context.encryption == "none":
        trigger_names.append("NO_ENCRYPTION")

    if not context.has_classification:
        trigger_names.append("NO_LABELS")

    return calculate_priority(
        exposure=exposure,
        triggers=trigger_names,
        size_bytes=context.size_bytes,
    )



# --- Queue Worker ---


class OCRQueueWorker:
    """
    Background worker that processes OCR jobs from a queue.

    Example:
        >>> queue = OCRPriorityQueue()
        >>> worker = OCRQueueWorker(queue, process_fn=run_ocr)
        >>> worker.start()
        >>> # ... enqueue jobs ...
        >>> worker.stop()
    """

    def __init__(
        self,
        queue: OCRPriorityQueue,
        process_fn: Callable[[OCRJob], Any],
        num_workers: int = 1,
        on_complete: Optional[Callable[[OCRJob, Any], None]] = None,
        on_error: Optional[Callable[[OCRJob, Exception], None]] = None,
    ):
        """
        Initialize worker.

        Args:
            queue: Queue to process
            process_fn: Function to call for each job
            num_workers: Number of worker threads
            on_complete: Callback on successful completion
            on_error: Callback on error
        """
        self.queue = queue
        self.process_fn = process_fn
        self.num_workers = num_workers
        self.on_complete = on_complete
        self.on_error = on_error

        self._workers: List[threading.Thread] = []
        self._running = False

    def start(self) -> None:
        """Start worker threads."""
        if self._running:
            return

        self._running = True

        for i in range(self.num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"OCRWorker-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)

        logger.info(f"Started {self.num_workers} OCR worker(s)")

    def stop(self, wait: bool = True, timeout: float = 5.0) -> None:
        """Stop worker threads."""
        self._running = False
        self.queue.stop()

        if wait:
            for t in self._workers:
                t.join(timeout=timeout)

        self._workers.clear()
        logger.info("OCR workers stopped")

    def _worker_loop(self) -> None:
        """Main worker loop."""
        while self._running:
            try:
                job = self.queue.dequeue(timeout=1.0)
                if job is None:
                    continue

                try:
                    result = self.process_fn(job)
                    if self.on_complete:
                        self.on_complete(job, result)

                except Exception as e:
                    logger.error(f"OCR job {job.job_id} failed: {e}")

                    if self.on_error:
                        self.on_error(job, e)

                    # Attempt retry
                    self.queue.requeue(job, error=str(e))

            except Exception as e:
                logger.error(f"Worker error: {e}")
                time.sleep(1.0)

    @property
    def is_running(self) -> bool:
        """Check if workers are running."""
        return self._running



# --- Exports ---


__all__ = [
    "OCRJob",
    "OCRPriorityQueue",
    "QueueStatus",
    "OCRQueueWorker",
    "calculate_priority",
    "calculate_priority_from_context",
]
