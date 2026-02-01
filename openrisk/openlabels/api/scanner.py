"""
Async scanner service for background file scanning.

Runs scans in a separate thread pool and streams results via async queues.
"""

import asyncio
import os
import stat as stat_module
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Dict, Any, List, AsyncIterator
import threading

from .models import (
    ScanStatus, ScanTargetType, ScanRequest, ScanResult,
    ScanProgress, ScanJob, ScanEvent, S3Credentials,
)


class AsyncScanner:
    """Async scanner that runs file scans in background threads.

    Results are streamed via async queues for real-time updates.
    """

    def __init__(self, max_workers: int = 8):
        self._max_workers = max_workers
        self._jobs: Dict[str, ScanJob] = {}
        self._results: Dict[str, List[ScanResult]] = {}
        self._queues: Dict[str, asyncio.Queue] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()

    def _get_executor(self) -> ThreadPoolExecutor:
        """Get or create the thread pool executor."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self._max_workers)
        return self._executor

    async def start_scan(self, request: ScanRequest) -> ScanJob:
        """Start a new scan job."""
        job_id = str(uuid.uuid4())[:8]
        now = time.time()

        job = ScanJob(
            job_id=job_id,
            status=ScanStatus.PENDING,
            path=request.path,
            target_type=request.target_type,
            progress=ScanProgress(current=0, total=0, percent=0.0),
            created_at=now,
        )

        with self._lock:
            self._jobs[job_id] = job
            self._results[job_id] = []
            self._queues[job_id] = asyncio.Queue()
            self._stop_events[job_id] = threading.Event()

        # Start scan in background
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            self._get_executor(),
            self._run_scan,
            job_id,
            request,
            loop,
        )

        return job

    def _run_scan(self, job_id: str, request: ScanRequest, loop: asyncio.AbstractEventLoop):
        """Run the scan in a background thread."""
        try:
            job = self._jobs[job_id]
            job.status = ScanStatus.RUNNING
            job.started_at = time.time()

            # Emit status change
            self._emit_event(job_id, loop, "status", {"status": "running"})

            if request.target_type == ScanTargetType.S3:
                self._scan_s3(job_id, request, loop)
            else:
                self._scan_local(job_id, request, loop)

            # Mark complete if not cancelled
            if job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.COMPLETED
                job.completed_at = time.time()
                self._emit_event(job_id, loop, "complete", {
                    "results_count": job.results_count,
                    "duration": job.completed_at - job.started_at,
                })

        except Exception as e:
            job = self._jobs.get(job_id)
            if job:
                job.status = ScanStatus.FAILED
                job.error = str(e)
                job.completed_at = time.time()
                self._emit_event(job_id, loop, "error", {"error": str(e)})

    def _emit_event(self, job_id: str, loop: asyncio.AbstractEventLoop,
                    event_type: str, data: Dict[str, Any]):
        """Emit an event to the job's queue."""
        queue = self._queues.get(job_id)
        if queue:
            event = ScanEvent(event=event_type, data=data)
            asyncio.run_coroutine_threadsafe(queue.put(event), loop)

    def _scan_local(self, job_id: str, request: ScanRequest, loop: asyncio.AbstractEventLoop):
        """Scan local filesystem."""
        from openlabels import Client
        from openlabels.adapters.scanner import detect_file as scanner_detect
        from openlabels.core.labels import generate_label_id, compute_content_hash_file

        path = Path(request.path)
        stop_event = self._stop_events[job_id]
        job = self._jobs[job_id]

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        # Collect files
        files = self._collect_files(path, stop_event)
        total = len(files)

        job.progress = ScanProgress(current=0, total=total, percent=0.0)
        self._emit_event(job_id, loop, "progress", {
            "current": 0, "total": total, "percent": 0.0
        })

        if total == 0:
            return

        # Create client
        client = Client()

        # Batch tracking for efficient event emission
        batch: List[Dict[str, Any]] = []
        batch_size = 50
        last_progress_time = 0.0
        progress_interval = 0.1  # seconds

        for i, file_path in enumerate(files):
            if stop_event.is_set():
                job.status = ScanStatus.CANCELLED
                break

            # Scan file
            result = self._scan_file(file_path, client, scanner_detect,
                                     generate_label_id, compute_content_hash_file)

            # Store result
            with self._lock:
                self._results[job_id].append(result)
                job.results_count += 1

            # Batch results
            batch.append(result.model_dump())

            # Emit batch when full
            if len(batch) >= batch_size:
                self._emit_event(job_id, loop, "batch", {"results": batch})
                batch = []

            # Throttled progress updates
            current_time = time.time()
            if current_time - last_progress_time >= progress_interval or i == total - 1:
                percent = ((i + 1) / total) * 100
                job.progress = ScanProgress(current=i + 1, total=total, percent=percent)
                self._emit_event(job_id, loop, "progress", {
                    "current": i + 1, "total": total, "percent": percent
                })
                last_progress_time = current_time

        # Flush remaining batch
        if batch:
            self._emit_event(job_id, loop, "batch", {"results": batch})

    def _collect_files(self, path: Path, stop_event: threading.Event) -> List[Path]:
        """Collect all files to scan."""
        files = []

        if path.is_file():
            return [path]

        try:
            for item in path.rglob("*"):
                if stop_event.is_set():
                    break
                try:
                    st = item.lstat()
                    if stat_module.S_ISREG(st.st_mode):
                        if not any(part.startswith(".") for part in item.parts):
                            if not any(excl in str(item) for excl in ["node_modules", "__pycache__", ".git"]):
                                files.append(item)
                except OSError:
                    continue
        except PermissionError:
            pass

        return files

    def _scan_file(self, file_path: Path, client, scanner_detect,
                   generate_label_id, compute_content_hash_file) -> ScanResult:
        """Scan a single file."""
        try:
            # Get file size
            try:
                size = file_path.stat().st_size
            except OSError:
                size = 0

            # Generate label ID and content hash
            label_id = generate_label_id()
            try:
                content_hash = compute_content_hash_file(str(file_path))
            except Exception:
                content_hash = None

            # Detect entities
            detection = scanner_detect(file_path)
            entities = detection.entity_counts

            # Extract spans with context
            spans_data = []
            text = detection.text
            for span in detection.spans:
                ctx_start = max(0, span.start - 50)
                ctx_end = min(len(text), span.end + 50)
                spans_data.append({
                    "start": span.start,
                    "end": span.end,
                    "text": span.text,
                    "entity_type": span.entity_type,
                    "confidence": span.confidence,
                    "detector": span.detector,
                    "context_before": text[ctx_start:span.start],
                    "context_after": text[span.end:ctx_end],
                })

            # Score the file
            score_result = client.score_file(file_path)
            tier = score_result.tier.value if hasattr(score_result.tier, 'value') else str(score_result.tier)

            return ScanResult(
                path=str(file_path),
                size=size,
                label_id=label_id,
                content_hash=content_hash,
                label_embedded=False,
                score=score_result.score,
                tier=tier,
                entities=entities,
                spans=spans_data,
                exposure="PRIVATE",
            )

        except Exception as e:
            return ScanResult(
                path=str(file_path),
                error=str(e),
            )

    def _scan_s3(self, job_id: str, request: ScanRequest, loop: asyncio.AbstractEventLoop):
        """Scan S3 bucket."""
        # S3 scanning implementation would go here
        # Similar to local but downloads to temp files first
        raise NotImplementedError("S3 scanning via API not yet implemented")

    async def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Get job status."""
        return self._jobs.get(job_id)

    async def get_results(self, job_id: str, offset: int = 0,
                          limit: int = 100) -> List[ScanResult]:
        """Get scan results."""
        results = self._results.get(job_id, [])
        return results[offset:offset + limit]

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a running scan."""
        stop_event = self._stop_events.get(job_id)
        if stop_event:
            stop_event.set()
            job = self._jobs.get(job_id)
            if job and job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.CANCELLED
                job.completed_at = time.time()
            return True
        return False

    async def stream_events(self, job_id: str) -> AsyncIterator[ScanEvent]:
        """Stream scan events for a job."""
        queue = self._queues.get(job_id)
        if not queue:
            return

        job = self._jobs.get(job_id)

        while True:
            # Check if job is done
            if job and job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                # Drain any remaining events
                while not queue.empty():
                    try:
                        event = queue.get_nowait()
                        yield event
                    except asyncio.QueueEmpty:
                        break
                break

            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue

    async def cleanup_job(self, job_id: str):
        """Clean up resources for a completed job."""
        with self._lock:
            self._jobs.pop(job_id, None)
            self._results.pop(job_id, None)
            self._queues.pop(job_id, None)
            self._stop_events.pop(job_id, None)

    def shutdown(self):
        """Shutdown the scanner."""
        # Cancel all running jobs
        for stop_event in self._stop_events.values():
            stop_event.set()

        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None


# Global scanner instance
_scanner: Optional[AsyncScanner] = None


def get_scanner() -> AsyncScanner:
    """Get or create the global scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = AsyncScanner()
    return _scanner
