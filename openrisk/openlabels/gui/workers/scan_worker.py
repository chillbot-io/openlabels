"""
Background scan worker.

Performs file scanning in a separate thread to keep the UI responsive.
Uses parallel processing for improved performance on multi-core systems.
Implements batched signal emission to prevent UI thread flooding.
"""

import os
import stat as stat_module
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Dict, Any, List

from PySide6.QtCore import QThread, Signal

# Default number of parallel workers (use CPU count, capped at 8)
DEFAULT_WORKERS = min(os.cpu_count() or 4, 8)

# Batching configuration
BATCH_SIZE = 50  # Emit results in batches of this size
BATCH_INTERVAL_MS = 100  # Or emit after this many milliseconds
PROGRESS_THROTTLE_MS = 50  # Minimum interval between progress updates (20 fps max)


class ScanWorker(QThread):
    """Background worker for scanning files with parallel processing.

    Uses batched signal emission to keep the UI responsive during large scans.
    Results are collected and emitted in batches rather than one at a time.
    """

    # Signals
    progress = Signal(int, int)      # current, total (throttled)
    result = Signal(dict)            # single scan result (legacy, for small scans)
    batch_results = Signal(list)     # batched results for better performance
    finished = Signal()              # scan complete
    error = Signal(str)              # error message

    def __init__(
        self,
        target_type: str,
        path: str,
        s3_credentials: Optional[Dict[str, str]] = None,
        parent=None,
        max_workers: int = DEFAULT_WORKERS,
        options: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(parent)
        self._target_type = target_type
        self._path = path
        self._s3_credentials = s3_credentials
        self._max_workers = max_workers
        # HIGH-001: Use threading.Event for thread-safe stop signaling
        self._stop_event = threading.Event()
        # Reuse single Client instance across scan operations
        self._client = None
        # Thread pool for parallel scanning
        self._executor: Optional[ThreadPoolExecutor] = None

        # Batching state for UI responsiveness
        self._result_batch: List[Dict[str, Any]] = []
        self._batch_lock = threading.Lock()
        self._last_batch_time = 0.0
        self._last_progress_time = 0.0

        # Advanced options
        opts = options or {}
        self._recursive = opts.get("recursive", True)
        self._follow_symlinks = opts.get("follow_symlinks", False)
        self._include_hidden = opts.get("include_hidden", False)
        self._extensions = opts.get("extensions")  # List or None (all)
        self._exclude_patterns = opts.get("exclude_patterns", ["node_modules", "__pycache__", ".git"])
        self._max_file_size_bytes = (opts.get("max_file_size_mb") or 0) * 1024 * 1024
        self._auto_embed = opts.get("auto_embed", True)
        self._exposure = opts.get("exposure", "PRIVATE")

    def stop(self):
        """Request the worker to stop (thread-safe)."""
        self._stop_event.set()
        # Shutdown executor if running
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def run(self):
        """Main worker thread."""
        try:
            if self._target_type == "s3":
                self._scan_s3()
            else:
                self._scan_local()
        except Exception as e:
            self.error.emit(str(e))

    def _get_client(self):
        """Get or create the shared Client instance."""
        if self._client is None:
            from openlabels import Client
            self._client = Client()
        return self._client

    def _queue_result(self, result: Dict[str, Any]):
        """Queue a result for batched emission.

        Results are collected and emitted in batches to prevent
        flooding the UI thread with individual signal emissions.
        """
        with self._batch_lock:
            self._result_batch.append(result)
            current_time = time.time() * 1000  # ms

            # Emit batch if size threshold reached or time elapsed
            should_emit = (
                len(self._result_batch) >= BATCH_SIZE or
                (current_time - self._last_batch_time) >= BATCH_INTERVAL_MS
            )

            if should_emit and self._result_batch:
                batch = self._result_batch
                self._result_batch = []
                self._last_batch_time = current_time
                self.batch_results.emit(batch)

    def _flush_results(self):
        """Flush any remaining results in the batch."""
        with self._batch_lock:
            if self._result_batch:
                batch = self._result_batch
                self._result_batch = []
                self.batch_results.emit(batch)

    def _throttled_progress(self, current: int, total: int):
        """Emit progress signal with throttling to prevent UI flooding.

        Limits progress updates to ~20 per second max.
        """
        current_time = time.time() * 1000  # ms

        # Always emit on first update, last update, or if enough time elapsed
        if (current == 1 or current == total or
                (current_time - self._last_progress_time) >= PROGRESS_THROTTLE_MS):
            self._last_progress_time = current_time
            self.progress.emit(current, total)

    def _extract_spans_with_context(self, detection, context_chars: int = 50) -> List[Dict[str, Any]]:
        """Extract spans with surrounding context for vault storage."""
        spans_data = []
        text = detection.text

        for span in detection.spans:
            # Extract context before
            ctx_start = max(0, span.start - context_chars)
            context_before = text[ctx_start:span.start]

            # Extract context after
            ctx_end = min(len(text), span.end + context_chars)
            context_after = text[span.end:ctx_end]

            spans_data.append({
                "start": span.start,
                "end": span.end,
                "text": span.text,
                "entity_type": span.entity_type,
                "confidence": span.confidence,
                "detector": span.detector,
                "context_before": context_before,
                "context_after": context_after,
            })

        return spans_data

    def _scan_local(self):
        """Scan local/SMB/NFS path with parallel processing."""
        path = Path(self._path)

        if not path.exists():
            self.error.emit(f"Path not found: {path}")
            return

        # Collect files first
        files = self._collect_files(path)
        total = len(files)

        if total == 0:
            self.progress.emit(0, 0)
            self.finished.emit()
            return

        self.progress.emit(0, total)

        # Use parallel processing for multiple files
        if total == 1 or self._max_workers == 1:
            # Single file or single-threaded mode
            self._scan_sequential(files, total)
        else:
            # Parallel scanning
            self._scan_parallel(files, total)

        self.finished.emit()

    def _scan_sequential(self, files: List[Path], total: int):
        """Scan files sequentially (fallback mode).

        Still uses batching for UI responsiveness even in sequential mode.
        """
        client = self._get_client()

        for i, file_path in enumerate(files):
            if self._stop_event.is_set():
                break

            result = self._scan_file(file_path, client)
            self._queue_result(result)
            self._throttled_progress(i + 1, total)

        self._flush_results()

    def _scan_parallel(self, files: List[Path], total: int):
        """Scan files in parallel using ThreadPoolExecutor.

        Uses batched result emission to prevent UI thread flooding.
        Progress updates are throttled to ~20 fps max.
        """
        completed = 0
        completed_lock = threading.Lock()

        # Create thread-local storage for Client instances
        # Each thread gets its own Client to avoid contention
        thread_local = threading.local()

        def get_thread_client():
            """Get or create a Client for the current thread."""
            if not hasattr(thread_local, 'client'):
                from openlabels import Client
                thread_local.client = Client()
            return thread_local.client

        def scan_task(file_path: Path) -> Dict[str, Any]:
            """Task executed in thread pool."""
            if self._stop_event.is_set():
                return None
            client = get_thread_client()
            return self._scan_file(file_path, client)

        # Create executor
        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

        try:
            # Submit all tasks
            futures = {
                self._executor.submit(scan_task, fp): fp
                for fp in files
            }

            # Process results as they complete
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break

                try:
                    result = future.result()
                    if result is not None:
                        # Queue result for batched emission
                        self._queue_result(result)

                        with completed_lock:
                            completed += 1
                            self._throttled_progress(completed, total)

                except Exception as e:
                    # Handle individual file errors
                    file_path = futures[future]
                    self._queue_result({
                        "path": str(file_path),
                        "size": 0,
                        "label_id": None,
                        "content_hash": None,
                        "label_embedded": False,
                        "score": 0,
                        "tier": "UNKNOWN",
                        "entities": {},
                        "spans": [],
                        "exposure": "PRIVATE",
                        "error": str(e),
                    })

                    with completed_lock:
                        completed += 1
                        self._throttled_progress(completed, total)

            # Flush any remaining results
            self._flush_results()

        finally:
            self._executor.shutdown(wait=True)
            self._executor = None

    def _collect_files(self, path: Path) -> List[Path]:
        """Collect all files to scan based on options."""
        files = []

        if path.is_file():
            return [path]

        try:
            # Use rglob for recursive, glob for non-recursive
            iterator = path.rglob("*") if self._recursive else path.glob("*")

            for item in iterator:
                if self._stop_event.is_set():
                    break
                try:
                    st = item.lstat()

                    # Skip symlinks unless explicitly following them
                    if stat_module.S_ISLNK(st.st_mode) and not self._follow_symlinks:
                        continue

                    if stat_module.S_ISREG(st.st_mode):
                        # Skip hidden files unless including them
                        if not self._include_hidden:
                            if any(part.startswith(".") for part in item.parts):
                                continue

                        # Skip files matching exclude patterns
                        item_str = str(item)
                        if any(excl in item_str for excl in self._exclude_patterns):
                            continue

                        # Filter by extension if specified
                        if self._extensions:
                            ext = item.suffix.lower()
                            if not any(ext == e.lower() if e.startswith('.') else ext == f'.{e.lower()}'
                                       for e in self._extensions):
                                continue

                        # Skip files larger than max size (if set)
                        if self._max_file_size_bytes > 0 and st.st_size > self._max_file_size_bytes:
                            continue

                        files.append(item)
                except OSError:
                    continue
        except PermissionError:
            pass

        return files

    def _scan_file(self, file_path: Path, client) -> Dict[str, Any]:
        """Scan a single file, generate its OpenLabels label, and embed it."""
        from openlabels.adapters.scanner import detect_file as scanner_detect  # noqa: F811
        from openlabels.core.labels import (
            generate_label_id, compute_content_hash_file,
            LabelSet, Label, compute_value_hash,
        )
        from openlabels.output.embed import write_embedded_label, supports_embedded_labels
        import time

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
                content_hash = "000000000000"

            # Detect entities
            detection = scanner_detect(file_path)
            entities = detection.entity_counts

            # Convert spans to serializable format with context
            spans_data = self._extract_spans_with_context(detection)

            # Score the file
            score_result = client.score_file(file_path)
            tier = score_result.tier.value if hasattr(score_result.tier, 'value') else str(score_result.tier)

            # Build Label objects for embedding
            labels = []
            for span in detection.spans:
                labels.append(Label(
                    type=span.entity_type,
                    confidence=span.confidence,
                    detector=getattr(span, 'detector', 'pattern'),
                    value_hash=compute_value_hash(span.text, span.entity_type),
                    count=1,
                ))

            # Deduplicate labels by type (aggregate counts)
            label_map = {}
            for label in labels:
                if label.type in label_map:
                    label_map[label.type].count += 1
                else:
                    label_map[label.type] = Label(
                        type=label.type,
                        confidence=label.confidence,
                        detector=label.detector,
                        value_hash=label.value_hash,
                        count=1,
                    )

            # Create LabelSet
            label_set = LabelSet(
                version=1,
                label_id=label_id,
                content_hash=content_hash,
                labels=list(label_map.values()),
                source="openlabels:1.0.0",
                timestamp=int(time.time()),
            )

            # Auto-embed label if enabled and file type supports it
            # Check for existing label first to avoid duplicates
            label_embedded = False
            if self._auto_embed and supports_embedded_labels(file_path):
                try:
                    from openlabels.output.embed import read_embedded_label
                    existing_label = read_embedded_label(file_path)

                    # Only write if no existing label or content changed
                    if existing_label is None:
                        label_embedded = write_embedded_label(file_path, label_set)
                    elif existing_label.content_hash != content_hash:
                        # Content changed, update the label
                        label_embedded = write_embedded_label(file_path, label_set)
                    else:
                        # Label exists and content unchanged, reuse existing
                        label_id = existing_label.label_id
                        label_embedded = True
                except Exception:
                    pass  # Embedding failed, continue without it

            return {
                "path": str(file_path),
                "size": size,
                "label_id": label_id,
                "content_hash": content_hash,
                "label_embedded": label_embedded,
                "score": score_result.score,
                "tier": tier,
                "entities": entities,
                "spans": spans_data,
                "exposure": self._exposure,
                "error": None,
            }

        except (OSError, IOError, ValueError, RuntimeError) as e:
            return {
                "path": str(file_path),
                "size": 0,
                "label_id": None,
                "content_hash": None,
                "label_embedded": False,
                "score": 0,
                "tier": "UNKNOWN",
                "entities": {},
                "spans": [],
                "exposure": self._exposure,
                "error": str(e),
            }

    def _scan_s3(self):
        """Scan S3 bucket."""
        try:
            import boto3
        except ImportError:
            self.error.emit("boto3 is required for S3 scanning. Install with: pip install boto3")
            return

        # Parse S3 path
        if self._path.startswith("s3://"):
            path_parts = self._path[5:].split("/", 1)
            bucket = path_parts[0]
            prefix = path_parts[1] if len(path_parts) > 1 else ""
        else:
            bucket = self._path
            prefix = ""

        # Create session
        try:
            if self._s3_credentials and self._s3_credentials.get("profile"):
                session = boto3.Session(profile_name=self._s3_credentials["profile"])
            elif self._s3_credentials:
                session = boto3.Session(
                    aws_access_key_id=self._s3_credentials.get("access_key"),
                    aws_secret_access_key=self._s3_credentials.get("secret_key"),
                    aws_session_token=self._s3_credentials.get("session_token"),
                    region_name=self._s3_credentials.get("region"),
                )
            else:
                session = boto3.Session()

            s3 = session.client("s3")
        except Exception as e:
            self.error.emit(f"Failed to connect to AWS: {e}")
            return

        client = self._get_client()

        # Check bucket ACL for exposure level
        bucket_exposure = self._get_bucket_exposure(s3, bucket)

        # List objects
        try:
            paginator = s3.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

            # First pass to count
            objects = []
            for page in pages:
                if self._stop_event.is_set():
                    return
                for obj in page.get("Contents", []):
                    if not obj["Key"].endswith("/"):  # Skip "folders"
                        objects.append(obj)

            total = len(objects)
            self.progress.emit(0, total)

            if total == 0:
                self.finished.emit()
                return

            # Use parallel processing for S3 objects
            if total == 1 or self._max_workers == 1:
                # Sequential mode - still use batching for consistency
                for i, obj in enumerate(objects):
                    if self._stop_event.is_set():
                        break
                    result = self._scan_s3_object(s3, bucket, obj, client, bucket_exposure)
                    self._queue_result(result)
                    self._throttled_progress(i + 1, total)
                self._flush_results()
            else:
                # Parallel mode
                self._scan_s3_parallel(s3, bucket, objects, client, bucket_exposure, total)

        except Exception as e:
            self.error.emit(f"Failed to list S3 objects: {e}")
            return

        self.finished.emit()

    def _scan_s3_parallel(self, s3_client, bucket: str, objects: List[Dict],
                          client, exposure: str, total: int):
        """Scan S3 objects in parallel with batched result emission."""
        completed = 0
        completed_lock = threading.Lock()

        def scan_task(obj: Dict) -> Dict[str, Any]:
            """Task executed in thread pool."""
            if self._stop_event.is_set():
                return None
            return self._scan_s3_object(s3_client, bucket, obj, client, exposure)

        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

        try:
            futures = {
                self._executor.submit(scan_task, obj): obj
                for obj in objects
            }

            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break

                try:
                    result = future.result()
                    if result is not None:
                        self._queue_result(result)

                        with completed_lock:
                            completed += 1
                            self._throttled_progress(completed, total)

                except Exception as e:
                    obj = futures[future]
                    self._queue_result({
                        "path": f"s3://{bucket}/{obj['Key']}",
                        "size": obj.get("Size", 0),
                        "label_id": None,
                        "content_hash": None,
                        "label_embedded": False,
                        "score": 0,
                        "tier": "UNKNOWN",
                        "entities": {},
                        "spans": [],
                        "exposure": exposure,
                        "error": str(e),
                    })

                    with completed_lock:
                        completed += 1
                        self._throttled_progress(completed, total)

            # Flush any remaining results
            self._flush_results()

        finally:
            self._executor.shutdown(wait=True)
            self._executor = None

    def _get_bucket_exposure(self, s3_client, bucket: str) -> str:
        """Determine exposure level based on S3 bucket ACL and public access settings.

        Returns:
            Exposure level: PUBLIC, ORG_WIDE, INTERNAL, or PRIVATE
        """
        try:
            # Check bucket public access block settings
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket)
                config = public_access.get("PublicAccessBlockConfiguration", {})

                # If all public access is blocked, bucket is PRIVATE
                if all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]):
                    return "PRIVATE"
            except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                pass  # No public access block = need to check ACL
            except Exception:
                pass  # Error checking = assume private for safety

            # Check bucket ACL for public grants
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    # Check for public access grants
                    if grantee.get("URI") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    ]:
                        return "PUBLIC"
            except Exception:
                pass  # Error = assume private

            # Default to PRIVATE if we can't determine
            return "PRIVATE"

        except Exception:
            return "PRIVATE"

    def _scan_s3_object(
        self, s3_client, bucket: str, obj: Dict, client, exposure: str = "PRIVATE"
    ) -> Dict[str, Any]:
        """Scan a single S3 object and generate its OpenLabels label."""
        import tempfile
        from pathlib import Path
        from openlabels.core.labels import generate_label_id, compute_content_hash_file

        key = obj["Key"]
        size = obj.get("Size", 0)

        try:
            # Download to temp file for scanning
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(key).suffix) as tmp:
                s3_client.download_fileobj(bucket, key, tmp)
                tmp_path = Path(tmp.name)

            try:
                # Generate label ID and content hash
                label_id = generate_label_id()
                try:
                    content_hash = compute_content_hash_file(str(tmp_path))
                except Exception:
                    content_hash = None

                # Scan the temp file
                from openlabels.adapters.scanner import detect_file as scanner_detect

                detection = scanner_detect(tmp_path)
                entities = detection.entity_counts

                # Convert spans to serializable format with context
                spans_data = self._extract_spans_with_context(detection)

                score_result = client.score_file(tmp_path)

                return {
                    "path": f"s3://{bucket}/{key}",
                    "size": size,
                    "label_id": label_id,
                    "content_hash": content_hash,
                    "label_embedded": False,  # S3 objects need re-upload to embed
                    "score": score_result.score,
                    "tier": score_result.tier.value if hasattr(score_result.tier, 'value') else str(score_result.tier),
                    "entities": entities,
                    "spans": spans_data,
                    "exposure": exposure,
                    "error": None,
                }
            finally:
                # Clean up temp file
                tmp_path.unlink(missing_ok=True)

        except (OSError, IOError, ValueError, RuntimeError) as e:
            return {
                "path": f"s3://{bucket}/{key}",
                "size": size,
                "label_id": None,
                "content_hash": None,
                "label_embedded": False,
                "score": 0,
                "tier": "UNKNOWN",
                "entities": {},
                "spans": [],
                "exposure": exposure,
                "error": str(e),
            }
