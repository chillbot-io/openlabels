"""
Google Cloud Storage adapter for cloud object store scanning (Phase L).

Implements the ReadAdapter protocol for GCS buckets:
- list_files: paginated blob listing
- read_file: blob download
- get_metadata: blob metadata refresh
- apply_label_and_sync: generation-based conditional re-upload

Requires ``google-cloud-storage``: install with ``pip install openlabels[gcs]``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from types import TracebackType
from typing import AsyncIterator, Optional

import asyncio

from openlabels.adapters.base import (
    ExposureLevel,
    FileInfo,
    FilterConfig,
    is_label_compatible,
)

try:
    from google.api_core.exceptions import GoogleAPIError
except ImportError:
    GoogleAPIError = Exception  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


class GCSAdapter:
    """Google Cloud Storage adapter — scans objects in GCS buckets.

    Parameters
    ----------
    bucket:
        GCS bucket name.
    prefix:
        Key prefix to scope scanning (default ``""`` = whole bucket).
    project:
        GCP project ID (optional — falls back to ADC default).
    credentials_path:
        Path to service account JSON key (optional).
    """

    _adapter_type = "gcs"

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        project: str | None = None,
        credentials_path: str | None = None,
    ) -> None:
        self._bucket_name = bucket
        self._prefix = prefix
        self._project = project
        self._credentials_path = credentials_path
        self._client = None
        self._bucket = None

    # ── ReadAdapter protocol ────────────────────────────────────────

    @property
    def adapter_type(self) -> str:
        return self._adapter_type

    def supports_delta(self) -> bool:
        return False  # delta via PubSubChangeProvider instead

    async def __aenter__(self) -> "GCSAdapter":
        self._client = await asyncio.to_thread(self._build_client)
        self._bucket = self._client.bucket(self._bucket_name)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client:
            self._client.close()
        self._client = None
        self._bucket = None

    async def test_connection(self, config: dict) -> bool:
        try:
            client = self._ensure_client()
            bucket = client.bucket(self._bucket_name)
            await asyncio.to_thread(bucket.exists)
            return True
        except (GoogleAPIError, OSError, ConnectionError):
            logger.exception("GCS connection test failed for bucket %s", self._bucket_name)
            return False

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: Optional[FilterConfig] = None,
    ) -> AsyncIterator[FileInfo]:
        """List blobs in the GCS bucket under *target* prefix.

        Args:
            target: Blob prefix (appended to adapter prefix).
            recursive: If False, use ``/`` delimiter for single-level listing.
            filter_config: Optional filter for extensions, size, etc.
        """
        client = self._ensure_client()
        bucket = client.bucket(self._bucket_name)
        prefix = self._resolve_prefix(target)
        delimiter = None if recursive else "/"

        kwargs: dict = {"prefix": prefix}
        if delimiter:
            kwargs["delimiter"] = delimiter

        blobs = await asyncio.to_thread(
            lambda: list(bucket.list_blobs(**kwargs))
        )

        for blob in blobs:
            name_str: str = blob.name
            # Skip "directory" markers
            if name_str.endswith("/"):
                continue

            short_name = name_str.rsplit("/", 1)[-1]
            modified = blob.updated or datetime.now(timezone.utc)
            size = blob.size or 0
            generation = blob.generation

            file_info = FileInfo(
                path=f"gs://{self._bucket_name}/{name_str}",
                name=short_name,
                size=size,
                modified=modified,
                adapter="gcs",
                item_id=name_str,  # full blob name for read/get_metadata
                exposure=ExposureLevel.PRIVATE,
                permissions={"generation": generation},
            )

            if filter_config and not filter_config.should_include(file_info):
                continue

            yield file_info

    async def read_file(
        self,
        file_info: FileInfo,
        max_size_bytes: int = 100 * 1024 * 1024,
    ) -> bytes:
        """Download blob content from GCS with size limit."""
        if file_info.size > max_size_bytes:
            raise ValueError(
                f"File too large for processing: {file_info.size} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )
        client = self._ensure_client()
        bucket = client.bucket(self._bucket_name)
        blob_name = file_info.item_id or file_info.path.split(
            f"gs://{self._bucket_name}/", 1
        )[-1]
        blob = bucket.blob(blob_name)
        content = await asyncio.to_thread(blob.download_as_bytes)
        if len(content) > max_size_bytes:
            raise ValueError(
                f"File content exceeds limit: {len(content)} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )
        return content

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Refresh metadata via blob reload."""
        client = self._ensure_client()
        bucket = client.bucket(self._bucket_name)
        blob_name = file_info.item_id or file_info.path.split(
            f"gs://{self._bucket_name}/", 1
        )[-1]
        blob = bucket.blob(blob_name)
        await asyncio.to_thread(blob.reload)

        return FileInfo(
            path=file_info.path,
            name=file_info.name,
            size=blob.size or file_info.size,
            modified=blob.updated or file_info.modified,
            owner=file_info.owner,
            adapter="gcs",
            item_id=blob_name,
            exposure=file_info.exposure,
            permissions={
                "generation": blob.generation,
                "metadata": blob.metadata or {},
            },
        )

    # ── Cloud label sync-back ───────────────────────────────────────

    async def apply_label_and_sync(
        self,
        file_info: FileInfo,
        label_id: str,
        label_name: str | None = None,
        content: bytes | None = None,
    ) -> dict:
        """Apply a sensitivity label by re-uploading with updated metadata.

        Uses the GCS generation number for conditional writes — if the
        object has been modified since the scan, the upload fails cleanly
        and the file will be re-scanned on the next cycle.

        Args:
            file_info: FileInfo from list_files / get_metadata.
            label_id: MIP label GUID.
            label_name: Human-readable label name.
            content: Pre-downloaded content (avoids a second GET).

        Returns:
            Dict with ``success``, ``method``, and optional ``error`` keys.
        """
        if not is_label_compatible(file_info.name):
            return {
                "success": False,
                "method": "skipped",
                "error": f"File type not label-compatible: {file_info.name}",
            }

        client = self._ensure_client()
        bucket = client.bucket(self._bucket_name)
        blob_name = file_info.item_id or file_info.path.split(
            f"gs://{self._bucket_name}/", 1
        )[-1]
        blob = bucket.blob(blob_name)

        # Fetch current metadata for generation check
        try:
            await asyncio.to_thread(blob.reload)
        except (GoogleAPIError, OSError) as exc:
            return {"success": False, "method": "gcs_metadata", "error": str(exc)}

        expected_generation = (file_info.permissions or {}).get("generation")
        current_generation = blob.generation
        if expected_generation is not None and current_generation != expected_generation:
            logger.warning(
                "Generation mismatch for %s: expected %s, got %s — re-scan on next cycle",
                blob_name, expected_generation, current_generation,
            )
            return {
                "success": False,
                "method": "gcs_metadata",
                "error": (
                    f"Generation mismatch: object modified since scan "
                    f"(expected {expected_generation}, got {current_generation})"
                ),
            }

        # Download content if not supplied
        if content is None:
            try:
                content = await asyncio.to_thread(blob.download_as_bytes)
            except (GoogleAPIError, OSError) as exc:
                return {"success": False, "method": "gcs_metadata", "error": str(exc)}

        # Update metadata with label info
        existing_metadata = dict(blob.metadata or {})
        existing_metadata["openlabels-label-id"] = label_id
        if label_name:
            existing_metadata["openlabels-label-name"] = label_name

        content_type = blob.content_type or "application/octet-stream"

        # Conditional re-upload using if_generation_match
        try:
            blob.metadata = existing_metadata
            blob.content_type = content_type
            await asyncio.to_thread(
                lambda: blob.upload_from_string(
                    content,
                    content_type=content_type,
                    if_generation_match=current_generation,
                )
            )
        except (GoogleAPIError, OSError) as exc:
            error_str = str(exc)
            if "conditionNotMet" in error_str or "412" in error_str:
                logger.warning("Conditional re-upload failed for %s: object modified", blob_name)
                return {
                    "success": False,
                    "method": "gcs_metadata",
                    "error": "Object modified during re-upload (generation mismatch)",
                }
            return {"success": False, "method": "gcs_metadata", "error": error_str}

        logger.info("Applied label %s to gs://%s/%s", label_id, self._bucket_name, blob_name)
        return {"success": True, "method": "gcs_metadata"}

    # ── GCS change detection (generation diff) ──────────────────────

    async def list_blobs_with_generations(
        self,
        prefix: str | None = None,
    ) -> dict[str, int]:
        """Return ``{blob_name: generation}`` for all blobs under *prefix*.

        Used by the generation-diff fallback when Pub/Sub notifications
        are not configured.
        """
        client = self._ensure_client()
        bucket = client.bucket(self._bucket_name)
        resolved = self._resolve_prefix(prefix or "")
        blobs = await asyncio.to_thread(
            lambda: list(bucket.list_blobs(prefix=resolved))
        )
        return {b.name: b.generation for b in blobs if not b.name.endswith("/")}

    # ── Internal helpers ────────────────────────────────────────────

    def _build_client(self):
        try:
            from google.cloud import storage
        except ImportError as exc:
            raise ImportError(
                "google-cloud-storage is required for GCS scanning. "
                "Install it with: pip install openlabels[gcs]"
            ) from exc

        kwargs: dict = {}
        if self._project:
            kwargs["project"] = self._project
        if self._credentials_path:
            from google.oauth2 import service_account
            credentials = service_account.Credentials.from_service_account_file(
                self._credentials_path
            )
            kwargs["credentials"] = credentials

        return storage.Client(**kwargs)

    def _ensure_client(self):
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _resolve_prefix(self, target: str) -> str:
        parts = [p for p in (self._prefix, target) if p]
        return "/".join(parts)
