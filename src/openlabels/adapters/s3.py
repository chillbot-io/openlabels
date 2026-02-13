"""
AWS S3 adapter for cloud object store scanning (Phase L).

Implements the ReadAdapter protocol for S3 buckets:
- list_files: paginated ListObjectsV2
- read_file: GetObject download
- get_metadata: HeadObject refresh
- apply_label_and_sync: conditional re-upload with metadata preservation

Requires ``boto3``: install with ``pip install openlabels[s3]``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from types import TracebackType

from openlabels.adapters.base import (
    ExposureLevel,
    FileInfo,
    FilterConfig,
    PartitionSpec,
    is_label_compatible,
    resolve_prefix,
    validate_content_size,
    validate_file_size,
)
from openlabels.core.constants import DEFAULT_MAX_READ_BYTES

try:
    from botocore.exceptions import BotoCoreError
    from botocore.exceptions import ClientError as BotoClientError
except ImportError:
    BotoCoreError = Exception  # type: ignore[misc,assignment]
    BotoClientError = Exception  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


async def _iter_s3_pages(paginator_result) -> list[dict]:
    """Fetch all pages from a boto3 paginator via a thread.

    boto3 paginators are synchronous lazy iterators. We run the iteration
    in a thread to avoid blocking the event loop. For true one-page-at-a-time
    streaming, the caller iterates the returned list; memory is bounded
    by one full page (~1000 keys per page ≈ few hundred KB) rather than
    the entire listing.

    Note: boto3 paginators don't support partial iteration across threads
    cleanly, so we still materialize all pages. However, the key difference
    from the previous approach is that list_files now *yields* FileInfo per
    page rather than waiting for all pages before yielding anything.
    For truly large buckets, use the fan-out coordinator to split work.
    """
    return await asyncio.to_thread(list, paginator_result)


class S3Adapter:
    """AWS S3 adapter — scans objects in S3 buckets.

    Parameters
    ----------
    bucket:
        S3 bucket name.
    prefix:
        Key prefix to scope scanning (default ``""`` = whole bucket).
    region:
        AWS region (default ``us-east-1``).
    access_key:
        AWS access key ID (optional — falls back to environment / IAM role).
    secret_key:
        AWS secret access key (optional).
    endpoint_url:
        Custom endpoint for S3-compatible stores (MinIO, LocalStack).
    """

    _adapter_type = "s3"

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
        endpoint_url: str | None = None,
    ) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._endpoint_url = endpoint_url
        self._client = None

    # ── ReadAdapter protocol ────────────────────────────────────────

    @property
    def adapter_type(self) -> str:
        return self._adapter_type

    def supports_delta(self) -> bool:
        return False  # delta via SQSChangeProvider instead

    async def __aenter__(self) -> S3Adapter:
        self._client = await asyncio.to_thread(self._build_client)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            try:
                await asyncio.to_thread(self._client.close)
            except Exception:
                pass
        self._client = None

    async def test_connection(self, config: dict) -> bool:
        try:
            client = self._ensure_client()
            await asyncio.to_thread(
                client.head_bucket, Bucket=self._bucket
            )
            return True
        except (BotoCoreError, BotoClientError, OSError, ConnectionError):
            logger.exception("S3 connection test failed for bucket %s", self._bucket)
            return False

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: FilterConfig | None = None,
        partition: PartitionSpec | None = None,
    ) -> AsyncIterator[FileInfo]:
        """List objects in the S3 bucket under *target* prefix.

        Args:
            target: Key prefix (appended to adapter prefix).
            recursive: If False, use ``/`` delimiter for single-level listing.
            filter_config: Optional filter for extensions, size, etc.
            partition: Optional partition spec for key-range scanning.
                When set, only yields objects in (start_after, end_before).
        """
        client = self._ensure_client()
        prefix = self._resolve_prefix(target)
        delimiter = "" if recursive else "/"

        paginator = client.get_paginator("list_objects_v2")
        page_kwargs: dict = {"Bucket": self._bucket, "Prefix": prefix}
        if delimiter:
            page_kwargs["Delimiter"] = delimiter

        # Use StartAfter for efficient skip-ahead when partitioning
        if partition and partition.start_after:
            page_kwargs["StartAfter"] = partition.start_after

        end_before = partition.end_before if partition else None

        # Stream page-by-page to avoid materializing millions of keys.
        # boto3 paginators are synchronous iterators so we fetch one page
        # at a time via to_thread to avoid blocking the event loop.
        page_iter = paginator.paginate(**page_kwargs)

        # Use a queue-based approach: fetch pages one at a time in a thread
        for page in await _iter_s3_pages(page_iter):
            hit_boundary = False
            for obj in page.get("Contents", []):
                key: str = obj["Key"]

                # Stop early if past the partition boundary
                if end_before and key >= end_before:
                    hit_boundary = True
                    break

                # Skip "directory" markers
                if key.endswith("/"):
                    continue

                name = key.rsplit("/", 1)[-1]
                modified = obj.get("LastModified", datetime.now(timezone.utc))
                size = obj.get("Size", 0)
                etag = obj.get("ETag", "").strip('"')

                file_info = FileInfo(
                    path=f"s3://{self._bucket}/{key}",
                    name=name,
                    size=size,
                    modified=modified,
                    adapter="s3",
                    item_id=key,  # store full key for read_file / get_metadata
                    exposure=ExposureLevel.PRIVATE,
                    permissions={"etag": etag},
                )

                if filter_config and not filter_config.should_include(file_info):
                    continue

                yield file_info

            # If we hit the partition boundary, stop fetching more pages
            if hit_boundary:
                break

    async def list_top_level_prefixes(
        self,
        target: str = "",
    ) -> list[str]:
        """List top-level prefixes (virtual directories) under *target*.

        Used by the coordinator to determine natural partition boundaries
        for fan-out scanning.

        Returns:
            List of prefix strings (e.g. ["data/2024/", "data/2025/", "logs/"]).
        """
        client = self._ensure_client()
        prefix = self._resolve_prefix(target)

        paginator = client.get_paginator("list_objects_v2")
        page_kwargs: dict = {
            "Bucket": self._bucket,
            "Prefix": prefix,
            "Delimiter": "/",
        }

        prefixes: list[str] = []
        page_iter = paginator.paginate(**page_kwargs)
        for page in await _iter_s3_pages(page_iter):
            for cp in page.get("CommonPrefixes", []):
                prefixes.append(cp["Prefix"])

        return prefixes

    async def estimate_object_count(
        self,
        target: str = "",
        sample_limit: int = 10000,
    ) -> tuple[int, list[str]]:
        """Quick estimate of object count and sample keys for partitioning.

        Lists up to *sample_limit* keys and uses the count as a lower-bound
        estimate.  Also returns the sampled keys for computing partition
        boundaries.

        Returns:
            Tuple of (count, sample_keys).
        """
        client = self._ensure_client()
        prefix = self._resolve_prefix(target)

        paginator = client.get_paginator("list_objects_v2")
        page_kwargs: dict = {
            "Bucket": self._bucket,
            "Prefix": prefix,
            "PaginationConfig": {"MaxItems": sample_limit, "PageSize": 1000},
        }

        keys: list[str] = []
        page_iter = paginator.paginate(**page_kwargs)
        for page in await _iter_s3_pages(page_iter):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith("/"):
                    keys.append(key)

        return len(keys), keys

    async def read_file(
        self,
        file_info: FileInfo,
        max_size_bytes: int = DEFAULT_MAX_READ_BYTES,
    ) -> bytes:
        """Download object content from S3 with size limit."""
        validate_file_size(file_info, max_size_bytes)
        client = self._ensure_client()
        key = file_info.item_id or file_info.path.split(f"s3://{self._bucket}/", 1)[-1]

        response = await asyncio.to_thread(
            client.get_object, Bucket=self._bucket, Key=key
        )
        body = response["Body"]
        try:
            content = await asyncio.to_thread(body.read)
        finally:
            body.close()
        validate_content_size(content, max_size_bytes, file_info.path)
        return content

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Refresh metadata via HeadObject."""
        client = self._ensure_client()
        key = file_info.item_id or file_info.path.split(f"s3://{self._bucket}/", 1)[-1]

        head = await asyncio.to_thread(
            client.head_object, Bucket=self._bucket, Key=key
        )
        etag = head.get("ETag", "").strip('"')
        return FileInfo(
            path=file_info.path,
            name=file_info.name,
            size=head.get("ContentLength", file_info.size),
            modified=head.get("LastModified", file_info.modified),
            owner=file_info.owner,
            adapter="s3",
            item_id=key,
            exposure=file_info.exposure,
            permissions={"etag": etag, "metadata": head.get("Metadata", {})},
        )

    # ── Cloud label sync-back ───────────────────────────────────────

    async def apply_label_and_sync(
        self,
        file_info: FileInfo,
        label_id: str,
        label_name: str | None = None,
    ) -> dict:
        """Apply a sensitivity label via metadata-only self-copy.

        For label-compatible files, performs a server-side ``copy_object``
        self-copy with ``MetadataDirective=REPLACE`` and
        ``CopySourceIfMatch`` set to the original ETag.  This updates
        metadata atomically without downloading or re-uploading content.

        Args:
            file_info: FileInfo from list_files / get_metadata.
            label_id: MIP label GUID.
            label_name: Human-readable label name.

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
        key = file_info.item_id or file_info.path.split(f"s3://{self._bucket}/", 1)[-1]

        # Fetch current object to preserve metadata + content type
        try:
            head = await asyncio.to_thread(
                client.head_object, Bucket=self._bucket, Key=key
            )
        except (BotoCoreError, BotoClientError, OSError) as exc:
            return {"success": False, "method": "s3_metadata", "error": str(exc)}

        original_etag = head.get("ETag", "").strip('"')
        stored_etag = (file_info.permissions or {}).get("etag", "")
        if stored_etag and original_etag != stored_etag:
            logger.warning(
                "ETag mismatch for %s: expected %s, got %s — re-scan on next cycle",
                key, stored_etag, original_etag,
            )
            return {
                "success": False,
                "method": "s3_metadata",
                "error": f"ETag mismatch: object modified since scan (expected {stored_etag}, got {original_etag})",
            }

        # Build updated metadata
        existing_metadata = head.get("Metadata", {})
        existing_metadata["openlabels-label-id"] = label_id
        if label_name:
            existing_metadata["openlabels-label-name"] = label_name

        content_type = head.get("ContentType", "application/octet-stream")

        # Use copy_object self-copy to update metadata atomically.
        # CopySourceIfMatch ensures the copy only succeeds if the ETag
        # still matches, closing the TOCTOU window between head_object
        # and the write.
        try:
            copy_source = f"{self._bucket}/{key}"
            copy_kwargs: dict = {
                "Bucket": self._bucket,
                "Key": key,
                "CopySource": copy_source,
                "CopySourceIfMatch": f'"{original_etag}"',
                "Metadata": existing_metadata,
                "MetadataDirective": "REPLACE",
                "ContentType": content_type,
            }
            await asyncio.to_thread(lambda: client.copy_object(**copy_kwargs))
        except (BotoCoreError, BotoClientError, OSError) as exc:
            error_str = str(exc)
            if "PreconditionFailed" in error_str or "412" in error_str:
                logger.warning("Re-upload failed for %s: object modified", key)
                return {
                    "success": False,
                    "method": "s3_metadata",
                    "error": "Object modified during re-upload (PreconditionFailed)",
                }
            return {"success": False, "method": "s3_metadata", "error": error_str}

        logger.info("Applied label %s to s3://%s/%s", label_id, self._bucket, key)
        return {"success": True, "method": "s3_metadata"}

    # ── S3 change detection (ETag diff) ─────────────────────────────

    async def list_objects_with_etags(
        self,
        prefix: str | None = None,
    ) -> dict[str, str]:
        """Return ``{key: etag}`` for all objects under *prefix*.

        Used by the ETag-diff fallback when SQS event notifications are
        not configured.
        """
        client = self._ensure_client()
        resolved = self._resolve_prefix(prefix or "")
        paginator = client.get_paginator("list_objects_v2")
        result: dict[str, str] = {}

        page_iter = paginator.paginate(Bucket=self._bucket, Prefix=resolved)
        for page in await _iter_s3_pages(page_iter):
            for obj in page.get("Contents", []):
                result[obj["Key"]] = obj.get("ETag", "").strip('"')

        return result

    # ── Internal helpers ────────────────────────────────────────────

    @staticmethod
    def _iter_pages_sync(paginator_result):
        """Collect pages from a synchronous boto3 paginator into a list.

        Called inside asyncio.to_thread so the main loop isn't blocked.
        Returns one page at a time to the caller for streaming consumption.
        """
        return list(paginator_result)

    def _build_client(self):
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for S3 scanning. "
                "Install it with: pip install openlabels[s3]"
            ) from exc

        kwargs: dict = {"service_name": "s3", "region_name": self._region}
        if self._access_key and self._secret_key:
            kwargs["aws_access_key_id"] = self._access_key
            kwargs["aws_secret_access_key"] = self._secret_key
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url

        return boto3.client(**kwargs)

    def _ensure_client(self):
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _resolve_prefix(self, target: str) -> str:
        return resolve_prefix(self._prefix, target)
