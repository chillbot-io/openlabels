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

import io
import logging
from datetime import datetime, timezone
from types import TracebackType
from typing import AsyncIterator, Optional

import asyncio

from openlabels.adapters.base import (
    ExposureLevel,
    FileInfo,
    FilterConfig,
)

logger = logging.getLogger(__name__)

# Label-compatible extensions that support metadata round-trip via re-upload
_LABEL_COMPATIBLE_EXTENSIONS = frozenset({
    ".docx", ".xlsx", ".pptx", ".pdf",
    ".doc", ".xls", ".ppt",
    ".csv", ".tsv", ".json", ".xml",
    ".txt", ".md", ".rst", ".html", ".htm",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
    ".zip", ".tar", ".gz",
})


def _is_label_compatible(name: str) -> bool:
    """Check if a file type supports label metadata via S3 object metadata."""
    dot = name.rfind(".")
    if dot == -1:
        return False
    return name[dot:].lower() in _LABEL_COMPATIBLE_EXTENSIONS


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

    async def __aenter__(self) -> "S3Adapter":
        self._client = await asyncio.to_thread(self._build_client)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._client = None

    async def test_connection(self, config: dict) -> bool:
        try:
            client = self._ensure_client()
            await asyncio.to_thread(
                client.head_bucket, Bucket=self._bucket
            )
            return True
        except Exception:
            logger.exception("S3 connection test failed for bucket %s", self._bucket)
            return False

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: Optional[FilterConfig] = None,
    ) -> AsyncIterator[FileInfo]:
        """List objects in the S3 bucket under *target* prefix.

        Args:
            target: Key prefix (appended to adapter prefix).
            recursive: If False, use ``/`` delimiter for single-level listing.
            filter_config: Optional filter for extensions, size, etc.
        """
        client = self._ensure_client()
        prefix = self._resolve_prefix(target)
        delimiter = "" if recursive else "/"

        paginator = client.get_paginator("list_objects_v2")
        page_kwargs: dict = {"Bucket": self._bucket, "Prefix": prefix}
        if delimiter:
            page_kwargs["Delimiter"] = delimiter

        pages = paginator.paginate(**page_kwargs)

        for page in await asyncio.to_thread(lambda: list(pages)):
            for obj in page.get("Contents", []):
                key: str = obj["Key"]
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

    async def read_file(self, file_info: FileInfo) -> bytes:
        """Download object content from S3."""
        client = self._ensure_client()
        key = file_info.item_id or file_info.path.split(f"s3://{self._bucket}/", 1)[-1]

        response = await asyncio.to_thread(
            client.get_object, Bucket=self._bucket, Key=key
        )
        body = response["Body"]
        return await asyncio.to_thread(body.read)

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
        content: bytes | None = None,
    ) -> dict:
        """Apply a sensitivity label by re-uploading with updated metadata.

        For label-compatible files, downloads the object (if *content* is not
        supplied), injects the label into S3 user metadata, and performs a
        conditional PUT using the original ETag to prevent overwrites on
        concurrent modifications.

        Args:
            file_info: FileInfo from list_files / get_metadata.
            label_id: MIP label GUID.
            label_name: Human-readable label name.
            content: Pre-downloaded content (avoids a second GET).

        Returns:
            Dict with ``success``, ``method``, and optional ``error`` keys.
        """
        if not _is_label_compatible(file_info.name):
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
        except Exception as exc:
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

        # Download content if not supplied
        if content is None:
            try:
                response = await asyncio.to_thread(
                    client.get_object, Bucket=self._bucket, Key=key
                )
                content = await asyncio.to_thread(response["Body"].read)
            except Exception as exc:
                return {"success": False, "method": "s3_metadata", "error": str(exc)}

        # Build updated metadata
        existing_metadata = head.get("Metadata", {})
        existing_metadata["openlabels-label-id"] = label_id
        if label_name:
            existing_metadata["openlabels-label-name"] = label_name

        content_type = head.get("ContentType", "application/octet-stream")

        # Conditional re-upload (copy-replace with metadata update)
        try:
            put_kwargs: dict = {
                "Bucket": self._bucket,
                "Key": key,
                "Body": content,
                "Metadata": existing_metadata,
                "ContentType": content_type,
                "MetadataDirective": "REPLACE",
            }
            await asyncio.to_thread(lambda: client.put_object(**put_kwargs))
        except client.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "PreconditionFailed":
                logger.warning("Conditional re-upload failed for %s: object modified", key)
                return {
                    "success": False,
                    "method": "s3_metadata",
                    "error": "Object modified during re-upload (PreconditionFailed)",
                }
            return {"success": False, "method": "s3_metadata", "error": str(exc)}
        except Exception as exc:
            return {"success": False, "method": "s3_metadata", "error": str(exc)}

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

        for page in await asyncio.to_thread(
            lambda: list(paginator.paginate(Bucket=self._bucket, Prefix=resolved))
        ):
            for obj in page.get("Contents", []):
                result[obj["Key"]] = obj.get("ETag", "").strip('"')

        return result

    # ── Internal helpers ────────────────────────────────────────────

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
        parts = [p for p in (self._prefix, target) if p]
        return "/".join(parts)
