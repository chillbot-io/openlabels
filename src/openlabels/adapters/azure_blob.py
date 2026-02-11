"""
Azure Blob Storage adapter for cloud object store scanning (Phase L).

Implements the ReadAdapter protocol for Azure Blob containers:
- list_files: paginated blob listing via ContainerClient
- read_file: blob download
- get_metadata: blob properties refresh
- apply_label_and_sync: ETag-based conditional metadata update

Requires ``azure-storage-blob``: install with ``pip install openlabels[azure]``.
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
)

try:
    from azure.core import MatchConditions as _MatchConditions
    from azure.core.exceptions import AzureError
except ImportError:
    AzureError = Exception  # type: ignore[misc,assignment]
    _MatchConditions = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class AzureBlobAdapter:
    """Azure Blob Storage adapter — scans blobs in Azure containers.

    Parameters
    ----------
    storage_account:
        Azure storage account name.
    container:
        Container name to scan.
    prefix:
        Blob name prefix to scope scanning (default ``""`` = whole container).
    connection_string:
        Full connection string (optional — takes precedence over account_key).
    account_key:
        Storage account key (optional — falls back to DefaultAzureCredential).
    sas_token:
        Shared access signature token (optional).
    """

    _adapter_type = "azure_blob"

    def __init__(
        self,
        storage_account: str,
        container: str,
        prefix: str = "",
        connection_string: str = "",
        account_key: str = "",
        sas_token: str = "",
    ) -> None:
        self._storage_account = storage_account
        self._container_name = container
        self._prefix = prefix
        self._connection_string = connection_string
        self._account_key = account_key
        self._sas_token = sas_token
        self._client = None
        self._container_client = None

    # ── ReadAdapter protocol ────────────────────────────────────────

    @property
    def adapter_type(self) -> str:
        return self._adapter_type

    def supports_delta(self) -> bool:
        return False  # delta via Event Grid / Storage Queue instead

    async def __aenter__(self) -> AzureBlobAdapter:
        self._client = await asyncio.to_thread(self._build_client)
        self._container_client = self._client.get_container_client(self._container_name)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client:
            await asyncio.to_thread(self._client.close)
        self._client = None
        self._container_client = None

    async def test_connection(self, config: dict) -> bool:
        try:
            container = self._ensure_container_client()
            await asyncio.to_thread(container.get_container_properties)
            return True
        except (AzureError, OSError, ConnectionError):
            logger.exception(
                "Azure Blob connection test failed for %s/%s",
                self._storage_account, self._container_name,
            )
            return False

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: FilterConfig | None = None,
        partition: PartitionSpec | None = None,
    ) -> AsyncIterator[FileInfo]:
        """List blobs in the Azure container under *target* prefix.

        Args:
            target: Blob name prefix (appended to adapter prefix).
            recursive: If False, list only the current "directory" level.
            filter_config: Optional filter for extensions, size, etc.
            partition: Optional partition spec for key-range scanning.
        """
        container = self._ensure_container_client()
        prefix = self._resolve_prefix(target)

        kwargs: dict = {"name_starts_with": prefix}
        if not recursive:
            blob_iter = container.walk_blobs(name_starts_with=prefix, delimiter="/")
        else:
            blob_iter = container.list_blobs(**kwargs)

        blobs = await asyncio.to_thread(lambda: list(blob_iter))

        start_after = partition.start_after if partition else None
        end_before = partition.end_before if partition else None

        for blob in blobs:
            blob_name: str = blob.name
            # Skip "directory" markers
            if blob_name.endswith("/"):
                continue
            # walk_blobs returns BlobPrefix objects for directories — skip them
            if not hasattr(blob, "size"):
                continue

            # Apply partition boundaries
            if start_after and blob_name <= start_after:
                continue
            if end_before and blob_name >= end_before:
                break

            short_name = blob_name.rsplit("/", 1)[-1]
            modified = blob.last_modified or datetime.now(timezone.utc)
            size = blob.size or 0
            etag = (blob.etag or "").strip('"')

            file_info = FileInfo(
                path=f"https://{self._storage_account}.blob.core.windows.net/{self._container_name}/{blob_name}",
                name=short_name,
                size=size,
                modified=modified,
                adapter="azure_blob",
                item_id=blob_name,  # full blob name for read/get_metadata
                exposure=ExposureLevel.PRIVATE,
                permissions={"etag": etag},
            )

            if filter_config and not filter_config.should_include(file_info):
                continue

            yield file_info

    async def list_top_level_prefixes(
        self,
        target: str = "",
    ) -> list[str]:
        """List top-level prefixes (virtual directories) under *target*."""
        container = self._ensure_container_client()
        prefix = self._resolve_prefix(target)

        blob_iter = container.walk_blobs(name_starts_with=prefix, delimiter="/")
        items = await asyncio.to_thread(lambda: list(blob_iter))
        # BlobPrefix objects have .name but no .size
        return [item.name for item in items if not hasattr(item, "size")]

    async def estimate_object_count(
        self,
        target: str = "",
        sample_limit: int = 10000,
    ) -> tuple[int, list[str]]:
        """Quick estimate of object count and sample keys for partitioning."""
        container = self._ensure_container_client()
        prefix = self._resolve_prefix(target)

        blobs = await asyncio.to_thread(
            lambda: list(container.list_blobs(name_starts_with=prefix, results_per_page=1000))
        )
        keys = [b.name for b in blobs[:sample_limit] if not b.name.endswith("/") and hasattr(b, "size")]
        return len(keys), keys

    async def read_file(
        self,
        file_info: FileInfo,
        max_size_bytes: int = 100 * 1024 * 1024,
    ) -> bytes:
        """Download blob content from Azure with size limit."""
        if file_info.size > max_size_bytes:
            raise ValueError(
                f"File too large for processing: {file_info.size} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )
        container = self._ensure_container_client()
        blob_name = file_info.item_id or self._extract_blob_name(file_info.path)
        blob_client = container.get_blob_client(blob_name)

        downloader = await asyncio.to_thread(blob_client.download_blob)
        content = await asyncio.to_thread(downloader.readall)
        if len(content) > max_size_bytes:
            raise ValueError(
                f"File content exceeds limit: {len(content)} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )
        return content

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Refresh metadata via blob properties."""
        container = self._ensure_container_client()
        blob_name = file_info.item_id or self._extract_blob_name(file_info.path)
        blob_client = container.get_blob_client(blob_name)

        props = await asyncio.to_thread(blob_client.get_blob_properties)
        etag = (props.etag or "").strip('"')

        return FileInfo(
            path=file_info.path,
            name=file_info.name,
            size=props.size or file_info.size,
            modified=props.last_modified or file_info.modified,
            owner=file_info.owner,
            adapter="azure_blob",
            item_id=blob_name,
            exposure=file_info.exposure,
            permissions={
                "etag": etag,
                "metadata": dict(props.metadata or {}),
            },
        )

    # ── Cloud label sync-back ───────────────────────────────────────

    async def apply_label_and_sync(
        self,
        file_info: FileInfo,
        label_id: str,
        label_name: str | None = None,
    ) -> dict:
        """Apply a sensitivity label via conditional metadata update.

        Uses the Azure ETag for conditional writes — if the blob has been
        modified since the scan, the update fails cleanly and the file will
        be re-scanned on the next cycle.

        Azure Blob supports setting custom metadata without re-uploading
        the blob content, making this more efficient than S3/GCS.

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

        container = self._ensure_container_client()
        blob_name = file_info.item_id or self._extract_blob_name(file_info.path)
        blob_client = container.get_blob_client(blob_name)

        # Fetch current properties for ETag check
        try:
            props = await asyncio.to_thread(blob_client.get_blob_properties)
        except (AzureError, OSError) as exc:
            return {"success": False, "method": "azure_metadata", "error": str(exc)}

        current_etag = (props.etag or "").strip('"')
        stored_etag = (file_info.permissions or {}).get("etag", "")
        if stored_etag and current_etag != stored_etag:
            logger.warning(
                "ETag mismatch for %s: expected %s, got %s — re-scan on next cycle",
                blob_name, stored_etag, current_etag,
            )
            return {
                "success": False,
                "method": "azure_metadata",
                "error": (
                    f"ETag mismatch: blob modified since scan "
                    f"(expected {stored_etag}, got {current_etag})"
                ),
            }

        # Build updated metadata (Azure metadata values must be strings)
        existing_metadata = dict(props.metadata or {})
        existing_metadata["openlabels_label_id"] = label_id
        if label_name:
            existing_metadata["openlabels_label_name"] = label_name

        # Conditional metadata-only update using if_match (ETag).
        # Azure allows setting metadata without re-uploading the blob.
        try:
            set_kwargs: dict = {"metadata": existing_metadata}
            if _MatchConditions is not None:
                set_kwargs["etag"] = props.etag
                set_kwargs["match_condition"] = _MatchConditions.IfNotModified
            await asyncio.to_thread(
                lambda: blob_client.set_blob_metadata(**set_kwargs)
            )
        except (AzureError, OSError) as exc:
            error_str = str(exc)
            if "ConditionNotMet" in error_str or "412" in error_str:
                logger.warning("Metadata update failed for %s: blob modified", blob_name)
                return {
                    "success": False,
                    "method": "azure_metadata",
                    "error": "Blob modified during metadata update (ConditionNotMet)",
                }
            return {"success": False, "method": "azure_metadata", "error": error_str}

        logger.info(
            "Applied label %s to %s/%s",
            label_id, self._container_name, blob_name,
        )
        return {"success": True, "method": "azure_metadata"}

    # ── Azure change detection (ETag diff) ──────────────────────────

    async def list_blobs_with_etags(
        self,
        prefix: str | None = None,
    ) -> dict[str, str]:
        """Return ``{blob_name: etag}`` for all blobs under *prefix*.

        Used by the ETag-diff fallback when Event Grid notifications
        are not configured.
        """
        container = self._ensure_container_client()
        resolved = self._resolve_prefix(prefix or "")
        blobs = await asyncio.to_thread(
            lambda: list(container.list_blobs(name_starts_with=resolved))
        )
        return {
            b.name: (b.etag or "").strip('"')
            for b in blobs
            if not b.name.endswith("/")
        }

    # ── Internal helpers ────────────────────────────────────────────

    def _build_client(self):
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise ImportError(
                "azure-storage-blob is required for Azure Blob scanning. "
                "Install it with: pip install openlabels[azure]"
            ) from exc

        if self._connection_string:
            return BlobServiceClient.from_connection_string(self._connection_string)

        account_url = f"https://{self._storage_account}.blob.core.windows.net"

        if self._account_key:
            return BlobServiceClient(
                account_url=account_url,
                credential=self._account_key,
            )

        if self._sas_token:
            return BlobServiceClient(
                account_url=account_url,
                credential=self._sas_token,
            )

        # Fall back to DefaultAzureCredential (managed identity, az login, etc.)
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
        except ImportError as exc:
            raise ImportError(
                "azure-identity is required for DefaultAzureCredential. "
                "Install it with: pip install azure-identity"
            ) from exc

        return BlobServiceClient(account_url=account_url, credential=credential)

    def _ensure_container_client(self):
        if self._container_client is None:
            if self._client is None:
                self._client = self._build_client()
            self._container_client = self._client.get_container_client(self._container_name)
        return self._container_client

    def _resolve_prefix(self, target: str) -> str:
        parts = [p for p in (self._prefix, target) if p]
        return "/".join(parts)

    def _extract_blob_name(self, path: str) -> str:
        """Extract blob name from full URL path."""
        marker = f"{self._container_name}/"
        idx = path.find(marker)
        if idx != -1:
            return path[idx + len(marker):]
        return path
