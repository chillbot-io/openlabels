"""
Unified labeling engine interface.

Provides a unified interface for applying MIP sensitivity labels across:
- Local files (MIP SDK or metadata fallback)
- SharePoint/OneDrive (Microsoft Graph API)

Features:
- Label caching with TTL for performance
- Automatic fallback chain (MIP SDK -> Office metadata -> PDF metadata -> Sidecar)
- Retry logic with exponential backoff
- Thread-safe singleton pattern for caching
"""

import asyncio
import io
import json
import logging
import threading
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

import httpx

from openlabels.adapters.base import FileInfo


logger = logging.getLogger(__name__)


# =============================================================================
# LABEL CACHE
# =============================================================================


@dataclass
class CachedLabel:
    """A cached sensitivity label."""

    id: str
    name: str
    description: str
    color: str
    priority: int
    parent_id: Optional[str]
    cached_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "color": self.color,
            "priority": self.priority,
            "parent_id": self.parent_id,
        }


class LabelCache:
    """
    Thread-safe cache for sensitivity labels.

    Caches labels fetched from Graph API to reduce API calls.
    Uses TTL-based expiration.
    """

    _instance: Optional["LabelCache"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "LabelCache":
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._labels: dict[str, CachedLabel] = {}
        self._labels_by_name: dict[str, str] = {}  # name -> id mapping
        self._last_refresh: Optional[datetime] = None
        self._ttl_seconds = 300  # 5 minutes default
        self._max_labels = 1000
        self._cache_lock = threading.RLock()
        self._initialized = True

    def configure(self, ttl_seconds: int = 300, max_labels: int = 1000) -> None:
        """Configure cache parameters."""
        with self._cache_lock:
            self._ttl_seconds = ttl_seconds
            self._max_labels = max_labels

    def is_expired(self) -> bool:
        """Check if cache has expired."""
        if self._last_refresh is None:
            return True
        age = (datetime.now(timezone.utc) - self._last_refresh).total_seconds()
        return age > self._ttl_seconds

    def get(self, label_id: str) -> Optional[CachedLabel]:
        """Get a label by ID."""
        with self._cache_lock:
            if self.is_expired():
                return None
            return self._labels.get(label_id)

    def get_by_name(self, name: str) -> Optional[CachedLabel]:
        """Get a label by name."""
        with self._cache_lock:
            if self.is_expired():
                return None
            label_id = self._labels_by_name.get(name)
            if label_id:
                return self._labels.get(label_id)
            return None

    def get_all(self) -> list[CachedLabel]:
        """Get all cached labels."""
        with self._cache_lock:
            if self.is_expired():
                return []
            return list(self._labels.values())

    def set(self, labels: list[dict]) -> None:
        """Set labels in cache (replaces all)."""
        with self._cache_lock:
            self._labels.clear()
            self._labels_by_name.clear()

            for label_data in labels[:self._max_labels]:
                label = CachedLabel(
                    id=label_data.get("id", ""),
                    name=label_data.get("name", ""),
                    description=label_data.get("description", ""),
                    color=label_data.get("color", ""),
                    priority=label_data.get("priority", 0),
                    parent_id=label_data.get("parent_id"),
                )
                self._labels[label.id] = label
                self._labels_by_name[label.name] = label.id

            self._last_refresh = datetime.now(timezone.utc)
            logger.debug(f"Cached {len(self._labels)} labels")

    def invalidate(self) -> None:
        """Clear the cache."""
        with self._cache_lock:
            self._labels.clear()
            self._labels_by_name.clear()
            self._last_refresh = None

    @property
    def stats(self) -> dict:
        """Get cache statistics."""
        with self._cache_lock:
            return {
                "label_count": len(self._labels),
                "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
                "ttl_seconds": self._ttl_seconds,
                "is_expired": self.is_expired(),
            }


# Global cache instance
_label_cache = LabelCache()


def get_label_cache() -> LabelCache:
    """Get the global label cache instance."""
    return _label_cache


# =============================================================================
# LABELING RESULT
# =============================================================================


@dataclass
class LabelResult:
    """Result of a labeling operation."""

    success: bool
    label_id: Optional[str] = None
    label_name: Optional[str] = None
    method: Optional[str] = None
    error: Optional[str] = None


@dataclass
class TokenCache:
    """Cache for Graph API access tokens."""

    access_token: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_valid(self) -> bool:
        """Check if token is still valid (with 5 min buffer)."""
        return bool(self.access_token and datetime.now(timezone.utc) < (self.expires_at - timedelta(minutes=5)))


class LabelingEngine:
    """
    Unified interface for applying sensitivity labels.

    Routes to appropriate labeling method based on file source:
    - Local files: MIP SDK via pythonnet (Windows) or metadata fallback
    - SharePoint/OneDrive: Microsoft Graph API
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        """
        Initialize the labeling engine.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Azure AD application ID
            client_secret: Azure AD client secret
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token_cache = TokenCache()

        # Retry configuration
        self._max_retries = 4
        self._base_delay = 2.0  # seconds

    async def _get_access_token(self) -> str:
        """Get Graph API access token with caching and retry logic."""
        if self._token_cache.is_valid():
            return self._token_cache.access_token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }

        last_error = None
        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(token_url, data=data)

                    if response.status_code == 429:
                        # Rate limited - use Retry-After header if present
                        retry_after = int(response.headers.get("Retry-After", self._base_delay * (2 ** attempt)))
                        logger.warning(f"Rate limited, retrying after {retry_after}s")
                        await asyncio.sleep(retry_after)
                        continue

                    response.raise_for_status()
                    token_data = response.json()

                    self._token_cache.access_token = token_data["access_token"]
                    expires_in = token_data.get("expires_in", 3600)
                    self._token_cache.expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

                    return self._token_cache.access_token

            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code >= 500:
                    # Server error - retry with backoff
                    await asyncio.sleep(self._base_delay * (2 ** attempt))
                else:
                    raise
            except httpx.RequestError as e:
                last_error = e
                await asyncio.sleep(self._base_delay * (2 ** attempt))

        raise Exception(f"Failed to get access token after {self._max_retries} retries: {last_error}")

    async def _graph_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[dict] = None,
    ) -> httpx.Response:
        """Make a Graph API request with retry logic and rate limiting."""
        token = await self._get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        url = f"https://graph.microsoft.com/v1.0{endpoint}"

        last_error = None
        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    if method.upper() == "GET":
                        response = await client.get(url, headers=headers)
                    elif method.upper() == "PATCH":
                        response = await client.patch(url, headers=headers, json=json_data)
                    elif method.upper() == "POST":
                        response = await client.post(url, headers=headers, json=json_data)
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")

                    if response.status_code == 429:
                        # Rate limited
                        retry_after = int(response.headers.get("Retry-After", self._base_delay * (2 ** attempt)))
                        logger.warning(f"Graph API rate limited, retrying after {retry_after}s")
                        await asyncio.sleep(retry_after)
                        continue

                    return response

            except httpx.RequestError as e:
                last_error = e
                logger.warning(f"Graph API request failed (attempt {attempt + 1}): {e}")
                await asyncio.sleep(self._base_delay * (2 ** attempt))

        raise Exception(f"Graph API request failed after {self._max_retries} retries: {last_error}")

    async def apply_label(
        self,
        file_info: FileInfo,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """
        Apply a sensitivity label to a file.

        Args:
            file_info: File information from an adapter
            label_id: MIP label GUID to apply
            label_name: Optional label name for metadata

        Returns:
            LabelResult with success status
        """
        if file_info.adapter == "filesystem":
            return await self._apply_local_label(file_info.path, label_id, label_name)
        elif file_info.adapter in ("sharepoint", "onedrive"):
            return await self._apply_graph_label(file_info, label_id, label_name)
        else:
            return LabelResult(
                success=False,
                error=f"Unknown adapter type: {file_info.adapter}",
            )

    async def _apply_local_label(
        self,
        file_path: str,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """Apply label to local file using MIP SDK or metadata fallback."""
        # Try MIP SDK first (Windows only)
        try:
            from openlabels.labeling.mip import MIPClient

            mip_client = MIPClient(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

            if await mip_client.initialize():
                result = await mip_client.apply_label(file_path, label_id)
                if result.success:
                    return LabelResult(
                        success=True,
                        label_id=label_id,
                        label_name=label_name,
                        method="mip_sdk",
                    )
        except ImportError as e:
            logger.debug(f"MIP SDK not installed: {e}")
        except RuntimeError as e:
            logger.debug(f"MIP SDK runtime error: {e}")
        except OSError as e:
            logger.debug(f"MIP SDK OS error: {e}")

        # Fallback to metadata-based labeling
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext in (".docx", ".xlsx", ".pptx"):
            return await self._apply_office_metadata(file_path, label_id, label_name)
        elif ext == ".pdf":
            return await self._apply_pdf_metadata(file_path, label_id, label_name)
        else:
            return await self._apply_sidecar(file_path, label_id, label_name)

    @staticmethod
    def _read_file_bytes(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    @staticmethod
    def _write_file_bytes(path: str, data: bytes) -> None:
        with open(path, "wb") as f:
            f.write(data)

    async def _apply_office_metadata(
        self,
        file_path: str,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """Apply label via Office document custom properties."""
        try:
            content = await asyncio.to_thread(self._read_file_bytes, file_path)

            with zipfile.ZipFile(io.BytesIO(content), "r") as zf:
                file_list = zf.namelist()

                # Read existing custom properties or create new
                custom_props_path = "docProps/custom.xml"
                if custom_props_path in file_list:
                    custom_xml = zf.read(custom_props_path).decode("utf-8")
                else:
                    custom_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
</Properties>'''

                # Add/update label properties
                import re

                # Remove existing label properties
                custom_xml = re.sub(r'<property[^>]*name="OpenLabels_[^"]*"[^>]*>.*?</property>', '', custom_xml, flags=re.DOTALL)
                custom_xml = re.sub(r'<property[^>]*name="Classification"[^>]*>.*?</property>', '', custom_xml, flags=re.DOTALL)

                # Find highest pid
                pids = re.findall(r'pid="(\d+)"', custom_xml)
                next_pid = max([int(p) for p in pids], default=1) + 1

                # Build new properties
                new_props = f'''
  <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="{next_pid}" name="OpenLabels_LabelId">
    <vt:lpwstr>{label_id}</vt:lpwstr>
  </property>
  <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="{next_pid + 1}" name="OpenLabels_LabelName">
    <vt:lpwstr>{label_name or ''}</vt:lpwstr>
  </property>
  <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="{next_pid + 2}" name="Classification">
    <vt:lpwstr>{label_name or label_id}</vt:lpwstr>
  </property>
'''
                # Insert before closing tag
                custom_xml = custom_xml.replace("</Properties>", new_props + "</Properties>")

                # Write updated file
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as out_zf:
                    for item in file_list:
                        if item != custom_props_path:
                            out_zf.writestr(item, zf.read(item))
                    out_zf.writestr(custom_props_path, custom_xml.encode("utf-8"))

                    # Update content types if custom.xml is new
                    if custom_props_path not in file_list:
                        content_types = zf.read("[Content_Types].xml").decode("utf-8")
                        if "custom.xml" not in content_types:
                            content_types = content_types.replace(
                                "</Types>",
                                '<Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/></Types>'
                            )
                            out_zf.writestr("[Content_Types].xml", content_types.encode("utf-8"))

                await asyncio.to_thread(self._write_file_bytes, file_path, output.getvalue())

            return LabelResult(
                success=True,
                label_id=label_id,
                label_name=label_name,
                method="office_metadata",
            )

        except PermissionError as e:
            logger.error(f"Permission denied applying Office metadata label: {e}")
            return await self._apply_sidecar(file_path, label_id, label_name)
        except OSError as e:
            logger.error(f"OS error applying Office metadata label: {e}")
            return await self._apply_sidecar(file_path, label_id, label_name)
        except zipfile.BadZipFile as e:
            logger.error(f"Invalid Office file format: {e}")
            return await self._apply_sidecar(file_path, label_id, label_name)

    def _apply_pdf_metadata_sync(
        self,
        file_path: str,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """Sync implementation of PDF metadata labeling (runs in thread)."""
        try:
            from pypdf import PdfReader, PdfWriter
        except ImportError:
            from PyPDF2 import PdfReader, PdfWriter

        reader = PdfReader(file_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        if reader.metadata:
            writer.add_metadata(dict(reader.metadata))

        writer.add_metadata({
            "/OpenLabels_LabelId": label_id,
            "/OpenLabels_LabelName": label_name or "",
            "/Classification": label_name or label_id,
        })

        with open(file_path, "wb") as f:
            writer.write(f)

        return LabelResult(
            success=True,
            label_id=label_id,
            label_name=label_name,
            method="pdf_metadata",
        )

    async def _apply_pdf_metadata(
        self,
        file_path: str,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """Apply label via PDF metadata (runs sync I/O in thread)."""
        try:
            return await asyncio.to_thread(
                self._apply_pdf_metadata_sync, file_path, label_id, label_name
            )
        except PermissionError as e:
            logger.error(f"Permission denied applying PDF metadata label: {e}")
            return await self._apply_sidecar(file_path, label_id, label_name)
        except OSError as e:
            logger.error(f"OS error applying PDF metadata label: {e}")
            return await self._apply_sidecar(file_path, label_id, label_name)
        except ValueError as e:
            logger.error(f"Invalid PDF format: {e}")
            return await self._apply_sidecar(file_path, label_id, label_name)

    async def _apply_sidecar(
        self,
        file_path: str,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """Apply label via sidecar file (fallback method)."""
        try:
            sidecar_path = f"{file_path}.openlabels"
            sidecar_data = {
                "label_id": label_id,
                "label_name": label_name,
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "applied_by": "openlabels",
            }

            def _write_sidecar():
                with open(sidecar_path, "w") as f:
                    json.dump(sidecar_data, f, indent=2)
            await asyncio.to_thread(_write_sidecar)

            return LabelResult(
                success=True,
                label_id=label_id,
                label_name=label_name,
                method="sidecar",
            )

        except PermissionError as e:
            return LabelResult(
                success=False,
                label_id=label_id,
                error=f"Permission denied creating sidecar file: {e}",
            )
        except OSError as e:
            return LabelResult(
                success=False,
                label_id=label_id,
                error=f"OS error creating sidecar file: {e}",
            )

    async def _apply_graph_label(
        self,
        file_info: FileInfo,
        label_id: str,
        label_name: Optional[str] = None,
    ) -> LabelResult:
        """Apply label using Graph API for SharePoint/OneDrive files."""
        try:
            # Build Graph API endpoint from file_info attributes
            # item_id format may be: "sites/{site_id}/drive/items/{item_id}" or just item ID
            item_id = file_info.item_id or ""

            # Determine the Graph API endpoint
            if file_info.adapter == "sharepoint":
                # SharePoint: /sites/{site_id}/drive/items/{item_id}
                if "/drive/items/" in item_id:
                    endpoint = f"/{item_id}"
                elif file_info.site_id and item_id:
                    endpoint = f"/sites/{file_info.site_id}/drive/items/{item_id}"
                else:
                    # Try to resolve from URL using shares API
                    endpoint = await self._resolve_share_url(file_info.path)
                    if not endpoint:
                        return LabelResult(
                            success=False,
                            label_id=label_id,
                            error="Could not resolve SharePoint file ID",
                        )
            else:
                # OneDrive: /users/{user_id}/drive/items/{item_id}
                if "/drive/items/" in item_id:
                    endpoint = f"/{item_id}"
                elif file_info.user_id and item_id:
                    endpoint = f"/users/{file_info.user_id}/drive/items/{item_id}"
                else:
                    endpoint = await self._resolve_share_url(file_info.path)
                    if not endpoint:
                        return LabelResult(
                            success=False,
                            label_id=label_id,
                            error="Could not resolve OneDrive file ID",
                        )

            # Apply sensitivity label via PATCH
            label_payload = {
                "sensitivityLabel": {
                    "labelId": label_id,
                    "assignmentMethod": "standard",
                }
            }

            response = await self._graph_request("PATCH", endpoint, label_payload)

            if response.status_code in (200, 204):
                return LabelResult(
                    success=True,
                    label_id=label_id,
                    label_name=label_name,
                    method="graph_api",
                )
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get("error", {}).get("message", response.text)
                return LabelResult(
                    success=False,
                    label_id=label_id,
                    error=f"Graph API error: {error_msg}",
                )

        except httpx.TimeoutException as e:
            logger.error(f"Timeout applying Graph API label: {e}")
            return LabelResult(
                success=False,
                label_id=label_id,
                error=f"Request timed out: {e}",
            )
        except httpx.ConnectError as e:
            logger.error(f"Connection error applying Graph API label: {e}")
            return LabelResult(
                success=False,
                label_id=label_id,
                error=f"Connection error: {e}",
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error applying Graph API label: {e}")
            return LabelResult(
                success=False,
                label_id=label_id,
                error=f"HTTP error {e.response.status_code}",
            )

    async def _resolve_share_url(self, url: str) -> Optional[str]:
        """Resolve a SharePoint/OneDrive URL to a Graph API driveItem path."""
        try:
            import base64

            # Encode URL for shares API
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            share_token = f"u!{encoded_url}"

            response = await self._graph_request("GET", f"/shares/{share_token}/driveItem")

            if response.status_code == 200:
                item_data = response.json()
                parent_ref = item_data.get("parentReference", {})
                drive_id = parent_ref.get("driveId")
                item_id = item_data.get("id")

                if drive_id and item_id:
                    return f"/drives/{drive_id}/items/{item_id}"

            return None

        except httpx.TimeoutException as e:
            logger.error(f"Timeout resolving share URL: {e}")
            return None
        except httpx.ConnectError as e:
            logger.error(f"Connection error resolving share URL: {e}")
            return None
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error resolving share URL: {e}")
            return None

    async def remove_label(self, file_info: FileInfo) -> LabelResult:
        """
        Remove sensitivity label from a file.

        Args:
            file_info: File information from an adapter

        Returns:
            LabelResult with success status
        """
        if file_info.adapter == "filesystem":
            return await self._remove_local_label(file_info.path)
        elif file_info.adapter in ("sharepoint", "onedrive"):
            return await self._remove_graph_label(file_info)
        else:
            return LabelResult(
                success=False,
                error=f"Unknown adapter type: {file_info.adapter}",
            )

    async def _remove_local_label(self, file_path: str) -> LabelResult:
        """Remove label from local file."""
        path = Path(file_path)
        ext = path.suffix.lower()

        # Remove sidecar file if exists
        sidecar_path = Path(f"{file_path}.openlabels")
        if sidecar_path.exists():
            sidecar_path.unlink()

        if ext in (".docx", ".xlsx", ".pptx"):
            return await self._remove_office_label(file_path)
        elif ext == ".pdf":
            return await self._remove_pdf_label(file_path)
        else:
            # Sidecar removal was enough
            return LabelResult(success=True, method="sidecar_removed")

    async def _remove_office_label(self, file_path: str) -> LabelResult:
        """Remove label from Office document custom properties."""
        try:
            with open(file_path, "rb") as f:
                content = f.read()

            with zipfile.ZipFile(io.BytesIO(content), "r") as zf:
                file_list = zf.namelist()
                custom_props_path = "docProps/custom.xml"

                if custom_props_path not in file_list:
                    return LabelResult(success=True, method="no_label_found")

                custom_xml = zf.read(custom_props_path).decode("utf-8")

                import re
                # Remove OpenLabels and Classification properties
                custom_xml = re.sub(r'<property[^>]*name="OpenLabels_[^"]*"[^>]*>.*?</property>\s*', '', custom_xml, flags=re.DOTALL)
                custom_xml = re.sub(r'<property[^>]*name="Classification"[^>]*>.*?</property>\s*', '', custom_xml, flags=re.DOTALL)

                # Write updated file
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as out_zf:
                    for item in file_list:
                        if item != custom_props_path:
                            out_zf.writestr(item, zf.read(item))
                    out_zf.writestr(custom_props_path, custom_xml.encode("utf-8"))

                with open(file_path, "wb") as f:
                    f.write(output.getvalue())

            return LabelResult(success=True, method="office_metadata_removed")

        except PermissionError as e:
            return LabelResult(success=False, error=f"Permission denied removing Office label: {e}")
        except OSError as e:
            return LabelResult(success=False, error=f"OS error removing Office label: {e}")
        except zipfile.BadZipFile as e:
            return LabelResult(success=False, error=f"Invalid Office file format: {e}")

    async def _remove_pdf_label(self, file_path: str) -> LabelResult:
        """Remove label from PDF metadata."""
        try:
            try:
                from pypdf import PdfReader, PdfWriter
            except ImportError:
                from PyPDF2 import PdfReader, PdfWriter

            reader = PdfReader(file_path)
            writer = PdfWriter()

            for page in reader.pages:
                writer.add_page(page)

            # Copy metadata except label fields
            if reader.metadata:
                clean_metadata = {
                    k: v for k, v in dict(reader.metadata).items()
                    if not k.startswith("/OpenLabels_") and k != "/Classification"
                }
                writer.add_metadata(clean_metadata)

            with open(file_path, "wb") as f:
                writer.write(f)

            return LabelResult(success=True, method="pdf_metadata_removed")

        except PermissionError as e:
            return LabelResult(success=False, error=f"Permission denied removing PDF label: {e}")
        except OSError as e:
            return LabelResult(success=False, error=f"OS error removing PDF label: {e}")
        except ValueError as e:
            return LabelResult(success=False, error=f"Invalid PDF format: {e}")

    async def _remove_graph_label(self, file_info: FileInfo) -> LabelResult:
        """Remove label from SharePoint/OneDrive file via Graph API."""
        try:
            item_id = file_info.item_id or ""

            if "/drive/items/" in item_id:
                endpoint = f"/{item_id}"
            elif file_info.site_id and item_id:
                endpoint = f"/sites/{file_info.site_id}/drive/items/{item_id}"
            elif file_info.user_id and item_id:
                endpoint = f"/users/{file_info.user_id}/drive/items/{item_id}"
            else:
                resolved = await self._resolve_share_url(file_info.path)
                if not resolved:
                    return LabelResult(success=False, error="Could not resolve file ID")
                endpoint = resolved

            # Remove label by setting to null
            response = await self._graph_request("PATCH", endpoint, {"sensitivityLabel": None})

            if response.status_code in (200, 204):
                return LabelResult(success=True, method="graph_api_removed")
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get("error", {}).get("message", response.text)
                return LabelResult(success=False, error=f"Graph API error: {error_msg}")

        except httpx.TimeoutException as e:
            return LabelResult(success=False, error=f"Request timed out: {e}")
        except httpx.ConnectError as e:
            return LabelResult(success=False, error=f"Connection error: {e}")
        except httpx.HTTPStatusError as e:
            return LabelResult(success=False, error=f"HTTP error {e.response.status_code}")

    async def get_available_labels(self, use_cache: bool = True) -> list[dict]:
        """
        Get available sensitivity labels from M365.

        Args:
            use_cache: Whether to use cached labels (default True)

        Returns:
            List of label dictionaries with id, name, description, color, priority
        """
        # Check cache first
        if use_cache and not _label_cache.is_expired():
            cached = _label_cache.get_all()
            if cached:
                return [label.to_dict() for label in cached]

        try:
            response = await self._graph_request("GET", "/informationProtection/policy/labels")

            if response.status_code != 200:
                logger.error(f"Failed to fetch labels: {response.text}")
                # Return cached labels even if expired, if API fails
                cached = _label_cache.get_all()
                return [label.to_dict() for label in cached] if cached else []

            data = response.json()
            labels = []

            for label in data.get("value", []):
                labels.append({
                    "id": label.get("id"),
                    "name": label.get("name"),
                    "description": label.get("description", ""),
                    "color": label.get("color", ""),
                    "priority": label.get("priority", 0),
                    "parent_id": label.get("parent", {}).get("id") if label.get("parent") else None,
                })

            # Update cache
            _label_cache.set(labels)

            return labels

        except httpx.TimeoutException as e:
            logger.error(f"Timeout getting available labels: {e}")
            cached = _label_cache.get_all()
            return [label.to_dict() for label in cached] if cached else []
        except httpx.ConnectError as e:
            logger.error(f"Connection error getting available labels: {e}")
            cached = _label_cache.get_all()
            return [label.to_dict() for label in cached] if cached else []
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error getting available labels: {e}")
            cached = _label_cache.get_all()
            return [label.to_dict() for label in cached] if cached else []

    def get_cached_label(self, label_id: str) -> Optional[dict]:
        """
        Get a label from cache by ID.

        Args:
            label_id: The label GUID

        Returns:
            Label dict if cached, None otherwise
        """
        cached = _label_cache.get(label_id)
        return cached.to_dict() if cached else None

    def get_cached_label_by_name(self, name: str) -> Optional[dict]:
        """
        Get a label from cache by name.

        Args:
            name: The label name

        Returns:
            Label dict if cached, None otherwise
        """
        cached = _label_cache.get_by_name(name)
        return cached.to_dict() if cached else None

    def invalidate_label_cache(self) -> None:
        """Invalidate the label cache, forcing a refresh on next access."""
        _label_cache.invalidate()

    @property
    def label_cache_stats(self) -> dict:
        """Get label cache statistics."""
        return _label_cache.stats

    async def get_current_label(self, file_info: FileInfo) -> Optional[dict]:
        """
        Get the current label on a file.

        Args:
            file_info: File to check

        Returns:
            Label dict with id and name, or None if no label
        """
        if file_info.adapter == "filesystem":
            return await self._get_local_label(file_info.path)
        elif file_info.adapter in ("sharepoint", "onedrive"):
            return await self._get_graph_label(file_info)
        return None

    async def _get_local_label(self, file_path: str) -> Optional[dict]:
        """Get label from local file metadata or sidecar."""
        path = Path(file_path)
        ext = path.suffix.lower()

        # Check sidecar first
        sidecar_path = Path(f"{file_path}.openlabels")
        if sidecar_path.exists():
            try:
                with open(sidecar_path) as f:
                    data = json.load(f)
                return {
                    "id": data.get("label_id"),
                    "name": data.get("label_name"),
                }
            except PermissionError as e:
                logger.debug(f"Permission denied reading sidecar label for {file_path}: {e}")
            except OSError as e:
                logger.debug(f"OS error reading sidecar label for {file_path}: {e}")
            except json.JSONDecodeError as e:
                logger.debug(f"Invalid JSON in sidecar for {file_path}: {e}")

        # Check Office document metadata
        if ext in (".docx", ".xlsx", ".pptx"):
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    if "docProps/custom.xml" in zf.namelist():
                        custom_xml = zf.read("docProps/custom.xml").decode("utf-8")
                        import re
                        label_match = re.search(r'name="OpenLabels_LabelId"[^>]*>.*?<vt:lpwstr>([^<]+)</vt:lpwstr>', custom_xml, re.DOTALL)
                        name_match = re.search(r'name="OpenLabels_LabelName"[^>]*>.*?<vt:lpwstr>([^<]+)</vt:lpwstr>', custom_xml, re.DOTALL)
                        if label_match:
                            return {
                                "id": label_match.group(1),
                                "name": name_match.group(1) if name_match else None,
                            }
            except PermissionError as e:
                logger.debug(f"Permission denied reading Office metadata label for {file_path}: {e}")
            except OSError as e:
                logger.debug(f"OS error reading Office metadata label for {file_path}: {e}")
            except zipfile.BadZipFile as e:
                logger.debug(f"Invalid Office file format for {file_path}: {e}")

        # Check PDF metadata
        if ext == ".pdf":
            try:
                try:
                    from pypdf import PdfReader
                except ImportError:
                    from PyPDF2 import PdfReader

                reader = PdfReader(file_path)
                if reader.metadata:
                    label_id = reader.metadata.get("/OpenLabels_LabelId")
                    label_name = reader.metadata.get("/OpenLabels_LabelName")
                    if label_id:
                        return {"id": label_id, "name": label_name}
            except PermissionError as e:
                logger.debug(f"Permission denied reading PDF metadata label for {file_path}: {e}")
            except OSError as e:
                logger.debug(f"OS error reading PDF metadata label for {file_path}: {e}")
            except ValueError as e:
                logger.debug(f"Invalid PDF format for {file_path}: {e}")

        return None

    async def _get_graph_label(self, file_info: FileInfo) -> Optional[dict]:
        """Get label from SharePoint/OneDrive file via Graph API."""
        try:
            item_id = file_info.item_id or ""

            if "/drive/items/" in item_id:
                endpoint = f"/{item_id}?$select=sensitivityLabel"
            elif file_info.site_id and item_id:
                endpoint = f"/sites/{file_info.site_id}/drive/items/{item_id}?$select=sensitivityLabel"
            elif file_info.user_id and item_id:
                endpoint = f"/users/{file_info.user_id}/drive/items/{item_id}?$select=sensitivityLabel"
            else:
                resolved = await self._resolve_share_url(file_info.path)
                if not resolved:
                    return None
                endpoint = f"{resolved}?$select=sensitivityLabel"

            response = await self._graph_request("GET", endpoint)

            if response.status_code == 200:
                data = response.json()
                label_data = data.get("sensitivityLabel")
                if label_data:
                    return {
                        "id": label_data.get("labelId"),
                        "name": label_data.get("displayName"),
                    }

            return None

        except httpx.TimeoutException as e:
            logger.error(f"Timeout getting Graph label: {e}")
            return None
        except httpx.ConnectError as e:
            logger.error(f"Connection error getting Graph label: {e}")
            return None
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error getting Graph label: {e}")
            return None
