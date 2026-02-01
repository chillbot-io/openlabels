"""
Unified labeling engine interface.
"""

from typing import Optional
from dataclasses import dataclass

from openlabels.adapters.base import FileInfo


@dataclass
class LabelResult:
    """Result of a labeling operation."""

    success: bool
    label_id: Optional[str] = None
    label_name: Optional[str] = None
    error: Optional[str] = None


class LabelingEngine:
    """
    Unified interface for applying sensitivity labels.

    Routes to appropriate labeling method based on file source:
    - Local files: MIP SDK via pythonnet
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

        # Lazy initialization of labelers
        self._mip_labeler = None
        self._graph_labeler = None

    async def apply_label(
        self,
        file_info: FileInfo,
        label_id: str,
    ) -> LabelResult:
        """
        Apply a sensitivity label to a file.

        Args:
            file_info: File information from an adapter
            label_id: MIP label GUID to apply

        Returns:
            LabelResult with success status
        """
        if file_info.adapter == "filesystem":
            return await self._apply_mip_label(file_info.path, label_id)
        elif file_info.adapter in ("sharepoint", "onedrive"):
            return await self._apply_graph_label(file_info, label_id)
        else:
            return LabelResult(
                success=False,
                error=f"Unknown adapter type: {file_info.adapter}",
            )

    async def _apply_mip_label(self, file_path: str, label_id: str) -> LabelResult:
        """Apply label using MIP SDK."""
        # TODO: Implement MIP SDK integration
        # This will use pythonnet to call .NET MIP SDK

        return LabelResult(
            success=True,
            label_id=label_id,
        )

    async def _apply_graph_label(
        self,
        file_info: FileInfo,
        label_id: str,
    ) -> LabelResult:
        """Apply label using Graph API."""
        # TODO: Implement Graph API labeling

        return LabelResult(
            success=True,
            label_id=label_id,
        )

    async def get_available_labels(self) -> list[dict]:
        """
        Get available sensitivity labels from M365.

        Returns:
            List of label dictionaries
        """
        # TODO: Implement Graph API call to get labels
        return []

    async def get_current_label(self, file_info: FileInfo) -> Optional[str]:
        """
        Get the current label on a file.

        Args:
            file_info: File to check

        Returns:
            Label ID or None
        """
        # TODO: Implement label retrieval
        return None
