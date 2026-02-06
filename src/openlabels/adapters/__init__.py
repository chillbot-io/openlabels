"""
Storage adapters for scanning different file sources.

Provides:
- FilesystemAdapter: Local and network file systems
- SharePointAdapter: SharePoint Online via Graph API
- OneDriveAdapter: OneDrive for Business via Graph API
- FilterConfig: File/account exclusion configuration
- GraphClient: Rate-limited Graph API client with connection pooling
"""

from openlabels.adapters.base import Adapter, FileInfo, ExposureLevel, FilterConfig
from openlabels.adapters.filesystem import FilesystemAdapter
from openlabels.adapters.sharepoint import SharePointAdapter
from openlabels.adapters.onedrive import OneDriveAdapter
from openlabels.adapters.graph_base import BaseGraphAdapter
from openlabels.adapters.graph_client import GraphClient, RateLimiterConfig

__all__ = [
    "Adapter",
    "FileInfo",
    "ExposureLevel",
    "FilterConfig",
    "FilesystemAdapter",
    "SharePointAdapter",
    "OneDriveAdapter",
    "BaseGraphAdapter",
    "GraphClient",
    "RateLimiterConfig",
]
