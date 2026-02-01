"""
Storage adapters for scanning different file sources.
"""

from openlabels.adapters.base import Adapter, FileInfo, ExposureLevel
from openlabels.adapters.filesystem import FilesystemAdapter
from openlabels.adapters.sharepoint import SharePointAdapter
from openlabels.adapters.onedrive import OneDriveAdapter

__all__ = [
    "Adapter",
    "FileInfo",
    "ExposureLevel",
    "FilesystemAdapter",
    "SharePointAdapter",
    "OneDriveAdapter",
]
