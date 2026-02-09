"""
Storage adapters for scanning different file sources.

Provides:
- FilesystemAdapter: Local and network file systems
- SharePointAdapter: SharePoint Online via Graph API
- OneDriveAdapter: OneDrive for Business via Graph API
- S3Adapter: AWS S3 buckets via boto3
- GCSAdapter: Google Cloud Storage via google-cloud-storage
- AzureBlobAdapter: Azure Blob Storage via azure-storage-blob
- FilterConfig: File/account exclusion configuration
- GraphClient: Rate-limited Graph API client with connection pooling
"""

from openlabels.adapters.base import (
    ReadAdapter,
    RemediationAdapter,
    FileInfo,
    ExposureLevel,
    FilterConfig,
    LABEL_COMPATIBLE_EXTENSIONS,
    is_label_compatible,
    supports_remediation,
)
from openlabels.adapters.filesystem import FilesystemAdapter
from openlabels.adapters.sharepoint import SharePointAdapter
from openlabels.adapters.onedrive import OneDriveAdapter
from openlabels.adapters.graph_base import BaseGraphAdapter
from openlabels.adapters.graph_client import GraphClient, RateLimiterConfig
from openlabels.adapters.health import AdapterHealth, AdapterHealthChecker
from openlabels.adapters.s3 import S3Adapter
from openlabels.adapters.gcs import GCSAdapter
from openlabels.adapters.azure_blob import AzureBlobAdapter

__all__ = [
    "ReadAdapter",
    "RemediationAdapter",
    "FileInfo",
    "ExposureLevel",
    "FilterConfig",
    "supports_remediation",
    "FilesystemAdapter",
    "SharePointAdapter",
    "OneDriveAdapter",
    "S3Adapter",
    "GCSAdapter",
    "AzureBlobAdapter",
    "BaseGraphAdapter",
    "GraphClient",
    "RateLimiterConfig",
    "AdapterHealth",
    "AdapterHealthChecker",
]
