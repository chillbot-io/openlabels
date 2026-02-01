"""
OpenLabels Adapters.

Adapters normalize detection results from various sources into a common format
that can be fed into the OpenLabels scoring engine.

Available adapters:
- MacieAdapter: AWS Macie + S3
- DLPAdapter: GCP DLP + GCS
- PurviewAdapter: Azure Purview + Blob
- NTFSAdapter: Windows NTFS + SMB shares
- NFSAdapter: NFS exports
- M365Adapter: SharePoint / OneDrive / Teams
- PresidioAdapter: Microsoft Presidio

For the built-in scanner, use:
    from openlabels.adapters.scanner import Detector, detect, detect_file
"""

from .base import (
    Adapter,
    Entity,
    NormalizedContext,
    NormalizedInput,
    ExposureLevel,
    EntityAggregator,
)
from .macie import MacieAdapter
from .dlp import DLPAdapter
from .purview import PurviewAdapter
from .ntfs import NTFSAdapter
from .nfs import NFSAdapter
from .m365 import M365Adapter
from .presidio import PresidioAdapter

__all__ = [
    "Adapter",
    "Entity",
    "NormalizedContext",
    "NormalizedInput",
    "ExposureLevel",
    "EntityAggregator",
    "MacieAdapter",
    "DLPAdapter",
    "PurviewAdapter",
    "NTFSAdapter",
    "NFSAdapter",
    "M365Adapter",
    "PresidioAdapter",
]
