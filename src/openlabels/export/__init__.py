"""SIEM export integration (Phase K).

Provides adapters for exporting OpenLabels findings to major SIEM platforms:
Splunk, Microsoft Sentinel, IBM QRadar, Elasticsearch, and generic syslog/CEF.
"""

from openlabels.export.adapters.base import ExportRecord, SIEMAdapter
from openlabels.export.engine import ExportEngine

__all__ = [
    "ExportEngine",
    "ExportRecord",
    "SIEMAdapter",
]
