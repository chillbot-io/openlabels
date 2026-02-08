"""
Event providers for the monitoring harvester.

Each provider implements the async ``EventProvider`` protocol and returns
``RawAccessEvent`` instances that the ``EventHarvester`` persists to
the ``file_access_events`` table.

Providers
---------
- ``WindowsSACLProvider`` — Windows Security Event Log via ``wevtutil``
- ``AuditdProvider`` — Linux auditd via ``ausearch``
- ``M365AuditProvider`` — Office 365 Management Activity API (SharePoint/OneDrive audit)
- ``GraphWebhookProvider`` — Microsoft Graph change notifications (delta queries)
"""

from .base import EventProvider, RawAccessEvent
from .windows import WindowsSACLProvider
from .linux import AuditdProvider

# M365AuditProvider and GraphWebhookProvider are imported lazily
# (they pull in httpx and GraphClient at import time).  Use:
#   from openlabels.monitoring.providers.m365_audit import M365AuditProvider
#   from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

__all__ = [
    "EventProvider",
    "RawAccessEvent",
    "WindowsSACLProvider",
    "AuditdProvider",
]
