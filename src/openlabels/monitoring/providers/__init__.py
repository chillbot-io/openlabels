"""
Event providers for the monitoring harvester.

Each provider wraps a platform-specific audit subsystem and yields
``RawAccessEvent`` instances that the ``EventHarvester`` persists to
the ``file_access_events`` table.

Providers
---------
- ``WindowsSACLProvider`` — Windows Security Event Log via ``wevtutil``
- ``AuditdProvider`` — Linux auditd via ``ausearch``
"""

from .base import EventProvider, RawAccessEvent
from .windows import WindowsSACLProvider
from .linux import AuditdProvider

__all__ = [
    "EventProvider",
    "RawAccessEvent",
    "WindowsSACLProvider",
    "AuditdProvider",
]
