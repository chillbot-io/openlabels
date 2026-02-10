"""
Base types for file access monitoring.

Defines the core data structures used across the monitoring module:
- AccessEvent: A single file access event
- WatchedFile: A file registered for monitoring
- MonitoringResult: Result of monitoring operations

Exception classes live in openlabels.exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class AccessAction(str, Enum):
    """Types of file access actions."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    RENAME = "rename"
    PERMISSION_CHANGE = "permission_change"
    UNKNOWN = "unknown"


@dataclass
class AccessEvent:
    """
    A single file access event.

    Represents one access to a monitored file, captured from
    platform audit logs (Windows Security Event Log, Linux auditd).
    """

    path: Path
    timestamp: datetime
    action: AccessAction

    # User information
    user_sid: str | None = None  # Windows SID or Linux UID
    user_name: str | None = None  # Resolved username
    user_domain: str | None = None  # Windows domain

    # Process information
    process_name: str | None = None
    process_id: int | None = None

    # Platform-specific
    event_id: int | None = None  # Windows Event ID or audit serial
    success: bool = True  # Whether access succeeded

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "path": str(self.path),
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "user_sid": self.user_sid,
            "user_name": self.user_name,
            "user_domain": self.user_domain,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "event_id": self.event_id,
            "success": self.success,
        }

    @property
    def user_display(self) -> str:
        """User in display format (DOMAIN\\user or user)."""
        if self.user_domain and self.user_name:
            return f"{self.user_domain}\\{self.user_name}"
        return self.user_name or self.user_sid or "unknown"


@dataclass
class WatchedFile:
    """
    A file registered for access monitoring.

    Tracks metadata about monitored files including risk tier,
    when monitoring was enabled, and last access information.
    """

    path: Path
    risk_tier: str  # "CRITICAL", "HIGH", etc.
    added_at: datetime = field(default_factory=datetime.now)

    # Monitoring status
    sacl_enabled: bool = False  # Windows: SACL added
    audit_rule_enabled: bool = False  # Linux: auditd rule added

    # Last access info
    last_event_at: datetime | None = None
    access_count: int = 0

    # Label reference
    label_id: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "path": str(self.path),
            "risk_tier": self.risk_tier,
            "added_at": self.added_at.isoformat(),
            "sacl_enabled": self.sacl_enabled,
            "audit_rule_enabled": self.audit_rule_enabled,
            "last_event_at": self.last_event_at.isoformat() if self.last_event_at else None,
            "access_count": self.access_count,
            "label_id": self.label_id,
        }


@dataclass
class MonitoringResult:
    """
    Result of a monitoring operation.

    Returned by enable_monitoring, disable_monitoring, etc.
    """

    success: bool
    path: Path
    message: str | None = None
    error: str | None = None

    # For enable operations
    sacl_enabled: bool = False
    audit_rule_enabled: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "path": str(self.path),
            "message": self.message,
            "error": self.error,
            "sacl_enabled": self.sacl_enabled,
            "audit_rule_enabled": self.audit_rule_enabled,
        }



# Windows Event IDs for file access
WINDOWS_EVENT_IDS = {
    4663: "Object access attempt",
    4656: "Handle requested",
    4658: "Handle closed",
    4660: "Object deleted",
    4670: "Permissions changed",
}

# Windows access mask bits
WINDOWS_ACCESS_MASKS = {
    0x1: AccessAction.READ,  # ReadData / ListDirectory
    0x2: AccessAction.WRITE,  # WriteData / AddFile
    0x4: AccessAction.WRITE,  # AppendData / AddSubdirectory
    0x10000: AccessAction.DELETE,  # Delete
    0x40000: AccessAction.PERMISSION_CHANGE,  # WriteDacl
}
