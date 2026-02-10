"""
Base types for remediation actions.

This module defines the common types used across all remediation
operations (quarantine, permission lockdown, etc.).

Exception classes live in openlabels.exceptions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class RemediationAction(str, Enum):
    """Types of remediation actions."""

    QUARANTINE = "quarantine"
    RESTORE = "restore"
    LOCKDOWN = "lockdown"
    NONE = "none"


@dataclass
class RemediationResult:
    """
    Result of a remediation action.

    Captures the outcome of quarantine or permission lockdown operations,
    including success/failure status, timestamps, and audit information.
    """

    success: bool
    action: RemediationAction
    source_path: Path
    timestamp: datetime = field(default_factory=datetime.now)

    # Quarantine-specific
    dest_path: Path | None = None

    # Lockdown-specific
    principals: list[str] | None = None
    previous_acl: str | None = None  # Base64-encoded for audit

    # Error information
    error: str | None = None
    error_code: int | None = None

    # Integrity
    file_hash: str | None = None  # SHA-256 at time of operation

    # Audit
    performed_by: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "action": self.action.value,
            "source_path": str(self.source_path),
            "dest_path": str(self.dest_path) if self.dest_path else None,
            "principals": self.principals,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
            "error_code": self.error_code,
            "file_hash": self.file_hash,
            "performed_by": self.performed_by,
        }

    @classmethod
    def success_quarantine(
        cls,
        source: Path,
        dest: Path,
        performed_by: str | None = None,
    ) -> "RemediationResult":
        """Create a successful quarantine result."""
        return cls(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=source,
            dest_path=dest,
            performed_by=performed_by,
        )

    @classmethod
    def success_lockdown(
        cls,
        path: Path,
        principals: list[str],
        previous_acl: str | None = None,
        performed_by: str | None = None,
    ) -> "RemediationResult":
        """Create a successful lockdown result."""
        return cls(
            success=True,
            action=RemediationAction.LOCKDOWN,
            source_path=path,
            principals=principals,
            previous_acl=previous_acl,
            performed_by=performed_by,
        )

    @classmethod
    def failure(
        cls,
        action: RemediationAction,
        source: Path,
        error: str,
        error_code: int | None = None,
    ) -> "RemediationResult":
        """Create a failure result."""
        return cls(
            success=False,
            action=action,
            source_path=source,
            error=error,
            error_code=error_code,
        )



def get_current_user() -> str:
    """
    Get the current user for audit logging.

    Returns username in DOMAIN\\user or user@domain format.
    """
    import getpass
    import os
    import platform

    username = getpass.getuser()

    if platform.system() == "Windows":
        # Try to get domain-qualified name
        domain = os.environ.get("USERDOMAIN", "")
        if domain:
            return f"{domain}\\{username}"

    return username
