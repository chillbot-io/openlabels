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
from typing import List, Optional


class RemediationAction(str, Enum):
    """Types of remediation actions."""

    QUARANTINE = "quarantine"
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
    dest_path: Optional[Path] = None

    # Lockdown-specific
    principals: Optional[List[str]] = None
    previous_acl: Optional[str] = None  # Base64-encoded for audit

    # Error information
    error: Optional[str] = None
    error_code: Optional[int] = None

    # Audit
    performed_by: Optional[str] = None

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
            "performed_by": self.performed_by,
        }

    @classmethod
    def success_quarantine(
        cls,
        source: Path,
        dest: Path,
        performed_by: Optional[str] = None,
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
        principals: List[str],
        previous_acl: Optional[str] = None,
        performed_by: Optional[str] = None,
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
        error_code: Optional[int] = None,
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
