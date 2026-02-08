"""
Remediation actions for sensitive files.

Provides quarantine (move to secure location) and permission lockdown
(restrict access to specified principals) capabilities.

Usage:
    from openlabels.remediation import quarantine, lock_down

    # Move sensitive file to quarantine
    result = quarantine(
        source=Path("/data/sensitive.xlsx"),
        destination=Path("/quarantine/2026-02/"),
    )

    # Lock down permissions to Administrators only
    result = lock_down(
        path=Path("/data/sensitive.xlsx"),
        allowed_principals=["BUILTIN\\Administrators"],
    )
"""

from .base import (
    RemediationResult,
    RemediationAction,
    get_current_user,
)
from openlabels.exceptions import (
    RemediationError,
    QuarantineError,
    RemediationPermissionError,
)
from .quarantine import quarantine, restore_from_quarantine
from .manifest import QuarantineEntry, QuarantineManifest
from .permissions import lock_down, get_current_acl

__all__ = [
    # Types
    "RemediationResult",
    "RemediationAction",
    # Manifest
    "QuarantineEntry",
    "QuarantineManifest",
    # Errors
    "RemediationError",
    "QuarantineError",
    "RemediationPermissionError",
    # Functions
    "quarantine",
    "restore_from_quarantine",
    "lock_down",
    "get_current_acl",
    "get_current_user",
]
