"""
Security utilities for OpenLabels.

Provides reusable functions for:
- Security event logging for monitoring and alerting
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from openlabels.auth.dependencies import CurrentUser

logger = logging.getLogger(__name__)


def log_security_event(
    event_type: str,
    user: Optional[CurrentUser] = None,
    details: dict | None = None,
    level: str = "warning",
):
    """
    Log a security-relevant event for monitoring and alerting.

    Args:
        event_type: Type of security event (e.g., "idor_attempt", "auth_failure")
        user: User who triggered the event (if known)
        details: Additional event details
        level: Log level (debug, info, warning, error)
    """
    log_data = {
        "event_type": event_type,
        "user_id": str(user.id) if user else None,
        "tenant_id": str(user.tenant_id) if user else None,
        **(details or {}),
    }

    message = f"SECURITY EVENT: {event_type} - {log_data}"

    if level == "debug":
        logger.debug(message)
    elif level == "info":
        logger.info(message)
    elif level == "error":
        logger.error(message)
    else:
        logger.warning(message)
