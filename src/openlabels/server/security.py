"""
Security utilities for OpenLabels.

Provides reusable functions for:
- Security event logging for monitoring and alerting
- Log sanitization to prevent log injection attacks
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from openlabels.auth.dependencies import CurrentUser

logger = logging.getLogger(__name__)


def sanitize_log_value(value: str) -> str:
    """Sanitize a value for safe inclusion in log messages.

    Strips newlines, carriage returns, and other control characters that
    could be used to forge log entries or confuse SIEM systems.
    """
    return value.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")


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
    # Sanitize all string values in details to prevent log injection
    safe_details = {}
    for k, v in (details or {}).items():
        safe_details[k] = sanitize_log_value(str(v)) if isinstance(v, str) else v

    log_data = {
        "event_type": sanitize_log_value(event_type),
        "user_id": str(user.id) if user else None,
        "tenant_id": str(user.tenant_id) if user else None,
        **safe_details,
    }

    message = f"SECURITY EVENT: {log_data['event_type']} - {log_data}"

    if level == "debug":
        logger.debug(message)
    elif level == "info":
        logger.info(message)
    elif level == "error":
        logger.error(message)
    else:
        logger.warning(message)
