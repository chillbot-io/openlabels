"""
Security utilities for OpenLabels.

Provides reusable functions for:
- Tenant isolation validation
- IDOR attempt detection and logging
- Log sanitization
- Security-related helpers
"""

import logging
import re
from typing import TYPE_CHECKING, Optional, TypeVar, Type, Any
from uuid import UUID

from openlabels.server.exceptions import NotFoundError, InternalError
from sqlalchemy.ext.asyncio import AsyncSession

# Use TYPE_CHECKING to avoid circular imports
# auth.dependencies imports from server.* which imports routes which imports auth
if TYPE_CHECKING:
    from openlabels.auth.dependencies import CurrentUser

logger = logging.getLogger(__name__)

# Generic type for database models
T = TypeVar("T")


async def get_resource_with_tenant_check(
    session: AsyncSession,
    model_class: Type[T],
    resource_id: UUID,
    user: "CurrentUser",
    resource_name: str = "Resource",
) -> T:
    """
    Retrieve a resource by ID with tenant isolation validation.

    This utility provides consistent tenant isolation checking with
    IDOR attempt logging for security monitoring.

    Args:
        session: Database session
        model_class: SQLAlchemy model class to query
        resource_id: ID of the resource to retrieve
        user: Current authenticated user
        resource_name: Human-readable name for error messages

    Returns:
        The requested resource if it exists and belongs to user's tenant

    Raises:
        NotFoundError: If resource not found or belongs to different tenant
        InternalError: If model is missing tenant_id attribute
    """
    resource = await session.get(model_class, resource_id)

    if not resource:
        logger.debug(f"{resource_name} not found: {resource_id}")
        raise NotFoundError(
            message=f"{resource_name} not found",
            resource_type=resource_name,
            resource_id=str(resource_id),
        )

    # Check tenant isolation
    resource_tenant_id = getattr(resource, "tenant_id", None)
    if resource_tenant_id is None:
        # Model doesn't have tenant_id - shouldn't happen with proper models
        logger.error(
            f"SECURITY: Model {model_class.__name__} missing tenant_id attribute"
        )
        raise InternalError(message="Internal server error")

    if resource_tenant_id != user.tenant_id:
        # Log potential IDOR attempt for security monitoring
        logger.warning(
            f"SECURITY: Potential IDOR attempt - User {user.id} (tenant {user.tenant_id}) "
            f"attempted to access {resource_name} {resource_id} belonging to tenant {resource_tenant_id}"
        )
        # Return 404 to prevent tenant enumeration
        raise NotFoundError(
            message=f"{resource_name} not found",
            resource_type=resource_name,
            resource_id=str(resource_id),
        )

    return resource


def validate_tenant_id(
    resource_tenant_id: UUID,
    user: "CurrentUser",
    resource_name: str = "Resource",
    resource_id: Optional[UUID] = None,
) -> bool:
    """
    Validate that a resource belongs to the user's tenant.

    This is a simpler validation for cases where you already have the resource.

    Args:
        resource_tenant_id: The tenant_id of the resource
        user: Current authenticated user
        resource_name: Human-readable name for logging
        resource_id: Optional resource ID for logging

    Returns:
        True if tenant matches

    Raises:
        NotFoundError: If tenant doesn't match
    """
    if resource_tenant_id != user.tenant_id:
        # Log potential IDOR attempt
        if resource_id:
            logger.warning(
                f"SECURITY: Potential IDOR attempt - User {user.id} (tenant {user.tenant_id}) "
                f"attempted to access {resource_name} {resource_id} belonging to tenant {resource_tenant_id}"
            )
        else:
            logger.warning(
                f"SECURITY: Potential IDOR attempt - User {user.id} (tenant {user.tenant_id}) "
                f"attempted to access {resource_name} belonging to tenant {resource_tenant_id}"
            )
        raise NotFoundError(
            message=f"{resource_name} not found",
            resource_type=resource_name,
            resource_id=str(resource_id) if resource_id else None,
        )

    return True


def log_security_event(
    event_type: str,
    user: Optional["CurrentUser"] = None,
    details: Optional[dict] = None,
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


# Patterns for sensitive data that should be redacted in logs
_SENSITIVE_PATTERNS = [
    # Tokens and secrets
    (re.compile(r'(access_token|refresh_token|id_token|api_key|secret)["\']?\s*[:=]\s*["\']?([^"\'&\s]{8,})', re.I), r'\1=***REDACTED***'),
    # Bearer tokens in headers
    (re.compile(r'(Bearer\s+)([A-Za-z0-9_.-]{20,})', re.I), r'\1***REDACTED***'),
    # Password fields
    (re.compile(r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', re.I), r'\1=***REDACTED***'),
    # Email addresses (partial redaction)
    (re.compile(r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'), lambda m: f"{m.group(1)[:2]}***@{m.group(2)}"),
    # Credit card numbers (basic pattern)
    (re.compile(r'\b(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})\b'), r'\1-****-****-\4'),
    # SSN pattern
    (re.compile(r'\b(\d{3})-?(\d{2})-?(\d{4})\b'), r'***-**-\3'),
]


def sanitize_for_logging(text: str) -> str:
    """
    Sanitize text for safe logging by redacting sensitive data.

    This function redacts common sensitive patterns like:
    - Access tokens and API keys
    - Passwords
    - Email addresses (partial)
    - Credit card numbers
    - Social security numbers

    Args:
        text: The text to sanitize

    Returns:
        Sanitized text with sensitive data redacted

    Example:
        >>> sanitize_for_logging('access_token=abc123xyz')
        'access_token=***REDACTED***'
    """
    if not text:
        return text

    result = text
    for pattern, replacement in _SENSITIVE_PATTERNS:
        if callable(replacement):
            result = pattern.sub(replacement, result)
        else:
            result = pattern.sub(replacement, result)

    return result


def truncate_for_logging(text: str, max_length: int = 200) -> str:
    """
    Truncate text for safe logging.

    Long error messages or response bodies should be truncated to prevent
    log file bloat and potential exposure of sensitive data.

    Args:
        text: The text to truncate
        max_length: Maximum length before truncation (default 200)

    Returns:
        Truncated text with indicator if truncated
    """
    if not text or len(text) <= max_length:
        return text

    return text[:max_length] + f"... [truncated, {len(text)} total chars]"
