"""
Security utilities for OpenLabels.

Provides reusable functions for:
- Tenant isolation validation
- IDOR attempt detection and logging
- Security-related helpers
"""

import logging
from typing import Optional, TypeVar, Type
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser

logger = logging.getLogger(__name__)

# Generic type for database models
T = TypeVar("T")


async def get_resource_with_tenant_check(
    session: AsyncSession,
    model_class: Type[T],
    resource_id: UUID,
    user: CurrentUser,
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
        HTTPException: 404 if resource not found or belongs to different tenant
    """
    resource = await session.get(model_class, resource_id)

    if not resource:
        logger.debug(f"{resource_name} not found: {resource_id}")
        raise HTTPException(
            status_code=404,
            detail=f"{resource_name} not found"
        )

    # Check tenant isolation
    resource_tenant_id = getattr(resource, "tenant_id", None)
    if resource_tenant_id is None:
        # Model doesn't have tenant_id - shouldn't happen with proper models
        logger.error(
            f"SECURITY: Model {model_class.__name__} missing tenant_id attribute"
        )
        raise HTTPException(status_code=500, detail="Internal server error")

    if resource_tenant_id != user.tenant_id:
        # Log potential IDOR attempt for security monitoring
        logger.warning(
            f"SECURITY: Potential IDOR attempt - User {user.id} (tenant {user.tenant_id}) "
            f"attempted to access {resource_name} {resource_id} belonging to tenant {resource_tenant_id}"
        )
        # Return 404 to prevent tenant enumeration
        raise HTTPException(
            status_code=404,
            detail=f"{resource_name} not found"
        )

    return resource


def validate_tenant_id(
    resource_tenant_id: UUID,
    user: CurrentUser,
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
        HTTPException: 404 if tenant doesn't match
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
        raise HTTPException(
            status_code=404,
            detail=f"{resource_name} not found"
        )

    return True


def log_security_event(
    event_type: str,
    user: Optional[CurrentUser] = None,
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
