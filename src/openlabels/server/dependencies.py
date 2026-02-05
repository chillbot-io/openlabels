"""
FastAPI dependency injection module for OpenLabels.

This module provides a centralized location for all dependency injection
providers used across the application. It integrates with existing modules
and provides type-safe, annotated dependencies for FastAPI routes.

Dependencies are organized into categories:
- Settings: Application configuration
- Database: Session management
- Authentication: User and tenant context
- Services: Business logic services
- Caching: Cache management

Usage:
    from openlabels.server.dependencies import (
        SettingsDep,
        DbSessionDep,
        TenantContextDep,
        CacheDep,
    )

    @router.get("/items")
    async def list_items(
        settings: SettingsDep,
        db: DbSessionDep,
        tenant: TenantContextDep,
    ) -> list[Item]:
        ...
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated, Any, AsyncGenerator

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import Settings, get_settings as _get_settings, load_yaml_config
from openlabels.server.db import get_session as _get_session
from openlabels.auth.dependencies import CurrentUser, get_current_user, get_optional_user, require_admin
from openlabels.server.cache import CacheManager, get_cache_manager as _get_cache_manager


# Import service classes
from openlabels.server.services.scan_service import ScanService
from openlabels.server.services.result_service import ResultService
from openlabels.server.services.label_service import LabelService
from openlabels.server.services.job_service import JobService
from openlabels.server.services.base import TenantContext as ServiceTenantContext


logger = logging.getLogger(__name__)


# =============================================================================
# SETTINGS PROVIDER
# =============================================================================


@lru_cache
def get_settings() -> Settings:
    """
    Get the application settings with caching.

    Settings are loaded from:
    1. Environment variables (highest priority)
    2. config.yaml file
    3. Default values (lowest priority)

    The result is cached using lru_cache for performance.
    Use clear_settings_cache() to force a reload.

    Returns:
        Settings: The application settings instance.

    Example:
        settings = get_settings()
        print(settings.server.host)
    """
    yaml_config = load_yaml_config()
    return Settings(**yaml_config)


def clear_settings_cache() -> None:
    """
    Clear the settings cache to force a reload on next access.

    Use this when configuration may have changed at runtime,
    such as after updating a config file.

    Example:
        clear_settings_cache()
        new_settings = get_settings()  # Will reload from disk
    """
    get_settings.cache_clear()
    # Also clear the original cache if it exists
    _get_settings.cache_clear()


# Annotated dependency for use in route signatures
SettingsDep = Annotated[Settings, Depends(get_settings)]


# =============================================================================
# DATABASE SESSION PROVIDER
# =============================================================================


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get an async database session for dependency injection.

    This wraps the core get_session function from db.py and provides
    automatic transaction management:
    - Session is committed on success
    - Session is rolled back on exception
    - Session is closed after use

    Yields:
        AsyncSession: An active database session.

    Raises:
        RuntimeError: If the database has not been initialized.

    Example:
        @router.get("/items")
        async def list_items(db: DbSessionDep) -> list[Item]:
            result = await db.execute(select(Item))
            return result.scalars().all()
    """
    async for session in _get_session():
        yield session


# Annotated dependency for use in route signatures
DbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]


# =============================================================================
# TENANT CONTEXT
# =============================================================================


class TenantContext:
    """
    Multi-tenant context for request handling.

    Provides tenant-scoped information extracted from the authenticated user.
    Use this to ensure all database queries and operations are properly
    scoped to the current tenant.

    Attributes:
        tenant_id: The UUID of the current tenant.
        user_id: The UUID of the authenticated user.
        user_email: The email address of the authenticated user.
        user_name: The display name of the authenticated user (may be None).
        is_admin: Whether the user has admin privileges.
        user: The full CurrentUser object for advanced use cases.

    Example:
        @router.get("/items")
        async def list_items(
            tenant: TenantContextDep,
            db: DbSessionDep,
        ) -> list[Item]:
            # Query is automatically scoped to tenant
            query = select(Item).where(Item.tenant_id == tenant.tenant_id)
            result = await db.execute(query)
            return result.scalars().all()
    """

    def __init__(self, user: CurrentUser) -> None:
        """
        Initialize tenant context from authenticated user.

        Args:
            user: The authenticated user from the auth dependency.
        """
        self._user = user
        self.tenant_id = user.tenant_id
        self.user_id = user.id
        self.user_email = user.email
        self.user_name = user.name
        self.is_admin = user.role == "admin"

    @property
    def user(self) -> CurrentUser:
        """Get the full CurrentUser object."""
        return self._user

    def __repr__(self) -> str:
        return (
            f"TenantContext(tenant_id={self.tenant_id}, "
            f"user_id={self.user_id}, "
            f"user_email={self.user_email!r}, "
            f"is_admin={self.is_admin})"
        )


async def get_tenant_context(
    user: CurrentUser = Depends(get_current_user),
) -> TenantContext:
    """
    Get the tenant context from the authenticated user.

    This dependency requires authentication and will raise 401
    if the user is not authenticated.

    Args:
        user: The authenticated user (injected by FastAPI).

    Returns:
        TenantContext: The tenant context for the current request.

    Raises:
        HTTPException: 401 if not authenticated.
    """
    return TenantContext(user)


async def get_optional_tenant_context(
    user: CurrentUser | None = Depends(get_optional_user),
) -> TenantContext | None:
    """
    Get the tenant context if the user is authenticated, otherwise None.

    Use this for routes that support both authenticated and anonymous access.

    Args:
        user: The authenticated user or None (injected by FastAPI).

    Returns:
        TenantContext | None: The tenant context or None if not authenticated.
    """
    if user is None:
        return None
    return TenantContext(user)


async def require_admin_context(
    user: CurrentUser = Depends(require_admin),
) -> TenantContext:
    """
    Get tenant context, requiring admin privileges.

    This dependency requires the user to have admin role.

    Args:
        user: The authenticated admin user (injected by FastAPI).

    Returns:
        TenantContext: The tenant context with admin privileges.

    Raises:
        HTTPException: 401 if not authenticated, 403 if not admin.
    """
    return TenantContext(user)


# Annotated dependencies for use in route signatures
TenantContextDep = Annotated[TenantContext, Depends(get_tenant_context)]
OptionalTenantContextDep = Annotated[TenantContext | None, Depends(get_optional_tenant_context)]
AdminContextDep = Annotated[TenantContext, Depends(require_admin_context)]


# =============================================================================
# CACHE PROVIDER
# =============================================================================


async def get_cache(settings: SettingsDep) -> CacheManager:
    """
    Get the cache manager instance.

    Returns the global cache manager, initializing it if necessary.
    The cache uses Redis when available, with in-memory fallback.

    Args:
        settings: Application settings (injected by FastAPI).

    Returns:
        CacheManager: The cache manager instance.

    Example:
        @router.get("/items/{item_id}")
        async def get_item(
            item_id: str,
            cache: CacheDep,
            db: DbSessionDep,
        ) -> Item:
            # Try cache first
            cached = await cache.get(f"item:{item_id}")
            if cached:
                return Item(**cached)

            # Fall back to database
            item = await db.get(Item, item_id)
            await cache.set(f"item:{item_id}", item.dict())
            return item
    """
    return await _get_cache_manager()


# Annotated dependency for use in route signatures
CacheDep = Annotated[CacheManager, Depends(get_cache)]


# =============================================================================
# SERVICE PROVIDERS
# =============================================================================
#
# These service providers use forward references because the service classes
# don't exist yet. When implementing services, update the imports and remove
# the Protocol definitions from TYPE_CHECKING.
#
# Pattern:
# 1. Create service class in src/openlabels/services/
# 2. Import it in this file
# 3. Update the get_*_service function to return the actual service
# =============================================================================


async def get_scan_service(
    db: DbSessionDep,
    tenant: TenantContextDep,
    settings: SettingsDep,
) -> ScanService:
    """
    Get the scan service for managing scan operations.

    The scan service handles:
    - Creating and managing scan jobs
    - Coordinating with adapters for file discovery
    - Tracking scan progress and results

    Args:
        db: Database session (injected by FastAPI).
        tenant: Tenant context (injected by FastAPI).
        settings: Application settings (injected by FastAPI).

    Returns:
        ScanService: The scan service instance.

    Example:
        @router.post("/scans")
        async def create_scan(
            target_id: str,
            scan_service: ScanServiceDep,
        ) -> ScanJob:
            return await scan_service.create_scan(target_id)
    """
    service_tenant = ServiceTenantContext(
        tenant_id=tenant.tenant_id,
        user_id=tenant.user_id,
        user_email=tenant.user_email,
        user_role="admin" if tenant.is_admin else "viewer",
    )
    return ScanService(db, service_tenant, settings)


async def get_label_service(
    db: DbSessionDep,
    tenant: TenantContextDep,
    settings: SettingsDep,
) -> LabelService:
    """
    Get the label service for managing sensitivity labels.

    The label service handles:
    - Syncing labels from Microsoft 365
    - Applying labels to files
    - Managing label rules and mappings

    Args:
        db: Database session (injected by FastAPI).
        tenant: Tenant context (injected by FastAPI).
        settings: Application settings (injected by FastAPI).

    Returns:
        LabelService: The label service instance.

    Example:
        @router.post("/files/{file_id}/label")
        async def apply_label(
            file_id: str,
            label_id: str,
            label_service: LabelServiceDep,
        ) -> dict:
            await label_service.apply_label(file_id, label_id)
            return {"status": "applied"}
    """
    service_tenant = ServiceTenantContext(
        tenant_id=tenant.tenant_id,
        user_id=tenant.user_id,
        user_email=tenant.user_email,
        user_role="admin" if tenant.is_admin else "viewer",
    )
    return LabelService(db, service_tenant, settings)


async def get_job_service(
    db: DbSessionDep,
    tenant: TenantContextDep,
    settings: SettingsDep,
) -> JobService:
    """
    Get the job service for managing background jobs.

    The job service handles:
    - Enqueueing and managing background jobs
    - Job status tracking and updates
    - Job cancellation and retry logic

    Args:
        db: Database session (injected by FastAPI).
        tenant: Tenant context (injected by FastAPI).
        settings: Application settings (injected by FastAPI).

    Returns:
        JobService: The job service instance.

    Example:
        @router.post("/jobs")
        async def enqueue_job(
            task_type: str,
            payload: dict,
            job_service: JobServiceDep,
        ) -> Job:
            return await job_service.enqueue(task_type, payload)
    """
    service_tenant = ServiceTenantContext(
        tenant_id=tenant.tenant_id,
        user_id=tenant.user_id,
        user_email=tenant.user_email,
        user_role="admin" if tenant.is_admin else "viewer",
    )
    return JobService(db, service_tenant, settings)


async def get_result_service(
    db: DbSessionDep,
    tenant: TenantContextDep,
    settings: SettingsDep,
    cache: CacheDep,
) -> Any:  # Will be: ResultService
    """
    Get the result service for managing scan results.

    The result service handles:
    - Querying and filtering scan results
    - Result aggregation and statistics
    - Result export functionality

    Args:
        db: Database session (injected by FastAPI).
        tenant: Tenant context (injected by FastAPI).
        settings: Application settings (injected by FastAPI).
        cache: Cache manager (injected by FastAPI).

    Returns:
        ResultService: The result service instance.

    Note:
        This is a forward reference. The actual ResultService class
        will be implemented in src/openlabels/services/result_service.py.

    Example:
        @router.get("/results")
        async def list_results(
            risk_tier: str | None = None,
            result_service: ResultServiceDep,
        ) -> list[ScanResult]:
            return await result_service.get_results(risk_tier=risk_tier)
    """
    # TODO: Replace with actual service implementation
    # from openlabels.services.result_service import ResultService
    # return ResultService(db=db, tenant=tenant, settings=settings, cache=cache)
    raise NotImplementedError(
        "ResultService is not yet implemented. "
        "Create src/openlabels/services/result_service.py"
    )


# Annotated dependencies for services (using Any until services are implemented)
ScanServiceDep = Annotated[Any, Depends(get_scan_service)]
LabelServiceDep = Annotated[Any, Depends(get_label_service)]
JobServiceDep = Annotated[Any, Depends(get_job_service)]
ResultServiceDep = Annotated[Any, Depends(get_result_service)]


# =============================================================================
# UTILITY DEPENDENCIES
# =============================================================================


async def get_request_id() -> str:
    """
    Generate a unique request ID for tracing.

    Returns:
        str: A unique request identifier.

    Example:
        @router.get("/items")
        async def list_items(request_id: RequestIdDep) -> dict:
            logger.info(f"[{request_id}] Listing items")
            return {"request_id": request_id}
    """
    from uuid import uuid4
    return str(uuid4())


RequestIdDep = Annotated[str, Depends(get_request_id)]


async def verify_tenant_access(
    tenant: TenantContextDep,
    resource_tenant_id: str,
) -> None:
    """
    Verify that the current user has access to a resource's tenant.

    Use this to verify cross-tenant access is not attempted.

    Args:
        tenant: The current tenant context.
        resource_tenant_id: The tenant ID of the resource being accessed.

    Raises:
        HTTPException: 403 if tenants don't match.

    Example:
        @router.get("/items/{item_id}")
        async def get_item(
            item_id: str,
            tenant: TenantContextDep,
            db: DbSessionDep,
        ) -> Item:
            item = await db.get(Item, item_id)
            await verify_tenant_access(tenant, str(item.tenant_id))
            return item
    """
    if str(tenant.tenant_id) != resource_tenant_id:
        logger.warning(
            f"Tenant access denied: user {tenant.user_id} (tenant {tenant.tenant_id}) "
            f"attempted to access resource in tenant {resource_tenant_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this resource",
        )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Settings
    "get_settings",
    "clear_settings_cache",
    "SettingsDep",
    # Database
    "get_db_session",
    "DbSessionDep",
    # Tenant context
    "TenantContext",
    "get_tenant_context",
    "get_optional_tenant_context",
    "require_admin_context",
    "TenantContextDep",
    "OptionalTenantContextDep",
    "AdminContextDep",
    # Cache
    "get_cache",
    "CacheDep",
    # Services (forward references)
    "get_scan_service",
    "get_label_service",
    "get_job_service",
    "get_result_service",
    "ScanServiceDep",
    "LabelServiceDep",
    "JobServiceDep",
    "ResultServiceDep",
    # Utilities
    "get_request_id",
    "RequestIdDep",
    "verify_tenant_access",
    # Re-exports from auth dependencies
    "CurrentUser",
    "get_current_user",
    "get_optional_user",
    "require_admin",
]
