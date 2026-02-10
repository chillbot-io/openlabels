"""Base service module providing session management, tenant isolation, and logging."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, func
from sqlalchemy import select as sa_select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import Settings

T = TypeVar("T")


class TenantContext(BaseModel):
    """Encapsulates tenant and user info for data isolation and audit trails.

    Typically constructed from CurrentUser in route handlers and passed to services.
    """

    tenant_id: UUID
    user_id: UUID | None = None
    user_email: str | None = None
    user_role: str | None = None

    model_config = ConfigDict(frozen=True)

    @classmethod
    def from_current_user(cls, user: CurrentUser) -> TenantContext:
        """Create TenantContext from a CurrentUser instance."""
        return cls(
            tenant_id=user.tenant_id,
            user_id=user.id,
            user_email=user.email,
            user_role=user.role,
        )

    @classmethod
    def system_context(cls, tenant_id: UUID) -> TenantContext:
        """Create a system-level context (no user) for background jobs."""
        return cls(tenant_id=tenant_id)


# Import CurrentUser for type hints (avoid circular import)
try:
    from openlabels.auth.dependencies import CurrentUser
except ImportError:
    CurrentUser = None  # type: ignore


class BaseService:
    """Abstract base class for all services.

    Transaction Management:
        Services do NOT auto-commit. The caller (usually a route handler)
        is responsible for committing after all service operations complete.
        This allows multiple service calls to be wrapped in a single transaction.

        Use the transaction() context manager for explicit transaction boundaries:

            async with service.transaction():
                await service.create_item("foo")
                await other_service.update_item(item_id)
                # Auto-commits on success, rolls back on exception
    """

    def __init__(
        self,
        session: AsyncSession,
        tenant: TenantContext,
        settings: Settings,
    ):
        self._session = session
        self._tenant = tenant
        self._settings = settings
        self._logger = logging.getLogger(self.__class__.__module__)

    @property
    def session(self) -> AsyncSession:
        """Database session for this service."""
        return self._session

    @property
    def tenant_id(self) -> UUID:
        """Current tenant UUID for data isolation."""
        return self._tenant.tenant_id

    @property
    def user_id(self) -> UUID | None:
        """Current user UUID, or None for system operations."""
        return self._tenant.user_id

    @property
    def settings(self) -> Settings:
        """Application settings."""
        return self._settings

    @property
    def tenant(self) -> TenantContext:
        """Full tenant context including user info."""
        return self._tenant

    async def commit(self) -> None:
        """Commit the current transaction. Prefer letting the route handler commit."""
        await self._session.commit()

    async def flush(self) -> None:
        """Flush pending changes without committing (useful for obtaining auto-generated IDs)."""
        await self._session.flush()

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        await self._session.rollback()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Context manager that commits on success and rolls back on exception."""
        try:
            yield
            await self.commit()
        except Exception:  # Intentionally broad: must rollback on any error before re-raising
            await self.rollback()
            raise

    async def get_tenant_entity(
        self,
        model_class: type[T],
        entity_id: UUID,
        entity_name: str = "Resource",
    ) -> T:
        """Fetch an entity by ID, raising NotFoundError if missing or wrong tenant."""
        from openlabels.exceptions import NotFoundError

        entity = await self._session.get(model_class, entity_id)
        if not entity or getattr(entity, "tenant_id", None) != self.tenant_id:
            raise NotFoundError(
                message=f"{entity_name} not found",
                resource_type=model_class.__name__,
                resource_id=str(entity_id),
            )
        return entity

    async def paginate(
        self,
        query: Select,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list, int]:
        """Execute a paginated query, returning (items, total_count)."""
        count_q = sa_select(func.count()).select_from(query.subquery())
        total = (await self._session.execute(count_q)).scalar() or 0
        rows = (await self._session.execute(query.offset(offset).limit(limit))).scalars().all()
        return list(rows), total

    def _log_debug(self, message: str, **kwargs) -> None:
        """Log a debug message with context."""
        self._logger.debug(
            f"[tenant={self.tenant_id}] {message}",
            extra={"tenant_id": str(self.tenant_id), **kwargs},
        )

    def _log_info(self, message: str, **kwargs) -> None:
        """Log an info message with context."""
        self._logger.info(
            f"[tenant={self.tenant_id}] {message}",
            extra={"tenant_id": str(self.tenant_id), **kwargs},
        )

    def _log_warning(self, message: str, **kwargs) -> None:
        """Log a warning message with context."""
        self._logger.warning(
            f"[tenant={self.tenant_id}] {message}",
            extra={"tenant_id": str(self.tenant_id), **kwargs},
        )

    def _log_error(self, message: str, **kwargs) -> None:
        """Log an error message with context."""
        self._logger.error(
            f"[tenant={self.tenant_id}] {message}",
            extra={"tenant_id": str(self.tenant_id), **kwargs},
        )
