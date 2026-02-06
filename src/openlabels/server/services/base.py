"""
Base service class for OpenLabels server.

Provides common functionality for all services:
- Database session management with explicit transaction control
- Tenant isolation via TenantContext
- Settings access
- Logging setup
"""

from abc import ABC
from contextlib import asynccontextmanager
import logging
from typing import AsyncIterator, Optional, TypeVar
from uuid import UUID

T = TypeVar("T")

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import Settings


class TenantContext(BaseModel):
    """
    Tenant context for service operations.

    Encapsulates the current tenant and user information for
    proper data isolation and audit trails.

    This is typically constructed from CurrentUser in route handlers
    and passed to services.

    Attributes:
        tenant_id: UUID of the current tenant
        user_id: UUID of the current user (optional for system operations)
        user_email: Email of the current user (optional)
        user_role: Role of the current user (optional)
    """

    tenant_id: UUID
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    user_role: Optional[str] = None

    class Config:
        """Pydantic configuration."""

        frozen = True  # Make immutable

    @classmethod
    def from_current_user(cls, user: "CurrentUser") -> "TenantContext":
        """
        Create TenantContext from CurrentUser.

        Args:
            user: CurrentUser instance from authentication

        Returns:
            TenantContext with user information
        """
        return cls(
            tenant_id=user.tenant_id,
            user_id=user.id,
            user_email=user.email,
            user_role=user.role,
        )

    @classmethod
    def system_context(cls, tenant_id: UUID) -> "TenantContext":
        """
        Create a system-level context for background jobs.

        Args:
            tenant_id: UUID of the tenant

        Returns:
            TenantContext without user information
        """
        return cls(tenant_id=tenant_id)


# Import CurrentUser for type hints (avoid circular import)
try:
    from openlabels.auth.dependencies import CurrentUser
except ImportError:
    CurrentUser = None  # type: ignore


class BaseService(ABC):
    """
    Abstract base class for all services.

    Provides common functionality including:
    - Database session access with commit/flush/rollback
    - Tenant context for data isolation
    - Settings access
    - Structured logging

    All services should extend this class to ensure consistent
    behavior across the application.

    Example:
        class MyService(BaseService):
            async def my_method(self) -> list[MyModel]:
                query = select(MyModel).where(
                    MyModel.tenant_id == self.tenant_id
                )
                result = await self.session.execute(query)
                return list(result.scalars().all())

            async def create_item(self, name: str) -> MyModel:
                item = MyModel(tenant_id=self.tenant_id, name=name)
                self.session.add(item)
                await self.flush()  # Get ID without committing
                return item

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
        """
        Initialize the base service.

        Args:
            session: Async database session for queries
            tenant: Tenant context for data isolation
            settings: Application settings
        """
        self._session = session
        self._tenant = tenant
        self._settings = settings
        self._logger = logging.getLogger(self.__class__.__module__)

    @property
    def session(self) -> AsyncSession:
        """
        Get the database session.

        Returns:
            The async database session for this service
        """
        return self._session

    @property
    def tenant_id(self) -> UUID:
        """
        Get the tenant ID for data isolation.

        Returns:
            UUID of the current tenant
        """
        return self._tenant.tenant_id

    @property
    def user_id(self) -> Optional[UUID]:
        """
        Get the user ID for audit trails.

        Returns:
            UUID of the current user, or None for system operations
        """
        return self._tenant.user_id

    @property
    def settings(self) -> Settings:
        """
        Get the application settings.

        Returns:
            Application settings instance
        """
        return self._settings

    @property
    def tenant(self) -> TenantContext:
        """
        Get the full tenant context.

        Returns:
            TenantContext with tenant and user information
        """
        return self._tenant

    async def commit(self) -> None:
        """
        Commit the current transaction.

        Persists all changes made in the current session.
        Use sparingly - prefer letting the route handler commit.

        Raises:
            SQLAlchemyError: If commit fails
        """
        await self._session.commit()

    async def flush(self) -> None:
        """
        Flush pending changes to the database.

        Synchronizes the session state with the database without
        committing. Useful for getting auto-generated IDs or
        checking constraints before final commit.

        Raises:
            SQLAlchemyError: If flush fails (e.g., constraint violation)
        """
        await self._session.flush()

    async def rollback(self) -> None:
        """
        Rollback the current transaction.

        Discards all uncommitted changes in the session.
        """
        await self._session.rollback()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """
        Explicit transaction boundary context manager.

        Provides ACID guarantees for a group of operations.
        Commits on successful exit, rolls back on exception.

        Usage:
            async with service.transaction():
                await service.create_item("foo")
                await service.update_item(item_id)
                # Commits automatically

            # Or with explicit error handling:
            async with service.transaction():
                try:
                    await service.risky_operation()
                except MyError:
                    raise  # Transaction rolls back

        Yields:
            None

        Raises:
            Exception: Re-raises any exception after rollback
        """
        try:
            yield
            await self.commit()
        except Exception:
            await self.rollback()
            raise

    async def get_tenant_entity(
        self,
        model_class: type[T],
        entity_id: UUID,
        entity_name: str = "Resource",
    ) -> T:
        """
        Fetch an entity by ID with tenant isolation.

        Loads the entity and verifies it belongs to the current tenant.

        Args:
            model_class: SQLAlchemy model class to query
            entity_id: Primary key of the entity
            entity_name: Human-readable name for error messages

        Returns:
            The entity instance

        Raises:
            NotFoundError: If entity doesn't exist or belongs to another tenant
        """
        from openlabels.server.exceptions import NotFoundError

        entity = await self._session.get(model_class, entity_id)
        if not entity or getattr(entity, "tenant_id", None) != self.tenant_id:
            raise NotFoundError(
                message=f"{entity_name} not found",
                resource_type=model_class.__name__,
                resource_id=str(entity_id),
            )
        return entity

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
