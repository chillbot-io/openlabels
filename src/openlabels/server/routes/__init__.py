"""
API route modules.

Uses lazy imports to avoid circular dependency issues when importing
individual route modules directly in tests.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.exceptions import NotFoundError
from openlabels.server.models import AuditLog

_module_cache = {}


async def get_or_404(session: AsyncSession, model_class, entity_id: UUID, *, tenant_id: UUID):
    """Fetch an entity by PK, raising NotFoundError if missing or wrong tenant."""
    entity = await session.get(model_class, entity_id)
    if not entity or getattr(entity, "tenant_id", None) != tenant_id:
        raise NotFoundError(
            message=f"{model_class.__name__} not found",
            resource_type=model_class.__name__,
            resource_id=str(entity_id),
        )
    return entity


def audit_log(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    user_id: UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    details: dict | None = None,
) -> None:
    """Add an audit log entry to the session (flushed on next commit/flush)."""
    session.add(AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    ))


def __getattr__(name: str):
    """Lazy import route modules to avoid circular imports."""
    if name in _module_cache:
        return _module_cache[name]

    valid_modules = {
        "audit", "auth", "browse", "credentials", "enumerate", "jobs",
        "scans", "results", "targets",
        "schedules", "labels", "dashboard", "ws", "ws_events", "users",
        "remediation", "monitoring", "health", "settings",
        "policies", "export", "reporting", "webhooks", "permissions",
        "query", "v1",
    }

    if name in valid_modules:
        import importlib
        module = importlib.import_module(f"openlabels.server.routes.{name}")
        _module_cache[name] = module
        return module

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "audit_log",
    "get_or_404",
    "audit",
    "auth",
    "browse",
    "credentials",
    "enumerate",
    "jobs",
    "scans",
    "results",
    "targets",
    "schedules",
    "labels",
    "dashboard",
    "ws",
    "ws_events",
    "users",
    "remediation",
    "monitoring",
    "health",
    "settings",
    "policies",
    "export",
    "reporting",
    "webhooks",
    "permissions",
    "query",
    "v1",
]
