"""
API route modules.

Uses lazy imports to avoid circular dependency issues when importing
individual route modules directly in tests.
"""

import json
from uuid import UUID

from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.exceptions import NotFoundError

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


def htmx_notify(
    message: str,
    type: str = "success",
    **extra_triggers: object,
) -> HTMLResponse:
    """
    Return an empty HTMX response with a notification trigger.

    Args:
        message: Notification message text
        type: Notification type ("success", "error", "warning", "info")
        **extra_triggers: Additional HX-Trigger events (e.g., refreshScans=True)

    Returns:
        HTMLResponse with HX-Trigger header
    """
    trigger: dict = {"notify": {"message": message, "type": type}}
    trigger.update(extra_triggers)
    return HTMLResponse(
        content="",
        headers={"HX-Trigger": json.dumps(trigger)},
    )


def __getattr__(name: str):
    """Lazy import route modules to avoid circular imports."""
    if name in _module_cache:
        return _module_cache[name]

    valid_modules = {
        "audit", "auth", "browse", "jobs", "scans", "results", "targets",
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
    "get_or_404",
    "htmx_notify",
    "audit",
    "auth",
    "browse",
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
