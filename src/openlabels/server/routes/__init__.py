"""
API route modules.

Uses lazy imports to avoid circular dependency issues when importing
individual route modules directly in tests.
"""

import json

from fastapi.responses import HTMLResponse

_module_cache = {}


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
        "audit", "auth", "jobs", "scans", "results", "targets",
        "schedules", "labels", "dashboard", "ws", "users",
        "remediation", "monitoring", "health", "settings",
        "policies", "export", "reporting", "v1",
    }

    if name in valid_modules:
        import importlib
        module = importlib.import_module(f"openlabels.server.routes.{name}")
        _module_cache[name] = module
        return module

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "audit",
    "auth",
    "jobs",
    "scans",
    "results",
    "targets",
    "schedules",
    "labels",
    "dashboard",
    "ws",
    "users",
    "remediation",
    "monitoring",
    "health",
    "settings",
    "policies",
    "export",
    "reporting",
    "v1",
]
