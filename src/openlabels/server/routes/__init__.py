"""
API route modules.

Uses lazy imports to avoid circular dependency issues when importing
individual route modules directly in tests.
"""

_module_cache = {}


def __getattr__(name: str):
    """Lazy import route modules to avoid circular imports."""
    if name in _module_cache:
        return _module_cache[name]

    valid_modules = {
        "audit", "auth", "jobs", "scans", "results", "targets",
        "schedules", "labels", "dashboard", "ws", "users",
        "remediation", "monitoring", "health", "settings",
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
]
