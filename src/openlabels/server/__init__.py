"""
OpenLabels Server - FastAPI-based API server.

This module provides the core server functionality:
- REST API endpoints for scan management
- WebSocket for real-time updates
- Database models and migrations
- Job queue management
"""


def __getattr__(name: str):
    """Lazy import to avoid loading heavy dependencies when only models are needed."""
    if name == "app":
        from openlabels.server.app import app
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["app"]
