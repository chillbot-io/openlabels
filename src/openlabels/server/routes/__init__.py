"""
API route modules.
"""

from openlabels.server.routes import (
    auth,
    scans,
    results,
    targets,
    schedules,
    labels,
    dashboard,
    ws,
    users,
)

__all__ = [
    "auth",
    "scans",
    "results",
    "targets",
    "schedules",
    "labels",
    "dashboard",
    "ws",
    "users",
]
