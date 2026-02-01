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
]
