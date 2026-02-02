"""
API route modules.
"""

from openlabels.server.routes import (
    audit,
    auth,
    jobs,
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
]
