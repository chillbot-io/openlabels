"""
API v1 router - aggregates all v1 API routes.

This module provides a versioned API router that groups all API endpoints
under the /api/v1 prefix for proper API versioning.
"""

from fastapi import APIRouter

from openlabels.server.routes import (
    auth,
    audit,
    jobs,
    scans,
    results,
    targets,
    schedules,
    labels,
    dashboard,
    ws,
    users,
    remediation,
    monitoring,
    health,
    settings,
    webhooks,
)

# Create the v1 API router
router = APIRouter()

# Authentication - /api/v1/auth/*
router.include_router(auth.router, tags=["Authentication"])

# Core API routes
router.include_router(audit.router, prefix="/audit", tags=["Audit"])
router.include_router(jobs.router, prefix="/jobs", tags=["Jobs"])
router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(results.router, prefix="/results", tags=["Results"])
router.include_router(targets.router, prefix="/targets", tags=["Targets"])
router.include_router(schedules.router, prefix="/schedules", tags=["Schedules"])
router.include_router(labels.router, prefix="/labels", tags=["Labels"])
router.include_router(users.router, prefix="/users", tags=["Users"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"])
router.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring"])
router.include_router(health.router, prefix="/health", tags=["Health"])
router.include_router(settings.router, prefix="/settings", tags=["Settings"])

# Webhook routes - /api/v1/webhooks/*
router.include_router(webhooks.router, tags=["Webhooks"])

# WebSocket routes - /api/v1/ws/*
router.include_router(ws.router, tags=["WebSocket"])
