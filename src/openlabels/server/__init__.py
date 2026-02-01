"""
OpenLabels Server - FastAPI-based API server.

This module provides the core server functionality:
- REST API endpoints for scan management
- WebSocket for real-time updates
- Database models and migrations
- Job queue management
"""

from openlabels.server.app import app

__all__ = ["app"]
