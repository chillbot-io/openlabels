"""
Service layer for OpenLabels server.

Services encapsulate business logic and provide a clean interface
between routes and data access. All services extend BaseService
for consistent tenant isolation and session management.
"""

from openlabels.server.services.base import BaseService
from openlabels.server.services.result_service import ResultService

__all__ = [
    "BaseService",
    "ResultService",
]
