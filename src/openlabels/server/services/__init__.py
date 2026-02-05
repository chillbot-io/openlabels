"""
Service layer for OpenLabels server.

Services encapsulate business logic and provide a clean interface
between routes and data access. All services extend BaseService
for consistent tenant isolation and session management.

Usage:
    from openlabels.server.services import ScanService, TenantContext
    from openlabels.server.config import get_settings

    # In a route handler:
    tenant = TenantContext.from_current_user(user)
    service = ScanService(session, tenant, get_settings())
    job = await service.create_scan(target_id)

Available Services:
    - ScanService: Scan job creation, retrieval, and management
    - LabelService: Sensitivity label and label rule management
    - JobService: Background job queue management
    - ResultService: Scan result querying and statistics

Base Classes:
    - BaseService: Abstract base class with session, tenant, and settings
    - TenantContext: Immutable tenant/user context for service operations
"""

from openlabels.server.services.base import BaseService, TenantContext
from openlabels.server.services.scan_service import ScanService
from openlabels.server.services.label_service import LabelService
from openlabels.server.services.job_service import JobService
from openlabels.server.services.result_service import ResultService

__all__ = [
    # Base classes
    "BaseService",
    "TenantContext",
    # Services
    "ScanService",
    "LabelService",
    "JobService",
    "ResultService",
]
