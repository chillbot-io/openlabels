"""
Pipeline configuration building for scan tasks.

Extracts ``_build_pipeline_config`` so it can be shared by the main scan
orchestrator and the partition worker without pulling in the entire scan
module.
"""

from __future__ import annotations

import logging

from openlabels.jobs.pipeline import PipelineConfig

logger = logging.getLogger(__name__)


async def _build_pipeline_config(settings, tenant_id=None, session=None) -> PipelineConfig:
    """Build pipeline config from settings, with optional tenant overrides.

    If *tenant_id* and *session* are provided, per-tenant overrides from
    ``TenantSettings.pipeline_max_concurrent_files`` and
    ``TenantSettings.pipeline_memory_budget_mb`` take precedence over the
    global configuration.
    """
    jobs = getattr(settings, "jobs", None)

    max_concurrent = getattr(jobs, "pipeline_max_concurrent_files", 8) if jobs else 8
    memory_budget = getattr(jobs, "pipeline_memory_budget_mb", 512) if jobs else 512
    pipeline_enabled = getattr(jobs, "pipeline_enabled", True) if jobs else True

    # Ensure we have valid int values (guard against mock objects in tests)
    if not isinstance(max_concurrent, int):
        max_concurrent = 8
    if not isinstance(memory_budget, int):
        memory_budget = 512

    # Per-tenant overrides from TenantSettings
    if tenant_id is not None and session is not None:
        try:
            from sqlalchemy import select as sa_select

            from openlabels.server.models import TenantSettings

            result = await session.execute(
                sa_select(TenantSettings).where(
                    TenantSettings.tenant_id == tenant_id
                )
            )
            tenant_settings = result.scalar_one_or_none()
            if tenant_settings is not None:
                ts_concurrent = getattr(tenant_settings, "pipeline_max_concurrent_files", None)
                if isinstance(ts_concurrent, int) and ts_concurrent > 0:
                    max_concurrent = ts_concurrent
                ts_memory = getattr(tenant_settings, "pipeline_memory_budget_mb", None)
                if isinstance(ts_memory, int) and ts_memory > 0:
                    memory_budget = ts_memory
        except (AttributeError, KeyError, TypeError, ValueError):
            logger.debug("Could not load tenant pipeline overrides for %s", tenant_id)

    config = PipelineConfig(
        max_concurrent_files=max_concurrent,
        memory_budget_mb=memory_budget,
    )

    # If pipeline is disabled globally, set concurrency to 1 (sequential)
    if not pipeline_enabled:
        config.max_concurrent_files = 1

    return config
