"""
Agent pool for parallel classification processing.

Agents are isolated worker processes, each with their own model instance.
This enables true parallelism on multi-core systems.
"""

from openlabels.core.agents.pool import (
    AgentPool,
    AgentPoolConfig,
    FileResult,
    ResultHandler,
    ScanOrchestrator,
)
from openlabels.core.agents.worker import ClassificationAgent, AgentResult

__all__ = [
    "AgentPool",
    "AgentPoolConfig",
    "ClassificationAgent",
    "AgentResult",
    "FileResult",
    "ResultHandler",
    "ScanOrchestrator",
]
