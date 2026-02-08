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
from openlabels.core.change_providers import ChangeProvider, FullWalkProvider

__all__ = [
    "AgentPool",
    "AgentPoolConfig",
    "ChangeProvider",
    "ClassificationAgent",
    "AgentResult",
    "FileResult",
    "FullWalkProvider",
    "ResultHandler",
    "ScanOrchestrator",
]
