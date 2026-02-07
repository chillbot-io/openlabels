"""Periodic adapter health checking.

Provides :class:`AdapterHealthChecker` which tests adapter connectivity
and reports latency / error metrics via :class:`AdapterHealth`.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from openlabels.adapters.base import ReadAdapter

logger = logging.getLogger(__name__)


@dataclass
class AdapterHealth:
    """Health snapshot for a single adapter."""

    adapter_type: str
    healthy: bool
    last_check: datetime
    latency_ms: float | None = None
    error: str | None = None


class AdapterHealthChecker:
    """Tests adapter connectivity on demand.

    Usage::

        checker = AdapterHealthChecker()
        checker.register(sharepoint_adapter)
        checker.register(filesystem_adapter)

        results = await checker.check_all()
        for name, health in results.items():
            print(f"{name}: {'OK' if health.healthy else health.error}")
    """

    def __init__(self) -> None:
        self._adapters: dict[str, ReadAdapter] = {}
        self._health: dict[str, AdapterHealth] = {}

    def register(self, adapter: ReadAdapter) -> None:
        """Register an adapter for health monitoring."""
        self._adapters[adapter.adapter_type] = adapter

    async def check_all(self) -> dict[str, AdapterHealth]:
        """Check all registered adapters and return health results."""
        tasks = [
            self._check_one(name, adapter)
            for name, adapter in self._adapters.items()
        ]
        await asyncio.gather(*tasks)
        return dict(self._health)

    async def _check_one(self, name: str, adapter: ReadAdapter) -> None:
        """Check a single adapter's health."""
        loop = asyncio.get_running_loop()
        start = loop.time()
        try:
            healthy = await adapter.test_connection({})
            latency = (loop.time() - start) * 1000
            self._health[name] = AdapterHealth(
                adapter_type=name,
                healthy=healthy,
                last_check=datetime.now(timezone.utc),
                latency_ms=latency,
            )
        except Exception as exc:
            self._health[name] = AdapterHealth(
                adapter_type=name,
                healthy=False,
                last_check=datetime.now(timezone.utc),
                error=f"{type(exc).__name__}: {exc}",
            )

    def get_health(self) -> dict[str, AdapterHealth]:
        """Return the most recent health results (without re-checking)."""
        return dict(self._health)
