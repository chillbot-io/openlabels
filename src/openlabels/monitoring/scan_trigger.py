"""
ScanTriggerBuffer — debounced priority queue for real-time scan
triggers (Phase I).

When a streaming provider detects a file change, the trigger buffer
applies:

1. **Registry check** — only tracked files with risk >= threshold.
2. **Debounce** — collapses rapid changes to the same file.
3. **Priority tiers** — CRITICAL (2 s), HIGH (5 s), MEDIUM (30 s).
4. **Rate cap** — max *rate_limit* scans per minute per tenant.
5. **Cooldown** — suppress re-triggers for *cooldown_seconds* after scan.

Usage::

    trigger = ScanTriggerBuffer(
        registry_lookup=registry.get_watched_file,
    )
    # Called by EventStreamManager on each event:
    trigger.on_event(raw_event)

    # Background task drains the queue:
    await trigger.run(shutdown_event)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from openlabels.monitoring.providers.base import RawAccessEvent

logger = logging.getLogger(__name__)

# ── Debounce tiers ───────────────────────────────────────────────────

_DEBOUNCE_BY_TIER: dict[str, float] = {
    "CRITICAL": 2.0,
    "HIGH": 5.0,
    "MEDIUM": 30.0,
}

_TIER_PRIORITY: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
}


@dataclass
class PendingScan:
    """A file change waiting to be dispatched as a scan task."""

    file_path: str
    risk_tier: str
    debounce_until: float  # monotonic time
    priority: int = 2
    event_count: int = 1
    first_event_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_event_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ScanTriggerBuffer:
    """Debounced priority queue for file-change-triggered scans."""

    def __init__(
        self,
        registry_lookup: Callable[[Path], object | None] | None = None,
        *,
        rate_limit: int = 10,
        cooldown_seconds: float = 60.0,
        min_risk_tier: str = "MEDIUM",
        dispatch_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        self._registry_lookup = registry_lookup
        self._rate_limit = rate_limit
        self._cooldown = cooldown_seconds
        self._min_tier = min_risk_tier
        self._dispatch_callback = dispatch_callback

        # Pending scans keyed by file_path
        self._pending: dict[str, PendingScan] = {}

        # Cooldown tracker: file_path → monotonic expiry time
        self._cooldowns: dict[str, float] = {}

        # Rate limiter: sliding window of dispatch times
        self._dispatch_times: list[float] = []

        # Stats
        self.total_events_received: int = 0
        self.total_scans_dispatched: int = 0
        self.total_events_filtered: int = 0
        self.total_events_debounced: int = 0
        self.total_events_rate_limited: int = 0

    def _tier_meets_threshold(self, tier: str) -> bool:
        """Check if a risk tier meets the minimum threshold."""
        tier_order = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            return tier_order.index(tier) >= tier_order.index(self._min_tier)
        except ValueError:
            return False

    def on_event(self, event: RawAccessEvent) -> None:
        """Handle a file change event (called from EventStreamManager).

        This is intentionally synchronous and non-blocking — it only
        updates the pending dict.  The async ``run()`` loop handles
        dispatch.
        """
        self.total_events_received += 1

        # Check cooldown
        now_mono = time.monotonic()
        cooldown_expiry = self._cooldowns.get(event.file_path, 0)
        if now_mono < cooldown_expiry:
            self.total_events_filtered += 1
            return

        # Check registry
        watched = None
        if self._registry_lookup is not None:
            watched = self._registry_lookup(Path(event.file_path))

        if watched is None:
            self.total_events_filtered += 1
            return

        risk_tier = getattr(watched, "risk_tier", "LOW")
        if not self._tier_meets_threshold(risk_tier):
            self.total_events_filtered += 1
            return

        # Debounce: update or create pending entry
        debounce_window = _DEBOUNCE_BY_TIER.get(risk_tier, 30.0)
        priority = _TIER_PRIORITY.get(risk_tier, 2)
        debounce_until = now_mono + debounce_window

        existing = self._pending.get(event.file_path)
        if existing is not None:
            # Reset debounce timer and update
            existing.debounce_until = debounce_until
            existing.event_count += 1
            existing.last_event_at = datetime.now(timezone.utc)
            self.total_events_debounced += 1
        else:
            self._pending[event.file_path] = PendingScan(
                file_path=event.file_path,
                risk_tier=risk_tier,
                debounce_until=debounce_until,
                priority=priority,
            )

    async def run(
        self,
        shutdown_event: asyncio.Event,
        tick_interval: float = 0.5,
    ) -> None:
        """Main loop — checks for ready scans and dispatches them."""
        logger.info(
            "ScanTriggerBuffer started: rate_limit=%d/min, "
            "cooldown=%.0fs, min_tier=%s",
            self._rate_limit,
            self._cooldown,
            self._min_tier,
        )

        while not shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    shutdown_event.wait(), timeout=tick_interval,
                )
                break
            except asyncio.TimeoutError:
                pass

            await self._dispatch_ready()

        # Final dispatch
        await self._dispatch_ready()

        logger.info(
            "ScanTriggerBuffer stopped: received=%d, dispatched=%d, "
            "filtered=%d, debounced=%d, rate_limited=%d",
            self.total_events_received,
            self.total_scans_dispatched,
            self.total_events_filtered,
            self.total_events_debounced,
            self.total_events_rate_limited,
        )

    async def _dispatch_ready(self) -> None:
        """Dispatch scans whose debounce window has expired."""
        now_mono = time.monotonic()

        # Clean expired cooldowns
        expired_cooldowns = [
            p for p, t in self._cooldowns.items() if t <= now_mono
        ]
        for p in expired_cooldowns:
            del self._cooldowns[p]

        # Clean expired rate-limit entries (older than 60s)
        cutoff = now_mono - 60.0
        self._dispatch_times = [
            t for t in self._dispatch_times if t > cutoff
        ]

        # Find ready scans (debounce expired), sorted by priority
        ready: list[PendingScan] = []
        still_pending: dict[str, PendingScan] = {}

        for path, scan in self._pending.items():
            if scan.debounce_until <= now_mono:
                ready.append(scan)
            else:
                still_pending[path] = scan

        self._pending = still_pending

        if not ready:
            return

        # Sort by priority (0=CRITICAL first)
        ready.sort(key=lambda s: s.priority)

        for scan in ready:
            # Check rate limit
            if len(self._dispatch_times) >= self._rate_limit:
                # Put back into pending with no additional debounce
                self._pending[scan.file_path] = scan
                scan.debounce_until = now_mono + 5.0  # Retry in 5s
                self.total_events_rate_limited += 1
                continue

            # Dispatch
            self._dispatch_scan(scan)

            # Record dispatch time and set cooldown
            self._dispatch_times.append(now_mono)
            self._cooldowns[scan.file_path] = now_mono + self._cooldown
            self.total_scans_dispatched += 1

    def _dispatch_scan(self, scan: PendingScan) -> None:
        """Dispatch a scan task for the given file."""
        logger.info(
            "Triggering scan: %s (tier=%s, events=%d, debounced %.1fs)",
            scan.file_path,
            scan.risk_tier,
            scan.event_count,
            (scan.last_event_at - scan.first_event_at).total_seconds(),
        )

        if self._dispatch_callback is not None:
            try:
                self._dispatch_callback(scan.file_path, scan.risk_tier)
            except Exception:
                logger.error(
                    "Scan dispatch callback failed for %s",
                    scan.file_path,
                    exc_info=True,
                )

    def get_stats(self) -> dict:
        """Return current trigger buffer statistics."""
        return {
            "total_events_received": self.total_events_received,
            "total_scans_dispatched": self.total_scans_dispatched,
            "total_events_filtered": self.total_events_filtered,
            "total_events_debounced": self.total_events_debounced,
            "total_events_rate_limited": self.total_events_rate_limited,
            "pending_scans": len(self._pending),
            "active_cooldowns": len(self._cooldowns),
        }
