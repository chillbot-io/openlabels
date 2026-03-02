"""Tests for the in-memory per-tenant rate limiter.

Covers:
* Basic rate limiting (requests allowed / denied at the boundary)
* Per-tenant isolation (one tenant's usage does not affect another)
* Stale-entry sweep (entries whose timestamps have all expired are removed)
* Max-size LRU eviction (oldest-accessed tenants are evicted when cap is hit)
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from openlabels.server.middleware.rate_limit import _InMemoryTenantBackend


# ── Basic rate limiting ───────────────────────────────────────────────

class TestBasicRateLimiting:
    def test_allows_requests_within_limit(self):
        backend = _InMemoryTenantBackend()
        for _ in range(5):
            allowed, m_rem, h_rem = backend.check_and_record("t1", rpm_limit=10, rph_limit=100)
            assert allowed is True
        # 5 requests used out of 10 RPM
        assert m_rem == 5

    def test_denies_when_rpm_exceeded(self):
        backend = _InMemoryTenantBackend()
        for _ in range(5):
            backend.check_and_record("t1", rpm_limit=5, rph_limit=100)
        # 6th request should be denied
        allowed, m_rem, h_rem = backend.check_and_record("t1", rpm_limit=5, rph_limit=100)
        assert allowed is False
        assert m_rem == 0

    def test_denies_when_rph_exceeded(self):
        backend = _InMemoryTenantBackend()
        for _ in range(3):
            backend.check_and_record("t1", rpm_limit=100, rph_limit=3)
        allowed, _, _ = backend.check_and_record("t1", rpm_limit=100, rph_limit=3)
        assert allowed is False

    def test_allows_after_window_expires(self):
        """After the minute window expires, requests should be allowed again."""
        backend = _InMemoryTenantBackend()
        # Fill up the minute limit
        for _ in range(5):
            backend.check_and_record("t1", rpm_limit=5, rph_limit=100)

        # Simulate time passing beyond the 60-second window by patching
        # monotonic to return a future timestamp.
        future = time.monotonic() + 61
        with patch("openlabels.server.middleware.rate_limit.time") as mock_time:
            mock_time.monotonic.return_value = future
            allowed, m_rem, _ = backend.check_and_record("t1", rpm_limit=5, rph_limit=100)
        assert allowed is True


# ── Per-tenant isolation ──────────────────────────────────────────────

class TestPerTenantIsolation:
    def test_tenants_have_independent_limits(self):
        backend = _InMemoryTenantBackend()
        # Fill up tenant A
        for _ in range(5):
            backend.check_and_record("tenant_a", rpm_limit=5, rph_limit=100)

        # Tenant A is now at the limit
        allowed_a, _, _ = backend.check_and_record("tenant_a", rpm_limit=5, rph_limit=100)
        assert allowed_a is False

        # Tenant B should still be allowed
        allowed_b, m_rem, _ = backend.check_and_record("tenant_b", rpm_limit=5, rph_limit=100)
        assert allowed_b is True
        assert m_rem == 4  # 1 used out of 5


# ── Stale entry sweep ────────────────────────────────────────────────

class TestStaleEntrySweep:
    def test_sweep_removes_expired_tenants(self):
        """Tenants whose timestamps are all older than the hour window
        should be removed during the periodic sweep.
        """
        backend = _InMemoryTenantBackend(sweep_interval=0)  # sweep every call

        # Record requests for two tenants
        backend.check_and_record("stale_tenant", rpm_limit=100, rph_limit=100)
        backend.check_and_record("active_tenant", rpm_limit=100, rph_limit=100)

        assert "stale_tenant" in backend._last_access
        assert "active_tenant" in backend._last_access

        # Fast-forward time beyond the 1-hour window so stale_tenant's
        # timestamps are all expired, then make a request from active_tenant
        # which triggers a sweep.
        future = time.monotonic() + 3601
        with patch("openlabels.server.middleware.rate_limit.time") as mock_time:
            mock_time.monotonic.return_value = future
            # active_tenant makes a new request — triggers sweep
            backend.check_and_record("active_tenant", rpm_limit=100, rph_limit=100)

        # stale_tenant should have been evicted; active_tenant stays
        assert "stale_tenant" not in backend._last_access
        assert "stale_tenant" not in backend._minute_counts
        assert "stale_tenant" not in backend._hour_counts
        # active_tenant still present (it just recorded a new timestamp)
        assert "active_tenant" in backend._last_access

    def test_sweep_does_not_remove_active_tenants(self):
        """Tenants with recent timestamps should survive a sweep."""
        backend = _InMemoryTenantBackend(sweep_interval=0)

        backend.check_and_record("t1", rpm_limit=100, rph_limit=100)
        backend.check_and_record("t2", rpm_limit=100, rph_limit=100)

        # Trigger sweep without advancing time — both should remain
        now = time.monotonic()
        with backend._lock:
            backend._sweep_stale(now)

        assert "t1" in backend._last_access
        assert "t2" in backend._last_access


# ── Max-size LRU eviction ────────────────────────────────────────────

class TestLRUEviction:
    def test_evicts_oldest_when_max_exceeded(self):
        """When the tenant count exceeds max_tenants, the oldest-accessed
        half should be evicted.
        """
        backend = _InMemoryTenantBackend(max_tenants=4)

        # Record requests for 4 tenants (at capacity)
        for i in range(4):
            backend.check_and_record(f"t{i}", rpm_limit=100, rph_limit=100)
        assert len(backend._last_access) == 4

        # 5th tenant pushes us over the max → LRU eviction
        backend.check_and_record("t_new", rpm_limit=100, rph_limit=100)

        # After eviction of oldest half (2 out of 5), we should have <= max
        assert len(backend._last_access) <= 4
        # The newest tenant should definitely survive
        assert "t_new" in backend._last_access

    def test_eviction_removes_least_recently_accessed(self):
        """The evicted tenants should be those with the oldest access times."""
        backend = _InMemoryTenantBackend(max_tenants=3)

        # Access t0 earliest, then t1, t2
        base = time.monotonic()
        with patch("openlabels.server.middleware.rate_limit.time") as mock_time:
            for i in range(3):
                mock_time.monotonic.return_value = base + i
                backend.check_and_record(f"t{i}", rpm_limit=100, rph_limit=100)

            # t3 triggers eviction; oldest half (t0) should be evicted
            mock_time.monotonic.return_value = base + 3
            backend.check_and_record("t3", rpm_limit=100, rph_limit=100)

        # t0 was the least recently accessed and should be gone
        assert "t0" not in backend._last_access
        # t3 (newest) must survive
        assert "t3" in backend._last_access

    def test_rate_limit_state_cleared_on_eviction(self):
        """Evicted tenants should lose their minute and hour counts."""
        backend = _InMemoryTenantBackend(max_tenants=2)

        backend.check_and_record("early", rpm_limit=100, rph_limit=100)
        backend.check_and_record("middle", rpm_limit=100, rph_limit=100)
        backend.check_and_record("late", rpm_limit=100, rph_limit=100)

        # 'early' should have been evicted (oldest of 3 when max is 2)
        assert "early" not in backend._minute_counts
        assert "early" not in backend._hour_counts
        assert "early" not in backend._last_access
