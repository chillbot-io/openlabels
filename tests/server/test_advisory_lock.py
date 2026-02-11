"""Tests for PostgreSQL advisory locks."""

import pytest

from openlabels.server.advisory_lock import AdvisoryLockID, try_advisory_lock


class TestAdvisoryLockID:
    def test_enum_values_are_unique(self):
        values = [member.value for member in AdvisoryLockID]
        assert len(values) == len(set(values))

    def test_known_lock_ids(self):
        assert AdvisoryLockID.EVENT_FLUSH == 100_001
        assert AdvisoryLockID.SIEM_EXPORT == 100_002
        assert AdvisoryLockID.STUCK_JOB_RECLAIM == 100_007


class TestTryAdvisoryLock:
    @pytest.mark.asyncio
    async def test_acquires_lock(self, test_db):
        acquired = await try_advisory_lock(test_db, AdvisoryLockID.EVENT_FLUSH)
        assert acquired is True

    @pytest.mark.asyncio
    async def test_same_session_can_reacquire(self, test_db):
        """Same session can acquire the same lock multiple times."""
        acquired1 = await try_advisory_lock(test_db, AdvisoryLockID.EVENT_FLUSH)
        acquired2 = await try_advisory_lock(test_db, AdvisoryLockID.EVENT_FLUSH)
        assert acquired1 is True
        assert acquired2 is True

    @pytest.mark.asyncio
    async def test_different_locks(self, test_db):
        a1 = await try_advisory_lock(test_db, AdvisoryLockID.EVENT_FLUSH)
        a2 = await try_advisory_lock(test_db, AdvisoryLockID.SIEM_EXPORT)
        assert a1 is True
        assert a2 is True
