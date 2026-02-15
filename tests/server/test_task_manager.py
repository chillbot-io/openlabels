"""Tests for BackgroundTaskManager."""

from __future__ import annotations

import asyncio

import pytest

from openlabels.server.task_manager import BackgroundTaskManager, TaskStatus


@pytest.fixture
def mgr() -> BackgroundTaskManager:
    return BackgroundTaskManager(max_restarts=3, max_backoff=0.2)


class TestRegisterTask:
    """Test registering an already-created asyncio.Task."""

    @pytest.mark.asyncio
    async def test_register_and_status(self, mgr: BackgroundTaskManager):
        shutdown = asyncio.Event()

        async def _worker():
            await shutdown.wait()

        task = asyncio.create_task(_worker())
        mgr.register_task("test_worker", task, shutdown)

        status = mgr.get_status()
        assert len(status) == 1
        assert status[0]["name"] == "test_worker"
        assert status[0]["status"] == "running"

        shutdown.set()
        await task

    @pytest.mark.asyncio
    async def test_is_healthy_when_running(self, mgr: BackgroundTaskManager):
        shutdown = asyncio.Event()

        async def _worker():
            await shutdown.wait()

        task = asyncio.create_task(_worker())
        mgr.register_task("healthy", task, shutdown)

        assert mgr.is_healthy() is True

        shutdown.set()
        await task


class TestSupervisedTask:
    """Test supervised task with auto-restart."""

    @pytest.mark.asyncio
    async def test_normal_completion(self, mgr: BackgroundTaskManager):
        """Task that exits normally when shutdown is set."""
        call_count = 0

        async def _task(shutdown_event: asyncio.Event, **_kw):
            nonlocal call_count
            call_count += 1
            await shutdown_event.wait()

        shutdown = asyncio.Event()
        task = mgr.supervised_task("normal", _task, shutdown_event=shutdown)

        await asyncio.sleep(0.05)
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)

        assert call_count == 1
        status = mgr.get_status()
        assert status[0]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_restart_on_crash(self, mgr: BackgroundTaskManager):
        """Task that crashes and gets restarted."""
        call_count = 0

        async def _crashing_task(shutdown_event: asyncio.Event, **_kw):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError(f"Crash #{call_count}")
            await shutdown_event.wait()

        shutdown = asyncio.Event()
        task = mgr.supervised_task("crasher", _crashing_task, shutdown_event=shutdown)

        # Wait for restarts (backoff: 0.2s max, so 2 restarts need ~0.6s)
        await asyncio.sleep(2.0)
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)

        assert call_count == 3  # crashed 2 times, 3rd run is normal

    @pytest.mark.asyncio
    async def test_max_restarts_exceeded(self, mgr: BackgroundTaskManager):
        """Task gives up after max consecutive failures."""
        call_count = 0

        async def _always_crashes(shutdown_event: asyncio.Event, **_kw):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("always fails")

        shutdown = asyncio.Event()
        task = mgr.supervised_task("doomed", _always_crashes, shutdown_event=shutdown)

        await asyncio.wait_for(task, timeout=10.0)

        # max_restarts=3, so it should crash 4 times (initial + 3 retries)
        assert call_count == 4
        status = mgr.get_status()
        assert status[0]["status"] == "stopped"
        assert status[0]["errors_total"] == 4

    @pytest.mark.asyncio
    async def test_kwargs_passed_through(self, mgr: BackgroundTaskManager):
        """Extra kwargs are forwarded to the coro factory."""
        received = {}

        async def _task(shutdown_event: asyncio.Event, **kwargs):
            received.update(kwargs)
            await shutdown_event.wait()

        shutdown = asyncio.Event()
        task = mgr.supervised_task(
            "params", _task, shutdown_event=shutdown, interval=42, label="test"
        )

        await asyncio.sleep(0.05)
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)

        assert received["interval"] == 42
        assert received["label"] == "test"


class TestHeartbeat:
    """Test heartbeat mechanism."""

    @pytest.mark.asyncio
    async def test_heartbeat_resets_consecutive_failures(self, mgr: BackgroundTaskManager):
        shutdown = asyncio.Event()

        async def _worker():
            await shutdown.wait()

        task = asyncio.create_task(_worker())
        mgr.register_task("hb", task, shutdown)

        # Simulate some failures then heartbeat
        info = mgr._tasks["hb"]
        info.consecutive_failures = 3
        mgr.heartbeat("hb")

        assert info.consecutive_failures == 0
        assert info.cycles_completed == 1

        shutdown.set()
        await task

    def test_heartbeat_unknown_task(self, mgr: BackgroundTaskManager):
        """Heartbeat for unknown task is silently ignored."""
        mgr.heartbeat("nonexistent")  # should not raise


class TestStopAll:
    """Test coordinated shutdown."""

    @pytest.mark.asyncio
    async def test_stops_all_tasks(self, mgr: BackgroundTaskManager):
        events = []

        async def _task(shutdown_event: asyncio.Event, label: str = ""):
            await shutdown_event.wait()
            events.append(label)

        s1 = asyncio.Event()
        s2 = asyncio.Event()
        mgr.supervised_task("a", _task, shutdown_event=s1, label="a")
        mgr.supervised_task("b", _task, shutdown_event=s2, label="b")

        await asyncio.sleep(0.05)
        await mgr.stop_all(timeout=2.0)

        assert "a" in events
        assert "b" in events

    @pytest.mark.asyncio
    async def test_force_cancels_stuck_tasks(self, mgr: BackgroundTaskManager):
        """Tasks that don't respond to shutdown are force-cancelled."""

        async def _stuck(shutdown_event: asyncio.Event, **_kw):
            while True:
                await asyncio.sleep(100)  # ignores shutdown

        mgr.supervised_task("stuck", _stuck)

        await asyncio.sleep(0.05)
        await mgr.stop_all(timeout=0.2)

        status = mgr.get_status()
        assert status[0]["status"] == "stopped"


class TestGetStatus:
    """Test status reporting."""

    @pytest.mark.asyncio
    async def test_empty_manager(self, mgr: BackgroundTaskManager):
        assert mgr.get_status() == []
        assert mgr.is_healthy() is True

    @pytest.mark.asyncio
    async def test_status_includes_error_info(self, mgr: BackgroundTaskManager):
        call_count = 0

        async def _crashes_once(shutdown_event: asyncio.Event, **_kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("test error")
            await shutdown_event.wait()

        shutdown = asyncio.Event()
        mgr.supervised_task("err", _crashes_once, shutdown_event=shutdown)

        await asyncio.sleep(0.5)
        status = mgr.get_status()
        assert status[0]["errors_total"] >= 1
        assert "ValueError" in (status[0].get("last_error") or "")

        shutdown.set()
        await asyncio.sleep(0.1)
