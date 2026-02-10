"""
Comprehensive tests for job queue API endpoints.

Tests focus on:
- Queue statistics endpoint
- Failed jobs listing and pagination
- Job details retrieval
- Requeue operations
- Job cancellation
- Worker status and configuration

All routes are mounted at /api/v1/jobs.
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4


@pytest.fixture
async def setup_jobs_data(test_db):
    """Set up test data for jobs endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, JobQueue as JobQueueModel

    # Get the existing tenant created by test_client (name includes random suffix)
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create various job queue entries
    jobs = []

    # Pending jobs
    for i in range(3):
        job = JobQueueModel(
            id=uuid4(),
            tenant_id=tenant.id,
            task_type="scan",
            payload={"target_id": str(uuid4())},
            priority=50,
            status="pending",
        )
        test_db.add(job)
        jobs.append(job)

    # Running jobs
    for i in range(2):
        job = JobQueueModel(
            id=uuid4(),
            tenant_id=tenant.id,
            task_type="label",
            payload={"file_id": str(uuid4())},
            priority=50,
            status="running",
            worker_id=f"worker-{i}",
            started_at=datetime.now(timezone.utc),
        )
        test_db.add(job)
        jobs.append(job)

    # Completed jobs
    for i in range(5):
        job = JobQueueModel(
            id=uuid4(),
            tenant_id=tenant.id,
            task_type="scan",
            payload={"target_id": str(uuid4())},
            priority=50,
            status="completed",
            completed_at=datetime.now(timezone.utc),
            result={"files_scanned": 100},
        )
        test_db.add(job)
        jobs.append(job)

    # Failed jobs
    failed_jobs = []
    for i in range(4):
        job = JobQueueModel(
            id=uuid4(),
            tenant_id=tenant.id,
            task_type="scan" if i < 2 else "label",
            payload={"target_id": str(uuid4())},
            priority=50,
            status="failed",
            error=f"Test error {i}",
            retry_count=3,
        )
        test_db.add(job)
        jobs.append(job)
        failed_jobs.append(job)

    # Cancelled jobs
    cancelled_job = JobQueueModel(
        id=uuid4(),
        tenant_id=tenant.id,
        task_type="scan",
        payload={"target_id": str(uuid4())},
        priority=50,
        status="cancelled",
    )
    test_db.add(cancelled_job)
    jobs.append(cancelled_job)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "jobs": jobs,
        "failed_jobs": failed_jobs,
        "session": test_db,
    }


class TestQueueStats:
    """Tests for GET /api/v1/jobs/stats endpoint."""

    async def test_returns_200_status(self, test_client, setup_jobs_data):
        """Stats endpoint should return 200 OK."""
        response = await test_client.get("/api/v1/jobs/stats")
        assert response.status_code == 200

    async def test_returns_stats_structure(self, test_client, setup_jobs_data):
        """Response should have expected stats structure."""
        response = await test_client.get("/api/v1/jobs/stats")
        assert response.status_code == 200
        data = response.json()

        assert "pending" in data
        assert "running" in data
        assert "completed" in data
        assert "failed" in data
        assert "cancelled" in data
        assert "failed_by_type" in data

    async def test_counts_are_accurate(self, test_client, setup_jobs_data):
        """Stats should accurately count jobs by status."""
        response = await test_client.get("/api/v1/jobs/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["pending"] == 3
        assert data["running"] == 2
        assert data["completed"] == 5
        assert data["failed"] == 4
        assert data["cancelled"] == 1

    async def test_failed_by_type_breakdown(self, test_client, setup_jobs_data):
        """Should break down failed jobs by task type."""
        response = await test_client.get("/api/v1/jobs/stats")
        assert response.status_code == 200
        data = response.json()

        failed_by_type = data["failed_by_type"]
        assert isinstance(failed_by_type, dict)
        # We have 2 failed scan jobs and 2 failed label jobs
        assert failed_by_type.get("scan", 0) == 2
        assert failed_by_type.get("label", 0) == 2

    async def test_root_endpoint_also_returns_stats(self, test_client, setup_jobs_data):
        """GET /api/v1/jobs should also return QueueStatsResponse."""
        response = await test_client.get("/api/v1/jobs")
        assert response.status_code == 200
        data = response.json()

        assert "pending" in data
        assert "running" in data
        assert "completed" in data
        assert "failed" in data
        assert "cancelled" in data
        assert "failed_by_type" in data


class TestListFailedJobs:
    """Tests for GET /api/v1/jobs/failed endpoint."""

    async def test_returns_200_status(self, test_client, setup_jobs_data):
        """Failed jobs endpoint should return 200 OK."""
        response = await test_client.get("/api/v1/jobs/failed")
        assert response.status_code == 200

    async def test_returns_paginated_response(self, test_client, setup_jobs_data):
        """Response should have full pagination structure."""
        response = await test_client.get("/api/v1/jobs/failed")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data
        assert "has_next" in data
        assert "has_previous" in data

    async def test_only_returns_failed_jobs(self, test_client, setup_jobs_data):
        """Should only return jobs with failed status."""
        response = await test_client.get("/api/v1/jobs/failed")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["status"] == "failed"

    async def test_total_count_is_accurate(self, test_client, setup_jobs_data):
        """Total count should match number of failed jobs."""
        response = await test_client.get("/api/v1/jobs/failed")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 4

    async def test_filter_by_task_type(self, test_client, setup_jobs_data):
        """Should filter failed jobs by task type."""
        response = await test_client.get("/api/v1/jobs/failed?task_type=scan")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["task_type"] == "scan"

    async def test_pagination_works(self, test_client, setup_jobs_data):
        """Should respect pagination parameters."""
        response = await test_client.get("/api/v1/jobs/failed?page=1&page_size=2")
        assert response.status_code == 200
        data = response.json()

        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["items"]) <= 2
        assert data["total_pages"] >= 1
        assert isinstance(data["has_next"], bool)
        assert isinstance(data["has_previous"], bool)

    async def test_job_response_structure(self, test_client, setup_jobs_data):
        """Job items should have expected fields matching JobResponse model."""
        response = await test_client.get("/api/v1/jobs/failed")
        assert response.status_code == 200
        data = response.json()

        if data["items"]:
            item = data["items"][0]
            assert "id" in item
            assert "task_type" in item
            assert "payload" in item
            assert "status" in item
            assert "error" in item
            assert "priority" in item
            assert "retry_count" in item
            assert "max_retries" in item
            assert "created_at" in item


class TestGetJob:
    """Tests for GET /api/v1/jobs/{job_id} endpoint."""

    async def test_returns_job_details(self, test_client, setup_jobs_data):
        """Should return job details."""
        job = setup_jobs_data["jobs"][0]
        response = await test_client.get(f"/api/v1/jobs/{job.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(job.id)
        assert data["task_type"] == job.task_type

    async def test_returns_404_for_nonexistent(self, test_client, setup_jobs_data):
        """Should return 404 for non-existent job."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/jobs/{fake_id}")
        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "NOT_FOUND"
        assert "message" in data

    async def test_returns_full_job_structure(self, test_client, setup_jobs_data):
        """Should return all job fields matching JobResponse model."""
        job = setup_jobs_data["jobs"][0]
        response = await test_client.get(f"/api/v1/jobs/{job.id}")
        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert "task_type" in data
        assert "payload" in data
        assert "priority" in data
        assert "status" in data
        assert "retry_count" in data
        assert "max_retries" in data
        assert "created_at" in data
        assert "scheduled_for" in data
        assert "started_at" in data
        assert "completed_at" in data
        assert "worker_id" in data
        assert "result" in data
        assert "error" in data


class TestRequeueJob:
    """Tests for POST /api/v1/jobs/{job_id}/requeue endpoint."""

    async def test_requeues_failed_job(self, test_client, setup_jobs_data):
        """Should requeue a failed job."""
        failed_job = setup_jobs_data["failed_jobs"][0]
        response = await test_client.post(
            f"/api/v1/jobs/{failed_job.id}/requeue",
            json={"reset_retries": True},
        )
        # Job exists in test data, requeue should succeed
        assert response.status_code == 200, \
            f"Expected 200 for requeuing existing failed job, got {response.status_code}"

    async def test_returns_success_message(self, test_client, setup_jobs_data):
        """Should return success message on requeue."""
        failed_job = setup_jobs_data["failed_jobs"][0]
        response = await test_client.post(
            f"/api/v1/jobs/{failed_job.id}/requeue",
            json={"reset_retries": True},
        )
        if response.status_code == 200:
            data = response.json()
            assert "message" in data
            assert "job_id" in data

    async def test_returns_404_for_nonexistent(self, test_client, setup_jobs_data):
        """Should return 404 for non-existent job."""
        fake_id = uuid4()
        response = await test_client.post(
            f"/api/v1/jobs/{fake_id}/requeue",
            json={"reset_retries": True},
        )
        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "NOT_FOUND"


class TestRequeueAllFailed:
    """Tests for POST /api/v1/jobs/requeue-all endpoint."""

    async def test_requeues_all_failed(self, test_client, setup_jobs_data):
        """Should requeue all failed jobs."""
        response = await test_client.post(
            "/api/v1/jobs/requeue-all",
            json={"reset_retries": True},
        )
        assert response.status_code == 200
        data = response.json()

        assert "message" in data
        assert "count" in data

    async def test_filter_by_task_type(self, test_client, setup_jobs_data):
        """Should only requeue failed jobs of specified type."""
        response = await test_client.post(
            "/api/v1/jobs/requeue-all",
            json={"task_type": "scan", "reset_retries": True},
        )
        assert response.status_code == 200
        data = response.json()

        assert "count" in data


class TestPurgeFailedJobs:
    """Tests for POST /api/v1/jobs/purge endpoint."""

    async def test_purges_failed_jobs(self, test_client, setup_jobs_data):
        """Should purge failed jobs."""
        response = await test_client.post(
            "/api/v1/jobs/purge",
            json={},
        )
        assert response.status_code == 200
        data = response.json()

        assert "message" in data
        assert "count" in data

    async def test_filter_by_task_type(self, test_client, setup_jobs_data):
        """Should only purge failed jobs of specified type."""
        response = await test_client.post(
            "/api/v1/jobs/purge",
            json={"task_type": "label"},
        )
        assert response.status_code == 200


class TestCancelJob:
    """Tests for POST /api/v1/jobs/{job_id}/cancel endpoint."""

    async def test_cancels_pending_job(self, test_client, setup_jobs_data):
        """Should cancel a pending job."""
        # Find a pending job
        pending_jobs = [j for j in setup_jobs_data["jobs"] if j.status == "pending"]
        assert pending_jobs, "Test setup should have pending jobs"
        job = pending_jobs[0]
        response = await test_client.post(f"/api/v1/jobs/{job.id}/cancel")
        # Pending job exists in test data, cancel should succeed
        assert response.status_code == 200, \
            f"Expected 200 for canceling existing pending job, got {response.status_code}"
        data = response.json()
        assert "message" in data
        assert "job_id" in data

    async def test_returns_404_for_nonexistent(self, test_client, setup_jobs_data):
        """Should return 404 for non-existent job."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/v1/jobs/{fake_id}/cancel")
        # Non-existent job should return 404 Not Found
        assert response.status_code == 404, \
            f"Expected 404 for canceling non-existent job, got {response.status_code}"
        data = response.json()
        assert data["error"] == "NOT_FOUND"


class TestWorkerStatus:
    """Tests for GET /api/v1/jobs/workers/status endpoint."""

    async def test_returns_200_status(self, test_client, setup_jobs_data):
        """Worker status endpoint should return 200 OK."""
        response = await test_client.get("/api/v1/jobs/workers/status")
        assert response.status_code == 200

    async def test_returns_status_structure(self, test_client, setup_jobs_data):
        """Response should have expected WorkerStatusResponse structure."""
        response = await test_client.get("/api/v1/jobs/workers/status")
        assert response.status_code == 200
        data = response.json()

        assert "status" in data
        assert "concurrency" in data
        assert "target_concurrency" in data
        assert "worker_id" in data
        assert "pid" in data

    async def test_no_running_workers_returns_stopped(self, test_client, setup_jobs_data):
        """With no running workers, status should be 'stopped'."""
        response = await test_client.get("/api/v1/jobs/workers/status")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "stopped"
        assert data["concurrency"] == 0
        assert data["target_concurrency"] == 0


class TestWorkerConfig:
    """Tests for POST /api/v1/jobs/workers/config endpoint."""

    async def test_requires_running_worker(self, test_client, setup_jobs_data):
        """Should fail with BAD_REQUEST if no worker is running."""
        from unittest.mock import patch, AsyncMock, MagicMock

        # Mock the state manager to return empty workers (no Redis needed)
        mock_state_manager = MagicMock()
        mock_state_manager.get_all_workers = AsyncMock(return_value={})

        with patch(
            "openlabels.jobs.worker.get_worker_state_manager",
            new_callable=AsyncMock,
            return_value=mock_state_manager,
        ):
            response = await test_client.post(
                "/api/v1/jobs/workers/config",
                json={"concurrency": 4},
            )
        # Expect 400 when no worker is running
        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "BAD_REQUEST"
        assert "message" in data


class TestJobsContentType:
    """Tests for response content type."""

    async def test_stats_returns_json(self, test_client, setup_jobs_data):
        """Stats endpoint should return JSON."""
        response = await test_client.get("/api/v1/jobs/stats")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    async def test_failed_returns_json(self, test_client, setup_jobs_data):
        """Failed jobs endpoint should return JSON."""
        response = await test_client.get("/api/v1/jobs/failed")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
