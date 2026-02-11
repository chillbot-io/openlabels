"""Tests for ResultService."""

from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from openlabels.server.services.base import TenantContext
from openlabels.server.services.result_service import ResultService


def _make_service(session, tenant_id):
    tenant = TenantContext(tenant_id=tenant_id, user_id=uuid4())
    return ResultService(session, tenant, MagicMock())


@pytest.fixture
async def result_fixtures(test_db):
    """Create tenant, job, and sample results."""
    from openlabels.server.models import Tenant, User, ScanTarget, ScanJob, ScanResult

    tenant = Tenant(name="Result Tenant", azure_tenant_id="result-test-tid")
    test_db.add(tenant)
    await test_db.flush()

    user = User(tenant_id=tenant.id, email="result@test.com", name="Tester", role="admin")
    test_db.add(user)
    await test_db.flush()

    target = ScanTarget(
        tenant_id=tenant.id, name="Target", adapter="filesystem",
        config={"path": "/tmp"}, created_by=user.id,
    )
    test_db.add(target)
    await test_db.flush()

    job = ScanJob(
        tenant_id=tenant.id, target_id=target.id, target_name="Target",
        name="Test Scan", status="completed", created_by=user.id,
    )
    test_db.add(job)
    await test_db.flush()

    # Create results with varying risk tiers
    results = []
    for i, (tier, score, entities) in enumerate([
        ("CRITICAL", 95, {"SSN": 3, "CREDIT_CARD": 2}),
        ("HIGH", 80, {"SSN": 1}),
        ("MEDIUM", 50, {"EMAIL": 5}),
        ("LOW", 25, {}),
        ("MINIMAL", 5, {}),
    ]):
        r = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path=f"/data/file{i}.txt",
            file_name=f"file{i}.txt",
            risk_score=score,
            risk_tier=tier,
            entity_counts=entities,
            total_entities=sum(entities.values()),
        )
        test_db.add(r)
        results.append(r)

    await test_db.commit()
    for r in results:
        await test_db.refresh(r)

    return {
        "tenant": tenant,
        "job": job,
        "results": results,
        "session": test_db,
    }


class TestGetResult:
    @pytest.mark.asyncio
    async def test_get_result_own_tenant(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        result = await svc.get_result(f["results"][0].id)
        assert result.id == f["results"][0].id
        assert result.risk_tier == "CRITICAL"
        assert result.risk_score == 95
        assert result.file_path == "/data/file0.txt"
        assert result.tenant_id == f["tenant"].id

    @pytest.mark.asyncio
    async def test_get_result_wrong_tenant(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], uuid4())

        result = await svc.get_result(f["results"][0].id)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_result_nonexistent(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        result = await svc.get_result(uuid4())
        assert result is None


class TestListResults:
    @pytest.mark.asyncio
    async def test_list_all(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        results, total = await svc.list_results()
        assert total == 5
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_list_by_job(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        results, total = await svc.list_results(job_id=f["job"].id)
        assert total == 5

    @pytest.mark.asyncio
    async def test_list_by_risk_tier(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        results, total = await svc.list_results(risk_tier="CRITICAL")
        assert total == 1
        assert results[0].risk_tier == "CRITICAL"

    @pytest.mark.asyncio
    async def test_list_has_pii(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        results, total = await svc.list_results(has_pii=True)
        assert total == 3  # CRITICAL, HIGH, MEDIUM have entities

    @pytest.mark.asyncio
    async def test_list_no_pii(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        results, total = await svc.list_results(has_pii=False)
        assert total == 2  # LOW, MINIMAL

    @pytest.mark.asyncio
    async def test_list_pagination(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        results, total = await svc.list_results(limit=2, offset=0)
        assert total == 5
        assert len(results) == 2


class TestDeleteResults:
    @pytest.mark.asyncio
    async def test_delete_by_job(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        deleted = await svc.delete_results(job_id=f["job"].id)
        assert deleted == 5

        _, total = await svc.list_results()
        assert total == 0


class TestGetStats:
    @pytest.mark.asyncio
    async def test_get_stats(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        stats = await svc.get_stats()
        assert stats["total_files"] == 5
        assert stats["files_with_pii"] == 3
        assert stats["critical_count"] == 1
        assert stats["high_count"] == 1
        assert stats["medium_count"] == 1
        assert stats["low_count"] == 1
        assert stats["minimal_count"] == 1

    @pytest.mark.asyncio
    async def test_get_stats_by_job(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        stats = await svc.get_stats(job_id=f["job"].id)
        assert stats["total_files"] == 5


class TestGetEntityTypeStats:
    @pytest.mark.asyncio
    async def test_entity_type_aggregation(self, result_fixtures):
        f = result_fixtures
        svc = _make_service(f["session"], f["tenant"].id)

        entity_stats = await svc.get_entity_type_stats()
        assert entity_stats["EMAIL"] == 5
        assert entity_stats["SSN"] == 4  # 3 + 1
        assert entity_stats["CREDIT_CARD"] == 2
