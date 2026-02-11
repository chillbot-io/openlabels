"""Tests for BaseService and TenantContext."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from openlabels.server.services.base import BaseService, TenantContext


# ---------------------------------------------------------------------------
# TenantContext
# ---------------------------------------------------------------------------


class TestTenantContext:
    def test_system_context(self):
        tid = uuid4()
        ctx = TenantContext.system_context(tid)
        assert ctx.tenant_id == tid
        assert ctx.user_id is None
        assert ctx.user_email is None
        assert ctx.user_role is None

    def test_frozen(self):
        from pydantic import ValidationError

        ctx = TenantContext(tenant_id=uuid4())
        with pytest.raises(ValidationError):
            ctx.tenant_id = uuid4()

    def test_from_current_user(self):
        user = MagicMock()
        user.tenant_id = uuid4()
        user.id = uuid4()
        user.email = "user@test.com"
        user.role = "admin"

        ctx = TenantContext.from_current_user(user)
        assert ctx.tenant_id == user.tenant_id
        assert ctx.user_id == user.id
        assert ctx.user_email == "user@test.com"
        assert ctx.user_role == "admin"


# ---------------------------------------------------------------------------
# BaseService
# ---------------------------------------------------------------------------


class TestBaseServiceProperties:
    def test_property_accessors(self):
        session = MagicMock()
        tenant = TenantContext(tenant_id=uuid4(), user_id=uuid4())
        settings = MagicMock()

        svc = BaseService(session, tenant, settings)

        assert svc.session is session
        assert svc.tenant_id == tenant.tenant_id
        assert svc.user_id == tenant.user_id
        assert svc.settings is settings
        assert svc.tenant is tenant


class TestTransaction:
    @pytest.mark.asyncio
    async def test_commit_on_success(self):
        session = AsyncMock()
        tenant = TenantContext(tenant_id=uuid4())
        svc = BaseService(session, tenant, MagicMock())

        async with svc.transaction():
            pass

        session.commit.assert_awaited_once()
        session.rollback.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_rollback_on_exception(self):
        session = AsyncMock()
        tenant = TenantContext(tenant_id=uuid4())
        svc = BaseService(session, tenant, MagicMock())

        with pytest.raises(ValueError):
            async with svc.transaction():
                raise ValueError("boom")

        session.rollback.assert_awaited_once()
        session.commit.assert_not_awaited()


class TestGetTenantEntity:
    @pytest.mark.asyncio
    async def test_returns_entity_for_correct_tenant(self):
        tid = uuid4()
        eid = uuid4()
        entity = MagicMock()
        entity.tenant_id = tid

        session = AsyncMock()
        session.get.return_value = entity

        svc = BaseService(session, TenantContext(tenant_id=tid), MagicMock())
        result = await svc.get_tenant_entity(MagicMock, eid)

        assert result is entity

    @pytest.mark.asyncio
    async def test_raises_not_found_for_wrong_tenant(self):
        from openlabels.exceptions import NotFoundError

        entity = MagicMock()
        entity.tenant_id = uuid4()

        session = AsyncMock()
        session.get.return_value = entity

        svc = BaseService(session, TenantContext(tenant_id=uuid4()), MagicMock())
        with pytest.raises(NotFoundError):
            await svc.get_tenant_entity(MagicMock, uuid4())

    @pytest.mark.asyncio
    async def test_raises_not_found_for_missing_entity(self):
        from openlabels.exceptions import NotFoundError

        session = AsyncMock()
        session.get.return_value = None

        svc = BaseService(session, TenantContext(tenant_id=uuid4()), MagicMock())
        with pytest.raises(NotFoundError):
            await svc.get_tenant_entity(MagicMock, uuid4())


class TestBaseServiceDB:
    """Tests requiring a real database session."""

    @pytest.mark.asyncio
    async def test_paginate_returns_items_and_total(self, test_db):
        from openlabels.server.models import Tenant

        # Create some tenants
        for i in range(5):
            t = Tenant(name=f"Tenant {i}", azure_tenant_id=f"azure-{i}-pag")
            test_db.add(t)
        await test_db.commit()

        from sqlalchemy import select

        svc = BaseService(test_db, TenantContext(tenant_id=uuid4()), MagicMock())
        query = select(Tenant)
        items, total = await svc.paginate(query, limit=3, offset=0)

        assert total == 5
        assert len(items) == 3

    @pytest.mark.asyncio
    async def test_paginate_empty(self, test_db):
        from openlabels.server.models import Tenant
        from sqlalchemy import select

        svc = BaseService(test_db, TenantContext(tenant_id=uuid4()), MagicMock())
        query = select(Tenant).where(Tenant.name == "nonexistent")
        items, total = await svc.paginate(query)

        assert total == 0
        assert items == []
