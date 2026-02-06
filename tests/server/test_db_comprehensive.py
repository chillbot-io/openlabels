"""
Tests for database connection and session management.

Unit tests verify error conditions and basic behavior.
Integration tests verify actual database behavior with PostgreSQL.

Run integration tests with:
    export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"
    pytest tests/server/test_db_comprehensive.py -v
"""

import pytest

from openlabels.server.db import (
    Base,
    close_db,
    get_session,
    get_session_context,
    get_session_factory,
    init_db,
)


class TestGetSessionUninitialized:
    """Tests for get_session error handling when not initialized."""

    async def test_raises_runtime_error(self):
        """get_session raises RuntimeError if database not initialized."""
        import openlabels.server.db as db_module

        original_factory = db_module._session_factory
        try:
            db_module._session_factory = None

            with pytest.raises(RuntimeError, match="Database not initialized"):
                async for session in get_session():
                    pass
        finally:
            db_module._session_factory = original_factory


class TestGetSessionContextUninitialized:
    """Tests for get_session_context error handling."""

    async def test_raises_runtime_error(self):
        """get_session_context raises RuntimeError if not initialized."""
        import openlabels.server.db as db_module

        original_factory = db_module._session_factory
        try:
            db_module._session_factory = None

            with pytest.raises(RuntimeError, match="Database not initialized"):
                async with get_session_context() as session:
                    pass
        finally:
            db_module._session_factory = original_factory


class TestGetSessionFactoryUninitialized:
    """Tests for get_session_factory error handling."""

    def test_raises_runtime_error(self):
        """get_session_factory raises RuntimeError if not initialized."""
        import openlabels.server.db as db_module

        original_factory = db_module._session_factory
        try:
            db_module._session_factory = None

            with pytest.raises(RuntimeError, match="Database not initialized"):
                get_session_factory()
        finally:
            db_module._session_factory = original_factory


class TestCloseDatabaseUninitialized:
    """Tests for close_db when not initialized."""

    async def test_handles_no_engine(self):
        """close_db should not raise when no engine exists."""
        import openlabels.server.db as db_module

        original_engine = db_module._engine
        try:
            db_module._engine = None

            # Should not raise
            await close_db()

            assert db_module._engine is None
        finally:
            db_module._engine = original_engine


# =============================================================================
# INTEGRATION TESTS - Require PostgreSQL
# =============================================================================


@pytest.mark.integration
class TestInitDbIntegration:
    """Integration tests for init_db with real PostgreSQL."""

    async def test_creates_working_engine(self, database_url):
        """init_db should create an engine that can connect."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            db_module._engine = None
            db_module._session_factory = None

            await init_db(database_url)

            assert db_module._engine is not None
            assert db_module._session_factory is not None

            # Should be able to execute a query
            async with db_module._session_factory() as session:
                from sqlalchemy import text
                result = await session.execute(text("SELECT 1"))
                assert result.scalar() == 1
        finally:
            if db_module._engine:
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory


@pytest.mark.integration
class TestGetSessionIntegration:
    """Integration tests for get_session with real PostgreSQL."""

    async def test_yields_working_session(self, database_url):
        """get_session should yield a session that can execute queries."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            async for session in get_session():
                from sqlalchemy import text
                result = await session.execute(text("SELECT 1 + 1"))
                assert result.scalar() == 2
                break
        finally:
            if db_module._engine:
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory

    async def test_commits_on_success(self, database_url):
        """get_session should commit changes on successful completion."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module
        from openlabels.server.models import Tenant

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            async with db_module._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            tenant_name = f"test-commit-{id(self)}"

            # Insert through get_session using async-for pattern.
            # Do NOT use break - it triggers GeneratorExit which bypasses commit.
            # The generator only yields once, so the loop exits naturally after commit.
            async for session in get_session():
                tenant = Tenant(name=tenant_name)
                session.add(tenant)

            # Verify commit in new session
            async for session2 in get_session():
                from sqlalchemy import select
                result = await session2.execute(
                    select(Tenant).where(Tenant.name == tenant_name)
                )
                found = result.scalar_one_or_none()
                assert found is not None
                assert found.name == tenant_name
                break
        finally:
            if db_module._engine:
                async with db_module._engine.begin() as conn:
                    await conn.run_sync(Base.metadata.drop_all)
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory

    async def test_rollbacks_on_exception(self, database_url):
        """get_session should rollback on exception."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module
        from openlabels.server.models import Tenant

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            async with db_module._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            tenant_name = f"test-rollback-{id(self)}"

            # Insert and raise exception
            with pytest.raises(ValueError):
                async for session in get_session():
                    tenant = Tenant(name=tenant_name)
                    session.add(tenant)
                    raise ValueError("Trigger rollback")

            # Verify rollback - tenant should not exist
            async for session in get_session():
                from sqlalchemy import select
                result = await session.execute(
                    select(Tenant).where(Tenant.name == tenant_name)
                )
                found = result.scalar_one_or_none()
                assert found is None, "Tenant should not exist after rollback"
                break
        finally:
            if db_module._engine:
                async with db_module._engine.begin() as conn:
                    await conn.run_sync(Base.metadata.drop_all)
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory


@pytest.mark.integration
class TestGetSessionContextIntegration:
    """Integration tests for get_session_context."""

    async def test_yields_working_session(self, database_url):
        """get_session_context should yield a working session."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            async with get_session_context() as session:
                from sqlalchemy import text
                result = await session.execute(text("SELECT 2 * 3"))
                assert result.scalar() == 6
        finally:
            if db_module._engine:
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory

    async def test_commits_on_success(self, database_url):
        """get_session_context should commit on successful exit."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module
        from openlabels.server.models import Tenant

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            async with db_module._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            tenant_name = f"test-context-commit-{id(self)}"

            async with get_session_context() as session:
                tenant = Tenant(name=tenant_name)
                session.add(tenant)

            # Verify commit
            async with get_session_context() as session:
                from sqlalchemy import select
                result = await session.execute(
                    select(Tenant).where(Tenant.name == tenant_name)
                )
                found = result.scalar_one_or_none()
                assert found is not None
        finally:
            if db_module._engine:
                async with db_module._engine.begin() as conn:
                    await conn.run_sync(Base.metadata.drop_all)
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory

    async def test_rollbacks_on_exception(self, database_url):
        """get_session_context should rollback on exception."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module
        from openlabels.server.models import Tenant

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            async with db_module._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            tenant_name = f"test-context-rollback-{id(self)}"

            with pytest.raises(ValueError):
                async with get_session_context() as session:
                    tenant = Tenant(name=tenant_name)
                    session.add(tenant)
                    raise ValueError("Trigger rollback")

            # Verify rollback
            async with get_session_context() as session:
                from sqlalchemy import select
                result = await session.execute(
                    select(Tenant).where(Tenant.name == tenant_name)
                )
                found = result.scalar_one_or_none()
                assert found is None, "Tenant should not exist after rollback"
        finally:
            if db_module._engine:
                async with db_module._engine.begin() as conn:
                    await conn.run_sync(Base.metadata.drop_all)
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory


@pytest.mark.integration
class TestCloseDbIntegration:
    """Integration tests for close_db."""

    async def test_disposes_engine(self, database_url):
        """close_db should dispose the engine properly."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)
            assert db_module._engine is not None

            await close_db()

            assert db_module._engine is None
        finally:
            db_module._engine = original_engine
            db_module._session_factory = original_factory


@pytest.mark.integration
class TestGetSessionFactoryIntegration:
    """Integration tests for get_session_factory."""

    async def test_returns_working_factory(self, database_url):
        """get_session_factory should return a usable factory."""
        if not database_url:
            pytest.skip("PostgreSQL not available")

        import openlabels.server.db as db_module

        original_engine = db_module._engine
        original_factory = db_module._session_factory

        try:
            await init_db(database_url)

            factory = get_session_factory()
            assert factory is not None

            async with factory() as session:
                from sqlalchemy import text
                result = await session.execute(text("SELECT 1"))
                assert result.scalar() == 1
        finally:
            if db_module._engine:
                await db_module._engine.dispose()
            db_module._engine = original_engine
            db_module._session_factory = original_factory
